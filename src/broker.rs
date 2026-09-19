//! The broker daemon: owns the vault session and serves wire requests over
//! the Unix domain socket. Dispatch is pure (`handle_request`) so the full
//! authn/authz matrix is testable without sockets; `serve` is the thin
//! socket loop (peer-UID check + thread per connection).

use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::audit::{Decision, Record};
use crate::broker_identity;
use crate::envelope::DerivedKeks;
use crate::error::VaultError;
use crate::fdpass;
use crate::fsops;
use crate::model::Op;
use crate::run;
use crate::session::{Session, SystemClock};
use crate::store;
use crate::wire::{self, Request, Response};

/// Operations only the human owner may call. An agent token on any of these
/// is rejected (`E_HUMAN_REQUIRED`) — I3.
const HUMAN_ONLY: &[&str] = &[
    "vault.create",
    "vault.unlock",
    "project.add",
    "project.list",
    "project.path.add",
    "project.path.remove",
    "project.remove",
    "secret.set",
    "secret.delete",
    "agents.add",
    "agents.revoke",
    "agents.list",
    "grants.grant",
    "grants.revoke",
    "grants.list",
    "audit.show",
    "audit.verify",
    "approvals.pending",
    "approvals.approve",
    "approvals.deny",
    "session.open",
    "session.touch",
    "session.close",
    "runs.list",
    "vault.health",
];

/// Agent-reachable ops not implemented in this build.
const NOT_YET: &[&str] = &[];

/// Parse the presented lease *credential* (`params.lease`) and refuse a
/// `lease_id` handle presented in its place.
///
/// The public `lease_id` authorizes nothing: it is a listing/revocation handle
/// (the MCP adapter maps it to a credential it holds, and the CLI uses the
/// credential file). Accepting it by ignoring it would silently run the
/// request on the caller's **full grant** — the opposite of what a caller
/// naming a lease intends — so it fails closed instead.
///
/// Structural errors surface as `E_INVALID_INPUT`; a credential value never
/// enters an audit entry or an error message.
fn lease_credential_param(req: &Request) -> Result<Option<&str>, &'static str> {
    let params = req.params.as_object().ok_or("params must be an object")?;
    // A handle is not a capability. Refuse rather than ignore.
    if params.get("lease_id").is_some_and(|v| !v.is_null()) {
        return Err(
            "lease_id is a public handle and does not authorize; present the credential instead",
        );
    }
    match params.get("lease") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) if !s.is_empty() => Ok(Some(s.as_str())),
        Some(serde_json::Value::String(_)) => Err("invalid lease credential"),
        _ => Err("invalid lease credential"),
    }
}

/// Ops where `params.lease_id` names the TARGET of the operation rather than
/// presenting a credential. `lease.revoke` takes the public handle of the
/// lease to revoke — `docs/protocol.md` documents it as "agent (own) /
/// human (any)" — exactly as `approvals.approve` takes an `approval_id`.
/// A handle is not a capability: the arm reads it as the thing to act on.
const LEASE_ID_IS_TARGET: &[&str] = &["lease.revoke"];

/// H-12(b): human ops (including every session-authenticated op) run at full
/// human authority, so a caller-named lease must never be silently ignored —
/// ignoring it would run at full authority when the caller meant narrowed.
/// Reject any non-null `params.lease`/`params.lease_id` with E_INVALID_INPUT.
/// H-12(a) falls out of separate tables: a session credential in
/// `params.lease` misses the lease digest table => E_LEASE_EXPIRED, and a
/// lease credential in `auth.session` misses the session table =>
/// E_SESSION_EXPIRED — never cross-authorized.
///
/// The exemption is deliberately per-KEY: on [`LEASE_ID_IS_TARGET`] ops the
/// `lease_id` is the target handle and is allowed, while `params.lease` (the
/// credential form) stays refused — no arm reads a credential there, and
/// ignoring a caller-named capability is exactly what this guard prevents.
fn reject_lease_on_human_op(req: &Request) -> Result<(), &'static str> {
    let params = req.params.as_object().ok_or("params must be an object")?;
    // A handle is not a capability. Refuse rather than ignore.
    if params.get("lease").is_some_and(|v| !v.is_null()) {
        return Err("human operations take no lease; leases narrow agent grants only");
    }
    if !LEASE_ID_IS_TARGET.contains(&req.op.as_str())
        && params.get("lease_id").is_some_and(|v| !v.is_null())
    {
        return Err("human operations take no lease; leases narrow agent grants only");
    }
    Ok(())
}

/// Parse `params.keys`: an omitted/null value means "every secret in the
/// project"; anything else must be an array of strings.
///
/// This is a security boundary, not a convenience: the previous
/// `as_array()`-then-`Option` reading collapsed *every* malformed shape
/// (string, object, number) into "no selection" = "all secrets", turning a
/// typo into a full dump of the project. `Some(vec![])` stays a deliberate
/// empty selection and is handled by the caller.
fn keys_param(params: &serde_json::Value) -> Result<Option<Vec<String>>, &'static str> {
    match params.get("keys") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str() {
                    Some(s) => out.push(s.to_string()),
                    None => return Err("keys must be an array of strings"),
                }
            }
            Ok(Some(out))
        }
        Some(_) => Err("keys must be an array of strings"),
    }
}

pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub vault_path: PathBuf,
    pub idle_lock: Duration,
}

/// Cap on concurrent connections so thread-per-connection cannot grow
/// without bound (each held connection blocks on its read).
pub const MAX_CONCURRENT_CONNECTIONS: usize = 32;

/// How long a freshly accepted connection may take to produce its first
/// request. A client that connects and stays silent holds one of the
/// [`MAX_CONCURRENT_CONNECTIONS`] slots — and therefore a thread — so an
/// unfriendly client could starve every real one. This is the window for the
/// *first byte*; an established request keeps the generous
/// [`CONNECTION_IDLE_TIMEOUT`], and `run_with_secrets` is exempt entirely
/// because it deliberately holds its connection for the child's lifetime.
pub const FIRST_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Read/write timeout applied once a connection has started talking.
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the idle watchdog waits before retrying a lock whose lifecycle
/// failed (e.g. an unwritable audit log). Bounds the retry rate without giving
/// up on the lock: the vault still closes as soon as a retry succeeds.
const IDLE_RETRY_BACKOFF: Duration = Duration::from_secs(5);

pub struct Daemon {
    config: DaemonConfig,
    session: Mutex<Option<Session>>,
    runs: Arc<run::RunRegistry>,
    connections: Arc<std::sync::atomic::AtomicUsize>,
    /// Idle auto-lock watchdog (H1). See [`Daemon::spawn_idle_watchdog`].
    idle: IdleWatchdog,
    /// Exclusive broker instance lock, held for the daemon's whole lifetime
    /// (C1): a second broker on the same socket fails closed instead of
    /// replacing this one, and clients use its holder to identify us.
    _instance_lock: crate::ipc::InstanceLock,
    /// Persistent Ed25519 broker identity (N1): loaded or generated from
    /// `<vault>.broker-id` at startup; the private key signs every
    /// `broker.hello` handshake so clients can pin the public key.
    identity: broker_identity::BrokerIdentity,
}

/// Autonomous idle-lock timer: it fires on wall-clock time alone, with no
/// request needed to trigger the check.
///
/// The timer thread never polls — it parks on the condition variable until
/// the armed deadline. Activity that pushes the window out re-arms the timer
/// (which just moves the deadline), so the wake-ups are one per window, not
/// one per tick.
#[derive(Clone)]
struct IdleWatchdog {
    /// Mutex + condvar are one `Arc` so the timer thread does not keep the
    /// `Daemon` alive (it also holds only a `Weak`).
    state: Arc<(Mutex<IdleWatch>, Condvar)>,
}

struct IdleWatch {
    /// When the vault must lock itself; `None` = unarmed (locked, or
    /// auto-lock disabled).
    deadline: Option<Instant>,
    /// Set by [`Daemon`]'s drop so the parked thread exits instead of
    /// lingering for the rest of the window.
    shutdown: bool,
}

impl IdleWatchdog {
    fn new() -> Self {
        Self {
            state: Arc::new((
                Mutex::new(IdleWatch {
                    deadline: None,
                    shutdown: false,
                }),
                Condvar::new(),
            )),
        }
    }

    /// Point the timer at `deadline` (`None` disarms it). Wakes the thread
    /// only when the deadline actually changes, so a request that leaves the
    /// window where it was costs no wake-up.
    fn arm(&self, deadline: Option<Instant>) {
        let (lock, cv) = &*self.state;
        let mut guard = lock.lock().expect("idle watchdog mutex poisoned");
        if guard.deadline == deadline {
            return;
        }
        guard.deadline = deadline;
        cv.notify_all();
    }

    /// Park until the armed deadline elapses. Returns `false` once the daemon
    /// has been dropped.
    fn wait_for_deadline(&self) -> bool {
        let (lock, cv) = &*self.state;
        let mut guard = lock.lock().expect("idle watchdog mutex poisoned");
        loop {
            if guard.shutdown {
                return false;
            }
            match guard.deadline {
                // Unarmed: parked until something arms us or shuts us down.
                None => guard = cv.wait(guard).expect("idle watchdog mutex poisoned"),
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return true;
                    }
                    let (next, _) = cv
                        .wait_timeout(guard, deadline - now)
                        .expect("idle watchdog mutex poisoned");
                    guard = next;
                }
            }
        }
    }

    fn shutdown(&self) {
        let (lock, cv) = &*self.state;
        lock.lock().expect("idle watchdog mutex poisoned").shutdown = true;
        cv.notify_all();
    }
}

/// Stop the idle timer when the daemon goes away: the thread holds only a
/// `Weak<Daemon>`, so this wake is what ends it instead of letting it park
/// until the deadline.
impl Drop for Daemon {
    fn drop(&mut self) {
        self.idle.shutdown();
    }
}

impl Daemon {
    /// This daemon's broker public key (test + `trust` use; the handshake is
    /// the production path). Exposed so tests can pin out-of-band exactly
    /// like a human comparing `trust show` output in the TTY ceremony.
    pub fn broker_public_key(&self) -> [u8; 32] {
        self.identity.public_key()
    }

    /// Test hook: sign a client nonce for `socket` exactly like
    /// `answer_hello` does, returning (server_nonce, signature).
    pub fn hello_for_test(
        &self,
        client_nonce: &[u8; 32],
        socket: &std::path::Path,
    ) -> Result<([u8; 32], [u8; 64]), VaultError> {
        self.identity.hello_reply(client_nonce, socket)
    }

    pub fn new(config: DaemonConfig) -> Result<Self, VaultError> {
        if let Some(parent) = config.socket_path.parent()
            && parent != Path::new("")
        {
            store::ensure_private_dir(parent)?;
        }
        // C1: single-instance exclusion. Taken BEFORE touching the socket
        // path, so we never unlink a socket another broker is serving: if
        // someone already holds the lock, this daemon refuses to start.
        let instance_lock = crate::ipc::InstanceLock::acquire(&config.socket_path)?;
        // N1: persistent broker identity, generated once and kept next to the
        // vault (`<vault>.broker-id`, mode 0600). Survives restarts so client
        // pins stay valid; a fresh vault gets a fresh identity. Loud on
        // generation: the fingerprint goes to stderr for out-of-band capture.
        let fresh = !broker_identity::identity_path(&config.vault_path).exists();
        let identity = broker_identity::BrokerIdentity::load_or_generate(&config.vault_path)?;
        if fresh {
            eprintln!(
                "svault: generated new broker identity (fingerprint {}); clients will pin it on first contact",
                broker_identity::fingerprint(&identity.public_key())
            );
        }
        // Only remove a leftover socket once we know no live broker owns it.
        // The lock is what decides liveness (the kernel drops it on process
        // death); a stale file from a crash is thus safely replaceable.
        if config.socket_path.exists() {
            std::fs::remove_file(&config.socket_path)?;
        }
        // The daemon owns the idle lifecycle: its watchdog runs the full
        // `lock_and_drain`, so the session must not lock itself from inside an
        // operation (H1 — one lifecycle, one owner).
        let session = if config.vault_path.exists() {
            let mut session =
                Session::load(&config.vault_path, config.idle_lock, Box::new(SystemClock))?;
            session.defer_idle_lock();
            Some(session)
        } else {
            None
        };
        Ok(Self {
            config,
            session: Mutex::new(session),
            runs: Arc::new(run::RunRegistry::new()),
            connections: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            idle: IdleWatchdog::new(),
            _instance_lock: instance_lock,
            identity,
        })
    }

    /// Arm the autonomous idle-lock timer on this session's deadline
    /// (`None` when the vault is locked or auto-lock is off).
    ///
    /// Called after anything that moves `last_activity` or changes lock state,
    /// so the timer always tracks the current window. [`Self::lock_and_drain`]
    /// disarms it by locking; the timer re-arms itself when the deadline is
    /// reached and the vault is still open.
    fn arm_idle_watchdog(&self, session: &Session) {
        self.idle.arm(session.idle_deadline());
    }

    /// Start the wall-clock thread that locks an idle vault with no request
    /// needed. Exactly one per daemon; the thread parks on a condition
    /// variable and exits when the daemon drops.
    fn spawn_idle_watchdog(self: &Arc<Self>) {
        let idle = self.idle.clone();
        let weak = Arc::downgrade(self);
        std::thread::spawn(move || {
            while idle.wait_for_deadline() {
                let Some(daemon) = weak.upgrade() else { break };
                // Same lifecycle as every other lock path: audit, terminate
                // managed runs, revoke leases/approvals, persist, zeroize.
                let mut guard = daemon.lock_session();
                let mut failed = false;
                if let Some(session) = guard.as_mut()
                    && session.idle_expired()
                    && !session.is_locked()
                {
                    failed = daemon.lock_and_drain(session, "human").is_err();
                }
                // Re-arm on whatever the session reports now: `None` after the
                // lock above, or a fresh deadline if a request refreshed the
                // window while we were waiting for the session lock.
                if let Some(session) = guard.as_ref() {
                    daemon.arm_idle_watchdog(session);
                }
                drop(guard);
                if failed {
                    // The lifecycle failed and the window is still in the past,
                    // so an immediate re-arm would spin. Wait one bounded retry
                    // interval instead: this preserves the confidentiality
                    // guarantee (the vault is still closed as soon as a retry
                    // succeeds) without turning the timer into a hot poll.
                    std::thread::sleep(IDLE_RETRY_BACKOFF);
                }
            }
        });
    }

    /// Accept loop: blocks forever serving connections (thread per
    /// connection). The socket is 0600 inside a 0700 directory.
    pub fn serve(self: Arc<Self>) -> Result<(), VaultError> {
        let listener = std::os::unix::net::UnixListener::bind(&self.config.socket_path)?;
        std::fs::set_permissions(
            &self.config.socket_path,
            std::fs::Permissions::from_mode(0o600),
        )?;
        // H1: the idle lock must happen on wall-clock time alone. Start the
        // daemon's own timer so no request is needed to notice the timeout.
        self.spawn_idle_watchdog();
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            if self.connections.load(std::sync::atomic::Ordering::SeqCst)
                >= MAX_CONCURRENT_CONNECTIONS
            {
                let _ = wire::write_response(
                    &mut stream,
                    &Response::err("conn", "E_PROTOCOL", "too many concurrent connections"),
                );
                continue;
            }
            self.connections
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let daemon = Arc::clone(&self);
            let connections = Arc::clone(&self.connections);
            std::thread::spawn(move || {
                // C5: the first request must arrive quickly, so a silent
                // client cannot pin a slot. Once the request is in,
                // `handle_connection` relaxes this for the reply.
                let _ = stream.set_read_timeout(Some(FIRST_REQUEST_TIMEOUT));
                let _ = stream.set_write_timeout(Some(CONNECTION_IDLE_TIMEOUT));
                let result = handle_connection(Arc::clone(&daemon), &mut stream);
                connections.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                if let Err(e) = result {
                    let _ = wire::write_response(
                        &mut stream,
                        &Response::err("connection", e.code(), e.to_string()),
                    );
                }
            });
        }
        Ok(())
    }

    /// Peer UID must equal the daemon owner: defense in depth over the
    /// socket file permissions.
    fn peer_uid_ok(fd: std::os::unix::io::RawFd) -> bool {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        ret == 0 && cred.uid == unsafe { libc::geteuid() }
    }
}

fn handle_connection(
    daemon: Arc<Daemon>,
    stream: &mut std::os::unix::net::UnixStream,
) -> Result<(), VaultError> {
    // SO_PEERCRED on the accepted connection reports the CLIENT's uid.
    if !Daemon::peer_uid_ok(stream.as_raw_fd()) {
        wire::write_response(
            stream,
            &Response::err("peer", "E_AUTH", "peer uid does not match the daemon owner"),
        )?;
        return Ok(());
    }
    // One request per connection; the first message may carry SCM_RIGHTS FDs.
    let (req, fds) = fdpass::recv_request_with_fds(stream)?;
    // N1: the signed handshake. A leading `broker.hello` line is answered
    // with the daemon's public key + signature over the domain-separated
    // message (client nonce, server nonce, canonical socket path), then the
    // real request is read on the SAME connection. A first line that is any
    // other op is a legacy direct request (daemon-side backward compatible;
    // trust is enforced client-side by new clients that always shake hands
    // first and NEVER fall back — see `Client::handshake`). The hello
    // carries no credentials and needs no auth; it is unsigned client →
    // signed server, one round trip, on the connection that will carry the
    // request — so the proof is bound to the peer being spoken to. Hello
    // lines are NEVER audited (unauthenticated, attacker-triggerable: audit
    // would be log spam with unauthenticated bytes in the trail), and a
    // hello carrying any FDs is rejected outright (hello is always a plain
    // write; only the SECOND line — the `run_with_secrets` request — may
    // carry exactly 3 FDs via `SCM_RIGHTS`).
    if req.op == broker_identity::HELLO_OP {
        if !fds.is_empty() {
            // Owned CLOEXEC FDs drop here (close-on-drop): hello takes none.
            wire::write_response(
                stream,
                &Response::err(
                    &req.id,
                    "E_PROTOCOL",
                    "broker.hello carries no file descriptors",
                ),
            )?;
            return Ok(());
        }
        let resp = daemon.answer_hello(&req);
        wire::write_response(stream, &resp)?;
        let _ = stream.set_read_timeout(Some(CONNECTION_IDLE_TIMEOUT));
        let (req, fds) = fdpass::recv_request_with_fds(stream)?;
        return daemon.dispatch_on_connection(stream, req, fds);
    }
    // The first request arrived within `FIRST_REQUEST_TIMEOUT`; from here the
    // connection is a known peer doing real work, so it gets the generous
    // timeout. `run_with_secrets` in particular stays open for the child's
    // whole life and must not be cut off by the intake window.
    let _ = stream.set_read_timeout(Some(CONNECTION_IDLE_TIMEOUT));
    // Terminal `return` (not a bare tail expression): keeps the two dispatch
    // exits visually symmetric with the early returns above.
    #[allow(clippy::needless_return)]
    return daemon.dispatch_on_connection(stream, req, fds);
}

impl Daemon {
    /// Answer a `broker.hello` handshake line: fresh server nonce + Ed25519
    /// signature over domain || client_nonce || server_nonce || socket path.
    /// Never fails closed with key material: failures are plain E_PROTOCOL.
    fn answer_hello(&self, req: &Request) -> Response {
        let client_nonce: [u8; broker_identity::NONCE_LEN] =
            match req.params.get("client_nonce").and_then(|v| v.as_str()) {
                Some(hex) => match crate::crypto::unhex(hex) {
                    Some(b) if b.len() == broker_identity::NONCE_LEN => {
                        let mut n = [0u8; broker_identity::NONCE_LEN];
                        n.copy_from_slice(&b);
                        n
                    }
                    _ => {
                        return Response::err(
                            &req.id,
                            "E_PROTOCOL",
                            "broker.hello needs a 32-byte hex client_nonce",
                        );
                    }
                },
                None => {
                    return Response::err(
                        &req.id,
                        "E_PROTOCOL",
                        "broker.hello needs a 32-byte hex client_nonce",
                    );
                }
            };
        let socket_path = self.config.socket_path.clone();
        match self.identity.hello_reply(&client_nonce, &socket_path) {
            Ok((server_nonce, sig)) => Response::ok(
                &req.id,
                serde_json::json!({
                    "public_key": crate::crypto::hex(&self.identity.public_key()),
                    "server_nonce": crate::crypto::hex(&server_nonce),
                    "signature": crate::crypto::hex(&sig),
                }),
            ),
            Err(e) => Response::err(&req.id, e.code(), e.to_string()),
        }
    }

    /// Post-handshake dispatch shared by hello and legacy paths.
    fn dispatch_on_connection(
        &self,
        stream: &mut std::os::unix::net::UnixStream,
        req: Request,
        fds: Vec<std::os::fd::OwnedFd>,
    ) -> Result<(), VaultError> {
        // Belt-and-braces: `broker.hello` is answered in `handle_connection`
        // and must never reach authenticated dispatch (it is unauthenticated
        // and unaudited by construction). A direct hello here is a protocol
        // error, never an op.
        if req.op == broker_identity::HELLO_OP {
            wire::write_response(
                stream,
                &Response::err(
                    &req.id,
                    "E_PROTOCOL",
                    "broker.hello is a handshake line, not an op",
                ),
            )?;
            return Ok(());
        }
        if req.op == "run_with_secrets" {
            return self.handle_run(stream, req, fds);
        }
        if !fds.is_empty() {
            // Owned CLOEXEC FDs drop here (close-on-drop); ordinary ops take no FDs.
            let mut guard = self.lock_session();
            if let Some(s) = guard.as_mut() {
                s.audit_run_denied(
                    "agent:unknown",
                    None,
                    &[],
                    None,
                    &VaultError::InvalidInput("unexpected file descriptors"),
                );
            }
            wire::write_response(
                stream,
                &Response::err(&req.id, "E_INVALID_INPUT", "unexpected file descriptors"),
            )?;
            return Ok(());
        }
        let resp = self.handle_request(req);
        wire::write_response(stream, &resp)
    }
}
impl Daemon {
    fn handle_run(
        &self,
        stream: &mut std::os::unix::net::UnixStream,
        req: Request,
        fds: Vec<OwnedFd>,
    ) -> Result<(), VaultError> {
        let id = req.id.clone();
        // H1: `handle_run` does not go through `handle_request`, so the idle
        // auto-lock must be applied here too. Without this, a
        // `run_with_secrets` request arriving after the idle window would
        // close the vault through the older path (which drops key material
        // but leaves other live runs alone) instead of the full lifecycle.
        {
            let mut guard = self.lock_session();
            if let Some(session) = guard.as_mut()
                && session.idle_expired()
                && !session.is_locked()
                && let Err(e) = self.lock_and_drain(session, "human")
            {
                wire::write_response(stream, &Response::err(&id, e.code(), e.to_string()))?;
                return Ok(());
            }
            // A run request can be the first thing to notice an expired window
            // (or the only request for a long time): keep the autonomous timer
            // in step with whatever this session now reports.
            if let Some(session) = guard.as_ref() {
                self.arm_idle_watchdog(session);
            }
        }
        if fds.len() != 3 {
            let mut guard = self.lock_session();
            if let Some(s) = guard.as_mut() {
                s.audit_run_denied(
                    "agent:unknown",
                    None,
                    &[],
                    None,
                    &VaultError::InvalidInput("expected exactly 3 file descriptors"),
                );
            }
            wire::write_response(
                stream,
                &Response::err(
                    &id,
                    "E_INVALID_INPUT",
                    "expected exactly 3 file descriptors",
                ),
            )?;
            return Ok(());
        }
        let params = match run::parse_run_params(&req.params) {
            Ok(p) => p,
            Err(e) => {
                let code = e.code();
                let msg = e.to_string();
                let mut guard = self.lock_session();
                if let Some(s) = guard.as_mut() {
                    s.audit_run_denied("agent:unknown", None, &[], None, &e);
                }
                wire::write_response(stream, &Response::err(&id, code, msg))?;
                return Ok(());
            }
        };
        struct Ready {
            actor: String,
            agent_id: String,
            project: String,
            keys: Vec<String>,
            secrets: Vec<(String, Vec<u8>)>,
            roots: Vec<PathBuf>,
        }
        let ready: Ready = {
            let mut guard = self.lock_session();
            let session = match guard.as_mut() {
                Some(s) => s,
                None => {
                    wire::write_response(
                        stream,
                        &Response::err(&id, "E_NOT_FOUND", "no vault exists; run svault init"),
                    )?;
                    return Ok(());
                }
            };
            let (token, passphrase) = (
                req.auth.as_ref().and_then(|a| a.token.as_deref()),
                req.auth.as_ref().and_then(|a| a.passphrase.as_deref()),
            );
            if token.is_some() && passphrase.is_some() {
                session.audit_run_denied(
                    "agent:unknown",
                    Some(params.project.as_str()),
                    &[],
                    None,
                    &VaultError::Protocol(
                        "provide either a token or a passphrase, not both".into(),
                    ),
                );
                wire::write_response(
                    stream,
                    &Response::err(
                        &id,
                        "E_PROTOCOL",
                        "provide either a token or a passphrase, not both",
                    ),
                )?;
                return Ok(());
            }
            let agent_id = match token.and_then(|t| session.resolve_agent(t)) {
                Some(a) => a,
                None => {
                    session.audit_run_denied(
                        "agent:unknown",
                        Some(params.project.as_str()),
                        &[],
                        None,
                        &VaultError::Auth,
                    );
                    wire::write_response(
                        stream,
                        &Response::err(&id, "E_AUTH", "authentication failed"),
                    )?;
                    return Ok(());
                }
            };
            let actor = format!("agent:{agent_id}");
            if session.ensure_run_unlocked().is_err() {
                session.audit_run_denied(
                    &actor,
                    Some(params.project.as_str()),
                    &[],
                    None,
                    &VaultError::Locked,
                );
                wire::write_response(stream, &Response::err(&id, "E_LOCKED", "vault is locked"))?;
                return Ok(());
            }
            let doc = match session.document() {
                Some(d) => d.clone(),
                None => {
                    session.audit_run_denied(
                        &actor,
                        Some(params.project.as_str()),
                        &[],
                        None,
                        &VaultError::Locked,
                    );
                    wire::write_response(
                        stream,
                        &Response::err(&id, "E_LOCKED", "vault is locked"),
                    )?;
                    return Ok(());
                }
            };
            let prec = match doc.project_by_name(&params.project).cloned() {
                Some(p) if doc.authorize(&agent_id, &p.id, Op::Run) => p,
                _ => {
                    session.audit_run_denied(
                        &actor,
                        Some(params.project.as_str()),
                        &[],
                        None,
                        &VaultError::Permission,
                    );
                    wire::write_response(
                        stream,
                        &Response::err(&id, "E_PERMISSION", "permission denied"),
                    )?;
                    return Ok(());
                }
            };
            let (key_names, secrets): (Vec<String>, Vec<(String, Vec<u8>)>) = match &params.keys {
                Some(list) => {
                    let mut names = Vec::with_capacity(list.len());
                    let mut vals = Vec::with_capacity(list.len());
                    let mut missing = false;
                    for k in list {
                        match doc.secret(&prec.id, k) {
                            Some(s) => {
                                names.push(k.clone());
                                vals.push((k.clone(), s.value.0.to_vec()));
                            }
                            None => {
                                missing = true;
                                names.push(k.clone());
                            }
                        }
                    }
                    if missing {
                        session.audit_run_denied(
                            &actor,
                            Some(params.project.as_str()),
                            &names,
                            None,
                            &VaultError::NotFound,
                        );
                        wire::write_response(
                            stream,
                            &Response::err(&id, "E_NOT_FOUND", "not found"),
                        )?;
                        return Ok(());
                    }
                    (names, vals)
                }
                None => {
                    let mut all: Vec<(String, Vec<u8>)> = doc
                        .secrets
                        .iter()
                        .filter(|s| s.project_id == prec.id)
                        .map(|s| (s.key.clone(), s.value.0.to_vec()))
                        .collect();
                    all.sort_by(|a, b| a.0.cmp(&b.0));
                    if all.is_empty() {
                        session.audit_run_denied(
                            &actor,
                            Some(params.project.as_str()),
                            &[],
                            None,
                            &VaultError::InvalidInput("no secrets to run with"),
                        );
                        wire::write_response(
                            stream,
                            &Response::err(
                                &id,
                                "E_INVALID_INPUT",
                                "invalid input: no secrets to run with",
                            ),
                        )?;
                        return Ok(());
                    }
                    if all.len() > run::MAX_KEYS {
                        let names: Vec<String> = all.iter().map(|(k, _)| k.clone()).collect();
                        session.audit_run_denied(
                            &actor,
                            Some(params.project.as_str()),
                            &names,
                            None,
                            &VaultError::InvalidInput("too many keys"),
                        );
                        wire::write_response(
                            stream,
                            &Response::err(&id, "E_INVALID_INPUT", "invalid input: too many keys"),
                        )?;
                        return Ok(());
                    }
                    let names: Vec<String> = all.iter().map(|(k, _)| k.clone()).collect();
                    (names, all)
                }
            };
            Ready {
                actor,
                agent_id,
                project: params.project.clone(),
                keys: key_names,
                secrets,
                roots: prec.paths.clone(),
            }
        };
        let child_env = match run::build_child_env(&params.env, &ready.secrets) {
            Ok(e) => e,
            Err(e) => {
                let code = e.code();
                let msg = e.to_string();
                let mut guard = self.lock_session();
                if let Some(s) = guard.as_mut() {
                    s.audit_run_denied(
                        &ready.actor,
                        Some(ready.project.as_str()),
                        &ready.keys,
                        None,
                        &e,
                    );
                }
                wire::write_response(stream, &Response::err(&id, code, msg))?;
                return Ok(());
            }
        };
        let (cwd_fd, cwd_path): (Option<OwnedFd>, Option<PathBuf>) = match &params.cwd {
            None => (None, None),
            Some(c) => {
                let p = PathBuf::from(c);
                match fsops::open_authorized_cwd(&p, &ready.roots) {
                    Ok(fd) => (Some(fd), Some(p)),
                    Err(e) => {
                        let code = e.code();
                        let msg = e.to_string();
                        let mut guard = self.lock_session();
                        if let Some(s) = guard.as_mut() {
                            s.audit_run_denied(
                                &ready.actor,
                                Some(ready.project.as_str()),
                                &ready.keys,
                                None,
                                &e,
                            );
                        }
                        wire::write_response(stream, &Response::err(&id, code, msg))?;
                        return Ok(());
                    }
                }
            }
        };
        let run_id = match run::new_run_id() {
            Ok(v) => v,
            Err(e) => {
                let code = e.code();
                let msg = e.to_string();
                let mut guard = self.lock_session();
                if let Some(s) = guard.as_mut() {
                    s.audit_run_denied(
                        &ready.actor,
                        Some(ready.project.as_str()),
                        &ready.keys,
                        None,
                        &e,
                    );
                }
                wire::write_response(stream, &Response::err(&id, code, msg))?;
                return Ok(());
            }
        };
        let reservation = match self
            .runs
            .try_reserve(&ready.agent_id, &ready.project, &run_id)
        {
            Ok(r) => r,
            Err(re) => {
                let (code, msg) = (re.code(), re.to_string());
                let audit_err = if code == "E_BUSY" {
                    VaultError::Busy
                } else {
                    VaultError::Protocol(msg.clone())
                };
                let mut guard = self.lock_session();
                if let Some(s) = guard.as_mut() {
                    s.audit_run_denied(
                        &ready.actor,
                        Some(ready.project.as_str()),
                        &ready.keys,
                        Some(run_id.as_str()),
                        &audit_err,
                    );
                }
                wire::write_response(stream, &Response::err(&id, code, msg))?;
                return Ok(());
            }
        };
        let mut fd_iter = fds.into_iter();
        let stdio: [OwnedFd; 3] = [
            fd_iter.next().expect("3 fds checked"),
            fd_iter.next().expect("3 fds checked"),
            fd_iter.next().expect("3 fds checked"),
        ];
        let executable = params.executable.clone();
        let argv = params.argv.clone();
        let arg_count = argv.len() as u64;
        let timeout_secs = params.timeout_secs;
        {
            let mut guard = self.lock_session();
            if let Some(s) = guard.as_mut()
                && s.audit_run_allowed(&ready.actor, &ready.project, &ready.keys, arg_count)
                    .is_err()
            {
                wire::write_response(
                    stream,
                    &Response::err(&id, "E_AUDIT_WRITE", "audit write failed"),
                )?;
                return Ok(());
            }
        }
        let mut child = match run::spawn_from_fds(&executable, &argv, &child_env, stdio, cwd_fd) {
            Ok(c) => c,
            Err(e) => {
                let ve = VaultError::from(e);
                let code = ve.code();
                let msg = ve.to_string();
                drop(reservation);
                let mut guard = self.lock_session();
                if let Some(s) = guard.as_mut() {
                    s.audit_run_denied(
                        &ready.actor,
                        Some(ready.project.as_str()),
                        &ready.keys,
                        Some(run_id.as_str()),
                        &ve,
                    );
                }
                wire::write_response(stream, &Response::err(&id, code, msg))?;
                return Ok(());
            }
        };
        let pid = child.id() as i32;
        let pgid = pid;
        if !reservation.activate(pid, pgid) {
            run::terminate_group(pgid);
            let _ = child.wait();
            let mut guard = self.lock_session();
            if let Some(session) = guard.as_mut() {
                session.audit_run_denied(
                    &ready.actor,
                    Some(ready.project.as_str()),
                    &ready.keys,
                    Some(run_id.as_str()),
                    &VaultError::Permission,
                );
            }
            wire::write_response(
                stream,
                &Response::err(&id, "E_PERMISSION", "run capability was revoked"),
            )?;
            return Ok(());
        }
        reservation.commit();
        {
            let mut guard = self.lock_session();
            if let Some(s) = guard.as_mut()
                && s.audit_run_started(
                    &ready.actor,
                    &ready.project,
                    &ready.keys,
                    &run_id,
                    &executable,
                    arg_count,
                    cwd_path.as_deref(),
                )
                .is_err()
            {
                drop(guard);
                self.finish_run(&run_id, pgid);
                let _ = child.wait();
                wire::write_response(
                    stream,
                    &Response::err(&id, "E_AUDIT_WRITE", "audit write failed"),
                )?;
                return Ok(());
            }
        }
        if wire::write_response(
            stream,
            &Response::ok(
                &id,
                json!({"run_id": run_id, "pid": pid, "status": "started"}),
            ),
        )
        .is_err()
        {
            self.finish_run(&run_id, pgid);
            let status = child.wait().ok();
            let exit_code = status.as_ref().and_then(|s| s.code());
            let sig = status.as_ref().and_then(run::exit_signal);
            let mut guard = self.lock_session();
            if let Some(s) = guard.as_mut() {
                let _ = s.audit_run_exited(
                    &ready.actor,
                    &ready.project,
                    &ready.keys,
                    &run_id,
                    &executable,
                    arg_count,
                    cwd_path.as_deref(),
                    exit_code,
                    sig.as_deref(),
                );
            }
            return Ok(());
        }
        let deadline =
            Instant::now() + Duration::from_secs(timeout_secs.unwrap_or(run::MAX_DURATION_SECS));
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.finish_run(&run_id, pgid);
                    let exit_code = status.code();
                    let sig = run::exit_signal(&status);
                    {
                        let mut guard = self.lock_session();
                        if let Some(s) = guard.as_mut()
                            && s.audit_run_exited(
                                &ready.actor,
                                &ready.project,
                                &ready.keys,
                                &run_id,
                                &executable,
                                arg_count,
                                cwd_path.as_deref(),
                                exit_code,
                                sig.as_deref(),
                            )
                            .is_err()
                            && !Self::peer_gone(stream)
                        {
                            let _ = wire::write_response(
                                stream,
                                &Response::err(&id, "E_AUDIT_WRITE", "audit write failed"),
                            );
                            return Ok(());
                        }
                    }
                    if !Self::peer_gone(stream) {
                        let mut body = run::exit_result(&status);
                        body["run_id"] = json!(run_id);
                        body["status"] = json!("exited");
                        let _ = wire::write_response(stream, &Response::ok(&id, body));
                    }
                    return Ok(());
                }
                Ok(None) => {}
                Err(_) => {
                    self.finish_run(&run_id, pgid);
                    let status = child.wait().ok();
                    let exit_code = status.as_ref().and_then(|s| s.code());
                    let sig = status.as_ref().and_then(run::exit_signal);
                    {
                        let mut guard = self.lock_session();
                        if let Some(s) = guard.as_mut() {
                            let _ = s.audit_run_exited(
                                &ready.actor,
                                &ready.project,
                                &ready.keys,
                                &run_id,
                                &executable,
                                arg_count,
                                cwd_path.as_deref(),
                                exit_code,
                                sig.as_deref(),
                            );
                        }
                    }
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                self.finish_run(&run_id, pgid);
                let status = child.wait().ok();
                let exit_code = status.as_ref().and_then(|s| s.code());
                let sig = status.as_ref().and_then(run::exit_signal);
                {
                    let mut guard = self.lock_session();
                    if let Some(s) = guard.as_mut() {
                        let _ = s.audit_run_exited(
                            &ready.actor,
                            &ready.project,
                            &ready.keys,
                            &run_id,
                            &executable,
                            arg_count,
                            cwd_path.as_deref(),
                            exit_code,
                            sig.as_deref(),
                        );
                    }
                }
                if !Self::peer_gone(stream) {
                    if let Some(status) = status {
                        let mut body = run::exit_result(&status);
                        body["run_id"] = json!(run_id);
                        body["status"] = json!("exited");
                        let _ = wire::write_response(stream, &Response::ok(&id, body));
                    } else {
                        let _ = wire::write_response(
                            stream,
                            &Response::err(&id, "E_IO", "io error: wait failed"),
                        );
                    }
                }
                return Ok(());
            }
            if Self::peer_gone(stream) {
                self.finish_run(&run_id, pgid);
                let status = child.wait().ok();
                let exit_code = status.as_ref().and_then(|s| s.code());
                let sig = status.as_ref().and_then(run::exit_signal);
                {
                    let mut guard = self.lock_session();
                    if let Some(s) = guard.as_mut() {
                        let _ = s.audit_run_exited(
                            &ready.actor,
                            &ready.project,
                            &ready.keys,
                            &run_id,
                            &executable,
                            arg_count,
                            cwd_path.as_deref(),
                            exit_code,
                            sig.as_deref(),
                        );
                    }
                }
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn peer_gone(stream: &std::os::unix::net::UnixStream) -> bool {
        let mut buf = [0u8; 1];
        let r = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if r >= 0 {
            // Any post-request byte is a protocol violation on the held
            // one-way launch connection. Treat data or EOF as disconnect.
            return true;
        }
        let e = std::io::Error::last_os_error().raw_os_error();
        matches!(e, Some(libc::ECONNRESET) | Some(libc::EPIPE))
    }

    fn finish_run(&self, run_id: &str, pgid: i32) {
        if self.runs.remove(run_id).is_some() {
            run::terminate_group(pgid);
        }
    }

    fn terminate_matching_runs(
        &self,
        session: &mut Session,
        actor: &str,
        agent: Option<&str>,
        project: Option<&str>,
    ) -> Result<(), VaultError> {
        let runs = self.runs.take_matching(agent, project);
        for (_, meta) in &runs {
            if meta.pgid > 0 {
                run::terminate_group(meta.pgid);
            }
        }
        for (run_id, meta) in runs {
            // Best-effort: the process groups above are already terminated, so
            // a full audit log must not turn a completed drain into a reported
            // failure (nor block the lock that called us).
            let _ = session.audit_run_revoked(actor, &meta.project, &run_id);
        }
        Ok(())
    }
}

/// The per-request facts [`Daemon::dispatch`] establishes and
/// [`Daemon::dispatch_op`] consumes.
struct OpContext<'a> {
    id: &'a str,
    actor: &'a str,
    identity: &'a Identity,
    is_agent: bool,
    proof: Option<&'a DerivedKeks>,
}

/// Who a request authenticated as. Established by
/// [`Daemon::dispatch`] and consumed by [`Daemon::dispatch_op`].
enum Identity {
    Human,
    Agent(String),
    Unauthenticated,
}

impl Daemon {
    fn lock_session(&self) -> MutexGuard<'_, Option<Session>> {
        self.session.lock().expect("session mutex poisoned")
    }

    fn runs_count(&self) -> u64 {
        self.runs.len() as u64
    }

    /// Pure dispatch: authentication (agent token → active agent), human-only
    /// enforcement (I3), grant evaluation (I6), execution, audit. Every
    /// request — allowed or denied — is audited (I7).
    pub fn handle_request(&self, req: Request) -> Response {
        // C5: a passphrase-carrying request implies one Argon2 derivation per
        // passphrase slot. Derive it BEFORE taking the session lock, so the
        // expensive step never blocks a cheap credential-free op
        // (`vault.status`) behind it. The lock is taken twice, briefly: once
        // to read the (secretless) KDF recipe, once to apply the result.
        let proof = match self.derive_human_proof(&req) {
            Ok(p) => p,
            Err(resp) => return resp,
        };
        let mut guard = self.lock_session();
        // H1: an expired idle window locks the vault with the SAME lifecycle
        // as an explicit `vault.lock` — including terminating active runs —
        // and it does so before the request is evaluated. Guarded on the
        // vault actually being open, so a locked session does not re-run the
        // lifecycle (and re-audit it) on every subsequent request.
        if let Some(session) = guard.as_mut()
            && session.idle_expired()
            && !session.is_locked()
            && let Err(e) = self.lock_and_drain(session, "human")
        {
            return Response::err(&req.id, e.code(), e.to_string());
        }
        let response = match self.dispatch(&mut guard, req, proof.as_ref()) {
            Ok(response) => response,
            Err(resp) => resp,
        };
        // The request may have moved the activity window (or the lock state):
        // point the autonomous timer at the current deadline before releasing
        // the session. This is a plain deadline update — no wake-up happens
        // unless the deadline actually changed.
        if let Some(session) = guard.as_ref() {
            self.arm_idle_watchdog(session);
        }
        response
    }

    /// Derive the KEK candidates for a passphrase request, holding the session
    /// lock only long enough to read the public KDF recipe.
    ///
    /// Returns `Ok(None)` when the request carries no usable passphrase (no
    /// credentials, or a token instead), and the fail-closed error response
    /// when the header itself cannot be used.
    fn derive_human_proof(&self, req: &Request) -> Result<Option<DerivedKeks>, Response> {
        let auth = req.auth.as_ref();
        // D-02: no Argon2 for session-present requests (the session path is
        // the cheap path; deriving here would be a DoS amplifier). The
        // exactly-one rule is enforced by dispatch; derivation must not pay
        // for a request that will be E_PROTOCOL.
        if auth.and_then(|a| a.session.as_deref()).is_some() {
            return Ok(None);
        }
        let Some(pass) = auth.and_then(|a| a.passphrase.as_deref()) else {
            return Ok(None);
        };
        // Both credentials at once is a protocol error; dispatch reports it.
        if auth.and_then(|a| a.token.as_deref()).is_some() {
            return Ok(None);
        }
        let recipe = {
            let guard = self.lock_session();
            match guard.as_ref() {
                // No vault yet: only `vault.create` is possible, and it
                // bootstraps its own key material.
                None => return Ok(None),
                Some(session) => match session.kek_recipe() {
                    Ok(recipe) => recipe,
                    Err(e) => return Err(Response::err(&req.id, e.code(), e.to_string())),
                },
            }
        };
        // Lock released: the expensive part runs unmuzzled by other requests.
        match recipe.derive(pass.as_bytes()) {
            Ok(derived) => Ok(Some(derived)),
            Err(e) => Err(Response::err(&req.id, e.code(), e.to_string())),
        }
    }

    /// Lock the vault the way `vault.lock` does — the single lifecycle every
    /// lock path shares: audit the lock, terminate the managed runs, revoke
    /// leases and approvals, persist, then zeroize.
    fn lock_and_drain(&self, session: &mut Session, actor: &str) -> Result<(), VaultError> {
        // A full audit log must never prevent the vault from being locked,
        // runs from being terminated, capabilities from being invalidated, or
        // keys from being zeroized (L2/lifecycle). Recording the lock is
        // therefore best-effort and uses the reserved headroom; the security
        // work below runs regardless.
        let _ = session.audit_record_lifecycle(
            actor,
            Record {
                actor,
                op: "vault.lock",
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        );
        // Drain first: termination of managed runs is the part that must not
        // be skipped, and it is also what makes the lock meaningful.
        let cleanup = self.terminate_matching_runs(session, actor, None, None);
        session.lock_persist()?;
        cleanup
    }

    fn dispatch(
        &self,
        guard: &mut MutexGuard<'_, Option<Session>>,
        req: Request,
        proof: Option<&DerivedKeks>,
    ) -> Result<Response, Response> {
        let id = req.id.clone();
        let no_vault = || Response::err(&id, "E_NOT_FOUND", "no vault exists; run svault init");

        let session = match guard.as_mut() {
            Some(s) => s,
            None => {
                // Only vault creation is possible without a vault.
                return if req.op == "vault.create" {
                    self.op_create(guard, &id, &req)
                } else {
                    Err(no_vault())
                };
            }
        };

        // Authentication precedence (H-01), in order: wire shape → exactly-one
        // credential (E_PROTOCOL, including non-string session) → identity
        // resolution (session digest → token digest → passphrase proof) →
        // session-on-unlock/create (E_SESSION_EXPIRED) → HUMAN_ONLY gate →
        // lock/expiry semantics → params validation → audit priority.
        // H-13: auth.session must be a string; wrong-type is E_PROTOCOL.
        // Empty string is a string but unusable: E_SESSION_EXPIRED, not
        // E_PROTOCOL (no oracle, no count-rule interaction).
        if let Some(auth) = req.auth.as_ref()
            && let Some(raw) = auth.session.as_ref()
            && raw.is_empty()
        {
            // Empty still counts as "a session was presented" for the
            // exactly-one rule: token+empty-session is E_PROTOCOL, but a lone
            // empty session is E_SESSION_EXPIRED.
            let others = auth.token.is_some() as u8 + auth.passphrase.is_some() as u8;
            if others > 0 {
                return Err(Response::err(
                    &id,
                    "E_PROTOCOL",
                    "provide exactly one credential: a token, a passphrase, or a session",
                ));
            }
            return Err(Response::err(
                &id,
                "E_SESSION_EXPIRED",
                "session expired or revoked",
            ));
        }
        // Non-string session cannot deserialize into AuthField (serde rejects
        // it as E_PROTOCOL "invalid request" at read_request) — pinned here
        // by construction; see H-13 test.
        // Absent credentials are NEVER human — only public ops (vault.status)
        // answer them; everything else fails closed with E_AUTH. A valid agent
        // token authenticates the agent; a passphrase is positive human proof,
        // verified against the vault's key slots on every privileged request;
        // a session credential is a server-minted human capability resolving
        // to human identity only.
        let (identity, actor): (Identity, String) = match (
            req.auth.as_ref().and_then(|a| a.token.as_deref()),
            req.auth.as_ref().and_then(|a| a.passphrase.as_deref()),
            req.auth.as_ref().and_then(|a| a.session.as_deref()),
        ) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => {
                return Err(Response::err(
                    &id,
                    "E_PROTOCOL",
                    "provide exactly one credential: a token, a passphrase, or a session",
                ));
            }
            (Some(token), None, None) => match session.resolve_agent(token) {
                Some(agent_id) => (
                    Identity::Agent(agent_id.clone()),
                    format!("agent:{agent_id}"),
                ),
                None => {
                    session.audit_denied(
                        "agent:unknown",
                        &req.op,
                        None,
                        &[],
                        None,
                        &VaultError::Auth,
                    );
                    return Err(Response::err(&id, "E_AUTH", "authentication failed"));
                }
            },
            (None, Some(_), None) => {
                // The proof was derived before the lock was taken (C5). It is
                // absent only when the derivation found no usable recipe — a
                // tampered header or a KDF outside the bounds — which must
                // fail closed, exactly like a wrong passphrase.
                let verified = proof.is_some_and(|d| session.proof_is_valid(d));
                if verified {
                    (Identity::Human, "human".to_string())
                } else {
                    session.audit_denied(
                        "unauthenticated",
                        &req.op,
                        None,
                        &[],
                        None,
                        &VaultError::Auth,
                    );
                    return Err(Response::err(&id, "E_AUTH", "authentication failed"));
                }
            }
            (None, None, Some(credential)) => match session.authorize_session(credential) {
                Ok(session_actor) => (Identity::Human, session_actor),
                Err(_) => {
                    return Err(Response::err(
                        &id,
                        "E_SESSION_EXPIRED",
                        "session expired or revoked",
                    ));
                }
            },
            (None, None, None) => (Identity::Unauthenticated, "unauthenticated".to_string()),
        };
        let is_agent = matches!(identity, Identity::Agent(_));

        // Public op: vault.status answers any identity (metadata only).
        // Everything else fails closed for unauthenticated requests. An empty
        // op name is not an operation, so nothing is recorded for it (M4: the
        // audit scope starts at an identifiable operation).
        if matches!(identity, Identity::Unauthenticated) && req.op != "vault.status" {
            if !req.op.is_empty() {
                session.audit_denied(
                    "unauthenticated",
                    &req.op,
                    None,
                    &[],
                    None,
                    &VaultError::Auth,
                );
            }
            return Err(Response::err(
                &id,
                "E_AUTH",
                "unauthenticated: this operation requires agent or human credentials",
            ));
        }

        // I3: human-only ops reject agent tokens.
        if is_agent && HUMAN_ONLY.contains(&req.op.as_str()) {
            session.audit_denied(&actor, &req.op, None, &[], None, &VaultError::HumanRequired);
            return Err(Response::err(
                &id,
                "E_HUMAN_REQUIRED",
                "this operation is human-only",
            ));
        }

        // H-12(b), centralized: human ops run at full human authority, so a
        // caller-named lease must never be silently ignored — ignoring it
        // would run at full authority when the caller meant narrowed. Any
        // non-null params.lease/params.lease_id on a HUMAN-authenticated
        // request is E_INVALID_INPUT (explicit null still counts as absent —
        // see the helper), except where `lease_id` is the operation's TARGET
        // rather than a credential (lease.revoke — see LEASE_ID_IS_TARGET).
        // Gated on Identity::Human specifically so agent ops
        // (secrets.list/inject_file/agent reveal/lease.*) that
        // legitimately present params.lease keep working untouched.
        if matches!(identity, Identity::Human)
            && let Err(why) = reject_lease_on_human_op(&req)
        {
            session.audit_denied(
                &actor,
                &req.op,
                None,
                &[],
                None,
                &VaultError::InvalidInput(why),
            );
            return Err(Response::err(&id, "E_INVALID_INPUT", why));
        }
        if NOT_YET.contains(&req.op.as_str()) {
            session.audit_denied(
                &actor,
                &req.op,
                None,
                &[],
                None,
                &VaultError::Protocol("op not available in this build".into()),
            );
            return Err(Response::err(
                &id,
                "E_PROTOCOL",
                "op not available in this build",
            ));
        }
        // M4: every request that reaches this point is identifiable (an op
        // name and an established actor), so a rejected one must leave a trace
        // even when the arm that rejected it did not record anything itself.
        // Marking the audit sequence avoids a second entry for arms that
        // already audited their denial.
        let audit_marker = session.audit_seq();
        let ctx = OpContext {
            id: &id,
            actor: &actor,
            identity: &identity,
            is_agent,
            proof,
        };
        let outcome = self.dispatch_op(session, &req, &ctx);
        // C-03: slide the session window only on an ALLOWED op — never on a
        // denial, never on expiry. `session.touch`/`open`/`close` manage their
        // own slide lifecycle; every other allowed human op via a session
        // credential renews it here, under the same mutex hold (C-02).
        if outcome.is_ok()
            && !matches!(
                req.op.as_str(),
                "session.touch" | "session.open" | "session.close"
            )
            && let Some(cred) = req.auth.as_ref().and_then(|a| a.session.as_deref())
        {
            session.slide_session(cred);
        }
        // An identifiable operation decides something, so a refusal must be
        // visible in the log. An empty op name is not an operation at all —
        // recording it would be inventing the very thing being audited — so it
        // is the one refusal the boundary leaves unrecorded.
        if let Err(resp) = &outcome
            && !req.op.is_empty()
            && session.audit_seq() == audit_marker
            && let Some(err) = resp.error.as_ref()
        {
            session.audit_denied_code(&actor, &req.op, req.params["project"].as_str(), &err.code);
        }
        outcome
    }

    /// Evaluate one op against an already-authenticated identity.
    ///
    /// Split out of [`Self::dispatch`] so that method can observe the
    /// outcome of every arm — including the ones that return early —
    /// without wrapping the whole match in a closure (which would reindent
    /// it wholesale and bury the change).
    fn dispatch_op(
        &self,
        session: &mut Session,
        req: &Request,
        ctx: &OpContext<'_>,
    ) -> Result<Response, Response> {
        let OpContext {
            id,
            actor,
            identity,
            is_agent,
            proof,
        } = *ctx;
        match req.op.as_str() {
            "inject_file" => {
                let Identity::Agent(agent_id) = identity else {
                    session.audit_denied(actor, "inject_file", None, &[], None, &VaultError::Auth);
                    return Err(Response::err(
                        id,
                        "E_AUTH",
                        "inject_file requires agent credentials",
                    ));
                };
                let Some(project) = req.params["project"].as_str() else {
                    return Err(Response::err(id, "E_INVALID_INPUT", "missing project"));
                };
                let Some(path) = req.params["path"].as_str() else {
                    return Err(Response::err(id, "E_INVALID_INPUT", "missing path"));
                };
                if session.is_locked() {
                    session.audit_denied(
                        actor,
                        "inject_file",
                        Some(project),
                        &[],
                        None,
                        &VaultError::Locked,
                    );
                    return Err(Response::err(id, "E_LOCKED", "vault is locked"));
                }
                let lease_credential = lease_credential_param(req).map_err(|why| {
                    session.audit_denied(
                        actor,
                        "inject_file",
                        Some(project),
                        &[],
                        None,
                        &VaultError::InvalidInput(why),
                    );
                    Response::err(id, "E_INVALID_INPUT", why)
                })?;
                let op_actor = session
                    .authorize_lease(agent_id, project, Op::Inject, lease_credential)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                let keys = keys_param(&req.params).map_err(|why| {
                    session.audit_denied(
                        actor,
                        "inject_file",
                        Some(project),
                        &[],
                        None,
                        &VaultError::InvalidInput(why),
                    );
                    Response::err(id, "E_INVALID_INPUT", why)
                })?;
                let report = session
                    .inject_file(&op_actor, project, path, keys.as_deref())
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(
                    id,
                    json!({
                        "path": report.path.display().to_string(),
                        "count": report.keys.len(),
                        "keys": report.keys,
                    }),
                ))
            }
            "vault.status" => {
                let st = session.status();
                session
                    .audit_record(
                        actor,
                        Record {
                            actor,
                            op: "vault.status",
                            project: None,
                            keys: &[],
                            target: None,
                            decision: Decision::Allowed,
                            reason: None,
                        },
                    )
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(
                    id,
                    json!({
                        "version": st.version,
                        "created": st.created_at.to_string(),
                        "locked": st.locked,
                    }),
                ))
            }
            "vault.lock" => {
                // One lifecycle for every lock path (explicit, idle, agent):
                // audit, terminate managed runs, revoke leases/approvals,
                // persist, zeroize.
                self.lock_and_drain(session, actor)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(id, json!({"locked": true})))
            }
            "secrets.list" => {
                // H-12(b) lease-on-human is enforced centrally in dispatch
                // for every Identity::Human request (see above); the agent
                // path below keeps its own lease_credential_param parsing.
                let project = req.params["project"]
                    .as_str()
                    .ok_or_else(|| Response::err(id, "E_INVALID_INPUT", "missing project"))?;
                // Lock state precedes authorization (I6): a locked vault
                // denies agent ops with E_LOCKED regardless of grants.
                if is_agent && session.is_locked() {
                    session.audit_denied(
                        actor,
                        "secrets.list",
                        Some(project),
                        &[],
                        None,
                        &VaultError::Locked,
                    );
                    return Err(Response::err(id, "E_LOCKED", "vault is locked"));
                }
                // Agents need a `read` grant on the project (I6); the human
                // owner does not.
                let op_actor = if let Identity::Agent(agent_id) = identity {
                    let lease_credential = lease_credential_param(req)
                        .map_err(|why| Response::err(id, "E_INVALID_INPUT", why))?;
                    session
                        .authorize_lease(agent_id, project, Op::Read, lease_credential)
                        .map_err(|e| Response::err(id, e.code(), e.to_string()))?
                } else {
                    actor.to_string()
                };
                let list = session
                    .secret_list(project, &op_actor)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(
                    id,
                    json!({"secrets": list.iter()
                    .map(|(k, u)| json!({"key": k, "updated": u.to_string()}))
                    .collect::<Vec<_>>()}),
                ))
            }
            "vault.unlock" => {
                // The human proof passphrase IS the unlock passphrase; the
                // dispatch already verified it against the key slots, and the
                // KEKs were derived before the lock was taken (C5) — reuse
                // them instead of paying for a second derivation.
                // `auth.session` never reaches here with a proof (it has no
                // passphrase to derive from): unlock needs the KEK, which only
                // the passphrase can derive, so a session presentation fails
                // `E_SESSION_EXPIRED` — enforced by the auth match treating a
                // session credential as already-resolved human identity with
                // `proof == None`. Reject it explicitly here for clarity.
                if req
                    .auth
                    .as_ref()
                    .and_then(|a| a.session.as_deref())
                    .is_some()
                {
                    return Err(Response::err(
                        id,
                        "E_SESSION_EXPIRED",
                        "session expired or revoked",
                    ));
                }
                let Some(derived) = proof else {
                    return Err(Response::err(id, "E_AUTH", "authentication failed"));
                };
                session
                    .unlock_with_proof(derived)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                // Unlock seeds a session so the passphrase is typed once: the
                // human just proved possession, mint with the default window.
                // Best-effort: the vault is already open and `vault.unlocked`
                // recorded by now, and the seed is Priority::Ordinary — so at
                // the audit soft ceiling the mint refuses with E_AUDIT_FULL.
                // That must not fail the unlock (threat-model §6: unlock
                // itself was fixed to never propagate an audit failure), and
                // must never mask the success. On mint failure return
                // unlocked:true with the session fields ABSENT — never a fake
                // credential — and report the skip on stderr like commit_with
                // reports a dropped lifecycle entry.
                match session.session_open(actor, crate::session::SESSION_DEFAULT_TTL_SECS) {
                    Ok((credential, prefix, expires_in, max_expires_in)) => {
                        let (expires_at, max_expires_at) =
                            session.session_display_times(expires_in, max_expires_in);
                        Ok(Response::ok(
                            id,
                            json!({
                                "unlocked": true,
                                "session_credential": credential,
                                "session_prefix": prefix,
                                "expires_at": expires_at,
                                "expires_in": expires_in,
                                "max_expires_at": max_expires_at,
                                "max_expires_in": max_expires_in,
                            }),
                        ))
                    }
                    Err(e) => {
                        eprintln!(
                            "svault: unlock session seed was NOT minted ({e}); \
                             the vault is unlocked and the client must call session.open"
                        );
                        Ok(Response::ok(id, json!({"unlocked": true})))
                    }
                }
            }
            "vault.create" => {
                // The vault Session existed (locked) when dispatch resolved it.
                Err(Response::err(id, "E_EXISTS", "vault already exists"))
            }
            "project.add" => {
                let (name, paths) = project_params(req)
                    .ok_or_else(|| Response::err(id, "E_INVALID_INPUT", "missing project name"))?;
                session
                    .project_add(actor, &name, &paths)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(id, json!({"added": name})))
            }
            "project.list" => {
                let list = session
                    .project_list(actor)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(
                    id,
                    json!({"projects": list.iter()
                    .map(|p| json!({"name": p.name, "paths": p.paths.iter()
                        .map(|x| x.display().to_string()).collect::<Vec<_>>()}))
                    .collect::<Vec<_>>()}),
                ))
            }
            "project.path.add" => {
                let (Some(name), Some(path)) =
                    (req.params["name"].as_str(), req.params["path"].as_str())
                else {
                    return Err(Response::err(id, "E_INVALID_INPUT", "missing name or path"));
                };
                session
                    .project_path_add(actor, name, Path::new(path))
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(id, json!({"added": path})))
            }
            "project.path.remove" => {
                let (Some(name), Some(path)) =
                    (req.params["name"].as_str(), req.params["path"].as_str())
                else {
                    return Err(Response::err(id, "E_INVALID_INPUT", "missing name or path"));
                };
                session
                    .project_path_remove(actor, name, Path::new(path))
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(id, json!({"removed": path})))
            }
            "project.remove" => {
                let Some(name) = req.params["name"].as_str() else {
                    return Err(Response::err(id, "E_INVALID_INPUT", "missing name"));
                };
                session
                    .project_remove(actor, name)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(id, json!({"removed": name})))
            }
            "secret.set" => {
                let (Some(project), Some(key), Some(value)) = (
                    req.params["project"].as_str(),
                    req.params["key"].as_str(),
                    req.params["value"].as_str(),
                ) else {
                    return Err(Response::err(
                        id,
                        "E_INVALID_INPUT",
                        "missing project, key or value",
                    ));
                };
                session
                    .secret_set(actor, project, key, value.as_bytes())
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(id, json!({"set": format!("{project}/{key}")})))
            }
            "secret.delete" => {
                let (Some(project), Some(key)) =
                    (req.params["project"].as_str(), req.params["key"].as_str())
                else {
                    return Err(Response::err(
                        id,
                        "E_INVALID_INPUT",
                        "missing project or key",
                    ));
                };
                session
                    .secret_delete(actor, project, key)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(
                    id,
                    json!({"deleted": format!("{project}/{key}")}),
                ))
            }
            "agents.add" => {
                let Some(name) = req.params["name"].as_str() else {
                    return Err(Response::err(id, "E_INVALID_INPUT", "missing name"));
                };
                let (agent_id, token) = session
                    .agent_add(actor, name)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(
                    id,
                    json!({"agent_id": agent_id, "token": token}),
                ))
            }
            "agents.revoke" => {
                let Some(name) = req.params["name"].as_str() else {
                    return Err(Response::err(id, "E_INVALID_INPUT", "missing name"));
                };
                let agent_id = session
                    .document()
                    .and_then(|doc| doc.agent_by_name(name))
                    .map(|agent| agent.id.clone());
                session
                    .agent_revoke(actor, name)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                self.terminate_matching_runs(
                    session,
                    actor,
                    Some(agent_id.as_deref().expect("revoked agent existed")),
                    None,
                )
                .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(id, json!({"revoked": name})))
            }
            "agents.list" => {
                let list = session
                    .agent_list(actor)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(
                    id,
                    json!({"agents": list.iter()
                    .map(|(name, status, prefix)| json!({
                        "name": name,
                        "status": format!("{status:?}").to_lowercase(),
                        "token_prefix": prefix,
                    }))
                    .collect::<Vec<_>>()}),
                ))
            }
            "grants.grant" => {
                let (Some(agent), Some(project)) =
                    (req.params["agent"].as_str(), req.params["project"].as_str())
                else {
                    return Err(Response::err(
                        id,
                        "E_INVALID_INPUT",
                        "missing agent or project",
                    ));
                };
                let ops = Op::parse_list(req.params["ops"].as_str().unwrap_or_default())
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                let previous_run_grant = session.document().and_then(|doc| {
                    let agent = doc.agent_by_name(agent)?;
                    let project = doc.project_by_name(project)?;
                    Some((
                        agent.id.clone(),
                        doc.authorize(&agent.id, &project.id, Op::Run),
                    ))
                });
                session
                    .grant_add(actor, agent, project, &ops)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                if !ops.contains(&Op::Run)
                    && let Some((agent_id, true)) = previous_run_grant
                {
                    self.terminate_matching_runs(session, "human", Some(&agent_id), Some(project))
                        .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                }
                Ok(Response::ok(
                    id,
                    json!({"granted": format!("{agent}/{project}")}),
                ))
            }
            "grants.revoke" => {
                let (Some(agent), Some(project)) =
                    (req.params["agent"].as_str(), req.params["project"].as_str())
                else {
                    return Err(Response::err(
                        id,
                        "E_INVALID_INPUT",
                        "missing agent or project",
                    ));
                };
                let agent_id = session
                    .document()
                    .and_then(|doc| doc.agent_by_name(agent))
                    .map(|record| record.id.clone());
                session
                    .grant_revoke(actor, agent, project)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                self.terminate_matching_runs(
                    session,
                    actor,
                    Some(agent_id.as_deref().expect("revoked grant agent existed")),
                    Some(project),
                )
                .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(
                    id,
                    json!({"revoked": format!("{agent}/{project}")}),
                ))
            }
            "grants.list" => {
                let list = session
                    .grant_list(actor)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(
                    id,
                    json!({"grants": list.iter()
                    .map(|g| json!({
                        "agent": g.agent,
                        "project": g.project,
                        "ops": g.ops.iter().map(|o| format!("{o:?}").to_lowercase())
                            .collect::<Vec<_>>(),
                        "revoked": g.revoked,
                    }))
                    .collect::<Vec<_>>()}),
                ))
            }
            "audit.show" => {
                // H-12(b) enforced centrally in dispatch (Identity::Human).
                let tail_raw = req.params.get("tail").cloned().unwrap_or(json!(20));
                let tail = tail_raw
                    .as_u64()
                    .ok_or_else(|| Response::err(id, "E_INVALID_INPUT", "tail must be 1..=1000"))?
                    as usize;
                if !(1..=1000).contains(&tail) {
                    return Err(Response::err(
                        id,
                        "E_INVALID_INPUT",
                        "tail must be 1..=1000",
                    ));
                }
                let before_seq = match req.params.get("before_seq") {
                    None | Some(Value::Null) => None,
                    Some(v) => Some(v.as_u64().ok_or_else(|| {
                        Response::err(id, "E_INVALID_INPUT", "invalid before_seq")
                    })?),
                };
                let (lines, next_before_seq) = session
                    .audit_show_page(actor, tail, before_seq)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(
                    id,
                    json!({"entries": lines.iter()
                    .map(|l| serde_json::to_value(l).expect("audit line serialization"))
                    .collect::<Vec<_>>(), "next_before_seq": next_before_seq}),
                ))
            }
            "audit.verify" => {
                let report = session
                    .audit_verify()
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(
                    id,
                    json!({"entries": report.entries,
                       "macs_verified": report.macs_verified,
                       "macs_null": report.macs_null}),
                ))
            }
            "lease.create" => {
                let Identity::Agent(agent_id) = identity else {
                    return Err(Response::err(
                        id,
                        "E_AUTH",
                        "lease.create requires agent credentials",
                    ));
                };
                let project = req.params["project"]
                    .as_str()
                    .ok_or_else(|| Response::err(id, "E_INVALID_INPUT", "missing project"))?;
                let ops = Op::parse_list(req.params["ops"].as_str().unwrap_or_default())
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                let ttl_secs = req.params["ttl_secs"]
                    .as_u64()
                    .ok_or_else(|| Response::err(id, "E_INVALID_INPUT", "missing ttl_secs"))?;
                let (lease, credential) = session
                    .lease_create(actor, agent_id, project, &ops, ttl_secs)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                // The credential is returned exactly once, here. Only its
                // digest and display prefix persist in the vault.
                Ok(Response::ok(
                    id,
                    json!({
                        "lease_id": lease.id,
                        "lease_prefix": lease.credential_prefix,
                        "lease_credential": credential,
                        "expires_at": lease.expires_at.to_string(),
                        "expires_in": ttl_secs,
                    }),
                ))
            }
            "lease.list" => {
                let owner = match identity {
                    Identity::Agent(agent_id) => Some(agent_id.as_str()),
                    Identity::Human => None,
                    Identity::Unauthenticated => unreachable!("rejected above"),
                };
                let leases = session
                    .lease_list(actor, owner)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                let now = time::OffsetDateTime::now_utc();
                let doc = session.document();
                Ok(Response::ok(
                    id,
                    json!({"leases": leases.iter().map(|lease| {
                    let project = doc
                        .and_then(|d| d.project_by_id(&lease.project_id))
                        .map(|p| p.name.as_str())
                        .unwrap_or("");
                    let expires_in = (lease.expires_at - now).whole_seconds().max(0) as u64;
                    let status = if lease.revoked_at.is_some() {
                        "revoked"
                    } else if now >= lease.expires_at {
                        "expired"
                    } else {
                        "active"
                    };
                    json!({
                        "lease_id": lease.id,
                        "lease_prefix": lease.credential_prefix,
                        "project": project,
                        "ops": lease.ops.iter()
                            .map(|op| format!("{op:?}").to_lowercase())
                            .collect::<Vec<_>>(),
                        "expires_at": lease.expires_at.to_string(),
                        "expires_in": expires_in,
                        "status": status,
                    })
                }).collect::<Vec<_>>() }),
                ))
            }
            "lease.revoke" => {
                let owner = match identity {
                    Identity::Agent(agent_id) => Some(agent_id.as_str()),
                    Identity::Human => None,
                    Identity::Unauthenticated => unreachable!("rejected above"),
                };
                let lease_id = req.params["lease_id"]
                    .as_str()
                    .ok_or_else(|| Response::err(id, "E_INVALID_INPUT", "missing lease_id"))?;
                session
                    .lease_revoke(actor, owner, lease_id)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(
                    id,
                    json!({"lease_id": lease_id, "revoked": true}),
                ))
            }
            "reveal" => {
                if matches!(identity, Identity::Human) {
                    if !req
                        .params
                        .get("approval_id")
                        .map(|v| v.is_null())
                        .unwrap_or(true)
                    {
                        return Err(Response::err(
                            id,
                            "E_INVALID_INPUT",
                            "human reveal takes no approval_id",
                        ));
                    }
                    // H-12(b) lease-on-human is enforced centrally in dispatch
                    // for every Identity::Human request (see above), with one
                    // error string; no per-arm duplicate here.
                    let project = req.params["project"]
                        .as_str()
                        .ok_or_else(|| Response::err(id, "E_INVALID_INPUT", "missing project"))?;
                    let key = req.params["key"]
                        .as_str()
                        .ok_or_else(|| Response::err(id, "E_INVALID_INPUT", "missing key"))?;
                    let value = session
                        .reveal_human(actor, project, key)
                        .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                    let value = String::from_utf8(value.to_vec()).map_err(|_| {
                        Response::err(id, "E_INVALID_INPUT", "secret is not valid UTF-8")
                    })?;
                    return Ok(Response::ok(id, json!({"value": value})));
                }
                let Identity::Agent(agent_id) = identity else {
                    return Err(Response::err(
                        id,
                        "E_AUTH",
                        "reveal requires agent credentials",
                    ));
                };
                let project = req.params["project"]
                    .as_str()
                    .ok_or_else(|| Response::err(id, "E_INVALID_INPUT", "missing project"))?;
                let key = req.params["key"]
                    .as_str()
                    .ok_or_else(|| Response::err(id, "E_INVALID_INPUT", "missing key"))?;
                let lease_credential = match lease_credential_param(req) {
                    Ok(v) => v,
                    Err(why) => {
                        return Err(Response::err(id, "E_INVALID_INPUT", why));
                    }
                };
                let op_actor = session
                    .authorize_lease(agent_id, project, Op::Reveal, lease_credential)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                if let Some(approval_id) = req.params["approval_id"].as_str() {
                    let value = session
                        .reveal_claim(&op_actor, agent_id, project, key, approval_id)
                        .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                    let value = String::from_utf8(value.to_vec()).map_err(|_| {
                        Response::err(id, "E_INVALID_INPUT", "secret is not valid UTF-8")
                    })?;
                    Ok(Response::ok(id, json!({"value": value})))
                } else {
                    let approval = session
                        .approval_request(&op_actor, agent_id, project, key)
                        .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                    let expires_in = (approval.pending_expires_at - time::OffsetDateTime::now_utc())
                        .whole_seconds()
                        .max(0) as u64;
                    Err(Response::err_data(
                        id,
                        "E_APPROVAL_PENDING",
                        "approval pending",
                        json!({"approval_id": approval.id, "expires_in": expires_in}),
                    ))
                }
            }
            "approvals.status" => {
                let Identity::Agent(agent_id) = identity else {
                    return Err(Response::err(
                        id,
                        "E_AUTH",
                        "approvals.status requires agent credentials",
                    ));
                };
                let approval_id = req.params["approval_id"]
                    .as_str()
                    .ok_or_else(|| Response::err(id, "E_INVALID_INPUT", "missing approval_id"))?;
                let status = session
                    .approval_status(agent_id, approval_id)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                let approval = session
                    .document()
                    .and_then(|d| d.approvals.iter().find(|a| a.id == approval_id));
                let (project, key, expires_in) = approval
                    .map(|approval| {
                        let project = session
                            .document()
                            .and_then(|d| d.project_by_id(&approval.project_id))
                            .map(|p| p.name.clone())
                            .unwrap_or_default();
                        let expires = approval
                            .claim_expires_at
                            .unwrap_or(approval.pending_expires_at);
                        let remaining = (expires - time::OffsetDateTime::now_utc())
                            .whole_seconds()
                            .max(0) as u64;
                        (project, approval.key.clone(), remaining)
                    })
                    .unwrap_or_default();
                Ok(Response::ok(
                    id,
                    json!({
                        "approval_id": approval_id,
                        "status": status,
                        "project": project,
                        "key": key,
                        "expires_in": expires_in,
                    }),
                ))
            }
            "approvals.pending" => {
                let approvals = session
                    .approval_pending(actor)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                let doc = session.document();
                Ok(Response::ok(
                    id,
                    json!({"approvals": approvals.iter().map(|approval| {
                    let project = doc
                        .and_then(|d| d.project_by_id(&approval.project_id))
                        .map(|p| p.name.as_str())
                        .unwrap_or("");
                    let agent = doc
                        .and_then(|d| d.agent_by_id(&approval.agent_id))
                        .map(|a| a.name.as_str())
                        .unwrap_or("");
                    json!({
                        "approval_id": approval.id,
                        "agent": agent,
                        "project": project,
                        "key": approval.key,
                        "status": "pending",
                        "expires_at": approval.pending_expires_at.to_string(),
                    })
                }).collect::<Vec<_>>() }),
                ))
            }
            "approvals.approve" | "approvals.deny" => {
                let approval_id = req.params["approval_id"]
                    .as_str()
                    .ok_or_else(|| Response::err(id, "E_INVALID_INPUT", "missing approval_id"))?;
                let approved = req.op == "approvals.approve";
                session
                    .approval_decide(actor, approval_id, approved)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(
                    id,
                    json!({
                        "approval_id": approval_id,
                        "status": if approved { "approved" } else { "denied" },
                    }),
                ))
            }
            "run_signal" => {
                let Identity::Agent(agent_id) = identity else {
                    session.audit_denied(actor, "run_signal", None, &[], None, &VaultError::Auth);
                    return Err(Response::err(
                        id,
                        "E_AUTH",
                        "run_signal requires agent credentials",
                    ));
                };
                let Some(run_id) = req.params["run_id"].as_str() else {
                    session.audit_denied(
                        actor,
                        "run_signal",
                        None,
                        &[],
                        None,
                        &VaultError::InvalidInput("missing run_id"),
                    );
                    return Err(Response::err(id, "E_INVALID_INPUT", "missing run_id"));
                };
                let Some(sig_name) = req.params["signal"].as_str() else {
                    session.audit_denied(
                        actor,
                        "run_signal",
                        None,
                        &[],
                        None,
                        &VaultError::InvalidInput("missing signal"),
                    );
                    return Err(Response::err(id, "E_INVALID_INPUT", "missing signal"));
                };
                let Some((project, _pid, pgid)) = self.runs.lookup_owned(agent_id, run_id) else {
                    session.audit_denied(
                        actor,
                        "run_signal",
                        None,
                        &[],
                        None,
                        &VaultError::NotFound,
                    );
                    return Err(Response::err(id, "E_NOT_FOUND", "not found"));
                };
                if session.ensure_run_unlocked().is_err() {
                    let _ = session.audit_run_signal(
                        actor,
                        &project,
                        run_id,
                        Decision::Denied,
                        Some(VaultError::Locked.code()),
                    );
                    return Err(Response::err(id, "E_LOCKED", "vault is locked"));
                }
                let authorized = session
                    .document()
                    .and_then(|d| {
                        let pid = d.project_by_name(&project)?.id.clone();
                        Some(d.authorize(agent_id, &pid, Op::Run))
                    })
                    .unwrap_or(false);
                if !authorized {
                    let _ = session.audit_run_signal(
                        actor,
                        &project,
                        run_id,
                        Decision::Denied,
                        Some(VaultError::Permission.code()),
                    );
                    return Err(Response::err(id, "E_PERMISSION", "permission denied"));
                }
                let sig = match run::parse_signal(sig_name) {
                    Ok(s) => s,
                    Err(e) => {
                        let code = e.code();
                        let msg = e.to_string();
                        let _ = session.audit_run_signal(
                            actor,
                            &project,
                            run_id,
                            Decision::Denied,
                            Some(code),
                        );
                        return Err(Response::err(id, code, msg));
                    }
                };
                // Recheck the live run immediately before signaling: the run
                // may have exited (and its pgid recycled) since lookup.
                match self.runs.lookup_owned(agent_id, run_id) {
                    Some((live_project, _, live_pgid))
                        if live_project == project && live_pgid == pgid => {}
                    _ => {
                        session.audit_denied(
                            actor,
                            "run_signal",
                            None,
                            &[],
                            None,
                            &VaultError::NotFound,
                        );
                        return Err(Response::err(id, "E_NOT_FOUND", "not found"));
                    }
                }
                if let Err(e) = run::signal_group(pgid, sig) {
                    let ve = VaultError::from(e);
                    let code = ve.code();
                    let _ = session.audit_run_signal(
                        actor,
                        &project,
                        run_id,
                        Decision::Denied,
                        Some(code),
                    );
                    return Err(Response::err(id, code, "signal failed"));
                }
                if session
                    .audit_run_signal(actor, &project, run_id, Decision::Allowed, None)
                    .is_err()
                {
                    return Err(Response::err(id, "E_AUDIT_WRITE", "audit write failed"));
                }
                Ok(Response::ok(
                    id,
                    json!({"run_id": run_id, "signaled": true}),
                ))
            }
            "session.open" => {
                // Caller must present passphrase proof only (HUMAN_ONLY rejects
                // agent tokens above; the three-way auth match rejects a
                // session credential here with E_SESSION_EXPIRED at dispatch).
                // `proof` is Some exactly when the passphrase verified.
                if req
                    .auth
                    .as_ref()
                    .and_then(|a| a.session.as_deref())
                    .is_some()
                {
                    return Err(Response::err(
                        id,
                        "E_SESSION_EXPIRED",
                        "session expired or revoked",
                    ));
                }
                let Some(_) = proof else {
                    session.audit_denied(actor, "session.open", None, &[], None, &VaultError::Auth);
                    return Err(Response::err(id, "E_AUTH", "authentication failed"));
                };
                let ttl_secs = match req.params.get("ttl_secs") {
                    None | Some(Value::Null) => crate::session::SESSION_DEFAULT_TTL_SECS,
                    Some(v) => v
                        .as_u64()
                        .ok_or_else(|| Response::err(id, "E_INVALID_INPUT", "invalid ttl_secs"))?,
                };
                let (credential, prefix, expires_in, max_expires_in) = session
                    .session_open(actor, ttl_secs)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                let (expires_at, max_expires_at) =
                    session.session_display_times(expires_in, max_expires_in);
                Ok(Response::ok(
                    id,
                    json!({
                        "session_credential": credential,
                        "session_prefix": prefix,
                        "expires_at": expires_at,
                        "expires_in": expires_in,
                        "max_expires_at": max_expires_at,
                        "max_expires_in": max_expires_in,
                    }),
                ))
            }
            "session.touch" => {
                let Some(credential) = req.auth.as_ref().and_then(|a| a.session.as_deref()) else {
                    // Passphrase path on touch is not the contract; touch is
                    // session-only. A passphrase here has no session to renew.
                    // Agent tokens were already rejected as HUMAN_ONLY; an
                    // unauthenticated touch fails closed below via the auth
                    // match (it cannot reach here unauthenticated).
                    return Err(Response::err(
                        id,
                        "E_SESSION_EXPIRED",
                        "session expired or revoked",
                    ));
                };
                let (_actor, expires_in, max_expires_in) = session
                    .session_touch(credential)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                let (expires_at, max_expires_at) =
                    session.session_display_times(expires_in, max_expires_in);
                Ok(Response::ok(
                    id,
                    json!({
                        "expires_at": expires_at,
                        "expires_in": expires_in,
                        "max_expires_at": max_expires_at,
                        "max_expires_in": max_expires_in,
                    }),
                ))
            }
            "session.close" => {
                let Some(credential) = req.auth.as_ref().and_then(|a| a.session.as_deref()) else {
                    return Err(Response::err(
                        id,
                        "E_SESSION_EXPIRED",
                        "session expired or revoked",
                    ));
                };
                session
                    .session_close(credential)
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(id, json!({"closed": true})))
            }
            "runs.list" => {
                // H-12(b) enforced centrally in dispatch (Identity::Human).
                let runs = self.runs.snapshot();
                let doc = session.document();
                let mut out: Vec<Value> = Vec::with_capacity(runs.len());
                for (run_id, meta) in runs {
                    let agent = doc
                        .and_then(|d| d.agent_by_id(&meta.agent))
                        .map(|a| a.name.clone())
                        .unwrap_or_else(|| meta.agent.clone());
                    let project = meta.project.clone();
                    out.push(json!({
                        "run_id": run_id,
                        "agent": agent,
                        "project": project,
                        "pid": meta.pid,
                        "started_at": meta.started_at.to_string(),
                        "status": "running",
                    }));
                }
                out.sort_by(|a, b| a["run_id"].as_str().cmp(&b["run_id"].as_str()));
                session
                    .audit_record(
                        actor,
                        Record {
                            actor,
                            op: "runs.list",
                            project: None,
                            keys: &[],
                            target: None,
                            decision: Decision::Allowed,
                            reason: None,
                        },
                    )
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(id, json!({"runs": out})))
            }
            "vault.health" => {
                // H-12(b) enforced centrally in dispatch (Identity::Human).
                let health =
                    session.vault_health(self.config.idle_lock.as_secs(), self.runs_count());
                session
                    .audit_record(
                        actor,
                        Record {
                            actor,
                            op: "vault.health",
                            project: None,
                            keys: &[],
                            target: None,
                            decision: Decision::Allowed,
                            reason: None,
                        },
                    )
                    .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
                Ok(Response::ok(id, health))
            }
            other => Err(Response::err(
                id,
                "E_PROTOCOL",
                format!("unknown op: {other}"),
            )),
        }
    }

    fn op_create(
        &self,
        guard: &mut MutexGuard<'_, Option<Session>>,
        id: &str,
        req: &Request,
    ) -> Result<Response, Response> {
        // No vault => no session registry exists, so any session credential
        // is unknown by construction: E_SESSION_EXPIRED (never E_AUTH, never
        // a create). S-06/C-10: vault.create never seeds a session.
        if req
            .auth
            .as_ref()
            .and_then(|a| a.session.as_deref())
            .is_some()
        {
            return Err(Response::err(
                id,
                "E_SESSION_EXPIRED",
                "session expired or revoked",
            ));
        }
        // Bootstrap: no vault exists to verify against; the passphrase may
        // arrive as the auth proof or as a param — it becomes the first
        // key-slot passphrase.
        let pass = req
            .auth
            .as_ref()
            .and_then(|a| a.passphrase.as_deref())
            .or_else(|| req.params["passphrase"].as_str())
            .ok_or_else(|| Response::err(id, "E_INVALID_INPUT", "missing passphrase"))?;
        let mut session = Session::create(
            &self.config.vault_path,
            pass.as_bytes(),
            self.config.idle_lock,
            Box::new(SystemClock),
        )
        .map_err(|e| Response::err(id, e.code(), e.to_string()))?;
        session.defer_idle_lock();
        **guard = Some(session);
        Ok(Response::ok(
            id,
            json!({"created": self.config.vault_path.display().to_string()}),
        ))
    }
}

fn project_params(req: &Request) -> Option<(String, Vec<PathBuf>)> {
    let name = req.params["name"].as_str()?.to_string();
    let paths = req.params["paths"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(PathBuf::from))
                .collect()
        })
        .unwrap_or_default();
    Some((name, paths))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestDir;
    use std::io::BufRead;

    fn daemon(dir: &TestDir) -> Daemon {
        Daemon::new(DaemonConfig {
            socket_path: dir.path().join("svault.sock"),
            vault_path: dir.path().join("vault.enc"),
            idle_lock: Duration::from_secs(60),
        })
        .unwrap()
    }

    fn req(id: &str, op: &str, token: Option<&str>, params: serde_json::Value) -> Request {
        Request {
            v: wire::VERSION,
            id: id.to_string(),
            op: op.to_string(),
            auth: Some(crate::wire::AuthField {
                token: token.map(str::to_string),
                passphrase: None,
                session: None,
            }),
            params,
        }
    }

    fn reqh(id: &str, op: &str, pass: &str, params: serde_json::Value) -> Request {
        Request {
            v: wire::VERSION,
            id: id.to_string(),
            op: op.to_string(),
            auth: Some(crate::wire::AuthField {
                token: None,
                passphrase: Some(pass.to_string()),
                session: None,
            }),
            params,
        }
    }

    fn reqn(id: &str, op: &str, params: serde_json::Value) -> Request {
        Request {
            v: wire::VERSION,
            id: id.to_string(),
            op: op.to_string(),
            auth: None,
            params,
        }
    }

    fn err_code(resp: &Response) -> String {
        resp.error.as_ref().unwrap().code.to_string()
    }

    #[test]
    fn no_vault_before_init() {
        let dir = TestDir::new();
        let d = daemon(&dir);
        let resp = d.handle_request(reqn("1", "vault.status", json!({})));
        assert_eq!(err_code(&resp), "E_NOT_FOUND");
    }

    #[test]
    fn full_setup_then_agent_list_with_grant() {
        let dir = TestDir::new();
        let d = daemon(&dir);
        // Create + unlock (human).
        let resp = d.handle_request(reqh(
            "1",
            "vault.create",
            "correct horse battery",
            json!({}),
        ));
        assert!(resp.ok);
        d.handle_request(reqh(
            "2",
            "vault.unlock",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh(
            "3",
            "project.add",
            "correct horse battery",
            json!({"name": "acme"}),
        ));
        d.handle_request(reqh(
            "4",
            "secret.set",
            "correct horse battery",
            json!({"project": "acme", "key": "STRIPE_KEY", "value": "sk-trap-0xf00dVALUE"}),
        ));

        // Enroll (human-only): the token comes back exactly once.
        let resp = d.handle_request(reqh(
            "5",
            "agents.add",
            "correct horse battery",
            json!({"name": "harness"}),
        ));
        assert!(resp.ok);
        let token = resp.result.unwrap()["token"].as_str().unwrap().to_string();

        // Agent without grant → E_PERMISSION.
        let resp = d.handle_request(req(
            "6",
            "secrets.list",
            Some(&token),
            json!({"project": "acme"}),
        ));
        assert_eq!(err_code(&resp), "E_PERMISSION");

        // Grant read → agent sees names, never values.
        d.handle_request(reqh(
            "7",
            "grants.grant",
            "correct horse battery",
            json!({"agent": "harness", "project": "acme", "ops": "read"}),
        ));
        let resp = d.handle_request(req(
            "8",
            "secrets.list",
            Some(&token),
            json!({"project": "acme"}),
        ));
        assert!(resp.ok);
        let text = serde_json::to_string(&resp).unwrap();
        assert!(text.contains("STRIPE_KEY"));
        assert!(!text.contains("sk-trap-0xf00dVALUE"));
    }

    #[test]
    fn unknown_and_revoked_tokens_fail_closed() {
        let dir = TestDir::new();
        let d = daemon(&dir);
        d.handle_request(reqh(
            "1",
            "vault.create",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh(
            "2",
            "vault.unlock",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh(
            "3",
            "project.add",
            "correct horse battery",
            json!({"name": "acme"}),
        ));
        let resp = d.handle_request(reqh(
            "4",
            "agents.add",
            "correct horse battery",
            json!({"name": "harness"}),
        ));
        let token = resp.result.unwrap()["token"].as_str().unwrap().to_string();
        d.handle_request(reqh(
            "5",
            "grants.grant",
            "correct horse battery",
            json!({"agent": "harness", "project": "acme", "ops": "read"}),
        ));

        // Unknown token.
        let resp = d.handle_request(req(
            "6",
            "secrets.list",
            Some("bogus-token"),
            json!({"project": "acme"}),
        ));
        assert_eq!(err_code(&resp), "E_AUTH");

        // Revoke → immediate.
        d.handle_request(reqh(
            "7",
            "agents.revoke",
            "correct horse battery",
            json!({"name": "harness"}),
        ));
        let resp = d.handle_request(req(
            "8",
            "secrets.list",
            Some(&token),
            json!({"project": "acme"}),
        ));
        assert_eq!(err_code(&resp), "E_AUTH");
    }

    #[test]
    fn human_only_ops_reject_agent_tokens() {
        let dir = TestDir::new();
        let d = daemon(&dir);
        d.handle_request(reqh(
            "1",
            "vault.create",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh(
            "2",
            "vault.unlock",
            "correct horse battery",
            json!({}),
        ));
        let resp = d.handle_request(reqh(
            "3",
            "agents.add",
            "correct horse battery",
            json!({"name": "harness"}),
        ));
        let token = resp.result.unwrap()["token"].as_str().unwrap().to_string();

        for op in [
            "agents.add",
            "agents.revoke",
            "agents.list",
            "grants.grant",
            "grants.list",
            "project.add",
            "project.list",
            "secret.set",
            "secret.delete",
            "audit.show",
            "audit.verify",
            "vault.unlock",
        ] {
            let resp = d.handle_request(req(
                op,
                op,
                Some(&token),
                json!({"name": "x", "project": "p", "passphrase": "x", "tail": 1}),
            ));
            assert_eq!(
                err_code(&resp),
                "E_HUMAN_REQUIRED",
                "op {op} must be human-only"
            );
        }
    }

    #[test]
    fn agent_can_lock_but_not_unlock_and_lock_takes_effect_immediately() {
        let dir = TestDir::new();
        let d = daemon(&dir);
        d.handle_request(reqh(
            "1",
            "vault.create",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh(
            "2",
            "vault.unlock",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh(
            "3",
            "project.add",
            "correct horse battery",
            json!({"name": "acme"}),
        ));
        let resp = d.handle_request(reqh(
            "4",
            "agents.add",
            "correct horse battery",
            json!({"name": "harness"}),
        ));
        let token = resp.result.unwrap()["token"].as_str().unwrap().to_string();
        d.handle_request(reqh(
            "5",
            "grants.grant",
            "correct horse battery",
            json!({"agent": "harness", "project": "acme", "ops": "read"}),
        ));

        // Agent locks the vault (fail-safe direction).
        let resp = d.handle_request(req("6", "vault.lock", Some(&token), json!({})));
        assert!(resp.ok);

        // Agent ops now fail locked...
        let resp = d.handle_request(req(
            "7",
            "secrets.list",
            Some(&token),
            json!({"project": "acme"}),
        ));
        assert_eq!(err_code(&resp), "E_LOCKED");

        // ...and only the human can unlock again; agents are always rejected.
        let resp = d.handle_request(req(
            "8",
            "vault.unlock",
            Some(&token),
            json!({"passphrase": "correct horse battery"}),
        ));
        assert_eq!(err_code(&resp), "E_HUMAN_REQUIRED");
        let resp = d.handle_request(reqh(
            "9",
            "vault.unlock",
            "correct horse battery",
            json!({}),
        ));
        assert!(resp.ok);
    }

    #[test]
    fn unimplemented_ops_report_protocol_errors() {
        let dir = TestDir::new();
        let d = daemon(&dir);
        d.handle_request(reqh(
            "1",
            "vault.create",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh(
            "2",
            "vault.unlock",
            "correct horse battery",
            json!({}),
        ));
        let resp = d.handle_request(reqh(
            "3",
            "agents.add",
            "correct horse battery",
            json!({"name": "harness"}),
        ));
        let token = resp.result.unwrap()["token"].as_str().unwrap().to_string();

        for op in [
            "agents.add",
            "agents.revoke",
            "agents.list",
            "grants.grant",
            "grants.list",
            "project.add",
            "project.list",
            "secret.set",
            "secret.delete",
            "audit.show",
            "audit.verify",
            "vault.unlock",
        ] {
            let resp = d.handle_request(req(
                op,
                op,
                Some(&token),
                json!({"name": "x", "project": "p", "passphrase": "x", "tail": 1}),
            ));
            assert_eq!(
                err_code(&resp),
                "E_HUMAN_REQUIRED",
                "op {op} must be human-only"
            );
        }

        // A valid agent omitting its token gains nothing: the request is
        // unauthenticated, never human (E_AUTH, not human-only path).
        let resp = d.handle_request(reqn("x1", "agents.add", json!({"name": "esc"})));
        assert_eq!(err_code(&resp), "E_AUTH");
        let resp = d.handle_request(reqn(
            "x2",
            "secret.set",
            json!({"project": "acme", "key": "K", "value": "v"}),
        ));
        assert_eq!(err_code(&resp), "E_AUTH");

        // The public op answers without credentials.
        let resp = d.handle_request(reqn("x3", "vault.status", json!({})));
        assert!(resp.ok);
    }

    #[test]
    fn unauthenticated_request_is_never_human() {
        // Scenario 1+2: no token/proof on a human op → denied; a valid agent
        // omitting its token gains nothing (it is unauthenticated, not human).
        let dir = TestDir::new();
        let d = daemon(&dir);
        d.handle_request(reqh(
            "1",
            "vault.create",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh(
            "2",
            "vault.unlock",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh(
            "3",
            "project.add",
            "correct horse battery",
            json!({"name": "acme"}),
        ));
        let resp = d.handle_request(reqh(
            "4",
            "agents.add",
            "correct horse battery",
            json!({"name": "harness"}),
        ));
        let token = resp.result.unwrap()["token"].as_str().unwrap().to_string();

        for op in [
            "agents.add",
            "grants.grant",
            "secret.set",
            "project.add",
            "audit.show",
        ] {
            let resp = d.handle_request(reqn("n1", op, json!({"name": "x", "project": "p"})));
            assert_eq!(
                err_code(&resp),
                "E_AUTH",
                "op {op} must require credentials"
            );
        }
        // The same requests with the agent's token stay human-only-rejected
        // (never elevated).
        let resp = d.handle_request(req(
            "n2",
            "agents.add",
            Some(&token),
            json!({"name": "esc"}),
        ));
        assert_eq!(err_code(&resp), "E_HUMAN_REQUIRED");
        let resp = d.handle_request(req(
            "n3",
            "secret.set",
            Some(&token),
            json!({"project": "acme", "key": "K", "value": "v"}),
        ));
        assert_eq!(err_code(&resp), "E_HUMAN_REQUIRED");
    }

    #[test]
    fn human_proof_gates_privileged_ops_without_oracle() {
        // Scenario 4+5: correct proof → allowed; wrong proof → denied with
        // the same generic message as every other auth failure.
        let dir = TestDir::new();
        let d = daemon(&dir);
        d.handle_request(reqh(
            "1",
            "vault.create",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh(
            "2",
            "vault.unlock",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh(
            "3",
            "project.add",
            "correct horse battery",
            json!({"name": "acme"}),
        ));

        let wrong = d.handle_request(reqh(
            "4",
            "secret.set",
            "wrong-passphrase-guess",
            json!({"project": "acme", "key": "K", "value": "v"}),
        ));
        assert_eq!(err_code(&wrong), "E_AUTH");
        let unknown_token = d.handle_request(req(
            "5",
            "secret.set",
            Some("bogus"),
            json!({"project": "acme", "key": "K", "value": "v"}),
        ));
        // No oracle: wrong proof and unknown identity produce identical
        // messages.
        assert_eq!(
            wrong.error.as_ref().unwrap().msg,
            unknown_token.error.as_ref().unwrap().msg
        );

        let ok = d.handle_request(reqh(
            "6",
            "secret.set",
            "correct horse battery",
            json!({"project": "acme", "key": "K", "value": "v"}),
        ));
        assert!(ok.ok);
    }

    #[test]
    fn passphrases_never_reach_audit_or_responses() {
        // Scenario 6: proof material is absent from audit entries and error
        // payloads even when the proof is wrong.
        let dir = TestDir::new();
        let d = daemon(&dir);
        d.handle_request(reqh(
            "1",
            "vault.create",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh(
            "2",
            "vault.unlock",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh(
            "3",
            "project.add",
            "correct horse battery",
            json!({"name": "acme"}),
        ));

        let trap = "TRAP-passphrase-0xf00d";
        let resp = d.handle_request(reqh(
            "4",
            "secret.set",
            trap,
            json!({"project": "acme", "key": "K", "value": "v"}),
        ));
        assert_eq!(err_code(&resp), "E_AUTH");
        let resp_text = serde_json::to_string(&resp).unwrap();
        assert!(!resp_text.contains(trap));

        let audit_path = crate::store::audit_path(&dir.path().join("vault.enc"));
        let audit = std::fs::read_to_string(audit_path).unwrap();
        assert!(!audit.contains(trap));
        assert!(!audit.contains("correct horse battery"));
    }

    #[test]
    fn token_file_write_refuses_overwrite_and_is_private() {
        // --write-token-file: 0600, refuse overwrite (and symlinks, via
        // O_CREAT|O_EXCL) on repeated use.
        let dir = TestDir::new();
        let d = daemon(&dir);
        d.handle_request(reqh(
            "1",
            "vault.create",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh(
            "2",
            "vault.unlock",
            "correct horse battery",
            json!({}),
        ));
        let path = dir.path().join("harness.token");
        let resp = d.handle_request(reqh(
            "3",
            "agents.add",
            "correct horse battery",
            json!({"name": "harness"}),
        ));
        let token = resp.result.unwrap()["token"].as_str().unwrap().to_string();
        crate::cli::write_token_file_for_test(&path, &token).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // Overwrite refused.
        assert!(crate::cli::write_token_file_for_test(&path, &token).is_err());
        // Contents intact.
        assert!(std::fs::read_to_string(&path).unwrap().contains(&token));
    }

    #[test]
    fn connection_limit_is_enforced() {
        let dir = TestDir::new();
        let d = Arc::new(daemon(&dir));
        let socket = dir.path().join("svault.sock");
        let server = Arc::clone(&d);
        std::thread::spawn(move || {
            let _ = server.serve();
        });
        for _ in 0..100 {
            if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // Hold MAX connections open (each blocks its thread on read).
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_CONNECTIONS {
            held.push(std::os::unix::net::UnixStream::connect(&socket).unwrap());
            std::thread::sleep(Duration::from_millis(20));
        }
        // The next connection is rejected with an immediate error response.
        let extra = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        let mut line = String::new();
        let mut reader = std::io::BufReader::new(&extra);
        reader.read_line(&mut line).unwrap();
        assert!(
            line.contains("too many concurrent connections"),
            "got: {line}"
        );
        drop(held);
    }

    #[test]
    fn create_twice_reports_exists() {
        let dir = TestDir::new();
        let d = daemon(&dir);
        let resp = d.handle_request(reqh(
            "1",
            "vault.create",
            "correct horse battery",
            json!({}),
        ));
        assert!(resp.ok);
        let resp = d.handle_request(reqh(
            "2",
            "vault.create",
            "correct horse battery",
            json!({}),
        ));
        assert_eq!(err_code(&resp), "E_EXISTS");
    }

    #[test]
    fn human_only_has_no_duplicates_and_no_entry_without_an_arm() {
        // D0 cleanup pin: the stale "projects.add" (no dispatch arm) was
        // removed; every HUMAN_ONLY entry must name a real human-only arm
        // exactly once. Cross-checked against dispatch_op arms in both
        // directions (no new public API — this lives in mod tests).
        let mut seen = std::collections::HashSet::new();
        for op in HUMAN_ONLY {
            assert!(seen.insert(*op), "duplicate HUMAN_ONLY entry: {op}");
        }
        assert!(
            !HUMAN_ONLY.contains(&"projects.add"),
            "stale entry must stay removed"
        );
        // Every HUMAN_ONLY entry has a dispatch arm (project.add is the real
        // arm; projects.add has none and must stay E_PROTOCOL unknown op).
        for op in HUMAN_ONLY {
            assert!(
                matches!(
                    *op,
                    "vault.create"
                        | "vault.unlock"
                        | "project.add"
                        | "project.list"
                        | "project.path.add"
                        | "project.path.remove"
                        | "project.remove"
                        | "secret.set"
                        | "secret.delete"
                        | "agents.add"
                        | "agents.revoke"
                        | "agents.list"
                        | "grants.grant"
                        | "grants.revoke"
                        | "grants.list"
                        | "audit.show"
                        | "audit.verify"
                        | "approvals.pending"
                        | "approvals.approve"
                        | "approvals.deny"
                        | "session.open"
                        | "session.touch"
                        | "session.close"
                        | "runs.list"
                        | "vault.health"
                ),
                "HUMAN_ONLY entry without a dispatch arm: {op}"
            );
        }
        // Behavior-preserving: projects.add on the wire still fails with
        // E_PROTOCOL unknown op (it never had an arm; it no longer matches
        // HUMAN_ONLY, so an agent token reports unknown-op instead of
        // human-only — identical outcome class: denied, audited, no capability).
        let dir = TestDir::new();
        let d = daemon(&dir);
        d.handle_request(reqh(
            "1",
            "vault.create",
            "correct horse battery",
            json!({}),
        ));
        let resp = d.handle_request(reqh(
            "2",
            "projects.add",
            "correct horse battery",
            json!({}),
        ));
        assert_eq!(err_code(&resp), "E_PROTOCOL");
    }

    #[test]
    fn unlock_succeeds_without_session_seed_when_audit_log_full() {
        // Threat-model §6 regression pin: the vault is already open and
        // `vault.unlocked` recorded (best-effort lifecycle) before the seed
        // is minted, and the seed is Priority::Ordinary — so at the soft
        // ceiling the mint refuses with E_AUDIT_FULL. That must not fail the
        // unlock or mask its success: unlocked:true with the session fields
        // ABSENT (never a fake credential, never a response error).
        let dir = TestDir::new();
        let d = daemon(&dir);
        d.handle_request(reqh(
            "1",
            "vault.create",
            "correct horse battery",
            json!({}),
        ));
        d.handle_request(reqh("2", "vault.lock", "correct horse battery", json!({})));
        {
            let mut guard = d.lock_session();
            let session = guard.as_mut().expect("vault exists");
            session.set_audit_limits_for_test(1, 1);
        }
        let resp = d.handle_request(reqh(
            "3",
            "vault.unlock",
            "correct horse battery",
            json!({}),
        ));
        assert!(
            resp.ok,
            "unlock must succeed at the ceiling, got {:?}",
            resp.error
        );
        let result = resp.result.as_ref().expect("ok carries a result");
        assert_eq!(result["unlocked"], true);
        for field in [
            "session_credential",
            "session_prefix",
            "expires_at",
            "expires_in",
            "max_expires_at",
            "max_expires_in",
        ] {
            assert!(
                result.get(field).is_none(),
                "field {field} must be absent when the seed was not minted"
            );
        }
        // The mint itself still fails closed: nothing stored, no credential.
        let resp = d.handle_request(reqh(
            "4",
            "session.open",
            "correct horse battery",
            json!({}),
        ));
        assert_eq!(err_code(&resp), "E_AUDIT_FULL");
    }
}
