//! D6 backend: thirty named commands over a secure broker connection.
//!
//! Architecture: frontend TS --named commands--> this module --svault
//! client--> `broker.hello` + pin --> UDS Wire v1 --> broker. There is NO
//! generic `call(op, params)` command: every operation is a separately named
//! function with a FIXED op and FIXED param shape.
//!
//! Security rules (enforced here, not in JS):
//! - The session credential lives in Rust ONLY (in [`AppState`], wrapped in
//!   `Zeroizing`). It NEVER crosses the IPC boundary, NEVER appears in a
//!   response to JS, and is NEVER logged.
//! - NO `println!`/`eprintln!`/log call anywhere in this file may include a
//!   passphrase, the session credential, a secret value, or a token.
//! - One request per connection: a FRESH broker call per operation; no
//!   long-lived connection in state (the broker closes after one request).
//! - Gate order per call (inside `svault::client::broker_call_with_auth` /
//!   `handshake_strict`): connect -> `ipc::verify_server` -> `broker.hello`
//!   -> pin decision, with ZERO credential bytes before the pin verifies. Pin
//!   mismatch fails closed: never auto-repin, never overwrite.
//! - The twenty-four D2+D3+D4+D6 commands are HUMAN-ONLY on the wire: every one of them
//!   authenticates with the session credential held in Rust. Never a
//!   passphrase (used only by `unlock`), never an agent token.
//! - `agent_add` returns the enrollment token exactly ONCE, in its response
//!   only: it crosses IPC on that response and is never retained server-side
//!   (no `AppState` field, no log line, no error carries it). The frontend
//!   must not persist it; an optional `token_path` persists it via
//!   `svault::cli::write_token_file` (`O_EXCL`: refuses overwrite) instead.

use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use svault::client::Auth;
use zeroize::Zeroizing;

/// Exactly the thirty D1+D2+D3+D4+D6 commands. The allowlist test pins this.
///
/// First trust happens at a TTY via the CLI ceremony; there is no pin-write
/// path here by design.
pub const COMMANDS: [&str; 30] = [
    "get_status",
    "pin_status",
    "probe_fingerprint",
    "unlock",
    "lock",
    "health",
    "overview_refresh",
    "projects_list",
    "project_add",
    "project_remove",
    "project_path_add",
    "project_path_remove",
    "secrets_list",
    "secret_set",
    "secret_delete",
    "agents_list",
    "agent_add",
    "agent_revoke",
    "grants_list",
    "grant_set",
    "grant_revoke",
    "approvals_pending",
    "approval_approve",
    "approval_deny",
    "reveal",
    "leases_list",
    "lease_revoke",
    "runs_list",
    "audit_show",
    "audit_verify",
];

/// Bound on the per-project `secrets.list` fan-out inside
/// [`overview_refresh`]: one connection per call and a 32-connection broker
/// intake cap, so this must never fan out over an unbounded project list.
/// Past the cap the overview still returns the bounded partial sum with
/// `secrets_total_exact: false` so the UI can render "≥ N".
pub const OVERVIEW_SECRETS_PROJECT_CAP: usize = 50;

/// Navigation-guard predicate for the Tauri webview: true ONLY for the
/// `tauri` scheme (case-insensitive), with no leading whitespace/control
/// byte. This project serves its UI from embedded assets
/// (`WebviewUrl::App`) with no `devUrl`, and the frontend router is
/// hash-only, so no http(s), file, data, blob, or javascript URL is ever
/// legitimate — this matches Tauri's documented `url.scheme() == "tauri"`
/// pattern. Tauri-free on purpose so it stays unit-testable in this module.
pub fn allow_navigation(raw_url: &str) -> bool {
    if raw_url.bytes().next().is_some_and(|b| b <= b' ') {
        return false;
    }
    raw_url
        .split_once(':')
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("tauri"))
}

/// Stable error shape crossing to JS: code + safe message only. Never
/// forwards raw `Debug`/`Display` of anything carrying secret material; a
/// broker/auth failure never leaks whether a passphrase was close.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CmdError {
    pub code: String,
    pub message: String,
}

impl CmdError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl From<svault::VaultError> for CmdError {
    fn from(e: svault::VaultError) -> Self {
        // Local (non-wire) failures only: connect-time trust/offline, pin
        // reads, fingerprint parsing. Broker refusals never take this path —
        // they arrive as `BrokerError` with the exact wire code (see
        // `From<BrokerError>` below). `Display` here is static except
        // `Io`/`Protocol`/`Corrupt`/`AuditWrite`, which can carry OS/peer or
        // detail text: scrub those to fixed strings so no path/peer bytes
        // leak into a JS-visible message.
        let code = e.code().to_string();
        let message = match &e {
            svault::VaultError::Io(_) => "filesystem error".to_string(),
            svault::VaultError::Protocol(_) => "protocol error".to_string(),
            svault::VaultError::Corrupt(_) => "vault file corrupted".to_string(),
            svault::VaultError::AuditWrite(_) => "audit write failed".to_string(),
            svault::VaultError::InvalidInput(_) => "invalid input".to_string(),
            svault::VaultError::AuditFull(_) => "audit log is full".to_string(),
            svault::VaultError::BrokerUntrusted(_) => {
                "broker identity could not be verified".to_string()
            }
            other => other.to_string(),
        };
        Self::new(code, message)
    }
}

/// Static JS-visible message per broker code. `BrokerError.code` is the
/// broker's own `E_*` string straight off the wire — forwarded VERBATIM as
/// `CmdError.code`, never guessed. `BrokerError.msg` is broker-authored
/// `VaultError::Display` text, which for a few variants carries detail
/// (paths, OS text), so it is NEVER forwarded verbatim: the message comes
/// from this table instead, keyed by CODE. Unknown codes keep their code
/// with a generic message — an unseen broker refusal still arrives intact
/// instead of collapsing to `E_PROTOCOL`. `data` stays dropped (D1
/// decision: `E_APPROVAL_PENDING` is out of scope).
pub(crate) fn broker_message(code: &str) -> &'static str {
    match code {
        "E_AUTH" => "authentication failed",
        "E_LOCKED" => "vault is locked",
        "E_BUSY" => "too many concurrent operations",
        "E_VAULT_CORRUPT" => "vault file corrupted",
        "E_INSECURE_PARAMS" => "kdf parameters outside accepted bounds",
        "E_WEAK_PASSPHRASE" => "passphrase must be at least 12 characters",
        "E_HUMAN_REQUIRED" => "this operation is human-only",
        "E_EXISTS" => "already exists",
        "E_MISMATCH" => "passphrases do not match",
        "E_NOT_FOUND" => "not found",
        "E_PERMISSION" => "permission denied",
        "E_PATH_NOT_AUTHORIZED" => "path outside authorized folders",
        "E_LEASE_EXPIRED" => "lease expired or revoked",
        "E_SESSION_EXPIRED" => "session expired or revoked",
        "E_APPROVAL_PENDING" => "approval pending",
        "E_APPROVAL_DENIED" => "approval denied",
        "E_APPROVAL_CONSUMED" => "approval already claimed",
        "E_APPROVAL_EXPIRED" => "approval expired",
        "E_TOO_LARGE" => "message too large",
        "E_VAULT_TOO_LARGE" => "vault would exceed the maximum size",
        "E_INVALID_INPUT" => "invalid input",
        "E_AUDIT_FULL" => "audit log is full",
        "E_AUDIT_WRITE" => "audit write failed",
        "E_BROKER_UNTRUSTED" => "broker identity could not be verified",
        "E_IO" => "filesystem error",
        "E_PROTOCOL" => "protocol error",
        _ => "broker error",
    }
}
impl From<svault::client::BrokerError> for CmdError {
    fn from(e: svault::client::BrokerError) -> Self {
        Self::new(e.code.clone(), broker_message(&e.code))
    }
}

/// Rust-side state. The session credential (when present) lives ONLY here,
/// inside `Zeroizing`, and never leaves Rust. The socket path + pin state are
/// cheap to re-derive per call; the client itself is NOT held (one request
/// per connection — fresh `Client` per broker call).
///
/// NO-SECRET-LOGGING RULE: no `println!`/`eprintln!`/log call in this module
/// may include a passphrase, the session credential, or a token.
pub struct AppState {
    /// Daemon socket path (explicit override or CLI default).
    pub socket: PathBuf,
    /// Server-minted human-session credential, set by `unlock`, dropped by
    /// `lock`. `None` = no session (locked or never unlocked).
    pub session: Mutex<Option<Zeroizing<String>>>,
}

impl AppState {
    pub fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            session: Mutex::new(None),
        }
    }

    /// Auth for an authenticated call: session credential when held.
    /// Callers needing passphrase auth (unlock, locked-health) pass it
    /// explicitly instead; this helper is for the session path only.
    fn session_auth(&self) -> Option<Auth> {
        self.session
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| Auth::Session(s.to_string())))
    }

    /// Drop the held session credential (lock path; also the window-close path
    /// in `main.rs`).
    pub fn drop_session(&self) {
        if let Ok(mut g) = self.session.lock() {
            *g = None;
        }
    }

    /// Take the held session credential out of state, leaving `None` behind.
    /// The window-close path takes (rather than drops) first so the
    /// credential is cleared from `AppState` unconditionally — including on
    /// the lock timeout path — while still handing the caller the value to
    /// authenticate the final lock with.
    pub fn take_session(&self) -> Option<Zeroizing<String>> {
        self.session.lock().ok().and_then(|mut g| g.take())
    }
}

/// One authenticated-or-not broker call over a fresh connection
/// (`svault::client::broker_call_with_auth`: connect -> `verify_server` ->
/// strict handshake+pin -> one request -> close; the single shared transport
/// also used by `mcp::broker_call`). Broker refusals arrive with their exact
/// wire `E_*` code (no guessing); local trust/offline failures arrive as
/// `E_BROKER_UNTRUSTED` (pin mismatch, no pin) or `E_IO` (dead socket).
/// Every `Auth` variant incl. `Session` is forwarded — the dashboard is the
/// HUMAN surface (contrast `mcp::broker_call`, which refuses `Session`
/// before any I/O per C-04/S-16).
fn call(
    socket: &std::path::Path,
    op: &str,
    auth: &svault::client::Auth,
    params: serde_json::Value,
) -> Result<serde_json::Value, CmdError> {
    svault::client::broker_call_with_auth(socket, op, auth, params).map_err(CmdError::from)
}

/// Session credential for a human-only op, with trust-first ordering: when no
/// session is held, still open (and drop) a strict connection first so a pin
/// mismatch surfaces as `E_BROKER_UNTRUSTED` and an offline socket as `E_IO`
/// — never a misleading `E_SESSION_EXPIRED` — while executing no operation.
/// The probe uses `broker_call` with a harmless public op (`vault.status`):
/// trust/offline failures surface here; any successful answer is discarded.
fn require_session_auth(state: &AppState) -> Result<svault::client::Auth, CmdError> {
    if let Some(auth) = state.session_auth() {
        return Ok(auth);
    }
    svault::client::broker_call_with_auth(
        &state.socket,
        "vault.status",
        &svault::client::Auth::None,
        serde_json::json!({}),
    )
    .map_err(CmdError::from)?;
    Err(CmdError::new(
        "E_SESSION_EXPIRED",
        "session expired or revoked",
    ))
}

// ---- outputs (all Serialize; none carries credential material) ----

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusOut {
    pub version: u32,
    pub created: String,
    pub locked: bool,
    pub online: bool,
    pub trusted: bool,
    /// True when the broker reports a vault exists. False on the no-vault
    /// (`E_NOT_FOUND`) arm and on the offline arm (unknown, not absent).
    /// Always serialized: consumers key first-run onboarding off its presence.
    pub initialized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinStatusOut {
    pub pinned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeOut {
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnlockIn {
    pub passphrase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnlockOut {
    pub unlocked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_expires_in: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockOut {
    pub locked: bool,
}

// ---- commands (pure logic; `main.rs` wraps each in `#[tauri::command]`) ----

/// `vault.status` (unauthenticated) + local pin state.
pub fn get_status(state: &AppState) -> Result<StatusOut, CmdError> {
    let res = call(
        &state.socket,
        "vault.status",
        &Auth::None,
        serde_json::json!({}),
    );
    let (version, created, locked) = match res {
        Ok(v) => (
            v.get("version").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            v.get("created")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            v.get("locked").and_then(|x| x.as_bool()).unwrap_or(true),
        ),
        Err(e) if e.code == "E_BROKER_UNTRUSTED" => {
            // Online (socket answered) but untrusted: surface distinctly.
            // NOTE: `locked: true` here is a synthesized fail-safe fallback,
            // not a broker observation — the gate refused before any status
            // fact could be read, so never treat it as broker truth.
            let fp = pin_fingerprint(state).ok().flatten();
            return Ok(StatusOut {
                version: 0,
                created: String::new(),
                locked: true,
                online: true,
                trusted: false,
                initialized: true,
                fingerprint: fp,
            });
        }
        // The broker answered but its own `vault.status` audit append failed
        // (soft/hard ceiling, write error): still ONLINE — transport, pin,
        // and identity all worked. Field values unknown; stay locked-shaped.
        Err(e) if e.code == "E_AUDIT_FULL" || e.code == "E_AUDIT_WRITE" || e.code == "E_BUSY" => {
            let pinned = svault::broker_identity::load_pin(&state.socket)
                .map(|o| o.is_some())
                .unwrap_or(false);
            return Ok(StatusOut {
                version: 0,
                created: String::new(),
                locked: true,
                online: true,
                trusted: pinned,
                initialized: true,
                fingerprint: if pinned {
                    pin_fingerprint(state).ok().flatten()
                } else {
                    None
                },
            });
        }
        // Running daemon with no vault yet (`vault.status` answers
        // `E_NOT_FOUND`): ONLINE, not offline. The gate refused nothing here
        // — the daemon answered, so transport + identity succeeded; only the
        // vault is absent. NOTE: `locked: true` is a synthesized fail-safe
        // shape, never a broker observation.
        Err(e) if e.code == "E_NOT_FOUND" => {
            let pinned = svault::broker_identity::load_pin(&state.socket)
                .map(|o| o.is_some())
                .unwrap_or(false);
            return Ok(StatusOut {
                version: 0,
                created: String::new(),
                locked: true,
                online: true,
                trusted: pinned,
                initialized: false,
                fingerprint: if pinned {
                    pin_fingerprint(state).ok().flatten()
                } else {
                    None
                },
            });
        }
        Err(_) => {
            // Offline: nothing is known (unknown, not absent), so
            // `initialized: false` means "no vault confirmed", not "no vault".
            return Ok(StatusOut {
                version: 0,
                created: String::new(),
                locked: true,
                online: false,
                trusted: false,
                initialized: false,
                fingerprint: None,
            });
        }
    };
    // Online + answered: trusted iff a pin exists for this socket. (A pin
    // mismatch already fails the status call itself via the strict gate, so
    // reaching here with a pin means hello verified under it.)
    let pinned = svault::broker_identity::load_pin(&state.socket)
        .map(|o| o.is_some())
        .unwrap_or(false);
    let fingerprint = if pinned {
        pin_fingerprint(state).ok().flatten()
    } else {
        None
    };
    Ok(StatusOut {
        version,
        created,
        locked,
        online: true,
        trusted: pinned,
        initialized: true,
        fingerprint,
    })
}

fn pin_fingerprint(state: &AppState) -> Result<Option<String>, CmdError> {
    let pin = svault::broker_identity::load_pin(&state.socket).map_err(CmdError::from)?;
    Ok(pin.map(|k| svault::broker_identity::fingerprint(&k)))
}

/// Local pin read only — no broker call.
pub fn pin_status(state: &AppState) -> Result<PinStatusOut, CmdError> {
    Ok(PinStatusOut {
        fingerprint: pin_fingerprint(state)?,
        pinned: svault::broker_identity::load_pin(&state.socket)
            .map(|o| o.is_some())
            .map_err(CmdError::from)?,
    })
}

/// Credential-free live probe (no pin required, zero credential bytes).
pub fn probe_fingerprint(state: &AppState) -> Result<ProbeOut, CmdError> {
    let key_hex = svault::broker_identity::broker_fingerprint_live(&state.socket)?;
    // Validate shape (64 lowercase hex) so a rogue peer's garbage fails here.
    let key = svault::broker_identity::parse_fingerprint(&key_hex).map_err(CmdError::from)?;
    Ok(ProbeOut {
        fingerprint: svault::broker_identity::fingerprint(&key),
    })
}

/// `vault.unlock` with the passphrase; caches ONLY the safe session metadata
/// for JS and holds the credential in Rust. Best-effort seed: at the audit
/// soft ceiling the unlock succeeds with all six session fields ABSENT.
pub fn unlock(state: &AppState, input: UnlockIn) -> Result<UnlockOut, CmdError> {
    // `Zeroizing`: the passphrase is wiped when this drops at return.
    let passphrase = Zeroizing::new(input.passphrase);
    let res = call(
        &state.socket,
        "vault.unlock",
        &Auth::Passphrase(passphrase.to_string()),
        serde_json::json!({}),
    )?;
    let unlocked = res
        .get("unlocked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !unlocked {
        return Err(CmdError::new("E_AUTH", "authentication failed"));
    }
    // Cache the session credential in Rust ONLY when the broker seeded one.
    if let Some(cred) = res.get("session_credential").and_then(|v| v.as_str()) {
        if let Ok(mut g) = state.session.lock() {
            *g = Some(Zeroizing::new(cred.to_string()));
        }
    } else if let Ok(mut g) = state.session.lock() {
        *g = None;
    }
    let str_field = |k: &str| res.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
    let u64_field = |k: &str| res.get(k).and_then(|v| v.as_u64());
    Ok(UnlockOut {
        unlocked: true,
        session_prefix: str_field("session_prefix"),
        expires_at: str_field("expires_at"),
        expires_in: u64_field("expires_in"),
        max_expires_at: str_field("max_expires_at"),
        max_expires_in: u64_field("max_expires_in"),
    })
}

/// Real `vault.lock` (session credential when held, else unauthenticated —
/// lock is fail-safe either way); then DROPS the Rust session holder.
pub fn lock(state: &AppState) -> Result<LockOut, CmdError> {
    let auth = state.session_auth().unwrap_or(Auth::None);
    // Best effort on the wire: even if the broker is offline, the local
    // session holder is dropped below (fail-safe direction).
    let wire = call(&state.socket, "vault.lock", &auth, serde_json::json!({}));
    state.drop_session();
    match wire {
        Ok(_) => Ok(LockOut { locked: true }),
        Err(e) if e.code == "E_IO" || e.code == "E_PROTOCOL" => {
            // Offline/unreachable: local state is still locked (credential
            // dropped). Report locked so the UI returns to the gate.
            Ok(LockOut { locked: true })
        }
        Err(e) => Err(e),
    }
}

/// Best-effort broker lock with a hard time budget, used on window close.
/// Returns true when the lock call completed inside `budget`; false when it
/// timed out. NEVER blocks longer than `budget` and NEVER panics.
///
/// `vault.lock` is NOT in the broker's `HUMAN_ONLY` list
/// (`src/broker.rs:29-55`), but an unauthenticated lock still cannot happen:
/// the dispatch gate rejects every non-`vault.status` op with `Auth::None`
/// as `E_AUTH`, so only a valid human session actually locks. That is why
/// the credential is threaded through here rather than dropped first (the
/// close handler takes it out of `AppState` and passes it in). The broker
/// call's own error is discarded (already locked or daemon offline are both
/// fine). Runs on a detached worker that is never joined: on timeout the
/// worker keeps running in the background while the caller proceeds to exit.
pub fn shutdown_lock(
    socket: &std::path::Path,
    auth: svault::client::Auth,
    budget: std::time::Duration,
) -> bool {
    let socket = socket.to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    // Detached on purpose: the handle is dropped, never joined, so a hung
    // daemon cannot stall exit. `Builder::spawn` (not `thread::spawn`) so a
    // resource-exhausted spawn fails as `Err` -> `false`, never a panic. A
    // panicking worker is contained too: without a join its panic never
    // propagates, `tx` drops, and `recv_timeout` reports `Disconnected`.
    // The process is exiting, so the residual lifetime of the `Auth` moved
    // into the worker is bounded by process teardown.
    let spawned = std::thread::Builder::new()
        .name("svault-shutdown-lock".to_string())
        .spawn(move || {
            let _ = svault::client::broker_call_with_auth(
                &socket,
                "vault.lock",
                &auth,
                serde_json::json!({}),
            );
            let _ = tx.send(());
        });
    if spawned.is_err() {
        return false;
    }
    rx.recv_timeout(budget).is_ok()
}

/// `vault.health` (in `HUMAN_ONLY`, so it works while locked via passphrase —
/// never `E_LOCKED`). Prefers the session credential; the `Auth::None`
/// fallback can only ever fail `E_AUTH` on the wire (the dispatch gate
/// rejects unauthenticated non-`vault.status` ops), never return partial reads.
pub fn health(state: &AppState) -> Result<serde_json::Value, CmdError> {
    let auth = state.session_auth().unwrap_or(Auth::None);
    call(&state.socket, "vault.health", &auth, serde_json::json!({}))
}

// ---- D2 outputs (all Serialize; none carries credential/secret material) ----

/// Aggregated overview: posture fields (always) + counters (only when
/// trusted and unlocked). Counters are `None` while locked/offline/untrusted
/// — NEVER a fabricated 0 — so the UI can distinguish "unknown" from "zero".
/// `session_held` reports only whether this process currently holds a
/// session credential (never the credential itself, which never crosses
/// IPC); the UI needs it because its own `session.present` goes stale after
/// the server-side sliding TTL lapses silently.
/// Never carries a credential, passphrase, or secret value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OverviewOut {
    pub online: bool,
    pub trusted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub version: u32,
    pub created: String,
    pub locked: bool,
    pub session_held: bool,
    pub projects: Option<u64>,
    pub secrets_total: Option<u64>,
    pub secrets_total_exact: bool,
    pub agents_active: Option<u64>,
    pub runs_active: Option<u64>,
    pub approvals_pending: Option<u64>,
    pub leases_active: Option<u64>,
    pub idle_lock_secs: Option<u64>,
    pub idle_in: Option<u64>,
    pub audit_bytes: Option<u64>,
    pub audit_soft_limit: Option<u64>,
    pub audit_hard_limit: Option<u64>,
    pub vault_bytes: Option<u64>,
    pub vault_max_bytes: Option<u64>,
}

/// Posture-only overview: all counters `None`, `secrets_total_exact: false`.
/// Used while locked, offline, untrusted, or on mismatch — never a
/// fabricated 0. `session_held` is still reported exactly: a posture-only
/// overview with a held session is legitimate (e.g. no session was ever
/// established vs. a held-but-degraded one are distinguishable).
fn posture_only(status: &StatusOut, session_held: bool) -> OverviewOut {
    OverviewOut {
        online: status.online,
        trusted: status.trusted,
        fingerprint: status.fingerprint.clone(),
        version: status.version,
        created: status.created.clone(),
        locked: status.locked,
        session_held,
        projects: None,
        secrets_total: None,
        secrets_total_exact: false,
        agents_active: None,
        runs_active: None,
        approvals_pending: None,
        leases_active: None,
        idle_lock_secs: None,
        idle_in: None,
        audit_bytes: None,
        audit_soft_limit: None,
        audit_hard_limit: None,
        vault_bytes: None,
        vault_max_bytes: None,
    }
}

/// `overview_refresh`: posture first (same logic as `get_status`), then —
/// ONLY when trusted and UNLOCKED — the human-session sub-calls in order:
/// `vault.health` → `project.list` → `agents.list` → `secrets.list` per
/// project (bounded by [`OVERVIEW_SECRETS_PROJECT_CAP`]).
///
/// Partial-failure rule: `E_SESSION_EXPIRED` from `vault.health` propagates
/// (the frontend uses it to force re-authentication). Every other individual
/// sub-call failure degrades that field to `None` instead of failing the
/// whole overview. Never calls `audit.show`/`audit.verify` here: the former
/// appends an entry per read, the latter is a full chain walk; the audit
/// byte/limit fields from `vault.health` are the honest cheap signal.
/// All human ops use the session credential held in Rust — never a
/// passphrase, never anything that crosses IPC.
pub fn overview_refresh(state: &AppState) -> Result<OverviewOut, CmdError> {
    let status = get_status(state)?;
    // Backend's own knowledge, evaluated ONCE: independent of whether the
    // sub-calls below succeed. Reports only WHETHER a credential is held —
    // never the credential, which never crosses IPC.
    let session_held = state.session_auth().is_some();
    // Posture gate: while locked, offline, untrusted, or mismatched, return
    // posture fields with all counters None. Do not call human ops here.
    if status.locked || !status.online || !status.trusted {
        return Ok(posture_only(&status, session_held));
    }
    let Some(auth) = state.session_auth() else {
        // Unlocked posture but no session held (e.g. unlocked out-of-band):
        // human ops would fail E_AUTH, so stay posture-only.
        return Ok(posture_only(&status, false));
    };
    // `vault.health` first: runs/approvals/leases/idle/audit/vault fields.
    // E_SESSION_EXPIRED propagates (frontend forces re-auth); any other
    // failure degrades the health-derived counters to None.
    let health = match call(&state.socket, "vault.health", &auth, serde_json::json!({})) {
        Ok(v) => Some(v),
        Err(e) if e.code == "E_SESSION_EXPIRED" => return Err(e),
        Err(_) => None,
    };
    // `project.list`: names only; the count feeds `projects` and the secret
    // fan-out below. Failure degrades to None (and skips the fan-out).
    let project_names: Option<Vec<String>> =
        match call(&state.socket, "project.list", &auth, serde_json::json!({})) {
            Ok(v) => Some(
                v.get("projects")
                    .and_then(|p| p.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|p| p.get("name").and_then(|n| n.as_str()))
                            .map(|s| s.to_string())
                            .collect()
                    })
                    .unwrap_or_default(),
            ),
            Err(e) if e.code == "E_SESSION_EXPIRED" => return Err(e),
            Err(_) => None,
        };
    // `agents.list`: count entries with `status == "active"`. A well-formed
    // response always carries an `agents` array (possibly empty: honestly 0).
    // A missing/non-array `agents` on success is malformed — report None
    // (unknown), never a fabricated 0.
    let agents_active: Option<u64> =
        match call(&state.socket, "agents.list", &auth, serde_json::json!({})) {
            Ok(v) => v.get("agents").and_then(|a| a.as_array()).map(|arr| {
                arr.iter()
                    .filter(|a| a.get("status").and_then(|s| s.as_str()) == Some("active"))
                    .count() as u64
            }),
            Err(e) if e.code == "E_SESSION_EXPIRED" => return Err(e),
            Err(_) => None,
        };
    // 32-connection broker intake cap, so never fan out unboundedly. Past the
    // cap, return the bounded partial sum with `secrets_total_exact: false`.
    let (secrets_total, secrets_total_exact) = match &project_names {
        None => (None, false),
        Some(names) => {
            let mut total: u64 = 0;
            let mut exact = true;
            let mut failed = false;
            for name in names.iter().take(OVERVIEW_SECRETS_PROJECT_CAP) {
                match call(
                    &state.socket,
                    "secrets.list",
                    &auth,
                    serde_json::json!({"project": name}),
                ) {
                    // A well-formed `secrets.list` always carries a `secrets`
                    // array; a missing/non-array value on success is
                    // malformed, so degrade the whole overview field to None
                    // rather than adding a guessed 0 to the sum.
                    Ok(v) => match v.get("secrets").and_then(|s| s.as_array()) {
                        Some(arr) => total += arr.len() as u64,
                        None => {
                            failed = true;
                            break;
                        }
                    },
                    Err(e) if e.code == "E_SESSION_EXPIRED" => return Err(e),
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            if names.len() > OVERVIEW_SECRETS_PROJECT_CAP {
                exact = false;
            }
            if failed {
                (None, false)
            } else {
                (Some(total), exact)
            }
        }
    };
    let u64_field =
        |v: Option<&serde_json::Value>, k: &str| v.and_then(|v| v.get(k)).and_then(|x| x.as_u64());
    Ok(OverviewOut {
        online: status.online,
        trusted: status.trusted,
        fingerprint: status.fingerprint.clone(),
        version: status.version,
        created: status.created.clone(),
        locked: status.locked,
        session_held,
        projects: project_names.map(|n| n.len() as u64),
        secrets_total,
        secrets_total_exact,
        agents_active,
        runs_active: u64_field(health.as_ref(), "runs_active"),
        approvals_pending: u64_field(health.as_ref(), "approvals_pending"),
        leases_active: u64_field(health.as_ref(), "leases_active"),
        idle_lock_secs: u64_field(health.as_ref(), "idle_lock_secs"),
        idle_in: u64_field(health.as_ref(), "idle_in"),
        audit_bytes: u64_field(health.as_ref(), "audit_bytes"),
        audit_soft_limit: u64_field(health.as_ref(), "audit_soft_limit"),
        audit_hard_limit: u64_field(health.as_ref(), "audit_hard_limit"),
        vault_bytes: u64_field(health.as_ref(), "vault_bytes"),
        vault_max_bytes: u64_field(health.as_ref(), "vault_max_bytes"),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectEntry {
    pub name: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectsOut {
    pub projects: Vec<ProjectEntry>,
}

/// `project.list` over the session credential. Names + paths only.
pub fn projects_list(state: &AppState) -> Result<ProjectsOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(&state.socket, "project.list", &auth, serde_json::json!({}))?;
    let projects = v
        .get("projects")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    Some(ProjectEntry {
                        name: p.get("name")?.as_str()?.to_string(),
                        paths: p
                            .get("paths")
                            .and_then(|x| x.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(ProjectsOut { projects })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectAddIn {
    pub name: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddedOut {
    pub added: String,
}

/// `project.add` over the session credential.
pub fn project_add(state: &AppState, input: ProjectAddIn) -> Result<AddedOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "project.add",
        &auth,
        serde_json::json!({"name": input.name, "paths": input.paths}),
    )?;
    Ok(AddedOut {
        added: v
            .get("added")
            .and_then(|a| a.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NameIn {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemovedOut {
    pub removed: String,
}

/// `project.remove` over the session credential. The broker refuses a project
/// that still has secrets (`E_INVALID_INPUT`); the project then remains.
pub fn project_remove(state: &AppState, input: NameIn) -> Result<RemovedOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "project.remove",
        &auth,
        serde_json::json!({"name": input.name}),
    )?;
    Ok(RemovedOut {
        removed: v
            .get("removed")
            .and_then(|a| a.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectPathIn {
    pub name: String,
    pub path: String,
}

/// `project.path.add` over the session credential.
pub fn project_path_add(state: &AppState, input: ProjectPathIn) -> Result<AddedOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "project.path.add",
        &auth,
        serde_json::json!({"name": input.name, "path": input.path}),
    )?;
    Ok(AddedOut {
        added: v
            .get("added")
            .and_then(|a| a.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

/// `project.path.remove` over the session credential.
pub fn project_path_remove(state: &AppState, input: ProjectPathIn) -> Result<RemovedOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "project.path.remove",
        &auth,
        serde_json::json!({"name": input.name, "path": input.path}),
    )?;
    Ok(RemovedOut {
        removed: v
            .get("removed")
            .and_then(|a| a.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretsListIn {
    pub project: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretEntry {
    pub key: String,
    pub updated: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretsOut {
    pub secrets: Vec<SecretEntry>,
}

/// `secrets.list` over the session credential. Key names + `updated`
/// timestamps only — the broker never sends values here.
pub fn secrets_list(state: &AppState, input: SecretsListIn) -> Result<SecretsOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "secrets.list",
        &auth,
        serde_json::json!({"project": input.project}),
    )?;
    let secrets = v
        .get("secrets")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    Some(SecretEntry {
                        key: s.get("key")?.as_str()?.to_string(),
                        updated: s.get("updated")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(SecretsOut { secrets })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretSetIn {
    pub project: String,
    pub key: String,
    /// Plaintext value. Moved into a `Zeroizing<String>` immediately on entry
    /// (see [`secret_set`]); never echoed in any response, log, or error.
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretSetOut {
    pub set: String,
}

/// `secret.set` over the session credential. The plaintext `value` is moved
/// into a `Zeroizing<String>` IMMEDIATELY on entry: never cloned, never
/// stored in `AppState`, never logged, never placed in an error, never echoed
/// back. The response carries only `{set: "<project>/<key>"}`. `CmdError`
/// cannot leak it: broker errors are stable `E_*` codes with static messages
/// (the `From` impls above scrub `Io`/`Protocol`/`Corrupt`), and no new path
/// forwards raw broker text. The `Zeroizing` wrapper drops (wipes) at return.
pub fn secret_set(state: &AppState, input: SecretSetIn) -> Result<SecretSetOut, CmdError> {
    let value = Zeroizing::new(input.value);
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "secret.set",
        &auth,
        serde_json::json!({"project": input.project, "key": input.key, "value": value.as_str()}),
    )?;
    // `value` (Zeroizing) drops here — wiped, never stored or echoed.
    Ok(SecretSetOut {
        set: v
            .get("set")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretDeleteIn {
    pub project: String,
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretDeleteOut {
    pub deleted: String,
}

/// `secret.delete` over the session credential. Second delete of the same key
/// fails `E_NOT_FOUND` (broker rule).
pub fn secret_delete(state: &AppState, input: SecretDeleteIn) -> Result<SecretDeleteOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "secret.delete",
        &auth,
        serde_json::json!({"project": input.project, "key": input.key}),
    )?;
    Ok(SecretDeleteOut {
        deleted: v
            .get("deleted")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

// ---- D3: agents, grants, approvals (identifiers + names only) ----
//
// No response here carries a secret VALUE or a reusable credential, with ONE
// deliberate exception: [`agent_add`] returns the enrollment token once, in
// its own response only (never recoverable afterwards). Prefixes, names, and
// approval keys are display-safe; everything else stays server-side. D4 adds
// the second and final exception: [`reveal`] returns one secret value in its
// own response only (see its doc). Nothing else in D4 carries a value or a
// credential: [`LeaseEntry`] has no credential field by construction, and
// [`RunEntry`] is safe metadata only.

/// One agent identity: name + status + token PREFIX. The prefix is a public
/// display hint; the token itself appears only in [`agent_add`]'s response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentEntry {
    pub name: String,
    pub status: String,
    pub token_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentsOut {
    pub agents: Vec<AgentEntry>,
}

/// `agents.list` over the session credential. Prefixes only — the broker
/// never sends tokens here, so a list response cannot leak one.
pub fn agents_list(state: &AppState) -> Result<AgentsOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(&state.socket, "agents.list", &auth, serde_json::json!({}))?;
    let agents = v
        .get("agents")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    Some(AgentEntry {
                        name: a.get("name")?.as_str()?.to_string(),
                        status: a.get("status")?.as_str()?.to_string(),
                        token_prefix: a.get("token_prefix")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(AgentsOut { agents })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentAddIn {
    pub name: String,
    /// Optional file to persist the one-time token via
    /// `svault::cli::write_token_file` (`O_EXCL`: refuses overwrite, mode
    /// 0600). `None`/empty = display-only delivery in the response.
    pub token_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentAddOut {
    pub agent_id: String,
    /// The one-time enrollment token: returned here once, never recoverable
    /// from the broker afterwards.
    pub token: String,
    pub token_saved_path: Option<String>,
}

/// `agents.add` over the session credential. The broker returns the token
/// exactly once, so it is wrapped in `Zeroizing` IMMEDIATELY: never logged,
/// never placed in an error, never stored in `AppState`. It crosses IPC a
/// single time, in this response (the CLI does the same); the `Zeroizing`
/// wrapper drops (wipes) at return. When `token_path` is set, the token is
/// additionally persisted with the CLI's safe writer — an existing file
/// fails `E_EXISTS` and is never silently replaced or bypassed.
pub fn agent_add(state: &AppState, input: AgentAddIn) -> Result<AgentAddOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "agents.add",
        &auth,
        serde_json::json!({"name": input.name}),
    )?;
    let agent_id = v
        .get("agent_id")
        .and_then(|s| s.as_str())
        .unwrap_or_default()
        .to_string();
    let token = Zeroizing::new(
        v.get("token")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string(),
    );
    let mut token_saved_path = None;
    if let Some(path) = input.token_path.as_deref().filter(|p| !p.is_empty()) {
        svault::cli::write_token_file(std::path::Path::new(path), token.as_str()).map_err(|e| {
            if matches!(e, svault::VaultError::Exists) {
                CmdError::new("E_EXISTS", broker_message("E_EXISTS"))
            } else {
                CmdError::from(e)
            }
        })?;
        token_saved_path = Some(path.to_string());
    }
    // `token` (Zeroizing) drops here — wiped after its single IPC crossing.
    Ok(AgentAddOut {
        agent_id,
        token: token.as_str().to_string(),
        token_saved_path,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedOut {
    pub revoked: String,
}

/// `agents.revoke` over the session credential: terminates the agent's runs
/// and invalidates its leases and approvals (broker rule).
pub fn agent_revoke(state: &AppState, input: NameIn) -> Result<RevokedOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "agents.revoke",
        &auth,
        serde_json::json!({"name": input.name}),
    )?;
    Ok(RevokedOut {
        revoked: v
            .get("revoked")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantEntry {
    pub agent: String,
    pub project: String,
    /// Lowercase capability strings, exactly as the broker reports them —
    /// including `manage`, which has no agent-callable op yet but is a real
    /// held grant that must round-trip (dropping it on re-save would silently
    /// revoke it).
    pub ops: Vec<String>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantsOut {
    pub grants: Vec<GrantEntry>,
}

/// `grants.list` over the session credential. Reports all five capabilities
/// faithfully (see [`GrantEntry::ops`]).
pub fn grants_list(state: &AppState) -> Result<GrantsOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(&state.socket, "grants.list", &auth, serde_json::json!({}))?;
    let grants = v
        .get("grants")
        .and_then(|g| g.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|g| {
                    Some(GrantEntry {
                        agent: g.get("agent")?.as_str()?.to_string(),
                        project: g.get("project")?.as_str()?.to_string(),
                        ops: g
                            .get("ops")
                            .and_then(|o| o.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        revoked: g.get("revoked").and_then(|r| r.as_bool()).unwrap_or(false),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(GrantsOut { grants })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantSetIn {
    pub agent: String,
    pub project: String,
    /// Comma-separated ops as the wire takes them (`"read,inject"`), NOT an
    /// array — the array shape exists only on `grants.list` responses. The
    /// frontend joins its checkbox set before calling.
    pub ops: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantedOut {
    pub granted: String,
}

/// `grants.grant` over the session credential (upsert). Accepts all five
/// capabilities including `manage` (see [`GrantEntry::ops`]).
pub fn grant_set(state: &AppState, input: GrantSetIn) -> Result<GrantedOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "grants.grant",
        &auth,
        serde_json::json!({"agent": input.agent, "project": input.project, "ops": input.ops}),
    )?;
    Ok(GrantedOut {
        granted: v
            .get("granted")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantRevokeIn {
    pub agent: String,
    pub project: String,
}

/// `grants.revoke` over the session credential.
pub fn grant_revoke(state: &AppState, input: GrantRevokeIn) -> Result<RevokedOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "grants.revoke",
        &auth,
        serde_json::json!({"agent": input.agent, "project": input.project}),
    )?;
    Ok(RevokedOut {
        revoked: v
            .get("revoked")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalEntry {
    pub approval_id: String,
    pub agent: String,
    pub project: String,
    /// The secret NAME awaiting reveal — safe to surface, like [`SecretEntry`];
    /// the VALUE never appears in any D3 type.
    pub key: String,
    pub status: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalsOut {
    pub approvals: Vec<ApprovalEntry>,
}

/// `approvals.pending` over the session credential. Requires an unlocked
/// vault (broker rule) and appends an audit entry per read — hence the
/// frontend polls it at a moderate interval, never per frame.
pub fn approvals_pending(state: &AppState) -> Result<ApprovalsOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "approvals.pending",
        &auth,
        serde_json::json!({}),
    )?;
    let approvals = v
        .get("approvals")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    Some(ApprovalEntry {
                        approval_id: a.get("approval_id")?.as_str()?.to_string(),
                        agent: a.get("agent")?.as_str()?.to_string(),
                        project: a.get("project")?.as_str()?.to_string(),
                        key: a.get("key")?.as_str()?.to_string(),
                        status: a.get("status")?.as_str()?.to_string(),
                        expires_at: a.get("expires_at")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(ApprovalsOut { approvals })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalDecisionIn {
    pub approval_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalDecisionOut {
    pub approval_id: String,
    pub status: String,
}

/// `approvals.approve` over the session credential.
pub fn approval_approve(
    state: &AppState,
    input: ApprovalDecisionIn,
) -> Result<ApprovalDecisionOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "approvals.approve",
        &auth,
        serde_json::json!({"approval_id": input.approval_id}),
    )?;
    Ok(ApprovalDecisionOut {
        approval_id: v
            .get("approval_id")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string(),
        status: v
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string(),
    })
}

/// `approvals.deny` over the session credential.
pub fn approval_deny(
    state: &AppState,
    input: ApprovalDecisionIn,
) -> Result<ApprovalDecisionOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "approvals.deny",
        &auth,
        serde_json::json!({"approval_id": input.approval_id}),
    )?;
    Ok(ApprovalDecisionOut {
        approval_id: v
            .get("approval_id")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string(),
        status: v
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string(),
    })
}
// ---- D4: reveal, leases, runs (audited human reads + safe metadata) ----
//
// `reveal` is the ONE intentional secret-value crossing on the whole
// dashboard surface (see its doc): every other D4 type carries identifiers,
// names, and timestamps only. `lease.create` and `run_signal` have NO command
// here — both hard-fail for a human identity (`E_AUTH`) and the dashboard
// must never invoke them on an agent's behalf.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevealIn {
    pub project: String,
    pub key: String,
}

/// THE ONE AUTHORIZED SECRET-VALUE CROSSING on the whole dashboard surface.
///
/// The human reveals directly (`reveal` with NO `approval_id` — passing one
/// is `E_INVALID_INPUT`); approvals exist for the AGENT path (`reveal_claim`
/// takes an `agent_id`), which the dashboard never invokes on an agent's
/// behalf. The broker audits every human reveal.
///
/// Containment: the value crosses IPC exactly ONCE, in this response, only in
/// reply to an explicit audited human reveal. It is wrapped in `Zeroizing`
/// from the wire, never stored in [`AppState`], never logged, and never
/// placed in a [`CmdError`] (broker errors map to static code-keyed messages
/// via [`broker_message`]; raw broker text is never forwarded).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevealOut {
    pub value: String,
}

/// `reveal` over the session credential. See [`RevealOut`] for the crossing
/// contract: the value is wiped (Zeroizing drop) right after building the
/// response, and no other path in this module may carry one.
pub fn reveal(state: &AppState, input: RevealIn) -> Result<RevealOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "reveal",
        &auth,
        serde_json::json!({"project": input.project, "key": input.key}),
    )?;
    // Missing/non-string `value` on a SUCCESS response is malformed: error
    // rather than an empty or fabricated value.
    let raw = v
        .get("value")
        .and_then(|s| s.as_str())
        .ok_or_else(|| CmdError::new("E_PROTOCOL", broker_message("E_PROTOCOL")))?;
    let value = Zeroizing::new(raw.to_string());
    // `value` (Zeroizing) drops here — wiped after its single IPC crossing.
    Ok(RevealOut {
        value: value.as_str().to_string(),
    })
}

/// One lease as the broker reports it to a human (who sees ALL leases).
/// Deliberately has NO credential field: only the digest/prefix persist in
/// the vault, so a list response cannot leak a credential by construction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseEntry {
    pub lease_id: String,
    pub lease_prefix: String,
    pub project: String,
    /// Lowercase capability strings, exactly as the broker reports them.
    pub ops: Vec<String>,
    pub expires_at: String,
    pub expires_in: u64,
    /// `"active" | "expired" | "revoked"`, broker-computed.
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeasesOut {
    pub leases: Vec<LeaseEntry>,
}

/// `lease.list` over the session credential. A human identity sees all
/// leases; an empty array is the honest fresh-vault answer, while a
/// missing/non-array `leases` on success is malformed and errors.
pub fn leases_list(state: &AppState) -> Result<LeasesOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(&state.socket, "lease.list", &auth, serde_json::json!({}))?;
    let arr = v
        .get("leases")
        .and_then(|l| l.as_array())
        .ok_or_else(|| CmdError::new("E_PROTOCOL", broker_message("E_PROTOCOL")))?;
    let leases = arr
        .iter()
        .filter_map(|l| {
            Some(LeaseEntry {
                lease_id: l.get("lease_id")?.as_str()?.to_string(),
                lease_prefix: l.get("lease_prefix")?.as_str()?.to_string(),
                project: l.get("project")?.as_str()?.to_string(),
                ops: l
                    .get("ops")
                    .and_then(|o| o.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                expires_at: l.get("expires_at")?.as_str()?.to_string(),
                expires_in: l
                    .get("expires_in")
                    .and_then(|e| e.as_u64())
                    .unwrap_or_default(),
                status: l.get("status")?.as_str()?.to_string(),
            })
        })
        .collect();
    Ok(LeasesOut { leases })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseRevokeIn {
    pub lease_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseRevokeOut {
    pub lease_id: String,
    pub revoked: bool,
}

/// `lease.revoke` over the session credential: a human may revoke any lease.
pub fn lease_revoke(state: &AppState, input: LeaseRevokeIn) -> Result<LeaseRevokeOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(
        &state.socket,
        "lease.revoke",
        &auth,
        serde_json::json!({"lease_id": input.lease_id}),
    )?;
    Ok(LeaseRevokeOut {
        lease_id: v
            .get("lease_id")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string(),
        revoked: v.get("revoked").and_then(|b| b.as_bool()).unwrap_or(false),
    })
}

/// One live run: safe metadata only — no argv, no env, no cwd, no executable,
/// no secret names. `pid` is the registry's pid (`i32`, as in
/// `svault::run::RunMeta` and the wire projection).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunEntry {
    pub run_id: String,
    pub agent: String,
    pub project: String,
    pub pid: i32,
    pub started_at: String,
    /// Always `"running"`: only live registry entries are listed.
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunsOut {
    pub runs: Vec<RunEntry>,
}

/// `runs.list` over the session credential. An empty array is the honest
/// fresh-vault answer; a missing/non-array `runs` on success is malformed
/// and errors rather than fabricating an empty list.
pub fn runs_list(state: &AppState) -> Result<RunsOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(&state.socket, "runs.list", &auth, serde_json::json!({}))?;
    let arr = v
        .get("runs")
        .and_then(|r| r.as_array())
        .ok_or_else(|| CmdError::new("E_PROTOCOL", broker_message("E_PROTOCOL")))?;
    let runs = arr
        .iter()
        .filter_map(|r| {
            Some(RunEntry {
                run_id: r.get("run_id")?.as_str()?.to_string(),
                agent: r.get("agent")?.as_str()?.to_string(),
                project: r.get("project")?.as_str()?.to_string(),
                pid: r.get("pid").and_then(|p| p.as_i64()).unwrap_or_default() as i32,
                started_at: r.get("started_at")?.as_str()?.to_string(),
                status: r.get("status")?.as_str()?.to_string(),
            })
        })
        .collect();
    Ok(RunsOut { runs })
}

// ---- D6: audit timeline + verification (human reads only) ----
//
// `audit.show` appends one entry per read (broker rule), so the frontend loads
// it on demand only — never on a timer, never inside `overview_refresh`. Each
// read snapshots the head BEFORE appending its own entry, so the returned page
// is never shifted by the read itself. `audit.verify` appends nothing: it is a
// pure chain/HMAC walk, and a structural failure arrives as `E_VAULT_CORRUPT`.
//
// The timeline row carries the requested field set only: no `hash`/`prev_hash`
// (chain internals), no `mac` bytes (replaced by the `authenticated` bit), no
// `target`/`cwd`/`executable`/`arg_count`/`result`/`exit_code`/`signal`.
/// One audit timeline row: identifiers + names only, never a secret value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntryOut {
    pub seq: u64,
    pub ts: String,
    pub actor: String,
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    pub keys: Vec<String>,
    /// `"allowed" | "denied"`, exactly as the broker reports it.
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// True iff the entry carries a non-null `mac` string: written while the
    /// vault was unlocked (`K_audit` in memory). `vault.status` appends while
    /// locked have `mac: null` and read back unauthenticated.
    pub authenticated: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditShowIn {
    pub tail: u64,
    pub before_seq: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditShowOut {
    pub entries: Vec<AuditEntryOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before_seq: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditVerifyOut {
    pub entries: u64,
    pub macs_verified: u64,
    pub macs_null: u64,
}
/// `audit.show` over the session credential. `tail` is validated locally
/// (1..=1000, the broker's own bound) before any I/O so an out-of-range page
/// fails fast without a round trip. `before_seq` crosses only when `Some` —
/// never as null. A well-formed success always carries an `entries` array, so
/// a missing/non-array `entries` is malformed and errors (never a fabricated
/// empty page); same for a `next_before_seq` that is present but neither a
/// number nor null. Malformed rows inside the array are skipped, matching
/// `leases_list`/`runs_list`.
pub fn audit_show(state: &AppState, input: AuditShowIn) -> Result<AuditShowOut, CmdError> {
    if !(1..=1000).contains(&input.tail) {
        return Err(CmdError::new(
            "E_INVALID_INPUT",
            broker_message("E_INVALID_INPUT"),
        ));
    }
    let auth = require_session_auth(state)?;
    let params = match input.before_seq {
        Some(b) => serde_json::json!({"tail": input.tail, "before_seq": b}),
        None => serde_json::json!({"tail": input.tail}),
    };
    let v = call(&state.socket, "audit.show", &auth, params)?;
    let arr = v
        .get("entries")
        .and_then(|e| e.as_array())
        .ok_or_else(|| CmdError::new("E_PROTOCOL", broker_message("E_PROTOCOL")))?;
    let next_before_seq = match v.get("next_before_seq") {
        None | Some(serde_json::Value::Null) => None,
        Some(n) => Some(
            n.as_u64()
                .ok_or_else(|| CmdError::new("E_PROTOCOL", broker_message("E_PROTOCOL")))?,
        ),
    };
    let entries = arr
        .iter()
        .filter_map(|l| {
            Some(AuditEntryOut {
                seq: l.get("seq")?.as_u64()?,
                ts: l.get("ts")?.as_str()?.to_string(),
                actor: l.get("actor")?.as_str()?.to_string(),
                op: l.get("op")?.as_str()?.to_string(),
                project: l
                    .get("project")
                    .and_then(|p| p.as_str())
                    .map(|p| p.to_string()),
                keys: l
                    .get("keys")
                    .and_then(|k| k.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                decision: l.get("decision")?.as_str()?.to_string(),
                reason: l
                    .get("reason")
                    .and_then(|r| r.as_str())
                    .map(|r| r.to_string()),
                run_id: l
                    .get("run_id")
                    .and_then(|r| r.as_str())
                    .map(|r| r.to_string()),
                authenticated: l.get("mac").and_then(|m| m.as_str()).is_some(),
            })
        })
        .collect();
    Ok(AuditShowOut {
        entries,
        next_before_seq,
    })
}
/// `audit.verify` over the session credential. Sends `{}` and parses the three
/// counters as `u64`; a success missing any of them is malformed and MUST
/// error — a fabricated zeroed result would falsely read as "clean". A
/// structural/HMAC/checkpoint failure arrives as `E_VAULT_CORRUPT` and
/// propagates verbatim through the `BrokerError` mapping below (never
/// translated into a success or a different code). Appends nothing.
pub fn audit_verify(state: &AppState) -> Result<AuditVerifyOut, CmdError> {
    let auth = require_session_auth(state)?;
    let v = call(&state.socket, "audit.verify", &auth, serde_json::json!({}))?;
    let malformed = || CmdError::new("E_PROTOCOL", broker_message("E_PROTOCOL"));
    Ok(AuditVerifyOut {
        entries: v
            .get("entries")
            .and_then(|e| e.as_u64())
            .ok_or_else(malformed)?,
        macs_verified: v
            .get("macs_verified")
            .and_then(|e| e.as_u64())
            .ok_or_else(malformed)?,
        macs_null: v
            .get("macs_null")
            .and_then(|e| e.as_u64())
            .ok_or_else(malformed)?,
    })
}
