//! Thin UDS client used by the CLI (and future SDKs). One request per
//! connection; responses are checked and mapped to the error taxonomy.
//!
//! `run_with_secrets` is the exception: one held connection carries two
//! responses (`started`, then `exited`) while the daemon-owned child lives.
//! The child inherits the caller's stdio through `SCM_RIGHTS`; only safe
//! metadata (`run_id`, `pid`, exit status) ever comes back on the wire —
//! never secret values, tokens, or child output.

use std::io::Write as _;
use std::os::fd::RawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

use crate::crypto;
use crate::error::VaultError;
use crate::wire::{self, AuthField, Request};

/// Request credentials: exactly one identity per call.
pub enum Auth {
    None,
    AgentToken(String),
    Passphrase(String),
    /// Server-minted human-session credential (dashboard D0). Presented as
    /// `auth.session`; resolves to human identity only.
    Session(String),
}

/// Safe metadata from a `started` response. No argv/env/secrets by construction.
pub struct RunStarted {
    pub run_id: String,
    pub pid: i32,
}

/// Safe metadata from an `exited` response: `exit_code` on clean exit,
/// `signal` when killed by a signal.
pub struct RunExit {
    pub run_id: String,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
}

/// Acknowledgement of a `run_signal` request.
pub struct RunSignaled {
    pub run_id: String,
    pub signaled: bool,
}

#[derive(Debug)]
pub struct Client {
    stream: UnixStream,
}

fn auth_field(auth: &Auth) -> Option<AuthField> {
    match auth {
        Auth::None => None,
        Auth::AgentToken(t) => Some(AuthField {
            token: Some(t.clone()),
            passphrase: None,
            session: None,
        }),
        Auth::Passphrase(p) => Some(AuthField {
            token: None,
            passphrase: Some(p.clone()),
            session: None,
        }),
        Auth::Session(s) => Some(AuthField {
            token: None,
            passphrase: None,
            session: Some(s.clone()),
        }),
    }
}

/// A broker-side failure, preserving the stable code, message, and optional
/// structured data (e.g. `approval_id`/`expires_in` on `E_APPROVAL_PENDING`).
/// Lives here (next to the single shared transport) so both the MCP adapter
/// and the human dashboard surface the exact wire code without guessing.
/// Re-exported from `mcp` for its existing callers.
pub struct BrokerError {
    pub code: String,
    pub msg: String,
    pub data: Option<Value>,
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.msg)
    }
}

impl BrokerError {
    fn io(e: std::io::Error) -> Self {
        Self {
            code: "E_IO".to_string(),
            msg: e.to_string(),
            data: None,
        }
    }

    pub(crate) fn protocol(why: impl Into<String>) -> Self {
        Self {
            code: "E_PROTOCOL".to_string(),
            msg: why.into(),
            data: None,
        }
    }

    /// CLI surface: one line the operator/agent can act on. Approval-pending
    /// keeps the claim pointers; everything else is `code: msg`.
    pub fn into_protocol(self) -> VaultError {
        if self.code == "E_APPROVAL_PENDING"
            && let Some(d) = self.data.as_ref()
        {
            let id = d.get("approval_id").and_then(Value::as_str).unwrap_or("");
            let exp = d
                .get("expires_in")
                .map(|v| v.to_string())
                .unwrap_or_default();
            return VaultError::Protocol(format!(
                "approval pending: approval_id={id} expires_in={exp}s"
            ));
        }
        VaultError::Protocol(self.to_string())
    }
}

/// One broker request over a fresh UDS connection: send, read the single
/// response line, close. Returns the `result` value, or the structured broker
/// failure with code, message, and data preserved. Single source of truth
/// for the strict-gated, code-preserving transport: both `mcp::broker_call`
/// (agent surface, refuses `Session` before delegating) and the dashboard
/// (human surface, all `Auth` variants incl. `Session`) call this.
pub fn broker_call_with_auth(
    socket: &Path,
    op: &str,
    auth: &Auth,
    params: Value,
) -> Result<Value, BrokerError> {
    use std::io::{BufRead, Write};
    let mut stream = UnixStream::connect(socket).map_err(BrokerError::io)?;
    // N1: lock check (defense in depth only; the authority is the signed
    // handshake + pin below). `verify_server` is deliberately NOT extended:
    // this caller adds the round trip after it.
    crate::ipc::verify_server(&stream, socket).map_err(|e| BrokerError {
        code: e.code().to_string(),
        msg: e.to_string(),
        data: None,
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(BrokerError::io)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(BrokerError::io)?;
    // N1: same handshake + strict pin as `Client::connect_with`
    // (NonInteractive): no pin → E_BROKER_UNTRUSTED, flag or not. There is
    // deliberately NO trust flag or env on this path — the harness that
    // spawns `mcp-serve` is agent-controlled, so any such knob would be a
    // self-pin primitive (F1). First use on a fresh machine fails closed
    // until a human pins once via any interactive CLI op.
    crate::broker_identity::handshake_strict(&mut stream, socket).map_err(|e| BrokerError {
        code: e.code().to_string(),
        msg: format!(
            "{e} (first MCP use on this machine fails closed until a human pins once: \
             run any `svault` command at a TTY and answer `yes`)"
        ),
        data: None,
    })?;
    let id = crate::crypto::hex(&crate::crypto::random_bytes::<8>().map_err(|e| match e {
        VaultError::Io(io) => BrokerError::io(io),
        other => BrokerError::protocol(other.to_string()),
    })?);
    let req = Request {
        v: wire::VERSION,
        id: id.clone(),
        op: op.to_string(),
        auth: auth_field(auth),
        params,
    };
    let mut line = serde_json::to_string(&req).map_err(|e| BrokerError::protocol(e.to_string()))?;
    line.push('\n');
    stream.write_all(line.as_bytes()).map_err(BrokerError::io)?;
    stream.flush().map_err(BrokerError::io)?;
    // Bounded single-line read; `wire::read_response` would drop the error
    // `data` the CLI/MCP surface needs (approval pointers), so parse raw.
    let mut reader = std::io::BufReader::new(&stream);
    let mut buf = Vec::new();
    reader
        .read_until(b'\n', &mut buf)
        .map_err(BrokerError::io)?;
    if buf.len() > crate::wire::MAX_MESSAGE_LEN + 1 {
        return Err(BrokerError::protocol("response too large"));
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    let resp: Value =
        serde_json::from_slice(&buf).map_err(|_| BrokerError::protocol("invalid response"))?;
    if resp.get("v") != Some(&json!(crate::wire::VERSION)) {
        return Err(BrokerError::protocol("unsupported protocol version"));
    }
    if resp.get("id").and_then(Value::as_str) != Some(id.as_str()) {
        return Err(BrokerError::protocol("response id mismatch"));
    }
    if resp.get("ok") == Some(&Value::Bool(true)) {
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    } else {
        let err = &resp["error"];
        Err(BrokerError {
            code: err
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("E_PROTOCOL")
                .to_string(),
            msg: err
                .get("msg")
                .and_then(Value::as_str)
                .unwrap_or("broker error")
                .to_string(),
            data: err.get("data").cloned().filter(|v| !v.is_null()),
        })
    }
}

/// Check the wire id, then map the response to the error taxonomy.
/// D-10: the session-expiry code round-trips to its variant so dashboard/Rust
/// callers can distinguish it; `E_AUTH` round-trips to `Auth` (generic,
/// oracle-free) for the same reason. Every other broker code still collapses
/// to `Protocol(msg)` (deliberately narrow — no wide refactor here).
fn checked_result(resp: wire::Response, id: &str) -> Result<Value, VaultError> {
    if resp.id != id {
        return Err(VaultError::Protocol("response id mismatch".into()));
    }
    match (resp.ok, resp.result, resp.error) {
        (true, Some(result), _) => Ok(result),
        (true, None, _) => Ok(json!(null)),
        (false, _, Some(err)) if err.code == "E_SESSION_EXPIRED" => Err(VaultError::SessionExpired),
        (false, _, Some(err)) if err.code == "E_AUTH" => Err(VaultError::Auth),
        (false, _, Some(err)) => Err(VaultError::Protocol(err.msg)),
        (false, _, None) => Err(VaultError::Protocol("error without message".into())),
    }
}

fn parse_started(id: &str, resp: wire::Response) -> Result<RunStarted, VaultError> {
    let result = checked_result(resp, id)?;
    if result.get("status").and_then(|v| v.as_str()) != Some("started") {
        return Err(VaultError::Protocol(
            "run: expected started response".into(),
        ));
    }
    let run_id = result
        .get("run_id")
        .and_then(|v| v.as_str())
        .ok_or(VaultError::Protocol(
            "run: started response missing run_id".into(),
        ))?
        .to_string();
    let pid = result
        .get("pid")
        .and_then(|v| v.as_i64())
        .and_then(|n| i32::try_from(n).ok())
        .filter(|n| *n > 0)
        .ok_or(VaultError::Protocol(
            "run: started response missing pid".into(),
        ))?;
    Ok(RunStarted { run_id, pid })
}

fn parse_exited(id: &str, run_id: &str, resp: wire::Response) -> Result<RunExit, VaultError> {
    let result = checked_result(resp, id)?;
    if result.get("status").and_then(|v| v.as_str()) != Some("exited") {
        return Err(VaultError::Protocol("run: expected exited response".into()));
    }
    let exited_run_id =
        result
            .get("run_id")
            .and_then(|v| v.as_str())
            .ok_or(VaultError::Protocol(
                "run: exited response missing run_id".into(),
            ))?;
    if exited_run_id != run_id {
        return Err(VaultError::Protocol("response run_id mismatch".into()));
    }
    let exit_code = match result.get("exit_code") {
        None => None,
        Some(v) => Some(
            v.as_i64()
                .and_then(|n| i32::try_from(n).ok())
                .ok_or(VaultError::Protocol("run: bad exit_code".into()))?,
        ),
    };
    let signal = match result.get("signal") {
        None => None,
        Some(v) => Some(
            v.as_str()
                .ok_or(VaultError::Protocol("run: bad signal".into()))?
                .to_string(),
        ),
    };
    if exit_code.is_none() && signal.is_none() {
        return Err(VaultError::Protocol(
            "run: exited response lacks status".into(),
        ));
    }
    Ok(RunExit {
        run_id: run_id.to_string(),
        exit_code,
        signal,
    })
}

/// How the client establishes broker trust on first contact.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum TrustMode {
    /// Fail closed when no pin exists (agents, MCP, CI, piped stdin).
    /// An agent can never establish trust.
    #[default]
    NonInteractive,
    /// A human at a TTY confirmed the fingerprint out-of-band; the pin may
    /// be written after the explicit confirmation.
    Interactive,
}

/// Options for [`Client::connect_with`]. `trust_fingerprint` is a
/// compare-assist for the TTY ceremony ONLY: when a human pins at a TTY and
/// the flag is present, a mismatch aborts before any prompt. It NEVER
/// authorizes a pin write on its own — non-interactive + no pin fails closed
/// with or without it (argv is agent-controlled; see F1).
#[derive(Clone, Debug, Default)]
pub struct ConnectOptions {
    pub trust: TrustMode,
    pub trust_fingerprint: Option<[u8; 32]>,
}

impl Client {
    /// Strict default: lock check + handshake + pin, non-interactive. First
    /// contact without a pin fails closed (`E_BROKER_UNTRUSTED`) — agents,
    /// MCP, and CI can never TOFU. Humans pass [`TrustMode::Interactive`]
    /// via [`Client::connect_with`].
    pub fn connect(socket: &Path) -> Result<Self, VaultError> {
        Self::connect_with(socket, &ConnectOptions::default())
    }

    /// Connect with an explicit trust mode. Ordering is the whole point:
    /// connect → lock-holder check (defense in depth) → signed handshake →
    /// pin decision — and only then is the client usable for credential
    /// calls. Any identity failure returns `E_BROKER_UNTRUSTED` having
    /// written zero credential bytes (the handshake line carries only a
    /// fresh random nonce).
    pub fn connect_with(socket: &Path, opts: &ConnectOptions) -> Result<Self, VaultError> {
        let mut stream = UnixStream::connect(socket).map_err(VaultError::from)?;
        // C1 (defense in depth): prove the peer holds this socket's instance
        // lock BEFORE the handshake. Failures map to E_BROKER_UNTRUSTED.
        crate::ipc::verify_server(&stream, socket).map_err(|_| {
            VaultError::BrokerUntrusted(
                "server identity could not be verified; refusing to send credentials \
                 (no svault daemon holds the instance lock for this socket)"
                    .into(),
            )
        })?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        Self::handshake(&mut stream, socket, opts)?;
        Ok(Self { stream })
    }
    /// Signed challenge-response + pin check on the connected stream. Sends
    /// exactly one credential-free line (fresh nonce), reads the reply with
    /// the bounded `wire` reader, and enforces the pin policy before
    /// returning. MUST NOT fall back to a legacy direct request on any hello
    /// failure (BLOCKER 3 — that retry would reintroduce N1 in one line).
    fn handshake(
        stream: &mut UnixStream,
        socket: &Path,
        opts: &ConnectOptions,
    ) -> Result<(), VaultError> {
        use crate::broker_identity as bi;
        // Non-interactive callers (and anyone without the TTY ceremony) share
        // the strict path byte-for-byte with `mcp::broker_call`.
        if opts.trust != TrustMode::Interactive {
            if opts.trust_fingerprint.is_some() {
                // A flag without a TTY is never a trust root (F1): fail the
                // same way as no flag, so argv cannot pin a rogue.
                return Err(VaultError::BrokerUntrusted(
                    "refusing to pin a broker identity non-interactively; refusing to send credentials \
                     (a human must pin once at a TTY: run any `svault` command interactively, \
                     verify the fingerprint out-of-band, answer `yes`)"
                        .into(),
                ));
            }
            return bi::handshake_strict(stream, socket);
        }
        Self::handshake_interactive(stream, socket, opts)
    }

    /// Interactive leg: same wire steps as [`bi::handshake_strict`], but a
    /// missing pin runs the TTY ceremony (with the flag as compare-assist)
    /// instead of failing closed.
    fn handshake_interactive(
        stream: &mut UnixStream,
        socket: &Path,
        opts: &ConnectOptions,
    ) -> Result<(), VaultError> {
        use crate::broker_identity as bi;
        let client_nonce: [u8; bi::NONCE_LEN] = crypto::random_bytes()?;
        let id = crypto::hex(&crypto::random_bytes::<8>()?);
        let hello = Request {
            v: wire::VERSION,
            id: id.clone(),
            op: bi::HELLO_OP.to_string(),
            auth: None,
            params: serde_json::json!({"client_nonce": crypto::hex(&client_nonce)}),
        };
        let mut line = serde_json::to_string(&hello)
            .map_err(|e| VaultError::Protocol(format!("request serialization: {e}")))?;
        line.push('\n');
        stream.write_all(line.as_bytes())?;
        stream.flush()?;
        let owned = stream.try_clone()?;
        let mut reader = std::io::BufReader::new(&owned);
        let resp = wire::read_response(&mut reader)?;
        if resp.id != id {
            return Err(VaultError::BrokerUntrusted(
                "broker handshake id mismatch".into(),
            ));
        }
        let (ok, result) = match (resp.ok, resp.result, resp.error) {
            (true, Some(r), _) => (true, r),
            (true, None, _) => {
                return Err(VaultError::BrokerUntrusted("broker handshake empty".into()));
            }
            (false, _, Some(e)) => {
                return Err(VaultError::BrokerUntrusted(format!(
                    "broker handshake refused: {}",
                    e.msg
                )));
            }
            (false, _, None) => {
                return Err(VaultError::BrokerUntrusted(
                    "broker handshake refused".into(),
                ));
            }
        };
        let _ = ok;
        let presented: [u8; 32] = match result
            .get("public_key")
            .and_then(|v| v.as_str())
            .and_then(crate::crypto::unhex)
            .filter(|b| b.len() == 32)
        {
            Some(b) => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&b);
                k
            }
            None => {
                return Err(VaultError::BrokerUntrusted(
                    "broker handshake presented no public key".into(),
                ));
            }
        };
        let server_nonce: [u8; bi::NONCE_LEN] = match result
            .get("server_nonce")
            .and_then(|v| v.as_str())
            .and_then(crate::crypto::unhex)
            .filter(|b| b.len() == bi::NONCE_LEN)
        {
            Some(b) => {
                let mut n = [0u8; bi::NONCE_LEN];
                n.copy_from_slice(&b);
                n
            }
            None => {
                return Err(VaultError::BrokerUntrusted(
                    "broker handshake presented no server nonce".into(),
                ));
            }
        };
        let signature: [u8; 64] = match result
            .get("signature")
            .and_then(|v| v.as_str())
            .and_then(crate::crypto::unhex)
            .filter(|b| b.len() == 64)
        {
            Some(b) => {
                let mut s = [0u8; 64];
                s.copy_from_slice(&b);
                s
            }
            None => {
                return Err(VaultError::BrokerUntrusted(
                    "broker handshake presented no signature".into(),
                ));
            }
        };
        // Signature binds (client_nonce, server_nonce, canonical socket
        // path): a recorded handshake is useless against our fresh nonce,
        // and a reply for another socket does not verify here. A bad
        // signature fails closed even when the pin matches — and there is
        // NO fallback: a failed hello is E_BROKER_UNTRUSTED, never a retry
        // of the request as a legacy direct first line (that retry would be
        // a one-line reintroduction of N1).
        if bi::verify_hello(&presented, &client_nonce, &server_nonce, &signature, socket).is_err() {
            return Err(VaultError::BrokerUntrusted(
                "broker signature verification failed".into(),
            ));
        }
        // Interactive leg: `decide_pin` only returns NeedHumanConfirm here
        // (it was called with interactive=true); the TTY ceremony owns the
        // single pin write.
        match bi::decide_pin(
            socket,
            &presented,
            true,
            opts.trust_fingerprint.as_ref(),
            true,
        )? {
            bi::PinDecision::Proceed(_) => Ok(()),
            bi::PinDecision::NeedHumanConfirm(fp) => {
                super::cli::confirm_broker_pin(&fp, opts.trust_fingerprint.as_ref())?;
                bi::store_pin(socket, &presented)?;
                Ok(())
            }
        }
    }

    /// One request per connection: send, read the response, close.
    pub fn call(&mut self, op: &str, auth: &Auth, params: Value) -> Result<Value, VaultError> {
        let id = crypto::hex(&crypto::random_bytes::<8>()?);
        let req = Request {
            v: wire::VERSION,
            id: id.clone(),
            op: op.to_string(),
            auth: auth_field(auth),
            params,
        };
        let mut line = serde_json::to_string(&req)
            .map_err(|e| VaultError::Protocol(format!("request serialization: {e}")))?;
        line.push('\n');
        self.stream.write_all(line.as_bytes())?;
        self.stream.flush()?;
        let mut reader = std::io::BufReader::new(&self.stream);
        let resp = wire::read_response(&mut reader)?;
        checked_result(resp, &id)
    }

    /// Launch a child with secrets: structural params plus borrowed stdio FDs
    /// (stdin/stdout/stderr, in that order) carried via `SCM_RIGHTS`. Holds
    /// the connection until the child exits; returns safe metadata only.
    pub fn run_with_secrets(
        &mut self,
        auth: &Auth,
        params: Value,
        stdio_fds: &[RawFd],
    ) -> Result<(RunStarted, RunExit), VaultError> {
        self.run_with_secrets_notify(auth, params, stdio_fds, |_| {})
    }

    /// Same, but `on_started` fires after the `started` line is validated and
    /// before blocking on `exited` — the CLI reports `run_id`/`pid` there.
    pub fn run_with_secrets_notify(
        &mut self,
        auth: &Auth,
        params: Value,
        stdio_fds: &[RawFd],
        on_started: impl FnOnce(&RunStarted),
    ) -> Result<(RunStarted, RunExit), VaultError> {
        let id = crypto::hex(&crypto::random_bytes::<8>()?);
        let req = Request {
            v: wire::VERSION,
            id: id.clone(),
            op: "run_with_secrets".to_string(),
            auth: auth_field(auth),
            params,
        };
        crate::fdpass::send_request_with_fds(&self.stream, &req, stdio_fds)?;
        // The child may outlive any fixed timeout; the daemon always answers
        // `exited` (or closes on kill), so wait without a read deadline.
        self.stream.set_read_timeout(None)?;
        // One reader for both lines: a second reader would lose bytes already
        // buffered with the first line.
        let mut reader = std::io::BufReader::new(&self.stream);
        let started = parse_started(&id, wire::read_response(&mut reader)?)?;
        on_started(&started);
        let exited = parse_exited(&id, &started.run_id, wire::read_response(&mut reader)?)?;
        Ok((started, exited))
    }

    /// Signal an owned live run. Ordinary single-response request.
    pub fn run_signal(
        &mut self,
        auth: &Auth,
        run_id: &str,
        signal: &str,
    ) -> Result<RunSignaled, VaultError> {
        let result = self.call(
            "run_signal",
            auth,
            json!({"run_id": run_id, "signal": signal}),
        )?;
        let acked = result
            .get("run_id")
            .and_then(|v| v.as_str())
            .ok_or(VaultError::Protocol(
                "run_signal response missing run_id".into(),
            ))?;
        if acked != run_id {
            return Err(VaultError::Protocol("response run_id mismatch".into()));
        }
        if result.get("signaled").and_then(|v| v.as_bool()) != Some(true) {
            return Err(VaultError::Protocol("run_signal not acknowledged".into()));
        }
        Ok(RunSignaled {
            run_id: acked.to_string(),
            signaled: true,
        })
    }
}
