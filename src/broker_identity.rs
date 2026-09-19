//! Broker identity: persistent Ed25519 identity, signed challenge-response
//! handshake, and per-socket client pins (TOFU).
//!
//! Why this exists: the kernel lock-holder check in [`crate::ipc`] proves
//! *which process holds the lock*, never *what that process is*. When the
//! legitimate daemon is down the lock is free, so any same-UID process can
//! take it, bind the socket path, and receive the human proof. This module
//! adds the missing piece: the daemon owns a persistent Ed25519 identity and
//! proves possession of its private key on every connection, before the
//! client writes any credential byte. The client remembers the broker's
//! **public** key per socket (TOFU pin) and fails closed on mismatch.
//!
//! What it does and does not defend (stated exactly, see threat model A2):
//! a blind squatter that holds the lock but does NOT know the identity
//! private key cannot obtain credentials — the handshake fails before any
//! credential byte is written. A same-UID process that can read the identity
//! private key file (`<vault>.broker-id`, mode 0600 — readable by its owner,
//! and the adversary in this model IS the owner) CAN forge proofs and is NOT
//! stopped. The pin store holds public keys only, so reading a pin buys an
//! adversary nothing. The mechanism closes the opportunistic window and makes
//! substitution loud (pin mismatch), not silent.
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::crypto;
use crate::error::VaultError;

/// Domain separation for the handshake signature. Binds the proof to this
/// protocol so a signature from any other context is useless here.
const DOMAIN: &[u8] = b"svault/broker-hello/v1";

/// Fresh nonces are 32 bytes from the existing OS-CSPRNG helper.
pub const NONCE_LEN: usize = 32;

pub const HELLO_OP: &str = "broker.hello";
/// Credential-free live fingerprint probe for in-app first-contact (TOFU).
/// Connects, sets 10 s timeouts, sends one `broker.hello` line with a fresh
/// 32-byte client nonce, reads one bounded response, checks the id, and
/// extracts `public_key`. Writes ZERO credential bytes and requires NO pin.
/// This is the single implementation; `cli::trust_show_live` delegates here.
pub fn broker_fingerprint_live(socket: &Path) -> Result<String, VaultError> {
    use std::io::Write as _;
    let mut stream = std::os::unix::net::UnixStream::connect(socket).map_err(VaultError::from)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
    let client_nonce: [u8; NONCE_LEN] = crate::crypto::random_bytes()?;
    let id = crate::crypto::hex(&crate::crypto::random_bytes::<8>()?);
    let hello = crate::wire::Request {
        v: crate::wire::VERSION,
        id: id.clone(),
        op: HELLO_OP.to_string(),
        auth: None,
        params: serde_json::json!({"client_nonce": crate::crypto::hex(&client_nonce)}),
    };
    let mut line = serde_json::to_string(&hello)
        .map_err(|e| VaultError::Protocol(format!("request serialization: {e}")))?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    stream.flush()?;
    let mut reader = std::io::BufReader::new(&stream);
    let resp = crate::wire::read_response(&mut reader)?;
    if resp.id != id || !resp.ok {
        return Err(VaultError::BrokerUntrusted(
            "broker handshake refused".into(),
        ));
    }
    let result = resp
        .result
        .ok_or(VaultError::BrokerUntrusted("broker handshake empty".into()))?;
    let key_hex =
        result
            .get("public_key")
            .and_then(|v| v.as_str())
            .ok_or(VaultError::BrokerUntrusted(
                "broker handshake presented no public key".into(),
            ))?;
    Ok(key_hex.to_string())
}

/// Default daemon socket path: `$XDG_RUNTIME_DIR/svault/svault.sock`.
/// Single implementation shared with the CLI (`cli::socket_path` delegates
/// here); the dashboard must not re-derive this path by hand.
pub fn default_socket_path() -> Result<PathBuf, VaultError> {
    let runtime = std::env::var("XDG_RUNTIME_DIR")
        .map_err(|_| VaultError::Io(std::io::Error::other("XDG_RUNTIME_DIR not set")))?;
    Ok(Path::new(&runtime).join("svault").join("svault.sock"))
}

/// `<vault>.broker-id`: sibling of the vault file, so it is persistent
/// (survives reboot, unlike `$XDG_RUNTIME_DIR`) and stable per vault.
pub fn identity_path(vault_path: &Path) -> PathBuf {
    vault_path.with_file_name(format!(
        "{}.broker-id",
        vault_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "vault.enc".to_string())
    ))
}

/// Directory holding one pin file per socket.
pub fn pin_dir() -> Result<PathBuf, VaultError> {
    let base = match std::env::var("XDG_DATA_HOME") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => {
            let home = std::env::var("HOME")
                .map_err(|_| VaultError::Io(std::io::Error::other("HOME not set")))?;
            PathBuf::from(home).join(".local/share")
        }
    };
    Ok(base.join("svault").join("pins"))
}

/// Canonical socket-path form shared by the pin hash, the
/// `socket_path_bytes` in the signature, and the stored-pin comparison
/// (protocol name: `canonical_socket_path`). Absolute + lexical only — never
/// `std::fs::canonicalize`, which needs the socket to exist (it may be
/// absent/stale) and would follow symlinks into a different identity.
/// Relative paths join onto the process cwd; `.`/`..`/duplicate separators
/// are normalized lexically; a trailing `/` (except root) is stripped.
pub fn canonical_socket_path(socket: &Path) -> PathBuf {
    let abs = if socket.is_absolute() {
        socket.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(socket)
    };
    let mut parts: Vec<std::ffi::OsString> = Vec::new();
    for comp in abs.components() {
        use std::path::Component;
        match comp {
            Component::RootDir => {
                parts.clear();
            }
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop();
            }
            Component::Prefix(p) => parts.push(p.as_os_str().to_os_string()),
            Component::Normal(c) => parts.push(c.to_os_string()),
        }
    }
    let mut out = PathBuf::from("/");
    out.extend(parts);
    out
}

/// One pin per broker socket, so two brokers on two sockets never collide:
/// `pins/<sha256(canonical-socket-path)>.pin`. The file holds JSON
/// `{socket, key_hex}` so a pin is refused when its stored path differs from
/// the canonical request path (no silent cross-path reuse).
pub fn pin_path(socket: &Path) -> Result<PathBuf, VaultError> {
    let canon = canonical_socket_path(socket);
    let digest = Sha256::digest(canon.as_os_str().as_encoded_bytes());
    Ok(pin_dir()?.join(format!("{digest:x}.pin")))
}

/// Lowercase hex fingerprint of a broker public key (what the human compares
/// out-of-band and what `--trust-fingerprint` asserts).
pub fn fingerprint(public_key: &[u8; 32]) -> String {
    crypto::hex(public_key)
}

/// Parse a user-supplied fingerprint: exactly 64 lowercase hex chars.
pub fn parse_fingerprint(s: &str) -> Result<[u8; 32], VaultError> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(VaultError::InvalidInput(
            "fingerprint must be 64 hex characters",
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).unwrap_or(16);
        let lo = (chunk[1] as char).to_digit(16).unwrap_or(16);
        if hi > 15 || lo > 15 {
            return Err(VaultError::InvalidInput(
                "fingerprint must be 64 hex characters",
            ));
        }
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

/// The exact bytes the daemon signs: domain || client_nonce || server_nonce
/// || canonical-socket-path-bytes. The client nonce makes a recorded
/// handshake useless against the client's fresh nonce (no replay); the
/// canonical socket path bytes stop a reply for socket A being replayed on
/// socket B (both ends apply [`canonical_socket_path`] to their configured
/// path, so spelling variants of one socket agree and distinct sockets
/// differ); the domain separator stops cross-protocol signature reuse.
pub fn signed_message(
    client_nonce: &[u8; NONCE_LEN],
    server_nonce: &[u8; NONCE_LEN],
    socket_path: &Path,
) -> Vec<u8> {
    let canon = canonical_socket_path(socket_path);
    let path_bytes = canon.as_os_str().as_encoded_bytes();
    let mut msg = Vec::with_capacity(DOMAIN.len() + 2 * NONCE_LEN + path_bytes.len());
    msg.extend_from_slice(DOMAIN);
    msg.extend_from_slice(client_nonce);
    msg.extend_from_slice(server_nonce);
    msg.extend_from_slice(path_bytes);
    msg
}

/// Daemon-side identity: the private key, kept in memory while serving.
pub struct BrokerIdentity {
    signing: SigningKey,
}

impl BrokerIdentity {
    /// Load the persistent identity, or generate (fixed 32-byte key from the
    /// existing `crypto::random_bytes` — no new RNG) and store it mode 0600
    /// via atomic write. Generation is loud: the caller logs the fingerprint.
    pub fn load_or_generate(vault_path: &Path) -> Result<Self, VaultError> {
        let path = identity_path(vault_path);
        if path.exists() {
            let bytes = std::fs::read(&path)?;
            if bytes.len() != 32 {
                return Err(VaultError::Corrupt("broker identity file".into()));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(Self {
                signing: SigningKey::from_bytes(&key),
            });
        }
        if let Some(parent) = path.parent()
            && parent != Path::new("")
        {
            crate::store::ensure_private_dir(parent)?;
        }
        let key = crypto::random_bytes::<32>()?;
        // Atomic 0600 create: temp + rename in the same directory.
        let tmp = path.with_extension("broker-id.tmp");
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&key)?;
            f.sync_all()?;
        }
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        std::fs::rename(&tmp, &path)?;
        Ok(Self {
            signing: SigningKey::from_bytes(&key),
        })
    }

    /// Generate a FRESH identity, replacing any existing one. Loud by
    /// design: every existing client pin fails closed afterwards until the
    /// human re-pins. Only `trust reset` calls this.
    pub fn regenerate(vault_path: &Path) -> Result<[u8; 32], VaultError> {
        let path = identity_path(vault_path);
        if let Some(parent) = path.parent()
            && parent != Path::new("")
        {
            crate::store::ensure_private_dir(parent)?;
        }
        let key = crypto::random_bytes::<32>()?;
        let tmp = path.with_extension("broker-id.tmp");
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&key)?;
            f.sync_all()?;
        }
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        std::fs::rename(&tmp, &path)?;
        Ok(SigningKey::from_bytes(&key).verifying_key().to_bytes())
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Answer a client nonce: fresh server nonce + signature over the
    /// domain-separated message. The socket path bound into the signature is
    /// the daemon's own configured path.
    pub fn hello_reply(
        &self,
        client_nonce: &[u8; NONCE_LEN],
        socket_path: &Path,
    ) -> Result<([u8; NONCE_LEN], [u8; 64]), VaultError> {
        let server_nonce: [u8; NONCE_LEN] = crypto::random_bytes()?;
        let msg = signed_message(client_nonce, &server_nonce, socket_path);
        let sig = self.signing.sign(&msg);
        Ok((server_nonce, sig.to_bytes()))
    }
}

/// Verify a `broker.hello` reply against the expected public key. Fails
/// closed on any malformed key/signature.
pub fn verify_hello(
    public_key: &[u8; 32],
    client_nonce: &[u8; NONCE_LEN],
    server_nonce: &[u8; NONCE_LEN],
    signature: &[u8; 64],
    socket_path: &Path,
) -> Result<(), VaultError> {
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| VaultError::BrokerUntrusted("broker public key is malformed".into()))?;
    let sig = Signature::from_bytes(signature);
    let msg = signed_message(client_nonce, server_nonce, socket_path);
    key.verify(&msg, &sig)
        .map_err(|_| VaultError::BrokerUntrusted("broker signature verification failed".into()))
}

/// Outcome of the client-side pin decision. `Proceed` carries the verified
/// public key (already pinned). `NeedHumanConfirm` carries the *untrusted*
/// fingerprint for the TTY ceremony — the caller must not proceed without a
/// live human typing `yes` on the controlling TTY. There is deliberately no
/// "proceed and write" outcome: every pin-file write happens inside the TTY
/// ceremony (BLOCKER 1 — a CLI flag or env var is agent-controlled argv, so
/// it can never be a standalone trust root).
pub enum PinDecision {
    Proceed([u8; 32]),
    NeedHumanConfirm([u8; 32]),
}

/// Client pin policy (pure decision, never writes):
/// - pin exists and the hello verifies under it → proceed;
/// - pin exists and anything differs → fail closed, never re-pin, never
///   overwrite (rotation is an explicit `trust reset` + TTY re-pin);
/// - no pin → defer to the caller: `TrustMode::Interactive` runs the TTY
///   ceremony (`--trust-fingerprint`, when present, only pre-compares inside
///   that ceremony — a mismatch aborts before prompting); anything else
///   fails closed. Non-interactive + no pin fails ALWAYS, flag or not: an
///   agent that could pin via argv would pin its own rogue (F1).
pub fn decide_pin(
    socket: &Path,
    presented: &[u8; 32],
    hello_ok: bool,
    trust_fingerprint: Option<&[u8; 32]>,
    interactive: bool,
) -> Result<PinDecision, VaultError> {
    if let Some(pinned) = load_pin(socket)? {
        if hello_ok && pinned == *presented {
            return Ok(PinDecision::Proceed(pinned));
        }
        return Err(VaultError::BrokerUntrusted(
            "broker identity does not match the pinned key; refusing to send credentials \
             (run `svault trust show` to compare, `trust reset` + re-pin after investigation)"
                .into(),
        ));
    }
    // No pin (first contact): the signature must already have verified —
    // callers check before reaching here — and nothing is written yet.
    if !hello_ok {
        return Err(VaultError::BrokerUntrusted(
            "broker signature verification failed".into(),
        ));
    }
    if let Some(fp) = trust_fingerprint
        && *fp != *presented
    {
        return Err(VaultError::BrokerUntrusted(
            "broker fingerprint does not match --trust-fingerprint; refusing to send credentials"
                .into(),
        ));
    }
    if !interactive {
        return Err(VaultError::BrokerUntrusted(
            "no pinned broker identity for this socket; refusing to send credentials \
             (a human must pin once at a TTY: run any svault command interactively, \
             verify the fingerprint out-of-band, answer `yes`)"
                .into(),
        ));
    }
    Ok(PinDecision::NeedHumanConfirm(*presented))
}

/// Atomically write the pin for `socket` via the audited
/// [`crate::store::save_atomic`] (temp + `O_EXCL` + 0600 + rename). Content
/// is JSON `{socket, key_hex}` holding the canonical path, so a pin is
/// refused when its stored path differs from the canonical request path.
/// MUST only be called inside the live-human TTY ceremony (after an explicit
/// `yes`, optionally with a pre-compared `--trust-fingerprint`).
pub fn store_pin(socket: &Path, public_key: &[u8; 32]) -> Result<(), VaultError> {
    let path = pin_path(socket)?;
    if let Some(parent) = path.parent() {
        crate::store::ensure_private_dir(parent)?;
    }
    let canon = canonical_socket_path(socket);
    let doc = serde_json::json!({
        "socket": canon.to_string_lossy(),
        "key_hex": crate::crypto::hex(public_key),
    });
    let bytes = serde_json::to_vec(&doc)
        .map_err(|e| VaultError::Protocol(format!("pin serialization: {e}")))?;
    crate::store::save_atomic(&path, &bytes)?;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

/// Read the pinned public key for `socket`, if any. Refuses the pin when its
/// stored canonical path differs from the request's canonical path, or when
/// the content is malformed — both fail closed, never ignored.
pub fn load_pin(socket: &Path) -> Result<Option<[u8; 32]>, VaultError> {
    let path = pin_path(socket)?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)?;
    // Legacy 32-byte raw pins (pre-JSON): accept only when no JSON parses.
    if bytes.len() == 32 && !bytes.starts_with(b"{") {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(Some(out));
    }
    let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
        VaultError::BrokerUntrusted(
            "broker pin file is corrupt; delete it and re-pin at a TTY".into(),
        )
    })?;
    let stored = v.get("socket").and_then(|s| s.as_str()).ok_or_else(|| {
        VaultError::BrokerUntrusted(
            "broker pin file is corrupt; delete it and re-pin at a TTY".into(),
        )
    })?;
    let canon = canonical_socket_path(socket);
    if stored != canon.to_string_lossy() {
        return Err(VaultError::BrokerUntrusted(
            "broker pin is for a different socket path; refusing to send credentials \
             (re-pin this exact path at a TTY)"
                .into(),
        ));
    }
    let hex = v.get("key_hex").and_then(|s| s.as_str()).ok_or_else(|| {
        VaultError::BrokerUntrusted(
            "broker pin file is corrupt; delete it and re-pin at a TTY".into(),
        )
    })?;
    let raw = crate::crypto::unhex(hex)
        .filter(|b| b.len() == 32)
        .ok_or_else(|| {
            VaultError::BrokerUntrusted(
                "broker pin file is corrupt; delete it and re-pin at a TTY".into(),
            )
        })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(Some(out))
}

/// Strict non-interactive handshake for paths with no TTY ceremony available
/// (`mcp::broker_call`): credential-free hello line → bounded reply read →
/// id check → field parse → signature verify against the canonical path →
/// pin check with `interactive = false` (no pin fails closed ALWAYS, and
/// `trust_fingerprint` is refused outright — there is no flag on those
/// paths). Any failure is `E_BROKER_UNTRUSTED` with zero credential bytes
/// written, and the caller MUST NOT retry the request as a legacy direct
/// first line. Shared with `Client` so both gates enforce byte-identical
/// policy from one function.
pub fn handshake_strict(
    stream: &mut std::os::unix::net::UnixStream,
    socket: &Path,
) -> Result<(), VaultError> {
    use std::io::Write as _;
    let client_nonce: [u8; NONCE_LEN] = crate::crypto::random_bytes()?;
    let id = crate::crypto::hex(&crate::crypto::random_bytes::<8>()?);
    let line = serde_json::json!({
        "v": crate::wire::VERSION,
        "id": id,
        "op": HELLO_OP,
        "params": {"client_nonce": crate::crypto::hex(&client_nonce)},
    });
    let mut line = serde_json::to_string(&line).map_err(|e| VaultError::Protocol(e.to_string()))?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    stream.flush()?;
    let owned = stream.try_clone()?;
    let mut reader = std::io::BufReader::new(&owned);
    // Bounded read: `wire::read_response` caps at MAX_MESSAGE_LEN (never a
    // hand-rolled unbounded `read_until`).
    let resp = crate::wire::read_response(&mut reader)
        .map_err(|_| VaultError::BrokerUntrusted("broker handshake failed".into()))?;
    if resp.id != id {
        return Err(VaultError::BrokerUntrusted(
            "broker handshake id mismatch".into(),
        ));
    }
    let result = match (resp.ok, resp.result, resp.error) {
        (true, Some(r), _) => r,
        (true, None, _) => {
            return Err(VaultError::BrokerUntrusted("broker handshake empty".into()));
        }
        (false, _, _) => {
            return Err(VaultError::BrokerUntrusted(
                "broker handshake refused".into(),
            ));
        }
    };
    let presented = parse_key(&result, "public_key")?;
    let server_nonce = parse_nonce(&result)?;
    let signature = parse_sig(&result)?;
    verify_hello(&presented, &client_nonce, &server_nonce, &signature, socket)?;
    match decide_pin(socket, &presented, true, None, false)? {
        PinDecision::Proceed(_) => Ok(()),
        PinDecision::NeedHumanConfirm(_) => Err(VaultError::BrokerUntrusted(
            "no pinned broker identity for this socket; refusing to send credentials \
             (a human must pin once at a TTY: run any `svault` command interactively, \
             verify the fingerprint out-of-band, answer `yes`)"
                .into(),
        )),
    }
}

fn parse_key(v: &serde_json::Value, field: &str) -> Result<[u8; 32], VaultError> {
    let mut out = [0u8; 32];
    let raw = v
        .get(field)
        .and_then(|x| x.as_str())
        .and_then(crate::crypto::unhex)
        .filter(|b| b.len() == 32)
        .ok_or_else(|| {
            VaultError::BrokerUntrusted("broker handshake presented no public key".into())
        })?;
    out.copy_from_slice(&raw);
    Ok(out)
}

fn parse_nonce(v: &serde_json::Value) -> Result<[u8; NONCE_LEN], VaultError> {
    let mut out = [0u8; NONCE_LEN];
    let raw = v
        .get("server_nonce")
        .and_then(|x| x.as_str())
        .and_then(crate::crypto::unhex)
        .filter(|b| b.len() == NONCE_LEN)
        .ok_or_else(|| {
            VaultError::BrokerUntrusted("broker handshake presented no server nonce".into())
        })?;
    out.copy_from_slice(&raw);
    Ok(out)
}

fn parse_sig(v: &serde_json::Value) -> Result<[u8; 64], VaultError> {
    let mut out = [0u8; 64];
    let raw = v
        .get("signature")
        .and_then(|x| x.as_str())
        .and_then(crate::crypto::unhex)
        .filter(|b| b.len() == 64)
        .ok_or_else(|| {
            VaultError::BrokerUntrusted("broker handshake presented no signature".into())
        })?;
    out.copy_from_slice(&raw);
    Ok(out)
}
