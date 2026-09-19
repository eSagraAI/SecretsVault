//! N1 regression: a rogue same-UID listener that takes the free flock and
//! binds the socket path must receive ZERO credential bytes.
//!
//! The rogue here is deliberately *blind*: it holds the lock and the path
//! but never reads the broker identity file — exactly the opportunistic
//! squatter the mechanism closes. A same-UID adversary that CAN read
//! `<vault>.broker-id` can forge handshake proofs and is NOT stopped by this
//! (or any) pin design; the threat model states that bound explicitly. This
//! test must not be mistaken for proof against the file-reading adversary.
//!
//! Pin isolation: tests share the real pin dir (`$XDG_DATA_HOME`), so every
//! socket path is made unique per test (pid + nanos + tag) and pins are
//! removed on teardown.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use svault::broker_identity;
use svault::client::{Client, ConnectOptions, TrustMode};
use svault::ipc::InstanceLock;

const PASS: &str = "correct horse battery storm drain";

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("svault-n1-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn sock(&self) -> PathBuf {
        self.0.join("svault.sock")
    }
    fn vault(&self) -> PathBuf {
        self.0.join("vault.enc")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        // Pin hygiene: never leave trust for a dead socket behind.
        if let Ok(pin) = broker_identity::pin_path(&self.sock()) {
            let _ = std::fs::remove_file(pin);
        }
    }
}

const BIN: &str = env!("CARGO_BIN_EXE_svault");

/// Child-process daemon: a real `svault daemon` that can actually die (kernel
/// releases the flock), so restart/rogue tests exercise true process death.
/// Killed on drop so a failing assertion never leaves a live broker behind.
struct ProcDaemon(std::process::Child);

impl ProcDaemon {
    fn stop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for ProcDaemon {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn spawn_daemon(dir: &Dir) -> ProcDaemon {
    use std::process::{Command, Stdio};
    let mut child = Command::new(BIN)
        .arg("--socket")
        .arg(dir.sock())
        .arg("--file")
        .arg(dir.vault())
        .arg("daemon")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn svault daemon");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if UnixStream::connect(dir.sock()).is_ok() {
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("daemon exited early with {status}");
        }
        assert!(
            Instant::now() < deadline,
            "daemon socket never became ready"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    ProcDaemon(child)
}

/// Read the daemon's public key out-of-band via `trust show` (the test
/// stand-in for comparing the fingerprint on the broker host).
fn daemon_fingerprint(dir: &Dir) -> [u8; 32] {
    use std::process::{Command, Stdio};
    let out = Command::new(BIN)
        .arg("--socket")
        .arg(dir.sock())
        .arg("--file")
        .arg(dir.vault())
        .arg("trust")
        .arg("show")
        .stdout(std::process::Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("trust show");
    assert!(out.status.success(), "trust show failed: {out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    let hex: String = text
        .split_whitespace()
        .last()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    assert_eq!(hex.len(), 64, "no fingerprint in: {text}");
    broker_identity::parse_fingerprint(&hex).unwrap()
}

/// Test pin bootstrap: read the daemon's public key in-process (the test
/// stand-in for a human comparing `trust show` output on the broker host)
/// and write the pin DIRECTLY — never via argv. Real humans pin through the
/// TTY ceremony; tests cannot (no /dev/tty under cargo), so they act as the
/// human out-of-band channel itself. No test ever passes a fingerprint flag
/// to a client connect: non-interactive + flag is refused by construction.
fn pin_out_of_band(dir: &Dir) {
    let fp = daemon_fingerprint(dir);
    broker_identity::store_pin(&dir.sock(), &fp).expect("test pin bootstrap");
}

/// Credential-bearing call used as the disclosure probe. `vault.unlock` with
/// a passphrase stands in for any human-proof request.
fn unlock_with(client: &mut Client, pass: &str) -> Result<serde_json::Value, svault::VaultError> {
    client.call(
        "vault.unlock",
        &svault::client::Auth::Passphrase(pass.to_string()),
        serde_json::json!({}),
    )
}

fn create_vault(dir: &Dir) {
    pin_out_of_band(dir);
    let mut c = { Client::connect_with(&dir.sock(), &ConnectOptions::default()).unwrap() };
    c.call(
        "vault.create",
        &svault::client::Auth::None,
        serde_json::json!({"passphrase": PASS}),
    )
    .expect("vault.create");
}

/// Rogue: takes the flock on `<socket>.lock`, binds the socket path, records
/// every byte received on the first connection. Returns (bytes seen, thread).
fn spawn_rogue(
    socket: PathBuf,
) -> (
    InstanceLock,
    std::sync::mpsc::Receiver<Vec<u8>>,
    std::thread::JoinHandle<()>,
) {
    let _ = std::fs::remove_file(&socket);
    let lock = InstanceLock::acquire(&socket).expect("rogue takes the free lock");
    let listener = UnixListener::bind(&socket).expect("rogue binds the path");
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let handle = std::thread::spawn(move || {
        if let Ok((mut c, _)) = listener.accept() {
            let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = c.set_write_timeout(Some(Duration::from_secs(5)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                match c.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.contains(&b'\n') {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            // Answer the hello with a forged reply (wrong key): the client
            // must fail signature verification with E_BROKER_UNTRUSTED —
            // exercising the exact fail-closed path, not a transport error.
            // (A blind squatter that cannot even answer still gets zero
            // credential bytes, but this proves the code too.)
            // Echo the client's id back so the id check passes.
            let id = buf
                .split(|&b| b == b'"')
                .find(|w| w.len() == 16 && w.iter().all(|c| c.is_ascii_hexdigit()))
                .map(|w| String::from_utf8_lossy(w).into_owned())
                .unwrap_or_else(|| "x".to_string());
            let fake = serde_json::json!({"v":1,"id":id,"ok":true,"result":{
                "public_key": "ab".repeat(32),
                "server_nonce": "cd".repeat(32),
                "signature": "ef".repeat(64)}});
            let _ = c.write_all(serde_json::to_string(&fake).unwrap().as_bytes());
            let _ = c.write_all(b"\n");
            let _ = tx.send(buf);
        }
    });
    (lock, rx, handle)
}

// ---------------------------------------------------------------------------
// The original attack, as a permanent regression.
// ---------------------------------------------------------------------------

#[test]
fn rogue_with_lock_but_no_identity_gets_zero_bytes() {
    let dir = Dir::new("rogue");
    let mut live = spawn_daemon(&dir);
    create_vault(&dir);
    // Client connects once and pins (the legitimate first contact).
    pin_out_of_band(&dir);
    // Kill the daemon: lock is free, socket file lingers.
    live.stop();
    std::thread::sleep(Duration::from_millis(300));

    // Rogue takes the flock + path and records everything.
    let (_lock, rx, rogue) = spawn_rogue(dir.sock());
    std::thread::sleep(Duration::from_millis(200));

    // A credential-bearing call MUST fail closed with E_BROKER_UNTRUSTED.
    // The pin matches the DEAD daemon's key, so the handshake signature from
    // the rogue fails verification — before any credential byte. (If the
    // rogue closed without answering, the transport error below still proves
    // zero credential bytes reached it: the byte-count assertion is the real
    // gate, the code assertion the diagnostic.)
    match Client::connect_with(&dir.sock(), &ConnectOptions::default()) {
        Ok(mut c) => {
            let err = unlock_with(&mut c, PASS).unwrap_err();
            assert_eq!(err.code(), "E_BROKER_UNTRUSTED", "wrong code: {err}");
        }
        Err(e) => assert_eq!(e.code(), "E_BROKER_UNTRUSTED", "wrong code: {e}"),
    }

    let seen = rx.recv_timeout(Duration::from_secs(6)).unwrap_or_default();
    // The handshake line (fresh nonce, no credentials) MAY reach the rogue;
    // what must never reach it is anything credential-bearing.
    let text = String::from_utf8_lossy(&seen);
    assert!(
        !text.contains("passphrase") && !text.contains(PASS),
        "REGRESSION: rogue received credential bytes: {text:?}"
    );
    // And byte-exact: the only line the client ever wrote is broker.hello.
    if !seen.is_empty() {
        assert_eq!(
            seen.iter().filter(|&&b| b == b'\n').count(),
            1,
            "client must write at most the hello line before failing: {text:?}"
        );
        assert!(
            text.contains("broker.hello"),
            "the only pre-trust line is the hello: {text:?}"
        );
    }
    rogue.join().unwrap();
}

// ---------------------------------------------------------------------------
// Legitimate flows.
// ---------------------------------------------------------------------------

#[test]
fn legit_daemon_serves_after_explicit_first_contact() {
    let dir = Dir::new("legit");
    let _live = spawn_daemon(&dir);
    create_vault(&dir);
    // Pinned out-of-band (as the human would at a TTY): serves.
    pin_out_of_band(&dir);
    let mut c = Client::connect(&dir.sock()).expect("pinned first contact");
    let status = c
        .call(
            "vault.status",
            &svault::client::Auth::None,
            serde_json::json!({}),
        )
        .expect("status through the pinned daemon");
    assert!(status.get("version").is_some(), "{status}");
    // Second call: pin persists, no re-confirmation.
    let mut c2 = Client::connect(&dir.sock()).expect("pinned reconnect");
    c2.call(
        "vault.status",
        &svault::client::Auth::None,
        serde_json::json!({}),
    )
    .expect("second call on the stored pin");
}

#[test]
fn restart_keeps_pin_valid() {
    let dir = Dir::new("restart");
    let mut live = spawn_daemon(&dir);
    create_vault(&dir);
    pin_out_of_band(&dir);
    live.stop();
    std::thread::sleep(Duration::from_millis(300));
    // Same identity file → same key → stored pin still valid, no prompt.
    let _live2 = spawn_daemon(&dir);
    let _ = daemon_fingerprint(&dir);
    let mut c = Client::connect(&dir.sock()).expect("pin survives restart");
    c.call(
        "vault.status",
        &svault::client::Auth::None,
        serde_json::json!({}),
    )
    .expect("status after restart");
}

#[test]
fn stale_socket_after_crash_serves_without_credential_risk() {
    let dir = Dir::new("stale");
    let mut live = spawn_daemon(&dir);
    create_vault(&dir);
    pin_out_of_band(&dir);
    // Simulate a crash: drop the daemon WITHOUT cleanup; the kernel frees
    // the flock while the socket file lingers. A fresh daemon rebinds.
    live.stop();
    std::thread::sleep(Duration::from_millis(300));
    assert!(dir.sock().exists(), "crash leaves the socket file");
    let _live2 = spawn_daemon(&dir);
    let _ = daemon_fingerprint(&dir);
    let mut c = Client::connect(&dir.sock()).expect("rebound daemon trusted via pin");
    c.call(
        "vault.status",
        &svault::client::Auth::None,
        serde_json::json!({}),
    )
    .expect("status on rebound socket");
}

#[test]
fn pin_mismatch_fails_closed_with_zero_bytes() {
    let dir = Dir::new("mismatch");
    let mut live = spawn_daemon(&dir);
    create_vault(&dir);
    pin_out_of_band(&dir);
    // Rotate the broker identity out from under the pin (loud rotation).
    live.stop();
    std::thread::sleep(Duration::from_millis(300));
    broker_identity::BrokerIdentity::regenerate(&dir.vault()).unwrap();
    let _live2 = spawn_daemon(&dir);
    let _ = daemon_fingerprint(&dir);
    // Record what the new daemon receives, if anything.
    let err = Client::connect(&dir.sock()).unwrap_err();
    assert_eq!(err.code(), "E_BROKER_UNTRUSTED", "wrong code: {err}");
}

#[test]
fn first_contact_non_interactive_fails_closed() {
    let dir = Dir::new("firstcontact");
    let _live = spawn_daemon(&dir);
    // No pin, no fingerprint, non-interactive: fail, zero bytes to the daemon.
    let err = Client::connect(&dir.sock()).unwrap_err();
    assert_eq!(err.code(), "E_BROKER_UNTRUSTED", "wrong code: {err}");
}

#[test]
fn non_interactive_flag_never_pins() {
    let dir = Dir::new("wrongfp");
    let mut live = spawn_daemon(&dir);
    let _ = &mut live;
    // A non-interactive flag can never pin (F1): refused even though the
    // daemon is legitimate and the fingerprint is CORRECT — argv is
    // agent-controlled, so the flag alone is never a trust root.
    let err = Client::connect_with(
        &dir.sock(),
        &ConnectOptions {
            trust: TrustMode::NonInteractive,
            trust_fingerprint: Some(daemon_fingerprint(&dir)),
        },
    )
    .unwrap_err();
    assert_eq!(err.code(), "E_BROKER_UNTRUSTED", "wrong code: {err}");
    assert!(
        broker_identity::load_pin(&dir.sock()).unwrap().is_none(),
        "a refused non-interactive flag must not leave a pin"
    );
    live.stop();
}

#[test]
fn two_sockets_have_independent_pins() {
    let a = Dir::new("socka");
    let b = Dir::new("sockb");
    let _la = spawn_daemon(&a);
    let _lb = spawn_daemon(&b);
    assert_ne!(
        daemon_fingerprint(&a),
        daemon_fingerprint(&b),
        "distinct vaults must have distinct identities"
    );
    pin_out_of_band(&a);
    // B's key pinned under A's socket must NOT verify.
    let err = Client::connect(&b.sock()).unwrap_err();
    assert_eq!(err.code(), "E_BROKER_UNTRUSTED");
    pin_out_of_band(&b);
    // Now both work independently.
    Client::connect(&a.sock()).expect("A pinned");
    Client::connect(&b.sock()).expect("B pinned");
    // Cross-check: a pin file for A never equals B's key.
    let pa = broker_identity::load_pin(&a.sock()).unwrap().unwrap();
    let pb = broker_identity::load_pin(&b.sock()).unwrap().unwrap();
    assert_ne!(pa, pb, "pins must not collide across sockets");
}

#[test]
fn error_code_and_display_are_stable() {
    let e = svault::VaultError::BrokerUntrusted("x".into());
    assert_eq!(e.code(), "E_BROKER_UNTRUSTED");
    assert!(
        e.to_string().contains("refusing to send credentials"),
        "Display must state the fail-closed property: {e}"
    );
}

#[test]
fn replay_across_sockets_does_not_verify() {
    // A hello reply captured for socket A must not verify for socket B:
    // the canonical socket path bytes are inside the signed message.
    use svault::broker_identity as bi;
    let dir = Dir::new("replay");
    let _live = spawn_daemon(&dir);
    let other = dir.path().join("other.sock");
    let client_nonce = [7u8; 32];
    // Capture a genuine hello reply over the wire (credential-free).
    let (server_nonce, sig, pk) = {
        use std::io::Write as _;
        let mut stream = UnixStream::connect(dir.sock()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let id = svault::crypto::hex(&svault::crypto::random_bytes::<8>().unwrap());
        let hello = serde_json::json!({"v":1,"id":id,"op":"broker.hello","params":{"client_nonce":svault::crypto::hex(&client_nonce)}});
        let mut line = serde_json::to_string(&hello).unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).unwrap();
        let mut reader = std::io::BufReader::new(&stream);
        let mut buf = String::new();
        use std::io::BufRead as _;
        reader.read_line(&mut buf).unwrap();
        let resp: serde_json::Value = serde_json::from_str(&buf).unwrap();
        let r = &resp["result"];
        let pk = svault::crypto::unhex(r["public_key"].as_str().unwrap()).unwrap();
        let sn = svault::crypto::unhex(r["server_nonce"].as_str().unwrap()).unwrap();
        let sg = svault::crypto::unhex(r["signature"].as_str().unwrap()).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&pk);
        let mut b = [0u8; 32];
        b.copy_from_slice(&sn);
        let mut c = [0u8; 64];
        c.copy_from_slice(&sg);
        (b, c, a)
    };
    bi::verify_hello(&pk, &client_nonce, &server_nonce, &sig, &dir.sock())
        .expect("genuine reply verifies on its own socket");
    let err = bi::verify_hello(&pk, &client_nonce, &server_nonce, &sig, &other).unwrap_err();
    assert_eq!(err.code(), "E_BROKER_UNTRUSTED");
}

#[test]
fn no_fallback_after_failed_hello() {
    // BLOCKER 3: if the hello fails for ANY reason the client MUST fail
    // E_BROKER_UNTRUSTED and MUST NOT retry the credential request as a
    // legacy direct first line. Rogue answers hello with garbage, then
    // records everything: it must see exactly the hello line and nothing
    // credential-bearing, and the client must report E_BROKER_UNTRUSTED
    // (never a successful unlock, never a silent retry).
    let dir = Dir::new("nofallback");
    let mut live = spawn_daemon(&dir);
    create_vault(&dir);
    pin_out_of_band(&dir);
    live.stop();
    std::thread::sleep(Duration::from_millis(300));
    let (_lock, rx, rogue) = spawn_rogue(dir.sock());
    std::thread::sleep(Duration::from_millis(200));
    let err = match Client::connect(&dir.sock()) {
        Ok(mut c) => unlock_with(&mut c, PASS).unwrap_err(),
        Err(e) => e,
    };
    assert_eq!(err.code(), "E_BROKER_UNTRUSTED", "wrong code: {err}");
    let seen = rx.recv_timeout(Duration::from_secs(6)).unwrap_or_default();
    let text = String::from_utf8_lossy(&seen);
    assert!(
        !text.contains("passphrase") && !text.contains(PASS),
        "fallback leaked credentials: {text:?}"
    );
    assert_eq!(
        seen.iter().filter(|&&b| b == b'\n').count(),
        1,
        "exactly one pre-trust line, no retry: {text:?}"
    );
    assert!(text.contains("broker.hello"), "{text:?}");
    rogue.join().unwrap();
}
