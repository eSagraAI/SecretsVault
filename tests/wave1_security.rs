//! Adversarial regressions for the C1–C4 findings of the integral audit.
//!
//! These are permanent tests: each one fails on the pre-fix code and pins the
//! guarantee that closed the finding.
//!
//! - `c1_*`: a same-UID process cannot receive the human proof, and a
//!   legitimate restart / stale socket still works.
//! - `c2_*`: a fatal signal to the real daemon produces no readable core.
//! - `c3_*`: a failing `write(2)` is an error, not an infinite loop; the
//!   previous file survives and the daemon keeps answering.
//! - `c4_*`: a mutation that would exceed the loader's caps is refused before
//!   the commit, leaving the previous vault valid.
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;
use svault::ipc::{InstanceLock, instance_lock_path, lock_holder_pid, verify_server};

const PASS: &str = "correct horse battery";
const TRAP: &str = "TRAP-c1c4-CANARY-0123456789abcdef";
const BIN: &str = env!("CARGO_BIN_EXE_svault");
const IDLE: Duration = Duration::from_secs(300);

/// Unique temp dir with explicit cleanup (kept on failure for debugging).
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("svault-wave1-{tag}-{n}"));
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
    fn passfile(&self) -> PathBuf {
        let p = self.0.join("pass");
        std::fs::write(&p, PASS).unwrap();
        p
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        // N1 pin hygiene: trust for a dead socket must not leak into the next
        // test (pins live outside the temp dir, keyed by socket path).
        if let Ok(pin) = svault::broker_identity::pin_path(&self.sock()) {
            let _ = std::fs::remove_file(pin);
        }
    }
}

/// N1 pin bootstrap: the test acts as the human out-of-band channel (reads
/// the daemon's public key in-process — same-process stand-in for comparing
/// `trust show` output on the broker host) and writes the pin DIRECTLY,
/// never via argv. Non-interactive CLI contexts may reuse a pin but never
/// create one, so every `cli()` call below needs this after spawning the
/// daemon that serves it.
fn pin_bootstrap(dir: &Dir) {
    use std::process::{Command, Stdio};
    const BIN: &str = env!("CARGO_BIN_EXE_svault");
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
    let fp = svault::broker_identity::parse_fingerprint(&hex).unwrap();
    svault::broker_identity::store_pin(&dir.sock(), &fp).expect("pin bootstrap");
}

/// L3: token files are live capabilities — create them 0600, never with the
/// umask (0644 by default), and never world-readable.
fn write_token_0600(path: &std::path::Path, token: &str) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create token file");
    f.write_all(token.as_bytes()).expect("write token");
    f.sync_all().expect("sync token");
}

/// A spawned daemon that is killed when it goes out of scope, so a failing
/// assertion cannot leave a live broker behind (test hygiene, and the socket
/// lock would otherwise block the next run).
struct DaemonProc(Child);

impl DaemonProc {
    fn id(&self) -> u32 {
        self.0.id()
    }
    fn kill(&mut self) -> std::io::Result<()> {
        self.0.kill()
    }
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.0.wait()
    }
}

impl Drop for DaemonProc {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

/// Real `svault daemon` process on `dir`'s socket.
fn spawn_daemon(dir: &Dir) -> DaemonProc {
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
    wait_socket(&dir.sock(), &mut child);
    DaemonProc(child)
}

fn wait_socket(socket: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if UnixStream::connect(socket).is_ok() {
            return;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("daemon exited early with {status}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("daemon socket never became ready: {}", socket.display());
}

fn cli(dir: &Dir, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN)
        .arg("--socket")
        .arg(dir.sock())
        .arg("--file")
        .arg(dir.vault())
        .arg("--passphrase-file")
        .arg(dir.passfile())
        .args(args)
        .output()
        .expect("run cli");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn cli_with_stdin(dir: &Dir, args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut child = Command::new(BIN)
        .arg("--socket")
        .arg(dir.sock())
        .arg("--file")
        .arg(dir.vault())
        .arg("--passphrase-file")
        .arg(dir.passfile())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run cli with stdin");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{stdin}\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// C1 — rogue same-UID listener cannot capture the human proof
// ---------------------------------------------------------------------------

/// The attack: a same-UID process unlinks the broker's socket and binds its
/// own listener at the same path, then a human runs a privileged command.
/// The human proof must never reach the impostor.
#[test]
fn c1_rogue_same_uid_listener_never_receives_the_human_proof() {
    let dir = Dir::new("rogue");
    let mut daemon = spawn_daemon(&dir);
    pin_bootstrap(&dir);
    assert_eq!(cli(&dir, &["init"]).0, 0, "init through the real daemon");

    // The impostor: same UID, unlink + bind the same path, and it captures
    // whatever it receives.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let rogue_path = dir.sock();
    let rogue = std::thread::spawn(move || {
        let _ = std::fs::remove_file(&rogue_path);
        let listener = UnixListener::bind(&rogue_path).expect("rogue bind");
        if let Ok((mut c, _)) = listener.accept() {
            let mut buf = Vec::new();
            let mut r = BufReader::new(c.try_clone().unwrap());
            let _ = r.read_until(b'\n', &mut buf);
            let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
            let _ = c.write_all(
                br#"{"v":1,"id":"x","ok":false,"error":{"code":"E_AUTH","msg":"denied"}}"#,
            );
            let _ = c.write_all(b"\n");
        }
    });
    // Wait until the impostor owns the path.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !dir.sock().exists() {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(100));

    // A human runs a privileged command. It must fail rather than disclose.
    let (code, out, err) = cli(&dir, &["unlock"]);
    assert_ne!(code, 0, "rogue server must not be accepted: {out}{err}");
    assert!(
        !out.contains(PASS) && !err.contains(PASS),
        "the passphrase appeared in CLI output: {out}{err}"
    );

    let captured = rx.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
    assert!(
        !captured.contains(PASS),
        "C1 REGRESSION: a rogue same-UID listener received the human proof: {captured}"
    );
    assert!(
        !captured.contains("passphrase"),
        "C1 REGRESSION: a request carrying credentials reached the impostor: {captured}"
    );

    rogue.join().unwrap();
    let _ = daemon.kill();
}

/// The MCP adapter must inherit the same gate: it holds an agent token.
#[test]
fn c1_mcp_adapter_refuses_a_rogue_listener() {
    let dir = Dir::new("mcp-rogue");
    let token_file = dir.path().join("bot.token");
    write_token_0600(&token_file, "agent-token-secret-material");

    // Rogue listener bound where the adapter expects the broker.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let rogue_path = dir.sock();
    let listener = UnixListener::bind(&rogue_path).unwrap();
    std::thread::spawn(move || {
        if let Ok((mut c, _)) = listener.accept() {
            // Signal acceptance immediately, then capture anything sent.
            let _ = tx.send("ACCEPTED".to_string());
            let mut buf = Vec::new();
            let _ = BufReader::new(c.try_clone().unwrap()).read_until(b'\n', &mut buf);
            let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
            let _ = c.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n");
        }
    });

    let mut child = Command::new(BIN)
        .arg("--socket")
        .arg(dir.sock())
        .arg("--token-file")
        .arg(&token_file)
        .arg("mcp-serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    {
        let mut sin = child.stdin.take().unwrap();
        writeln!(
            sin,
            "{}",
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                   "params":{"name":"list_secrets","arguments":{"project":"acme"}}})
        )
        .unwrap();
        sin.flush().unwrap();
    }
    let mut out = String::new();
    let _ = BufReader::new(child.stdout.take().unwrap()).read_line(&mut out);
    let _ = child.kill();
    let _ = child.wait();

    let first = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    assert_eq!(
        first, "ACCEPTED",
        "test setup: the impostor must have accepted the adapter's connection"
    );
    let captured = rx.recv_timeout(Duration::from_secs(3)).unwrap_or_default();
    assert!(
        !captured.contains("agent-token-secret-material"),
        "C1 REGRESSION: the MCP adapter sent its token to an unverified server: {captured}"
    );
    assert!(
        captured.is_empty(),
        "C1 REGRESSION: the adapter wrote a request to an unverified server: {captured}"
    );
    assert!(
        out.contains("isError") || out.contains("E_PROTOCOL"),
        "the adapter must fail closed, got: {out}"
    );
}

/// A legitimate restart must work: after a clean shutdown the lock is free,
/// so the same socket path can be reused without manual cleanup.
#[test]
fn c1_restart_after_clean_shutdown_is_allowed() {
    let dir = Dir::new("restart");
    let mut first = spawn_daemon(&dir);
    pin_bootstrap(&dir);
    assert_eq!(cli(&dir, &["init"]).0, 0);
    first.kill().unwrap();
    first.wait().unwrap();

    // Process death releases the flock: a fresh daemon must start, and it must
    // be able to replace the socket file the dead one left behind.
    let mut second = spawn_daemon(&dir);
    let (code, out, err) = cli(&dir, &["status"]);
    assert_eq!(code, 0, "restart must serve: {out}{err}");
    assert!(out.contains("version:"));
    let _ = second.kill();
}

/// A concurrent second daemon must fail closed instead of taking over the
/// socket of the running one.
#[test]
fn c1_second_daemon_on_the_same_socket_is_refused() {
    let dir = Dir::new("excl");
    let mut first = spawn_daemon(&dir);
    pin_bootstrap(&dir);
    assert_eq!(cli(&dir, &["init"]).0, 0);
    let before = cli(&dir, &["status"]);
    assert_eq!(before.0, 0);

    // Second daemon, same socket path: must exit non-zero and must not have
    // removed the live socket.
    let out = Command::new(BIN)
        .arg("--socket")
        .arg(dir.sock())
        .arg("--file")
        .arg(dir.vault())
        .arg("daemon")
        .output()
        .unwrap();
    assert_ne!(
        out.status.code().unwrap_or(-1),
        0,
        "a second daemon must refuse to start on a live socket"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("too many concurrent operations") || err.contains("E_BUSY"),
        "expected E_BUSY, got: {err}"
    );

    // The first daemon still owns and serves the socket.
    let after = cli(&dir, &["status"]);
    assert_eq!(after.0, 0, "the running daemon must be unaffected");
    let _ = first.kill();
}

/// The mechanism itself, at the unit level: the lock holder is the peer, and
/// a listener without the lock is rejected.
#[test]
fn c1_server_identity_gate_accepts_only_the_lock_holder() {
    let dir = Dir::new("gate");
    let socket = dir.sock();
    let lock = InstanceLock::acquire(&socket).unwrap();
    assert_eq!(
        lock_holder_pid(lock.path()),
        Some(std::process::id() as i32)
    );

    let good = UnixListener::bind(&socket).unwrap();
    let c = UnixStream::connect(&socket).unwrap();
    let _a = good.accept().unwrap();
    assert!(
        verify_server(&c, &socket).is_ok(),
        "the lock holder verifies"
    );

    // Same process, same socket, but the lock is gone: refused.
    drop(lock);
    assert!(verify_server(&c, &socket).is_err());

    // A path with no instance lock at all: refused.
    let other = dir.path().join("other.sock");
    let l2 = UnixListener::bind(&other).unwrap();
    let c2 = UnixStream::connect(&other).unwrap();
    let _a2 = l2.accept().unwrap();
    assert!(verify_server(&c2, &other).is_err());

    // The lock path is a sibling of the socket, in the same private dir.
    assert_eq!(
        instance_lock_path(&socket),
        socket.with_extension("sock.lock")
    );
    let mode = std::fs::metadata(instance_lock_path(&socket))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "the lock file must be private");
}

// ---------------------------------------------------------------------------
// C2 — no readable core dump from the real daemon
// ---------------------------------------------------------------------------

/// The real daemon disables core generation: after a fatal signal there is no
/// dump, and the vault's plaintext is therefore not recoverable from disk.
#[test]
fn c2_fatal_signal_produces_no_readable_core() {
    let dir = Dir::new("core");
    let mut daemon = spawn_daemon(&dir);
    pin_bootstrap(&dir);
    assert_eq!(cli(&dir, &["init"]).0, 0);
    assert_eq!(cli(&dir, &["unlock"]).0, 0);
    assert_eq!(cli(&dir, &["project", "add", "acme"]).0, 0, "project add");
    let (code, _o, e) = cli_with_stdin(&dir, &["secret", "set", "acme", "K"], TRAP);
    assert_eq!(code, 0, "secret set: {e}");

    let pid = daemon.id() as i32;
    // The daemon must report a zero core limit and be non-dumpable.
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let core_line = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .expect("core limit line");
    // "Max core file size <soft> <hard> bytes"
    let fields: Vec<&str> = core_line.split_whitespace().collect();
    assert_eq!(
        (fields.get(4), fields.get(5)),
        (Some(&"0"), Some(&"0")),
        "C2 REGRESSION: core dumps are not disabled: {core_line}"
    );
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    assert!(
        status.lines().any(|l| l == "CoreDumping:\t0"),
        "CoreDumping must be 0"
    );

    // Ask the kernel to dump the process and prove nothing lands on disk.
    let cores_before = count_cores(pid);
    unsafe { libc::kill(pid, libc::SIGABRT) };
    let status = daemon.wait().unwrap();
    assert!(
        !status.success(),
        "the daemon should die from the signal, got {status:?}"
    );
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        count_cores(pid),
        cores_before,
        "C2 REGRESSION: a core dump exists for the daemon pid {pid}"
    );

    // Whatever core files exist for this pid must not contain the secret.
    for core in cores_for(pid) {
        let bytes = std::fs::read(&core).unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains(TRAP),
            "C2 REGRESSION: secret recovered from {}",
            core.display()
        );
    }
}

/// Count coredump entries coredumpctl knows about for a pid.
fn count_cores(pid: i32) -> usize {
    cores_for(pid).len()
}

fn cores_for(pid: i32) -> Vec<PathBuf> {
    let mut out = Vec::new();
    // systemd-coredump store
    if let Ok(rd) = std::fs::read_dir("/var/lib/systemd/coredump") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.contains(&format!(".{pid}.")) || name.ends_with(&format!(".{pid}")) {
                out.push(e.path());
            }
        }
    }
    // core_pattern files in the cwd
    if let Ok(rd) = std::fs::read_dir(std::env::temp_dir()) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("core") && name.contains(&pid.to_string()) {
                out.push(e.path());
            }
        }
    }
    out
}

// C3 (write-failure handling) lives in `tests/wave1_write_failure.rs`: it
// changes RLIMIT_FSIZE process-wide, and spawned children inherit it, so it
// must not share a test binary with anything else.

// ---------------------------------------------------------------------------
// C4 — the commit never produces a vault the loader rejects
// ---------------------------------------------------------------------------

/// A mutation whose result would exceed `MAX_FILE_LEN` must fail before the
/// commit, leaving the previous vault valid and loadable — the pre-fix code
/// wrote an unopenable file.
///
/// The vault is pre-grown to just under the cap *without* going through
/// `secret_set` (which re-seals the whole document per call and would make
/// this quadratic); the mutation under test is then a single real
/// `secret_set`, so the property exercised is exactly the production one.
#[test]
fn c4_oversize_commit_is_refused_and_previous_vault_stays_valid() {
    use svault::envelope::{Envelope, MAX_FILE_LEN};
    use svault::session::Session;

    let dir = Dir::new("size");
    let vault = dir.vault();
    let mut s = Session::create(
        &vault,
        PASS.as_bytes(),
        IDLE,
        Box::new(svault::session::SystemClock),
    )
    .unwrap();
    s.project_add("human", "acme", &[]).unwrap();
    s.secret_set("human", "acme", "KEEP", b"previous-value")
        .unwrap();
    drop(s);

    // Grow the sealed document to just under the cap, keeping the audit
    // checkpoint intact so the vault stays unlockable.
    let passphrase = PASS.as_bytes();
    let bytes = std::fs::read(&vault).unwrap();
    let mut env = Envelope::parse(&bytes).unwrap();
    let keys = env.unlock(passphrase).unwrap();
    let mut doc_bytes = env.open_document(&keys).unwrap();
    let mut doc: svault::model::VaultDocument = serde_json::from_slice(&doc_bytes).unwrap();
    zeroize::Zeroize::zeroize(&mut doc_bytes);
    let checkpoint = doc.audit_head.clone();

    let project_id = doc.project_by_name("acme").unwrap().id.clone();
    // Grow to the largest document that still validates: add a 64 KiB value
    // (the documented maximum) step by step and keep it only while the
    // resulting file would still be persistable. That leaves less headroom
    // than one further value, which is exactly the boundary under test.
    let value = vec![b'A'; 64 * 1024];
    let now = time::OffsetDateTime::now_utc();
    let mut n = 0usize;
    loop {
        doc.secrets.push(svault::model::Secret {
            project_id: project_id.clone(),
            key: format!("FILL{n:05}"),
            value: svault::envelope::B64(zeroize::Zeroizing::new(value.clone())),
            created_at: now,
            updated_at: now,
        });
        let probe = serde_json::to_vec(&doc).unwrap();
        let projected = 14 + probe.len() + 24 + 16;
        if projected > MAX_FILE_LEN {
            doc.secrets.pop();
            break;
        }
        n += 1;
        assert!(n < 500, "did not approach the cap");
    }
    assert!(
        n > 100,
        "expected a substantially filled vault, got {n} secrets"
    );
    doc.audit_head = checkpoint;
    let mut grown = serde_json::to_vec(&doc).unwrap();
    env.reseal_document(&grown, &keys).unwrap();
    zeroize::Zeroize::zeroize(&mut grown);
    env.validate_persistable()
        .expect("the grown vault must still be under the cap");
    let before = env.to_bytes();
    assert!(
        before.len() < MAX_FILE_LEN,
        "setup produced {} bytes (cap {MAX_FILE_LEN})",
        before.len()
    );
    std::fs::write(&vault, &before).unwrap();

    // Sanity: the pre-grown vault opens.
    let mut reopened = Session::load(&vault, IDLE, Box::new(svault::session::SystemClock)).unwrap();
    reopened.unlock(passphrase).unwrap();
    assert!(
        reopened.document().unwrap().secrets.len() > n / 2,
        "fill present"
    );
    drop(reopened);

    // One more real mutation of a 64 KiB value must push it past the cap.
    let mut s = Session::load(&vault, IDLE, Box::new(svault::session::SystemClock)).unwrap();
    s.unlock(passphrase).unwrap();
    let err = s
        .secret_set("human", "acme", "ONEMORE", &value)
        .expect_err("crossing the cap must be refused");
    assert_eq!(
        err.code(),
        "E_VAULT_TOO_LARGE",
        "expected the size refusal, got {err}"
    );
    drop(s);

    // The refusal happened before the commit: the file is byte-identical to
    // the pre-mutation state and still reloadable.
    let after = std::fs::read(&vault).unwrap();
    assert_eq!(
        after, before,
        "C4 REGRESSION: the refused mutation modified the vault on disk"
    );
    assert!(
        after.len() < MAX_FILE_LEN,
        "the stored vault must stay under the cap"
    );
    let mut reloaded = Session::load(&vault, IDLE, Box::new(svault::session::SystemClock)).unwrap();
    reloaded.unlock(passphrase).unwrap();
    let doc = reloaded.document().unwrap();
    assert!(
        doc.secrets.iter().any(|s| s.key == "KEEP"),
        "the pre-existing secret must survive"
    );
    assert_eq!(
        doc.secrets
            .iter()
            .find(|s| s.key == "KEEP")
            .unwrap()
            .value
            .0
            .as_slice(),
        b"previous-value",
        "the pre-existing value must be unchanged"
    );
    assert!(
        !doc.secrets.iter().any(|s| s.key == "ONEMORE"),
        "the refused secret must not be present"
    );
}

/// The envelope's own guard: a synthetic document past the cap is refused by
/// `validate_persistable` using exactly the constants the parser enforces.
#[test]
fn c4_envelope_guard_and_parser_agree_on_the_cap() {
    let now = time::OffsetDateTime::now_utc();
    let small = svault::envelope::Envelope::create(PASS.as_bytes(), b"{}", now).unwrap();
    assert!(small.validate_persistable().is_ok());

    // A document that pushes the file over MAX_FILE_LEN.
    let big = vec![b'A'; svault::envelope::MAX_FILE_LEN + 1024];
    let env = svault::envelope::Envelope::create(PASS.as_bytes(), &big, now).unwrap();
    assert_eq!(
        env.validate_persistable().map_err(|e| e.code()),
        Err("E_VAULT_TOO_LARGE"),
        "an oversize envelope must be refused before it is written"
    );
    // And the parser agrees: this is exactly what it would reject.
    let bytes = env.to_bytes();
    assert!(matches!(
        svault::envelope::Envelope::parse(&bytes),
        Err(svault::VaultError::Corrupt(_))
    ));
}
