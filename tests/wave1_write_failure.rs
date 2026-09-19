//! C3 (audit finding) — a failing `write(2)` must be an error, never an
//! infinite loop.
//!
//! Lives in its own test binary because it imposes `RLIMIT_FSIZE` on the
//! daemon it spawns; keeping it isolated avoids any interaction with the
//! other adversarial suites.
//!
//! Pre-fix behaviour (reproduced): `written += write(...).max(0)` turned
//! `-1` into `0`, so the loop never advanced. Because `inject_file` runs
//! under the daemon-wide session mutex, the whole broker wedged at 100% CPU —
//! `vault.status`, `audit verify`, and even `vault.lock` (which would drop the
//! key material) stopped answering, and the temp file was left behind.
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;
use svault::session::{Session, SystemClock};

const PASS: &[u8] = b"correct horse battery";
const BIN: &str = env!("CARGO_BIN_EXE_svault");
const IDLE: Duration = Duration::from_secs(300);
/// `ulimit -f` counts 512-byte blocks: 64 blocks = 32 KiB. Larger than the
/// daemon's audit growth for this scenario (vault.created + unlock serve +
/// `vault.unlocked` Lifecycle + the session.seed `session.open` + pin files),
/// far smaller than the ~60 KiB dotenv file the agent asks for.
// ponytail: file-size calibration for the failing-write rig; raise if the daemon's
// steady-state audit/pin growth approaches this ceiling.
const FSIZE_LIMIT_BLOCKS: u32 = 64;

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("svault-c3-{tag}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        // N1 pin hygiene: trust for a dead socket must not leak across tests.
        let sock = self.0.join("svault.sock");
        if let Ok(pin) = svault::broker_identity::pin_path(&sock) {
            let _ = std::fs::remove_file(pin);
        }
    }
}

/// N1 pin bootstrap: act as the human out-of-band channel (`trust show` →
/// compare → write pin directly, never via argv). Non-interactive CLI
/// contexts reuse pins but never create them.
fn pin_bootstrap(socket: &Path, vault: &Path) {
    use std::process::Stdio;
    let out = Command::new(BIN)
        .arg("--socket")
        .arg(socket)
        .arg("--file")
        .arg(vault)
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
    // Pin hygiene: a stale pin for this path must not survive across tests.
    if let Ok(pin) = svault::broker_identity::pin_path(socket) {
        let _ = std::fs::remove_file(pin);
    }
    let fp = svault::broker_identity::parse_fingerprint(&hex).unwrap();
    svault::broker_identity::store_pin(socket, &fp).expect("pin bootstrap");
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

/// One raw wire request, bounded: returns `None` if nothing arrives in time.
/// Used as the liveness probe — any response proves the daemon is not wedged.
fn probe(socket: &Path, op: &str, auth: Option<(&str, &str)>) -> Option<serde_json::Value> {
    let mut s = UnixStream::connect(socket).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let auth = match auth {
        None => json!(null),
        Some((k, v)) => json!({k: v}),
    };
    let req = json!({"v":1,"id":"probe","op":op,"auth":auth,"params":{}});
    s.write_all(format!("{req}\n").as_bytes()).ok()?;
    let mut line = String::new();
    BufReader::new(&s).read_line(&mut line).ok()?;
    if line.trim().is_empty() {
        return None;
    }
    serde_json::from_str(line.trim()).ok()
}

#[test]
fn c3_write_failure_errors_cleanly_and_daemon_keeps_serving() {
    let dir = Dir::new("efbig");
    let authorized = dir.path().join("authorized");
    std::fs::create_dir_all(&authorized).unwrap();
    let dest = authorized.join(".env");
    std::fs::write(&dest, b"SENTINEL=untouched\n").unwrap();
    let vault = dir.path().join("vault.enc");
    let socket = dir.path().join("svault.sock");
    let passfile = dir.path().join("pass");
    std::fs::write(&passfile, PASS).unwrap();

    // Build the vault with ONE large secret (the documented 64 KiB maximum),
    // so the injected dotenv file is far larger than the file-size limit that
    // is about to be imposed on the daemon.
    let big_value = vec![b'V'; 60 * 1024];
    let (agent_id, token) = {
        let mut s = Session::create(&vault, PASS, IDLE, Box::new(SystemClock)).unwrap();
        s.project_add("human", "acme", std::slice::from_ref(&authorized))
            .unwrap();
        s.secret_set("human", "acme", "BIG", &big_value).unwrap();
        let (id, tok) = s.agent_add("human", "bot").unwrap();
        s.grant_add("human", "bot", "acme", &[svault::model::Op::Inject])
            .unwrap();
        (id, tok)
    };
    assert!(!agent_id.is_empty());
    let token_file = dir.path().join("bot.token");
    write_token_0600(&token_file, &token);

    // Spawn the daemon with RLIMIT_FSIZE set before it serves. The limit makes
    // write(2) fail with EFBIG partway through the dotenv publication.
    let script = format!(
        "ulimit -f {FSIZE_LIMIT_BLOCKS}; exec '{BIN}' --socket '{}' --file '{}' daemon",
        socket.display(),
        vault.display()
    );
    let mut daemon = Command::new("/bin/sh")
        .arg("-c")
        .arg(&script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn limited daemon");
    wait_socket(&socket, &mut daemon);
    pin_bootstrap(&socket, &vault);

    // The limit really is in force for the daemon we will exercise.
    let limits = std::fs::read_to_string(format!("/proc/{}/limits", daemon.id())).unwrap();
    let core = limits
        .lines()
        .find(|l| l.starts_with("Max file size"))
        .expect("a file-size limit line");
    let fields: Vec<&str> = core.split_whitespace().collect();
    assert_eq!(
        fields.get(4),
        Some(&"32768"),
        "the test requires the limit to be applied: {core}"
    );

    // Unlock: agent digests are rebuilt at unlock, and the vault must be
    // unlocked for `inject_file` to be authorized at all.
    let unlock = Command::new(BIN)
        .arg("--socket")
        .arg(&socket)
        .arg("--file")
        .arg(&vault)
        .arg("--passphrase-file")
        .arg(&passfile)
        .arg("unlock")
        .output()
        .expect("unlock");
    assert_eq!(
        unlock.status.code().unwrap_or(-1),
        0,
        "unlock must succeed: {}",
        String::from_utf8_lossy(&unlock.stderr)
    );

    // The agent asks for an injection that cannot fit.
    let started = Instant::now();
    let mut child = Command::new(BIN)
        .arg("--socket")
        .arg(&socket)
        .arg("--file")
        .arg(&vault)
        .arg("--token-file")
        .arg(&token_file)
        .arg("inject")
        .arg("acme")
        .arg(".env")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn inject");

    // Bounded wait: the pre-fix daemon never answers at all.
    let mut finished = false;
    for _ in 0..300 {
        if child.try_wait().unwrap().is_some() {
            finished = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if !finished {
        let _ = child.kill();
        let _ = daemon.kill();
        let _ = daemon.wait();
        panic!(
            "C3 REGRESSION: inject_file returned no error within 6s under a write failure — \
             writes spin forever and the daemon is wedged at 100% CPU"
        );
    }
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_ne!(
        out.status.code().unwrap_or(-1),
        0,
        "the injection must fail: {err}"
    );
    assert!(
        err.contains("too large") || err.contains("File too large") || err.contains("E_IO"),
        "the OS write error must surface to the caller, got: {err}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "C3: the failure must be prompt, took {:?}",
        started.elapsed()
    );

    // The previous destination is byte-for-byte intact.
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        b"SENTINEL=untouched\n",
        "the previously injected file must be untouched by the failed write"
    );

    // No temp-file residue in the authorized folder.
    let residue: Vec<String> = std::fs::read_dir(&authorized)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert!(
        residue.is_empty(),
        "C3 REGRESSION: the failed write left temp files behind: {residue:?}"
    );

    // The daemon still answers: the session mutex was not lost to a spin.
    let resp = probe(&socket, "vault.status", None);
    assert!(
        resp.is_some(),
        "C3 REGRESSION: the daemon stopped answering every request (mutex wedged)"
    );

    // And a privileged request still works, so the whole pipeline is intact.
    let status = Command::new(BIN)
        .arg("--socket")
        .arg(&socket)
        .arg("--file")
        .arg(&vault)
        .arg("--passphrase-file")
        .arg(&passfile)
        .arg("project")
        .arg("list")
        .output()
        .unwrap();
    assert_eq!(
        status.status.code().unwrap_or(-1),
        0,
        "a human operation must still succeed after the failure: {}",
        String::from_utf8_lossy(&status.stderr)
    );

    let _ = daemon.kill();
}
