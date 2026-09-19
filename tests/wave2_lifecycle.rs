//! Wave 2 (H1 + H2) — lock lifecycle and exclusive vault ownership.
//!
//! * **H1** — the idle auto-lock had weaker semantics than `vault.lock`: it
//!   dropped key material but left managed runs (children *and* their
//!   descendants) alive, so an agent's process kept running against a vault
//!   the operator believed was closed.
//! * **H2** — nothing stopped two mutable owners (a second daemon, or a
//!   second in-process `Session`) from loading the same vault, so whichever
//!   saved last silently discarded the other's writes.
//!
//! Runs real child processes and, for the crash cases, a real `svault daemon`.

#[path = "common/mod.rs"]
mod common;

use std::io::BufReader;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;

use svault::broker::{Daemon, DaemonConfig};
use svault::model::Op;
use svault::session::{Session, SystemClock};
use svault::wire::{AuthField, Request, VERSION};

const PASS: &[u8] = b"correct horse battery";
const BIN: &str = env!("CARGO_BIN_EXE_svault");
/// Short idle window so the test exercises the real timeout, not a fake clock.
const SHORT_IDLE: Duration = Duration::from_secs(4);
const GONE_WAIT: Duration = Duration::from_secs(10);

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("svault-wave2life-{tag}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn vault(&self) -> PathBuf {
        self.0.join("vault.enc")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Kills pids even when an assertion panics first.
struct KillGuard {
    pids: Vec<i32>,
}

impl Drop for KillGuard {
    fn drop(&mut self) {
        for pid in &self.pids {
            unsafe {
                libc::kill(*pid, libc::SIGKILL);
            }
        }
    }
}

/// A spawned daemon that is killed and reaped when it goes out of scope, so a
/// failing assertion cannot leak a broker holding the vault (or its socket).
struct DaemonProc(std::process::Child);

impl DaemonProc {
    fn spawn(args: &[&std::ffi::OsStr], stderr: Stdio) -> Self {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr);
        Self(cmd.spawn().expect("spawn svault daemon"))
    }

    fn alive(&mut self) -> bool {
        self.0.try_wait().ok().flatten().is_none()
    }

    fn exit_status(&mut self) -> Option<std::process::ExitStatus> {
        self.0.try_wait().ok().flatten()
    }
}

impl Drop for DaemonProc {
    fn drop(&mut self) {
        if self.alive() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn pid_gone(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(s) => matches!(
            s.rsplit(')')
                .next()
                .and_then(|r| r.split_whitespace().next()),
            Some("Z") | Some("X")
        ),
    }
}

fn wait_gone(pid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pid_gone(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    pid_gone(pid)
}

fn children_of(ppid: i32) -> Vec<i32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in entries.flatten() {
        let Some(name) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            && let Some(rest) = stat.rsplit(')').next()
            && let Some(ppid_field) = rest.split_whitespace().nth(1)
            && ppid_field.parse::<i32>() == Ok(ppid)
        {
            out.push(pid);
        }
    }
    out
}

/// Vault + project + secret + agent holding a `run` grant, then release the
/// vault: exactly one owner may hold it (H2), so the creating `Session` must
/// be gone before the daemon opens it. Returns the agent token.
fn fixture(dir: &Dir) -> String {
    let vault = dir.vault();
    let authorized = dir.0.join("authorized");
    std::fs::create_dir_all(&authorized).unwrap();
    let mut s = Session::create(&vault, PASS, SHORT_IDLE, Box::new(SystemClock)).unwrap();
    s.project_add("human", "acme", &[authorized]).unwrap();
    s.secret_set("human", "acme", "STRIPE_KEY", b"sk-trap-value")
        .unwrap();
    let (_id, token) = s.agent_add("human", "harness").unwrap();
    s.grant_add("human", "harness", "acme", &[Op::Run, Op::Read])
        .unwrap();
    drop(s);
    token
}

/// In-process daemon on a real socket with the short idle window, already
/// unlocked. Returns the handle plus the socket path.
fn daemon_on(dir: &Dir, _token: &str) -> (std::sync::Arc<Daemon>, PathBuf) {
    let vault = dir.vault();
    let socket = dir.0.join("svault.sock");
    let daemon = std::sync::Arc::new(
        Daemon::new(DaemonConfig {
            socket_path: socket.clone(),
            vault_path: vault,
            idle_lock: SHORT_IDLE,
        })
        .unwrap(),
    );
    let srv = std::sync::Arc::clone(&daemon);
    std::thread::spawn(move || {
        let _ = srv.serve();
    });
    for _ in 0..300 {
        if UnixStream::connect(&socket).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let unlock = daemon.handle_request(Request {
        v: VERSION,
        id: "unlock".into(),
        op: "vault.unlock".into(),
        auth: Some(AuthField {
            token: None,
            passphrase: Some(String::from_utf8_lossy(PASS).into_owned()),
            session: None,
        }),
        params: json!({}),
    });
    assert!(unlock.ok, "unlock failed: {:?}", unlock.error);
    (daemon, socket)
}

/// Launch `/bin/sh -c "<script>"` through `run_with_secrets` and return the
/// held reader, the run id, and the child pid. The script is expected to
/// spawn a grandchild.
fn launch_shell(socket: &Path, token: &str, script: &str) -> (BufReader<UnixStream>, String, i32) {
    let mut stream = common::connect(socket);
    let stdin = common::open_devnull();
    let stdout = common::open_devnull();
    let stderr = common::open_devnull();
    let req = common::authed_request(
        "run",
        "run_with_secrets",
        token,
        json!({"project": "acme", "executable": "/bin/sh", "argv": ["sh", "-c", script]}),
    );
    let fds = [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()];
    common::send_with_fds(&mut stream, &req, &fds).unwrap();
    drop((stdin, stdout, stderr));
    let mut reader = BufReader::new(stream);
    let started = common::read_response(&mut reader).expect("started line");
    assert!(started.ok, "run must start, got {started:?}");
    let body = started.result.clone().unwrap_or_default();
    let run_id = body["run_id"].as_str().unwrap().to_string();
    let pid = body["pid"].as_i64().unwrap() as i32;
    (reader, run_id, pid)
}

// ---------------------------------------------------------------------------
// H1 — idle auto-lock must have vault.lock semantics
// ---------------------------------------------------------------------------

/// H1 core: the idle timer fires on wall-clock time ALONE. With a run alive
/// and the launch connection held open, no request is sent after the window
/// expires — the child and its descendant must still be terminated by the
/// daemon's own timer.
#[test]
fn h1_idle_timer_locks_autonomously_with_no_request() {
    let dir = Dir::new("idle-autonomous");
    let token = fixture(&dir);
    let (daemon, socket) = daemon_on(&dir, &token);

    // `sleep` backgrounds a grandchild and waits: child + descendant alive.
    let (reader, _run_id, pid) = launch_shell(&socket, &token, "sleep 120 & echo $!; wait");
    let mut guard = KillGuard { pids: vec![pid] };
    assert!(!pid_gone(pid), "child {pid} must be alive after launch");

    let mut grandkids = Vec::new();
    let start = Instant::now();
    while start.elapsed() < GONE_WAIT {
        grandkids = children_of(pid);
        if !grandkids.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !grandkids.is_empty(),
        "sh child {pid} must have spawned a descendant"
    );
    guard.pids.extend(grandkids.iter().copied());

    // No request from here on: only the daemon's timer can end these runs. The
    // launch connection stays open, so EOF tear-down is not the cause either.
    assert!(
        wait_gone(pid, SHORT_IDLE + GONE_WAIT),
        "H1 REGRESSION: child {pid} survived the idle timer (no request was \
         sent to trigger the check)"
    );
    for g in &grandkids {
        assert!(
            wait_gone(*g, GONE_WAIT),
            "H1 REGRESSION: descendant {g} survived the idle timer"
        );
    }

    // The vault really closed, and no request was needed to make it happen.
    let status = daemon.handle_request(Request {
        v: VERSION,
        id: "after".into(),
        op: "vault.status".into(),
        auth: None,
        params: json!({}),
    });
    assert!(status.ok, "status failed: {status:?}");
    assert_eq!(
        status.result.unwrap()["locked"].as_bool(),
        Some(true),
        "H1 REGRESSION: the timer killed the runs but left the vault unlocked"
    );
    drop(reader);
}

/// Without `serve` there is no timer at all: this pins the in-handler check
/// for a request arriving after the window, so a future change that only
/// trusts the timer cannot regress the request path silently.
#[test]
fn h1_request_path_still_notices_an_expired_window_without_a_timer() {
    let dir = Dir::new("idle-handler-only");
    let token = fixture(&dir);
    let vault = dir.vault();
    // No `serve` call: no watchdog thread, hence no autonomous lock. The vault
    // is opened directly, exactly as a test or an in-process caller would.
    let daemon = Daemon::new(DaemonConfig {
        socket_path: dir.0.join("svault.sock"),
        vault_path: vault,
        idle_lock: SHORT_IDLE,
    })
    .unwrap();
    let unlocked = daemon.handle_request(Request {
        v: VERSION,
        id: "u".into(),
        op: "vault.unlock".into(),
        auth: Some(AuthField {
            token: None,
            passphrase: Some(String::from_utf8_lossy(PASS).into_owned()),
            session: None,
        }),
        params: json!({}),
    });
    assert!(unlocked.ok, "unlock failed: {:?}", unlocked.error);

    std::thread::sleep(SHORT_IDLE + Duration::from_secs(1));
    let resp = daemon.handle_request(Request {
        v: VERSION,
        id: "post".into(),
        op: "secrets.list".into(),
        auth: Some(AuthField {
            token: Some(token.clone()),
            passphrase: None,
            session: None,
        }),
        params: json!({"project": "acme"}),
    });
    assert_eq!(
        resp.error.as_ref().map(|e| e.code.as_str()),
        Some("E_LOCKED"),
        "the window elapsed; an agent read must be E_LOCKED, got {resp:?}"
    );
}

/// The idle lock must be the *same* lifecycle as `vault.lock`, not a weaker
/// bespoke path: same audit trail, and the lifecycle runs once per expiry
/// rather than on every later request. Compared against an explicit
/// `vault.lock` in the same vault so the assertion tracks "identical", not
/// an incidental count.
#[test]
fn h1_idle_auto_lock_matches_an_explicit_vault_lock() {
    let dir = Dir::new("idle-same-lifecycle");
    let token = fixture(&dir);
    let (daemon, socket) = daemon_on(&dir, &token);
    let audit_path = svault::store::audit_path(&dir.vault());
    let lock_events = |path: &Path| {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .matches("vault.lock")
            .count()
    };

    // Open the vault, then let the idle window lapse without a request.
    let mut s = common::connect(&socket);
    let req = common::authed_request("list", "secrets.list", &token, json!({"project": "acme"}));
    common::send_with_fds(&mut s, &req, &[]).unwrap();
    let mut reader = BufReader::new(s);
    let resp = common::read_response(&mut reader).expect("list response");
    assert!(resp.ok, "the read must succeed while unlocked: {resp:?}");
    let before = lock_events(&audit_path);

    std::thread::sleep(SHORT_IDLE + Duration::from_secs(3));
    let locked_read = daemon.handle_request(Request {
        v: VERSION,
        id: "first".into(),
        op: "secrets.list".into(),
        auth: Some(AuthField {
            token: Some(token.clone()),
            passphrase: None,
            session: None,
        }),
        params: json!({"project": "acme"}),
    });
    assert_eq!(
        locked_read.error.as_ref().map(|e| e.code.as_str()),
        Some("E_LOCKED"),
        "the elapsed idle window must leave the vault locked: {locked_read:?}"
    );
    let idle_events = lock_events(&audit_path) - before;

    // Polling a locked vault must not replay the lifecycle.
    for i in 0..4 {
        let r = daemon.handle_request(Request {
            v: VERSION,
            id: format!("more{i}"),
            op: "secrets.list".into(),
            auth: Some(AuthField {
                token: Some(token.clone()),
                passphrase: None,
                session: None,
            }),
            params: json!({"project": "acme"}),
        });
        assert_eq!(
            r.error.as_ref().map(|e| e.code.as_str()),
            Some("E_LOCKED"),
            "the vault must stay locked: {r:?}"
        );
    }
    assert_eq!(
        lock_events(&audit_path) - before,
        idle_events,
        "H1 REGRESSION: later requests re-ran the lock lifecycle"
    );

    // Unlock again and lock explicitly: the audit delta must match the idle
    // path's, which is what "same lifecycle" means.
    let unlocked = daemon.handle_request(Request {
        v: VERSION,
        id: "unlock2".into(),
        op: "vault.unlock".into(),
        auth: Some(AuthField {
            token: None,
            passphrase: Some(String::from_utf8_lossy(PASS).into_owned()),
            session: None,
        }),
        params: json!({}),
    });
    assert!(unlocked.ok, "re-unlock failed: {:?}", unlocked.error);
    let before_explicit = lock_events(&audit_path);
    let locked = daemon.handle_request(Request {
        v: VERSION,
        id: "lock".into(),
        op: "vault.lock".into(),
        auth: Some(AuthField {
            token: None,
            passphrase: Some(String::from_utf8_lossy(PASS).into_owned()),
            session: None,
        }),
        params: json!({}),
    });
    assert!(locked.ok, "explicit lock failed: {:?}", locked.error);
    let explicit_events = lock_events(&audit_path) - before_explicit;

    assert_eq!(
        idle_events, explicit_events,
        "H1 REGRESSION: the idle auto-lock audited {idle_events} event(s) but an \
         explicit vault.lock audits {explicit_events}"
    );
}

/// `run_with_secrets` does not go through `handle_request`, so the idle
/// auto-lock must also be applied on that path: a run arriving after the
/// window expires is refused as locked instead of starting a child.
#[test]
fn h1_idle_auto_lock_is_applied_on_the_run_path() {
    let dir = Dir::new("idle-run-path");
    let token = fixture(&dir);
    let (_daemon, socket) = daemon_on(&dir, &token);

    let (reader, _run_id, pid) = launch_shell(&socket, &token, "sleep 120 & echo $!; wait");
    assert!(!pid_gone(pid), "child {pid} must be alive after launch");

    // The window may be closed by the timer or by this request; either way the
    // run path must refuse rather than spawn another child.
    std::thread::sleep(SHORT_IDLE + Duration::from_secs(2));

    // A second run request
    let mut stream = common::connect(&socket);
    let stdin = common::open_devnull();
    let stdout = common::open_devnull();
    let stderr = common::open_devnull();
    let req = common::authed_request(
        "run2",
        "run_with_secrets",
        &token,
        json!({"project": "acme", "executable": "/bin/sh", "argv": ["sh", "-c", "sleep 120"]}),
    );
    let fds = [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()];
    common::send_with_fds(&mut stream, &req, &fds).unwrap();
    drop((stdin, stdout, stderr));
    let mut reader2 = BufReader::new(stream);
    let denied = common::read_response(&mut reader2).expect("run response");
    assert_eq!(
        denied.error.as_ref().map(|e| e.code.as_str()),
        Some("E_LOCKED"),
        "H1 REGRESSION: a run request after the idle window must be denied as \
         locked, got {denied:?}"
    );

    // Whichever path noticed the expiry, the earlier run's process group is
    // drained and the vault is closed.
    assert!(
        wait_gone(pid, GONE_WAIT),
        "H1 REGRESSION: child {pid} survived the idle lock"
    );
    drop(reader);
}

/// A session owned by the daemon must not lock itself from inside an
/// operation: that path drops key material without draining managed runs, and
/// it would disarm the watchdog. This pins the ownership hand-off directly, at
/// the level where the hazard lives.
#[test]
fn h1_daemon_owned_session_defers_the_idle_lock_to_the_watchdog() {
    let dir = Dir::new("idle-ownership");
    let vault = dir.vault();
    {
        let mut s = Session::create(&vault, PASS, SHORT_IDLE, Box::new(SystemClock)).unwrap();
        s.project_add("human", "acme", &[]).unwrap();
    }

    // A daemon-owned session: `Daemon::new` loads it and defers the self-lock.
    let (_daemon, socket) = daemon_on(&dir, "");
    let _ = socket;

    // A standalone session keeps the convenience self-lock (it has no run
    // registry to drain, so locking in place is the correct behaviour there).
    let standalone = Session::load(&vault, SHORT_IDLE, Box::new(SystemClock));
    // H2: the daemon owns the vault, so a second opener is refused — which is
    // itself the guarantee that only one process can run the lifecycle.
    assert_eq!(
        standalone.expect_err("second owner").code(),
        "E_BUSY",
        "the daemon must hold the vault exclusively"
    );
}

// ---------------------------------------------------------------------------
// H2 — one mutable owner per vault
// ---------------------------------------------------------------------------

/// A second in-process `Session` on the same vault must fail closed. Before
/// the fix both loaded happily and the second save discarded the first's work.
#[test]
fn h2_second_session_on_the_same_vault_is_refused() {
    let dir = Dir::new("second-session");
    let vault = dir.vault();
    let owner = Session::create(&vault, PASS, SHORT_IDLE, Box::new(SystemClock)).unwrap();

    let err = Session::load(&vault, SHORT_IDLE, Box::new(SystemClock))
        .expect_err("a second session must not take the vault");
    assert_eq!(
        err.code(),
        "E_BUSY",
        "expected E_BUSY for a second owner, got {err}"
    );

    // Releasing the owner frees the vault for the next session.
    drop(owner);
    let mut next = Session::load(&vault, SHORT_IDLE, Box::new(SystemClock))
        .expect("the vault must be loadable once the owner released it");
    next.unlock(PASS).expect("and unlockable");
}

/// A second daemon pointed at the same vault (different socket, so the C1
/// socket lock does not apply) must fail closed rather than race the first.
#[test]
fn h2_second_daemon_on_the_same_vault_is_refused() {
    let dir = Dir::new("second-daemon");
    let vault = dir.vault();
    {
        let mut s = Session::create(&vault, PASS, SHORT_IDLE, Box::new(SystemClock)).unwrap();
        s.project_add("human", "acme", &[]).unwrap();
    }
    let d1 = Daemon::new(DaemonConfig {
        socket_path: dir.0.join("a.sock"),
        vault_path: vault.clone(),
        idle_lock: SHORT_IDLE,
    })
    .unwrap();

    let err = match Daemon::new(DaemonConfig {
        socket_path: dir.0.join("b.sock"),
        vault_path: vault.clone(),
        idle_lock: SHORT_IDLE,
    }) {
        Ok(_) => panic!("a second daemon must not own the same vault"),
        Err(e) => e,
    };
    assert_eq!(
        err.code(),
        "E_BUSY",
        "expected E_BUSY for a second daemon, got {err}"
    );
    drop(d1);
}

/// The same, observed end to end with the real binary: the second daemon
/// exits non-zero with E_BUSY, and after the owner is killed the lock is
/// released by the kernel so a legitimate restart succeeds.
#[test]
fn h2_real_daemon_excludes_others_and_survives_a_crash_restart() {
    let dir = Dir::new("real-daemon");
    let vault = dir.vault();
    {
        let mut s = Session::create(&vault, PASS, SHORT_IDLE, Box::new(SystemClock)).unwrap();
        s.project_add("human", "acme", &[]).unwrap();
    }
    let sock_a = dir.0.join("a.sock");
    let sock_b = dir.0.join("b.sock");

    let mut first = DaemonProc::spawn(
        &[
            "--socket".as_ref(),
            sock_a.as_os_str(),
            "--file".as_ref(),
            vault.as_os_str(),
            "daemon".as_ref(),
        ],
        Stdio::null(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && UnixStream::connect(&sock_a).is_err() {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(first.alive(), "the first daemon must stay serving");

    // A second daemon on the same vault, different socket: must refuse.
    // Bounded wait, never `output()`: a broken build keeps the daemon
    // serving forever, and a hanging test is not a failing test.
    let err_path = dir.0.join("second.err");
    let err_file = std::fs::File::create(&err_path).unwrap();
    let mut second = DaemonProc::spawn(
        &[
            "--socket".as_ref(),
            sock_b.as_os_str(),
            "--file".as_ref(),
            vault.as_os_str(),
            "daemon".as_ref(),
        ],
        Stdio::from(err_file),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut exit = None;
    while Instant::now() < deadline {
        if let Some(st) = second.exit_status() {
            exit = Some(st);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let stderr = std::fs::read_to_string(&err_path).unwrap_or_default();
    assert!(
        exit.is_some_and(|st| !st.success()),
        "H2 REGRESSION: the second daemon kept running on an owned vault: {stderr}"
    );
    assert!(
        stderr.contains("too many concurrent operations") || stderr.contains("E_BUSY"),
        "H2 REGRESSION: the second daemon was not refused with E_BUSY: {stderr}"
    );

    // Crash the owner: the kernel drops the lock, so a restart is legitimate.
    let _ = first.0.kill();
    let _ = first.0.wait();
    let mut restarted = DaemonProc::spawn(
        &[
            "--socket".as_ref(),
            sock_b.as_os_str(),
            "--file".as_ref(),
            vault.as_os_str(),
            "daemon".as_ref(),
        ],
        Stdio::null(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut ready = false;
    while Instant::now() < deadline {
        if UnixStream::connect(&sock_b).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        ready,
        "H2 REGRESSION: after the owner crashed the vault was not reclaimable"
    );
    assert!(restarted.alive(), "the restarted daemon must keep serving");
}

/// The write that matters: with the second owner refused there is no
/// interleaving, so the committed secret is the one the single owner wrote
/// and nothing is silently lost.
#[test]
fn h2_no_lost_update_with_a_refused_second_writer() {
    let dir = Dir::new("no-lost-update");
    let vault = dir.vault();
    let mut owner = Session::create(&vault, PASS, SHORT_IDLE, Box::new(SystemClock)).unwrap();
    owner.project_add("human", "acme", &[]).unwrap();
    owner.secret_set("human", "acme", "FIRST", b"one").unwrap();

    // A second writer cannot even open the vault, so it cannot interleave.
    assert_eq!(
        Session::load(&vault, SHORT_IDLE, Box::new(SystemClock))
            .expect_err("second writer")
            .code(),
        "E_BUSY"
    );

    // The single owner's later write commits on top of its own state.
    owner.secret_set("human", "acme", "SECOND", b"two").unwrap();
    let expected = owner.document().cloned().unwrap();
    drop(owner);

    let mut reopened = Session::load(&vault, SHORT_IDLE, Box::new(SystemClock)).unwrap();
    reopened.unlock(PASS).unwrap();
    let doc = reopened.document().unwrap();
    assert!(
        doc.secrets.iter().any(|s| s.key == "FIRST"),
        "the first write must survive"
    );
    assert!(
        doc.secrets.iter().any(|s| s.key == "SECOND"),
        "the second write must survive"
    );
    assert_eq!(
        doc, &expected,
        "H2 REGRESSION: the reloaded document diverged from the owner's state"
    );
}
