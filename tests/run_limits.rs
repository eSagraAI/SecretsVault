//! Run limits RED tests: concurrency caps and input/environment bounds.
//! All use real UDS daemon + SCM_RIGHTS; every test fails today on
//! `E_PROTOCOL op not available`, proving the behavior is missing.

#[path = "common/mod.rs"]
mod common;

use std::io::BufReader;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use serde_json::json;

const GONE_WAIT: Duration = Duration::from_secs(5);

struct KillGuard {
    pids: Vec<i32>,
}

impl Drop for KillGuard {
    fn drop(&mut self) {
        for pid in &self.pids {
            if !pid_gone(*pid) {
                unsafe {
                    libc::kill(*pid, libc::SIGKILL);
                }
            }
        }
    }
}

fn pid_gone(pid: i32) -> bool {
    let r = unsafe { libc::kill(pid, 0) };
    if r == 0 {
        return proc_state(pid) == Some('Z');
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        || proc_state(pid) == Some('Z')
}

fn proc_state(pid: i32) -> Option<char> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = text.rfind(')')?;
    text[end + 1..].split_whitespace().next()?.chars().next()
}

fn wait_gone(pid: i32, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if pid_gone(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    pid_gone(pid)
}

fn err_code(resp: &svault::wire::Response) -> String {
    resp.error.as_ref().unwrap().code.clone()
}

fn resp_text(resp: &svault::wire::Response) -> String {
    serde_json::to_string(resp).unwrap()
}

/// Send `run_with_secrets` with exactly three FDs; return first response.
fn attempt(fix: &common::Fixture, id: &str, params: serde_json::Value) -> svault::wire::Response {
    let mut stream = common::connect(&fix.socket);
    let stdin = common::open_devnull();
    let stdout = common::open_devnull();
    let stderr = common::open_devnull();
    let req = common::authed_request(id, "run_with_secrets", &fix.token, params);
    let fds = [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()];
    common::send_with_fds(&mut stream, &req, &fds).unwrap();
    drop((stdin, stdout, stderr));
    let mut reader = BufReader::new(stream);
    common::read_response(&mut reader).expect("response line")
}

/// Launch a held `/bin/sleep 30` run; return held reader, run_id, pid.
fn launch_held(fix: &common::Fixture, id: &str) -> (BufReader<UnixStream>, String, i32) {
    let mut stream = common::connect(&fix.socket);
    let stdin = common::open_devnull();
    let stdout = common::open_devnull();
    let stderr = common::open_devnull();
    let req = common::authed_request(
        id,
        "run_with_secrets",
        &fix.token,
        json!({"project": "acme", "executable": "/bin/sleep", "argv": ["sleep", "30"]}),
    );
    let fds = [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()];
    common::send_with_fds(&mut stream, &req, &fds).unwrap();
    drop((stdin, stdout, stderr));
    let mut reader = BufReader::new(stream);
    let started = common::read_response(&mut reader).expect("started line");
    assert!(started.ok, "held run must start, got {started:?}");
    let body = started.result.clone().unwrap_or_default();
    let run_id = body
        .get("run_id")
        .and_then(|v| v.as_str())
        .expect("started run_id")
        .to_string();
    let pid = body
        .get("pid")
        .and_then(|v| v.as_i64())
        .expect("started pid") as i32;
    assert!(pid > 0, "pid must be positive, got {body:?}");
    (reader, run_id, pid)
}

fn signal_run(fix: &common::Fixture, id: &str, run_id: &str) -> svault::wire::Response {
    let mut stream = common::connect(&fix.socket);
    let req = common::authed_request(
        id,
        "run_signal",
        &fix.token,
        json!({"run_id": run_id, "signal": "TERM"}),
    );
    common::send_with_fds(&mut stream, &req, &[]).unwrap();
    let mut reader = BufReader::new(stream);
    common::read_response(&mut reader).expect("signal ack")
}

fn assert_rejected_before_spawn(resp: &svault::wire::Response) {
    assert!(!resp.ok, "over-limit run must be rejected, got {resp:?}");
    let code = err_code(resp);
    assert!(
        ["E_INVALID_INPUT", "E_TOO_LARGE"].contains(&code.as_str()),
        "limit rejection must be bounded input error, got {resp:?}"
    );
    let text = resp_text(resp);
    assert!(
        text.len() < 8192,
        "error must be bounded, got {} bytes",
        text.len()
    );
    assert!(!text.contains(common::TRAP), "broker leaked secret: {text}");
    assert!(
        !text.contains("run_id") && !text.contains("\"pid\""),
        "rejected run must not spawn: {text}"
    );
}

#[test]
fn four_concurrent_held_runs_succeed() {
    let fix = common::setup();
    let mut held = Vec::new();
    let mut guard = KillGuard { pids: Vec::new() };
    for i in 0..4 {
        let (reader, _run_id, pid) = launch_held(&fix, &format!("run-cap-{i}"));
        guard.pids.push(pid);
        held.push(reader);
    }
    assert_eq!(guard.pids.len(), 4, "four runs must be held");
    drop(held);
    for pid in &guard.pids {
        assert!(
            wait_gone(*pid, GONE_WAIT),
            "child {pid} must die on disconnect"
        );
    }
}

#[test]
fn fifth_run_rejected_and_existing_remain_controllable() {
    let fix = common::setup();
    let mut held = Vec::new();
    let mut ids = Vec::new();
    let mut guard = KillGuard { pids: Vec::new() };
    for i in 0..4 {
        let (reader, run_id, pid) = launch_held(&fix, &format!("run-keep-{i}"));
        guard.pids.push(pid);
        held.push(reader);
        ids.push(run_id);
    }
    let fifth = attempt(
        &fix,
        "run-excess",
        json!({"project": "acme", "executable": "/bin/sleep", "argv": ["sleep", "30"]}),
    );
    assert!(
        !fifth.ok,
        "fifth concurrent run must be rejected, got {fifth:?}"
    );
    let code = err_code(&fifth);
    assert!(
        [
            "E_BUSY",
            "E_LIMIT",
            "E_TOO_MANY",
            "E_INVALID_INPUT",
            "E_TOO_LARGE"
        ]
        .contains(&code.as_str()),
        "excess rejection must be a limit error, got {fifth:?}"
    );
    for (i, run_id) in ids.iter().enumerate() {
        let ack = signal_run(&fix, &format!("sig-keep-{i}"), run_id);
        assert!(
            ack.ok,
            "held run {run_id} must stay controllable, got {ack:?}"
        );
    }
    drop(held);
    for pid in &guard.pids {
        assert!(
            wait_gone(*pid, GONE_WAIT),
            "child {pid} must die on disconnect"
        );
    }
}

#[test]
fn wrong_fd_counts_rejected() {
    let fix = common::setup();
    for count in [1usize, 2, 4] {
        let mut stream = common::connect(&fix.socket);
        let stdin = common::open_devnull();
        let stdout = common::open_devnull();
        let stderr = common::open_devnull();
        let extra = common::open_devnull();
        let all = [
            stdin.as_raw_fd(),
            stdout.as_raw_fd(),
            stderr.as_raw_fd(),
            extra.as_raw_fd(),
        ];
        let fds = &all[..count.min(4)];
        // For counts 1/2 take the prefix; for 4 take all four.
        let req = common::authed_request(
            &format!("run-fd{count}"),
            "run_with_secrets",
            &fix.token,
            json!({"project": "acme", "executable": "/usr/bin/env", "argv": ["env"]}),
        );
        common::send_with_fds(&mut stream, &req, fds).unwrap();
        drop((stdin, stdout, stderr, extra));
        let mut reader = BufReader::new(stream);
        let resp = common::read_response(&mut reader).expect("response line");
        assert!(!resp.ok, "{count} FDs must be rejected, got {resp:?}");
        assert_eq!(err_code(&resp), "E_INVALID_INPUT", "got {resp:?}");
    }
}

#[test]
fn executable_and_argv_limits_rejected_before_spawn() {
    let fix = common::setup();
    let long_exe = format!("/bin/{}", "a".repeat(4100));
    let resp = attempt(
        &fix,
        "run-long-exe",
        json!({"project": "acme", "executable": long_exe, "argv": ["x"]}),
    );
    assert_rejected_before_spawn(&resp);

    let many_argv: Vec<String> = (0..257).map(|i| format!("a{i}")).collect();
    let resp = attempt(
        &fix,
        "run-many-argv",
        json!({"project": "acme", "executable": "/usr/bin/env", "argv": many_argv}),
    );
    assert_rejected_before_spawn(&resp);

    let big = "a".repeat(140 * 1024);
    let resp = attempt(
        &fix,
        "run-big-argv",
        json!({"project": "acme", "executable": "/usr/bin/env", "argv": ["env", big]}),
    );
    assert_rejected_before_spawn(&resp);
}

#[test]
fn keys_and_env_limits_rejected_before_spawn() {
    let fix = common::setup();
    let many_keys: Vec<String> = (0..257).map(|i| format!("K{i:03}")).collect();
    let resp = attempt(
        &fix,
        "run-many-keys",
        json!({"project": "acme", "executable": "/usr/bin/env", "argv": ["env"], "keys": many_keys}),
    );
    assert_rejected_before_spawn(&resp);

    let mut map = serde_json::Map::new();
    for i in 0..257 {
        map.insert(format!("XDG_LIM{i:03}"), json!("v"));
    }
    let resp = attempt(
        &fix,
        "run-many-env",
        json!({"project": "acme", "executable": "/usr/bin/env", "argv": ["env"], "env": map}),
    );
    assert_rejected_before_spawn(&resp);

    let big = "b".repeat(140 * 1024);
    let resp = attempt(
        &fix,
        "run-big-env",
        json!({"project": "acme", "executable": "/usr/bin/env", "argv": ["env"], "env": {"PATH": big}}),
    );
    assert_rejected_before_spawn(&resp);

    let huge = "c".repeat(1_100_000);
    let resp = attempt(
        &fix,
        "run-huge-env",
        json!({"project": "acme", "executable": "/usr/bin/env", "argv": ["env"], "env": {"PATH": huge}}),
    );
    assert!(
        !resp.ok,
        "resulting env >1MiB must be rejected, got {resp:?}"
    );
    let text = resp_text(&resp);
    assert!(
        text.len() < 8192,
        "error must be bounded, got {} bytes",
        text.len()
    );
    assert!(!text.contains(common::TRAP), "broker leaked secret");
}
