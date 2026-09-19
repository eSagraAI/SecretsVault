//! Run lifecycle RED tests: exit codes, `run_signal`, disconnect kill,
//! and process-group cleanup on disconnect. All use real child processes
//! with bounded waits; every test fails today on `E_PROTOCOL op not
//! available`, proving the intended behavior is missing.

#[path = "common/mod.rs"]
mod common;

use std::io::{BufReader, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use serde_json::json;

const GONE_WAIT: Duration = Duration::from_secs(5);

/// Best-effort SIGKILL of owned pids, even when an assert panics first.
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

/// True once the pid no longer exists. A zombie counts as gone: the
/// process has terminated and only awaits its reaper.
fn pid_gone(pid: i32) -> bool {
    let r = unsafe { libc::kill(pid, 0) };
    if r == 0 {
        return proc_state(pid) == Some('Z');
    }
    let errno = std::io::Error::last_os_error().raw_os_error();
    if errno == Some(libc::ESRCH) {
        return true;
    }
    proc_state(pid) == Some('Z')
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

fn children_of(ppid: i32) -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        if pid == ppid {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some(end) = text.rfind(')') else {
            continue;
        };
        let mut fields = text[end + 1..].split_whitespace();
        fields.next(); // state
        if fields.next().is_some_and(|p| p.parse::<i32>() == Ok(ppid)) {
            out.push(pid);
        }
    }
    out
}

/// Launch `executable`/`argv` on a fresh daemon connection, read `started`,
/// return the owned reader plus `run_id` and child pid.
fn launch(
    fix: &common::Fixture,
    id: &str,
    executable: &str,
    argv: serde_json::Value,
) -> (BufReader<std::os::unix::net::UnixStream>, String, i32) {
    let mut stream = common::connect(&fix.socket);
    let stdin = common::open_devnull();
    let stdout = common::open_devnull();
    let stderr = common::open_devnull();
    let req = common::authed_request(
        id,
        "run_with_secrets",
        &fix.token,
        json!({"project": "acme", "executable": executable, "argv": argv}),
    );
    let fds = [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()];
    common::send_with_fds(&mut stream, &req, &fds).unwrap();
    drop((stdin, stdout, stderr));
    let mut reader = BufReader::new(stream);
    let started = common::read_response(&mut reader).expect("started line");
    assert!(started.ok, "started must succeed, got {started:?}");
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
    assert!(pid > 0, "started pid must be positive, got {body:?}");
    (reader, run_id, pid)
}

#[test]
fn nonzero_exit_code_in_final_response() {
    let fix = common::setup();
    let (mut reader, _run_id, pid) =
        launch(&fix, "run-exit3", "/bin/sh", json!(["sh", "-c", "exit 3"]));
    let _guard = KillGuard { pids: vec![pid] };
    let exited = common::read_response(&mut reader).expect("exited line");
    assert!(exited.ok, "exited must succeed, got {exited:?}");
    let body = exited.result.clone().unwrap_or_default();
    assert_eq!(
        body.get("exit_code").and_then(|v| v.as_i64()),
        Some(3),
        "final must carry exit_code 3, got {body:?}"
    );
}

#[test]
fn run_signal_terminates_owned_run() {
    let fix = common::setup();
    let (mut reader, run_id, pid) = launch(&fix, "run-sig", "/bin/sleep", json!(["sleep", "30"]));
    let _guard = KillGuard { pids: vec![pid] };

    let mut sig = common::connect(&fix.socket);
    let sig_req = common::authed_request(
        "sig-1",
        "run_signal",
        &fix.token,
        json!({"run_id": run_id, "signal": "TERM"}),
    );
    common::send_with_fds(&mut sig, &sig_req, &[]).unwrap();
    let mut sig_reader = BufReader::new(sig);
    let ack = common::read_response(&mut sig_reader).expect("run_signal ack");
    assert!(ack.ok, "run_signal must succeed, got {ack:?}");

    let exited = common::read_response(&mut reader).expect("exited line");
    assert!(exited.ok, "exited must succeed, got {exited:?}");
    let body = exited.result.clone().unwrap_or_default();
    let signal = body.get("signal").cloned().unwrap_or_default().to_string();
    assert!(
        signal.contains("TERM") || signal.contains("15"),
        "final must name TERM, got {body:?}"
    );
    assert!(
        wait_gone(pid, GONE_WAIT),
        "signalled child {pid} must be gone"
    );
}

#[test]
fn disconnect_kills_child() {
    let fix = common::setup();
    let (reader, _run_id, pid) = launch(&fix, "run-disc", "/bin/sleep", json!(["sleep", "30"]));
    let _guard = KillGuard { pids: vec![pid] };
    assert!(
        !pid_gone(pid),
        "child {pid} must be alive before disconnect"
    );
    drop(reader); // launch-connection disconnect must kill the run
    assert!(
        wait_gone(pid, GONE_WAIT),
        "child {pid} must die on disconnect"
    );
}

#[test]
fn trailing_data_cannot_mask_launch_disconnect() {
    let fix = common::setup();
    let (mut reader, _run_id, pid) = launch(
        &fix,
        "run-trailing-disconnect",
        "/bin/sleep",
        json!(["sleep", "30"]),
    );
    let _guard = KillGuard { pids: vec![pid] };
    reader.get_mut().write_all(b"x").unwrap();
    reader.get_mut().shutdown(Shutdown::Both).unwrap();
    drop(reader);
    assert!(
        wait_gone(pid, GONE_WAIT),
        "post-request data must not mask disconnect for child {pid}"
    );
}

#[test]
fn disconnect_cleans_process_group_grandchild() {
    let fix = common::setup();
    let (reader, _run_id, pid) = launch(
        &fix,
        "run-pgroup",
        "/bin/sh",
        json!(["sh", "-c", "sleep 30 & wait"]),
    );
    let mut guard = KillGuard { pids: vec![pid] };

    let start = Instant::now();
    let mut grandkids = Vec::new();
    while start.elapsed() < GONE_WAIT {
        grandkids = children_of(pid);
        if !grandkids.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !grandkids.is_empty(),
        "sh child {pid} must spawn a grandchild"
    );
    guard.pids.extend(grandkids.iter().copied());

    drop(reader); // disconnect must kill the whole dedicated process group
    assert!(
        wait_gone(pid, GONE_WAIT),
        "child {pid} must die on disconnect"
    );
    for g in &grandkids {
        assert!(
            wait_gone(*g, GONE_WAIT),
            "grandchild {g} must die on disconnect"
        );
    }
}
