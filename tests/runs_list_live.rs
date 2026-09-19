//! `runs.list` regression with a REAL live process.
//!
//! One long-running child via the held `run_with_secrets` connection, then
//! `runs.list` as the human: exact six-key allowlist, identity resolution,
//! trap-marker absence in the response, disappearance after TERM, and audit
//! absence of secret/argv/env markers.

#[path = "common/mod.rs"]
mod common;

use std::io::{BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use serde_json::json;
use svault::wire::{AuthField, Request, Response, VERSION};

const GONE_WAIT: Duration = Duration::from_secs(5);
const POLL_STEP: Duration = Duration::from_millis(20);
const PASS: &str = "correct horse battery";
const ARGV_MARKER: &str = "runslist-ARGV-marker-9f3a";
const ENV_MARKER: &str = "runslist-ENV-marker-7c1b";

/// Best-effort SIGKILL of owned pids, even when an assert panics first.
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

/// True once the pid no longer exists. A zombie counts as gone: the
/// process has terminated and only awaits its reaper.
fn pid_gone(pid: i32) -> bool {
    let r = unsafe { libc::kill(pid, 0) };
    if r == 0 {
        return proc_state(pid) == Some('Z');
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
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
        std::thread::sleep(POLL_STEP);
    }
    pid_gone(pid)
}

/// Human (passphrase) request, same wire shape `setup()` uses for unlock.
fn human(id: &str, op: &str, params: serde_json::Value) -> Request {
    Request {
        v: VERSION,
        id: id.to_string(),
        op: op.to_string(),
        auth: Some(AuthField {
            token: None,
            passphrase: Some(PASS.to_string()),
            session: None,
        }),
        params,
    }
}

fn send(_op_id: &str, req: &Request, socket: &std::path::Path) -> Response {
    let mut stream = common::connect(socket);
    let mut bytes = serde_json::to_string(req).unwrap();
    bytes.push('\n');
    stream.write_all(bytes.as_bytes()).unwrap();
    let mut reader = BufReader::new(stream);
    common::read_response(&mut reader).expect("response line")
}

fn result(resp: &Response) -> &serde_json::Value {
    resp.result.as_ref().expect("ok carries a result")
}

#[test]
fn runs_list_live_run_is_allowlisted_trap_free_and_disappears() {
    let fix = common::setup();

    // 1-2. ONE long-running child carrying greppable markers through the
    // real channels the contract forbids from the response: an argv marker,
    // the trap secret in the child env (keys: [STRIPE_KEY] selects it), and
    // a caller env marker via allowlisted TERM. `/bin/sh -c 'sleep 30 # <marker>'`
    // keeps the marker genuinely in the child argv while staying alive ~30 s.
    let script = format!("sleep 30 # {ARGV_MARKER}");
    let mut stream: UnixStream = common::connect(&fix.socket);
    let (stdin, stdout, stderr) = (
        common::open_devnull(),
        common::open_devnull(),
        common::open_devnull(),
    );
    let req = common::authed_request(
        "run-live",
        "run_with_secrets",
        &fix.token,
        json!({
            "project": "acme",
            "executable": "/bin/sh",
            "argv": ["sh", "-c", script],
            "keys": ["STRIPE_KEY"],
            "env": {"TERM": ENV_MARKER},
        }),
    );
    let fds = [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()];
    common::send_with_fds(&mut stream, &req, &fds).unwrap();
    drop((stdin, stdout, stderr));
    let mut reader = BufReader::new(stream);
    let started = common::read_response(&mut reader).expect("started line");
    assert!(started.ok, "started must succeed, got {started:?}");
    let body = started.result.clone().unwrap_or_default();
    let run_id = body["run_id"].as_str().expect("started run_id").to_string();
    let pid = body["pid"].as_i64().expect("started pid") as i32;
    assert!(pid > 0, "started pid must be positive, got {body:?}");
    let _guard = KillGuard { pids: vec![pid] };
    assert!(!pid_gone(pid), "child {pid} must be alive after launch");

    // 3-4. runs.list as the HUMAN on a fresh connection.
    let resp = send(
        "list-1",
        &human("list-1", "runs.list", json!({})),
        &fix.socket,
    );
    assert!(resp.ok, "runs.list must succeed, got {:?}", resp.error);
    let runs = result(&resp)["runs"]
        .as_array()
        .expect("runs must be an array")
        .clone();
    assert_eq!(runs.len(), 1, "exactly one live run expected, got {runs:?}");
    let row = &runs[0];
    assert_eq!(row["run_id"].as_str(), Some(run_id.as_str()));
    assert_eq!(row["pid"].as_i64(), Some(pid as i64));
    // Exact six-key allowlist (sorted key SET equality): a future field
    // addition to the response fails here by design.
    let mut keys: Vec<&str> = row
        .as_object()
        .expect("run row must be an object")
        .keys()
        .map(|s| s.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["agent", "pid", "project", "run_id", "started_at", "status"],
        "runs.list row must carry exactly the allowlisted keys"
    );
    assert_eq!(
        row["agent"],
        json!("harness"),
        "agent must be the resolved NAME"
    );
    assert_eq!(row["project"], json!("acme"));
    assert_eq!(row["status"], json!("running"));
    let started_at = row["started_at"]
        .as_str()
        .expect("started_at must be a string");
    assert!(!started_at.is_empty(), "started_at must be non-empty");
    // House timestamp format is `OffsetDateTime::to_string()` (Display, e.g.
    // "2026-09-16 13:09:32.06 +00:00:00") — the same rendering every other
    // wire timestamp in this codebase uses (vault.status created, lease
    // expires_at, session expires_at). Pin the shape the wire promises
    // (date + time + UTC offset, non-empty) rather than RFC3339, which the
    // wire never promised here. `time` has no FromStr for OffsetDateTime,
    // so assert structure, not a parse round-trip.
    assert!(
        started_at.contains("+00:00:00") && started_at.contains('-') && started_at.contains(':'),
        "started_at must carry date, time and UTC offset, got {started_at:?}"
    );

    // 5. Trap: raw response body carries none of the forbidden markers.
    // (Executable path IS allowed in the response per the audit contract
    // note below — but runs.list never emits it, so assert absence here.)
    let body_text = serde_json::to_string(&resp).unwrap();
    assert!(
        !body_text.contains(common::TRAP),
        "runs.list response must not contain the trap secret"
    );
    assert!(
        !body_text.contains(ARGV_MARKER),
        "runs.list response must not contain the argv marker"
    );
    assert!(
        !body_text.contains(ENV_MARKER),
        "runs.list response must not contain the env marker"
    );
    assert!(
        !body_text.contains("/bin/sh"),
        "runs.list response must not contain the executable path"
    );

    // 6. TERM on its own connection; held connection reports exit; child gone.
    let mut sig: UnixStream = common::connect(&fix.socket);
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
    assert!(
        wait_gone(pid, GONE_WAIT),
        "signalled child {pid} must be gone"
    );

    // 7. Poll until the registry drops the run (removal happens on the
    // launch handler's thread — a zero-wait assert would be flaky), then
    // assert the list is EMPTY.
    let start = Instant::now();
    let final_resp = loop {
        let r = send(
            "list-n",
            &human("list-n", "runs.list", json!({})),
            &fix.socket,
        );
        assert!(r.ok, "poll runs.list must succeed, got {:?}", r.error);
        let runs = result(&r)["runs"].as_array().cloned().unwrap_or_default();
        let still_there = runs.iter().any(|row| row["run_id"] == run_id);
        if !still_there {
            break r;
        }
        assert!(
            start.elapsed() < GONE_WAIT,
            "run {run_id} must disappear from runs.list within {GONE_WAIT:?}"
        );
        std::thread::sleep(POLL_STEP);
    };
    assert_eq!(
        result(&final_resp)["runs"].as_array().map(Vec::len),
        Some(0),
        "runs.list must be empty after the run exits"
    );

    // 8. Audit carries NONE of the secret/argv/env markers. The audit DOES
    // legitimately log the executable path and key NAMES for run
    // started/exited events (contract: executable allowed there, key names
    // only) — so executable absence is asserted on the RESPONSE only
    // (step 5), never here.
    let audit = std::fs::read_to_string(fix.dir.path().join("audit.jsonl")).unwrap_or_default();
    assert!(
        !audit.contains(common::TRAP),
        "audit must not contain the trap secret value"
    );
    assert!(
        !audit.contains(ARGV_MARKER),
        "audit must not contain the argv marker"
    );
    assert!(
        !audit.contains(ENV_MARKER),
        "audit must not contain the env marker value"
    );
}
