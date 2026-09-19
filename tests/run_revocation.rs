//! Strong capability-revocation tests for active daemon-managed runs.

#[path = "common/mod.rs"]
mod common;

use std::io::BufReader;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::json;
use svault::wire::{AuthField, Request, Response, VERSION};

const PASS: &str = "correct horse battery";
const GONE_WAIT: Duration = Duration::from_secs(5);

struct KillGuard(Vec<i32>);

impl Drop for KillGuard {
    fn drop(&mut self) {
        for pid in &self.0 {
            if !pid_gone(*pid) {
                unsafe { libc::kill(*pid, libc::SIGKILL) };
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
}

fn proc_state(pid: i32) -> Option<char> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = text.rfind(')')?;
    text[end + 1..].split_whitespace().next()?.chars().next()
}

fn wait_gone(pid: i32) -> bool {
    let start = Instant::now();
    while start.elapsed() < GONE_WAIT {
        if pid_gone(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    pid_gone(pid)
}

fn wait_reaped(pid: i32) -> bool {
    let start = Instant::now();
    while start.elapsed() < GONE_WAIT {
        if proc_state(pid).is_none() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    proc_state(pid).is_none()
}

fn human_request(id: &str, op: &str, params: serde_json::Value) -> Request {
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

fn plain_call(socket: &Path, req: &Request) -> Response {
    let mut stream = common::connect(socket);
    common::send_with_fds(&mut stream, req, &[]).unwrap();
    common::read_response(&mut BufReader::new(&stream)).unwrap()
}

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
    let started = common::read_response(&mut reader).expect("started response");
    assert!(started.ok, "run did not start: {started:?}");
    let body = started.result.unwrap();
    let run_id = body["run_id"].as_str().unwrap().to_string();
    let pid = body["pid"].as_i64().unwrap() as i32;
    (reader, run_id, pid)
}

fn assert_final_and_reaped(mut reader: BufReader<std::os::unix::net::UnixStream>, pid: i32) {
    assert!(wait_gone(pid), "child {pid} survived capability withdrawal");
    let final_response = common::read_response(&mut reader).expect("final response");
    assert!(final_response.ok, "bad final response: {final_response:?}");
    assert!(wait_reaped(pid), "child {pid} remained as a zombie");
}

fn audit_text(fix: &common::Fixture) -> String {
    let response = plain_call(
        &fix.socket,
        &human_request("audit", "audit.show", json!({"tail": 200})),
    );
    assert!(response.ok, "audit.show failed: {response:?}");
    serde_json::to_string(&response).unwrap()
}

#[test]
fn grant_revoke_terminates_matching_active_run() {
    let fix = common::setup();
    let (reader, run_id, pid) = launch(&fix, "grant-run", "/bin/sleep", json!(["sleep", "30"]));
    let _guard = KillGuard(vec![pid]);

    let revoked = plain_call(
        &fix.socket,
        &human_request(
            "grant-revoke",
            "grants.revoke",
            json!({"agent": "harness", "project": "acme"}),
        ),
    );
    assert!(revoked.ok, "grant revoke failed: {revoked:?}");
    assert_final_and_reaped(reader, pid);

    let audit = audit_text(&fix);
    assert!(audit.contains("grants.revoke"));
    assert!(audit.contains(&run_id));
    assert!(audit.contains("revoked"));
    assert!(!audit.contains(common::TRAP));
}

#[test]
fn grant_upsert_removing_run_terminates_active_run_and_frees_quota() {
    let fix = common::setup();
    let (reader, run_id, pid) = launch(&fix, "upsert-run", "/bin/sleep", json!(["sleep", "30"]));
    let _guard = KillGuard(vec![pid]);

    let updated = plain_call(
        &fix.socket,
        &human_request(
            "grant-upsert-read-only",
            "grants.grant",
            json!({"agent": "harness", "project": "acme", "ops": "read"}),
        ),
    );
    assert!(updated.ok, "grant upsert failed: {updated:?}");
    assert_final_and_reaped(reader, pid);

    let audit = audit_text(&fix);
    assert!(audit.contains("grants.grant"));
    assert!(audit.contains(&run_id));
    assert!(audit.contains("revoked"));
    assert!(!audit.contains(common::TRAP));

    let restored = plain_call(
        &fix.socket,
        &human_request(
            "grant-upsert-restore-run",
            "grants.grant",
            json!({"agent": "harness", "project": "acme", "ops": "read,run"}),
        ),
    );
    assert!(restored.ok, "run grant restore failed: {restored:?}");

    let mut readers = Vec::new();
    let mut active_guard = KillGuard(Vec::new());
    for i in 0..4 {
        let (reader, _, pid) = launch(
            &fix,
            &format!("quota-after-upsert-{i}"),
            "/bin/sleep",
            json!(["sleep", "30"]),
        );
        readers.push(reader);
        active_guard.0.push(pid);
    }
    drop(readers);
    for pid in &active_guard.0 {
        assert!(wait_reaped(*pid), "cleanup did not reap child {pid}");
    }
}

#[test]
fn agent_revoke_terminates_all_owned_active_runs() {
    let fix = common::setup();
    let (reader_a, run_a, pid_a) =
        launch(&fix, "agent-run-a", "/bin/sleep", json!(["sleep", "30"]));
    let (reader_b, run_b, pid_b) =
        launch(&fix, "agent-run-b", "/bin/sleep", json!(["sleep", "30"]));
    let _guard = KillGuard(vec![pid_a, pid_b]);

    let revoked = plain_call(
        &fix.socket,
        &human_request("agent-revoke", "agents.revoke", json!({"name": "harness"})),
    );
    assert!(revoked.ok, "agent revoke failed: {revoked:?}");
    assert_final_and_reaped(reader_a, pid_a);
    assert_final_and_reaped(reader_b, pid_b);

    let audit = audit_text(&fix);
    assert!(audit.contains("agents.revoke"));
    assert!(audit.contains(&run_a));
    assert!(audit.contains(&run_b));
    assert!(!audit.contains(common::TRAP));
}

#[test]
fn vault_lock_terminates_all_active_runs_before_zeroization() {
    let fix = common::setup();
    let (reader, run_id, pid) = launch(&fix, "lock-run", "/bin/sleep", json!(["sleep", "30"]));
    let _guard = KillGuard(vec![pid]);

    let locked = plain_call(
        &fix.socket,
        &common::authed_request("lock", "vault.lock", &fix.token, json!({})),
    );
    assert!(locked.ok, "vault lock failed: {locked:?}");
    assert_final_and_reaped(reader, pid);

    let audit = audit_text(&fix);
    assert!(audit.contains("vault.lock"));
    assert!(audit.contains(&run_id));
    assert!(audit.contains("revoked"));
    assert!(!audit.contains(common::TRAP));
}

#[test]
fn natural_exit_racing_revoke_leaves_no_stale_quota_or_zombie() {
    let fix = common::setup();
    for i in 0..8 {
        let (reader, _run_id, pid) =
            launch(&fix, &format!("race-{i}"), "/bin/true", json!(["true"]));
        let _guard = KillGuard(vec![pid]);
        let revoked = plain_call(
            &fix.socket,
            &human_request(
                &format!("race-revoke-{i}"),
                "grants.revoke",
                json!({"agent": "harness", "project": "acme"}),
            ),
        );
        assert!(revoked.ok, "race revoke {i} failed: {revoked:?}");
        assert_final_and_reaped(reader, pid);
        let granted = plain_call(
            &fix.socket,
            &human_request(
                &format!("race-grant-{i}"),
                "grants.grant",
                json!({"agent": "harness", "project": "acme", "ops": "run"}),
            ),
        );
        assert!(granted.ok, "race regrant {i} failed: {granted:?}");
    }

    let mut readers = Vec::new();
    let mut guard = KillGuard(Vec::new());
    for i in 0..4 {
        let (reader, _, pid) = launch(
            &fix,
            &format!("quota-after-race-{i}"),
            "/bin/sleep",
            json!(["sleep", "30"]),
        );
        readers.push(reader);
        guard.0.push(pid);
    }
    drop(readers);
    for pid in &guard.0 {
        assert!(wait_reaped(*pid), "cleanup did not reap child {pid}");
    }
}
