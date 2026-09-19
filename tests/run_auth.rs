//! Auth/policy RED tests for `run_with_secrets` (Phase 5).
//!
//! Each case sends a well-formed request with exactly three SCM_RIGHTS FDs
//! so the denial comes from auth/policy, never FD validation. Currently
//! RED: the op answers `E_PROTOCOL op not available`.

#[path = "common/mod.rs"]
mod common;

use std::io::BufReader;
use std::os::fd::AsRawFd;
use std::path::Path;

use serde_json::json;
use svault::wire::{AuthField, Request, Response, VERSION};

const PASS: &str = "correct horse battery";

fn err_code(resp: &Response) -> String {
    resp.error.as_ref().unwrap().code.clone()
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

/// One plain (no-FD) request/response round trip for privileged setup ops.
fn plain_call(socket: &Path, req: &Request) -> Response {
    let mut stream = common::connect(socket);
    common::send_with_fds(&mut stream, req, &[]).unwrap();
    common::read_response(&mut BufReader::new(&stream)).unwrap()
}

/// Well-formed `run_with_secrets` attempt carrying exactly three FDs;
/// returns the first (`started`) response line.
fn run_attempt(socket: &Path, id: &str, token: &str, params: serde_json::Value) -> Response {
    let mut stream = common::connect(socket);
    let (stdout_r, stdout_w) = common::make_pipe();
    let stdin = common::open_devnull();
    let stderr = common::open_devnull();
    let req = common::authed_request(id, "run_with_secrets", token, params);
    let fds = [stdin.as_raw_fd(), stdout_w.as_raw_fd(), stderr.as_raw_fd()];
    common::send_with_fds(&mut stream, &req, &fds).unwrap();
    drop((stdout_r, stdout_w, stdin, stderr));
    common::read_response(&mut BufReader::new(&stream)).unwrap()
}

fn base_params() -> serde_json::Value {
    json!({"project": "acme", "executable": "/usr/bin/env", "argv": ["env"]})
}

#[test]
fn absent_run_grant_is_denied_permission() {
    let fix = common::setup();
    let add = plain_call(
        &fix.socket,
        &human_request("auth-add", "agents.add", json!({"name": "norun"})),
    );
    assert!(add.ok, "setup agents.add failed: {add:?}");
    let token = add.result.as_ref().unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let grant = plain_call(
        &fix.socket,
        &human_request(
            "auth-grant",
            "grants.grant",
            json!({"agent": "norun", "project": "acme", "ops": "read"}),
        ),
    );
    assert!(grant.ok, "setup grants.grant failed: {grant:?}");

    let resp = run_attempt(&fix.socket, "run-nogrant", &token, base_params());
    assert!(!resp.ok, "run without grant must be denied, got {resp:?}");
    assert_eq!(err_code(&resp), "E_PERMISSION", "got {resp:?}");
}

#[test]
fn revoked_grant_denies_next_launch_immediately() {
    let fix = common::setup();
    let revoke = plain_call(
        &fix.socket,
        &human_request(
            "auth-revoke",
            "grants.revoke",
            json!({"agent": "harness", "project": "acme"}),
        ),
    );
    assert!(revoke.ok, "setup grants.revoke failed: {revoke:?}");

    let resp = run_attempt(&fix.socket, "run-revoked", &fix.token, base_params());
    assert!(!resp.ok, "run after revoke must be denied, got {resp:?}");
    assert_eq!(err_code(&resp), "E_PERMISSION", "got {resp:?}");
}

#[test]
fn locked_vault_denies_run_with_locked() {
    let fix = common::setup();
    let lock = plain_call(
        &fix.socket,
        &common::authed_request("auth-lock", "vault.lock", &fix.token, json!({})),
    );
    assert!(lock.ok, "setup vault.lock failed: {lock:?}");

    let resp = run_attempt(&fix.socket, "run-locked", &fix.token, base_params());
    assert!(!resp.ok, "run on locked vault must be denied, got {resp:?}");
    assert_eq!(err_code(&resp), "E_LOCKED", "got {resp:?}");
}

#[test]
fn missing_key_fails_closed_not_found() {
    let fix = common::setup();
    let mut params = base_params();
    params["keys"] = json!(["NO_SUCH_KEY"]);
    let resp = run_attempt(&fix.socket, "run-missing-key", &fix.token, params);
    assert!(
        !resp.ok,
        "run with missing key must fail closed, got {resp:?}"
    );
    assert_eq!(err_code(&resp), "E_NOT_FOUND", "got {resp:?}");
}
