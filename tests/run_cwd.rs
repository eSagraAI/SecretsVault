//! Cwd tests for `run_with_secrets` (RED phase).
//! Child-visible outcomes travel only through the passed stdout FD;
//! broker responses remain secret-free.

#[path = "common/mod.rs"]
mod common;

use std::io::{BufReader, Read};
use std::os::fd::AsRawFd;

use serde_json::json;

/// Send `run_with_secrets` with exactly three FDs. Both response lines are
/// read on one `BufReader`. A rejected run yields `None` for `exited`.
fn run_cwd(
    fix: &common::Fixture,
    id: &str,
    params: serde_json::Value,
) -> (
    svault::wire::Response,
    Option<svault::wire::Response>,
    String,
) {
    let mut stream = common::connect(&fix.socket);
    let (stdout_r, stdout_w) = common::make_pipe();
    let stdin = common::open_devnull();
    let stderr = common::open_devnull();
    let req = common::authed_request(id, "run_with_secrets", &fix.token, params);
    let fds = [stdin.as_raw_fd(), stdout_w.as_raw_fd(), stderr.as_raw_fd()];
    common::send_with_fds(&mut stream, &req, &fds).unwrap();
    drop((stdout_w, stdin, stderr));
    let mut reader = BufReader::new(&stream);
    let started = common::read_response(&mut reader).unwrap();
    if !started.ok {
        return (started, None, String::new());
    }
    let exited = common::read_response(&mut reader).unwrap();
    let mut out = String::new();
    std::fs::File::from(stdout_r)
        .read_to_string(&mut out)
        .unwrap();
    (started, Some(exited), out)
}

fn err_code(resp: &svault::wire::Response) -> String {
    resp.error.as_ref().unwrap().code.clone()
}

#[test]
fn allowed_cwd_is_child_actual_cwd() {
    let fix = common::setup();
    let sub = fix.dir.path().join("authorized").join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    let (started, exited, out) = run_cwd(
        &fix,
        "run-cwd-allowed",
        json!({"project": "acme", "executable": "/bin/pwd", "argv": ["pwd"], "cwd": sub.to_str().unwrap()}),
    );
    assert!(started.ok, "started must succeed, got {started:?}");
    let exited = exited.unwrap();
    assert!(exited.ok, "exited must succeed, got {exited:?}");
    let expected = std::fs::canonicalize(&sub).unwrap();
    assert_eq!(
        out.trim(),
        expected.to_str().unwrap(),
        "child cwd must be the authorized subdirectory, got {out:?}"
    );
}

#[test]
fn cwd_outside_authorized_fails_before_spawn() {
    let fix = common::setup();
    let outside = fix.dir.path().to_str().unwrap().to_string();
    let (started, exited, out) = run_cwd(
        &fix,
        "run-cwd-outside",
        json!({"project": "acme", "executable": "/bin/pwd", "argv": ["pwd"], "cwd": outside}),
    );
    assert!(!started.ok, "outside cwd must be rejected, got {started:?}");
    assert_eq!(
        err_code(&started),
        "E_PATH_NOT_AUTHORIZED",
        "got {started:?}"
    );
    assert!(
        exited.is_none(),
        "rejected run must not spawn, got {exited:?}"
    );
    assert!(
        out.is_empty(),
        "rejected run must produce no child output, got {out:?}"
    );
}

#[test]
fn cwd_authorization_is_not_a_sandbox() {
    let fix = common::setup();
    let authorized = fix.dir.path().join("authorized");
    let sub = authorized.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    let marker = "cwd-nonsandbox-marker-7f3a";
    std::fs::write(authorized.join("marker.txt"), marker).unwrap();
    let (started, exited, out) = run_cwd(
        &fix,
        "run-cwd-nonsandbox",
        json!({"project": "acme", "executable": "/bin/cat", "argv": ["cat", "../marker.txt"], "cwd": sub.to_str().unwrap()}),
    );
    assert!(started.ok, "started must succeed, got {started:?}");
    let exited = exited.unwrap();
    assert!(exited.ok, "exited must succeed, got {exited:?}");
    assert!(
        out.contains(marker),
        "child in authorized subdir must read parent marker via normal OS access, got {out:?}"
    );
}
