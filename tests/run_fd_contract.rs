//! FD-passing contract for `run_with_secrets` (RED phase).
//! Raw protocol: params `{project,executable,argv,cwd?,keys?,env?}` with
//! exactly three SCM_RIGHTS FDs; `started` then `exited` response lines.

#[path = "common/mod.rs"]
mod common;

use std::io::{BufReader, Read};
use std::os::fd::AsRawFd;

use serde_json::json;

fn err_code(resp: &svault::wire::Response) -> String {
    resp.error.as_ref().unwrap().code.clone()
}

#[test]
fn zero_fds_is_rejected_safely() {
    let fix = common::setup();
    let mut stream = common::connect(&fix.socket);
    let req = common::authed_request(
        "run-zero",
        "run_with_secrets",
        &fix.token,
        json!({"project": "acme", "executable": "/usr/bin/env", "argv": ["env"]}),
    );
    common::send_with_fds(&mut stream, &req, &[]).unwrap();
    let mut reader = BufReader::new(&stream);
    let resp = common::read_response(&mut reader).unwrap();
    assert!(!resp.ok, "zero FDs must be rejected, got {resp:?}");
    assert_eq!(err_code(&resp), "E_INVALID_INPUT", "got {resp:?}");
}

#[test]
fn three_fds_runs_env_and_streams_stdout() {
    let fix = common::setup();
    let mut stream = common::connect(&fix.socket);
    let (stdout_r, stdout_w) = common::make_pipe();
    let stdin = common::open_devnull();
    let stderr = common::open_devnull();
    let req = common::authed_request(
        "run-env",
        "run_with_secrets",
        &fix.token,
        json!({"project": "acme", "executable": "/usr/bin/env", "argv": ["env"]}),
    );
    let fds = [stdin.as_raw_fd(), stdout_w.as_raw_fd(), stderr.as_raw_fd()];
    common::send_with_fds(&mut stream, &req, &fds).unwrap();
    drop((stdout_w, stdin, stderr));

    let mut reader = BufReader::new(&stream);
    let started = common::read_response(&mut reader).unwrap();
    assert!(started.ok, "started must succeed, got {started:?}");
    let started_text = serde_json::to_string(&started).unwrap();
    assert!(started_text.contains("run_id"), "got {started_text}");
    assert!(!started_text.contains(common::TRAP), "broker leaked secret");
    let exited = common::read_response(&mut reader).unwrap();
    assert!(exited.ok, "exited must succeed, got {exited:?}");
    let exited_text = serde_json::to_string(&exited).unwrap();
    assert!(exited_text.contains("exit_code"), "got {exited_text}");

    let mut out = String::new();
    let mut f = std::fs::File::from(stdout_r);
    f.read_to_string(&mut out).unwrap();
    assert!(out.contains(common::TRAP), "child stdout must carry secret");
}
