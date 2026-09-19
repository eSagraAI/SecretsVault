//! Environment tests for `run_with_secrets` (RED phase).
//! Child-visible outcomes travel only through the passed stdout FD;
//! broker responses remain secret-free.

#[path = "common/mod.rs"]
mod common;

use std::io::{BufReader, Read};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

use serde_json::json;

fn err_code(resp: &svault::wire::Response) -> String {
    resp.error.as_ref().unwrap().code.clone()
}

/// Like `common::setup` but with caller-chosen secrets (the shared fixed
/// fixture cannot express these cases) and a `run`+`inject`+`read` grant.
fn setup_with(secrets: &[(&str, &[u8])]) -> common::Fixture {
    use std::sync::Arc;
    use std::time::Duration;
    use svault::broker::{Daemon, DaemonConfig};
    use svault::model::Op;
    use svault::session::{Session, SystemClock};
    use svault::wire::{AuthField, Request, VERSION};

    const PASS: &[u8] = b"correct horse battery";
    const IDLE: Duration = Duration::from_secs(60);

    let dir = common::TestDir::new();
    let vault_path = dir.path().join("vault.enc");
    let socket_path = dir.path().join("svault.sock");
    let authorized = dir.path().join("authorized");
    std::fs::create_dir_all(&authorized).unwrap();

    let mut s = Session::create(&vault_path, PASS, IDLE, Box::new(SystemClock)).unwrap();
    s.project_add("human", "acme", &[authorized]).unwrap();
    for (k, v) in secrets {
        s.secret_set("human", "acme", k, v).unwrap();
    }
    let (_id, token) = s.agent_add("human", "harness").unwrap();
    s.grant_add("human", "harness", "acme", &[Op::Run, Op::Inject, Op::Read])
        .unwrap();
    drop(s);

    let daemon = Daemon::new(DaemonConfig {
        socket_path: socket_path.clone(),
        vault_path: vault_path.clone(),
        idle_lock: IDLE,
    })
    .unwrap();
    let daemon = Arc::new(daemon);
    let srv = Arc::clone(&daemon);
    std::thread::spawn(move || {
        let _ = srv.serve();
    });
    for _ in 0..200 {
        if UnixStream::connect(&socket_path).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let unlock = daemon.handle_request(Request {
        v: VERSION,
        id: "unlock".to_string(),
        op: "vault.unlock".to_string(),
        auth: Some(AuthField {
            token: None,
            passphrase: Some("correct horse battery".to_string()),
            session: None,
        }),
        params: json!({}),
    });
    assert!(unlock.ok, "setup unlock failed: {:?}", unlock.error);
    common::Fixture {
        dir,
        token,
        socket: socket_path,
    }
}

/// Send `run_with_secrets` with exactly three FDs. Both response lines are
/// read on one `BufReader` (a second reader would lose bytes already
/// buffered with the first line). A rejected run yields `None` for `exited`.
fn run_env(
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

#[test]
fn selected_secrets_arrive_and_unselected_absent() {
    let fix = setup_with(&[
        ("STRIPE_KEY", common::TRAP.as_bytes()),
        ("DECOY_KEY", b"decoy-marker-9z81"),
    ]);
    let (started, exited, out) = run_env(
        &fix,
        "run-keys",
        json!({"project": "acme", "executable": "/usr/bin/env", "argv": ["env"], "keys": ["STRIPE_KEY"]}),
    );
    assert!(started.ok, "started must succeed, got {started:?}");
    let started_text = serde_json::to_string(&started).unwrap();
    assert!(started_text.contains("run_id"), "got {started_text}");
    assert!(
        !started_text.contains(common::TRAP) && !started_text.contains("decoy-marker-9z81"),
        "broker leaked secret: {started_text}"
    );
    let exited = exited.unwrap();
    assert!(exited.ok, "exited must succeed, got {exited:?}");
    let exited_text = serde_json::to_string(&exited).unwrap();
    assert!(exited_text.contains("exit_code"), "got {exited_text}");
    assert!(
        !exited_text.contains(common::TRAP) && !exited_text.contains("decoy-marker-9z81"),
        "broker leaked secret: {exited_text}"
    );
    assert!(out.contains(common::TRAP), "child must see selected secret");
    assert!(out.contains("STRIPE_KEY="), "got {out}");
    assert!(
        !out.contains("decoy-marker-9z81") && !out.contains("DECOY_KEY="),
        "unselected secret leaked to child: {out}"
    );
}

#[test]
fn forbidden_env_never_reaches_child() {
    let fix = common::setup();
    let (started, exited, out) = run_env(
        &fix,
        "run-forbidden",
        json!({"project": "acme", "executable": "/usr/bin/env", "argv": ["env"],
            "env": {"SVAULT_TOKEN": "evil-token-abc123", "TOKEN": "evil2",
                    "PASSPHRASE": "evil-pass-abc123", "SVAULT_INTERNAL": "evil4",
                    "LD_PRELOAD": "/tmp/evil.so"}}),
    );
    assert!(started.ok, "started must succeed, got {started:?}");
    let started_text = serde_json::to_string(&started).unwrap();
    assert!(!started_text.contains(common::TRAP), "broker leaked secret");
    assert!(
        !started_text.contains("evil-token-abc123")
            && !started_text.contains("evil-pass-abc123")
            && !started_text.contains(&fix.token),
        "broker leaked token material: {started_text}"
    );
    let exited = exited.unwrap();
    assert!(exited.ok, "exited must succeed, got {exited:?}");
    let exited_text = serde_json::to_string(&exited).unwrap();
    assert!(
        !exited_text.contains("evil-token-abc123")
            && !exited_text.contains("evil-pass-abc123")
            && !exited_text.contains(&fix.token),
        "broker leaked token material: {exited_text}"
    );
    assert!(out.contains(common::TRAP), "child must still see secrets");
    assert!(
        !out.contains("evil-token-abc123") && !out.contains("evil-pass-abc123"),
        "forbidden values reached child: {out}"
    );
    assert!(
        !out.contains("SVAULT_TOKEN=") && !out.contains("SVAULT_INTERNAL="),
        "token/internal vars reached child: {out}"
    );
    assert!(
        !out.contains("TOKEN=") && !out.contains("PASSPHRASE="),
        "forbidden token/passphrase vars reached child: {out}"
    );
    assert!(
        !out.contains("LD_PRELOAD="),
        "forbidden LD_PRELOAD reached child: {out}"
    );
}

#[test]
fn tricky_values_survive_exactly() {
    let tricky = "ünï✓=a$b\nL2\tT$HOME";
    let fix = setup_with(&[("TRICKY_KEY", tricky.as_bytes())]);
    let (started, exited, out) = run_env(
        &fix,
        "run-tricky",
        json!({"project": "acme", "executable": "/usr/bin/printenv",
               "argv": ["printenv", "TRICKY_KEY"], "keys": ["TRICKY_KEY"]}),
    );
    assert!(started.ok, "started must succeed, got {started:?}");
    let started_text = serde_json::to_string(&started).unwrap();
    assert!(!started_text.contains("ünï✓"), "broker leaked value");
    let exited = exited.unwrap();
    assert!(exited.ok, "exited must succeed, got {exited:?}");
    let exited_text = serde_json::to_string(&exited).unwrap();
    assert!(!exited_text.contains("ünï✓"), "broker leaked value");
    assert_eq!(out, format!("{tricky}\n"), "value must survive exactly");
}

#[test]
fn nul_secret_accepted_at_rest_but_rejected_for_run_and_unchanged() {
    let nul: &[u8] = b"a\x00b";
    let fix = setup_with(&[("GOOD_KEY", b"good-value-123"), ("NUL_KEY", nul)]);
    // Run selecting the NUL secret must be rejected (env cannot carry NUL).
    let mut stream = common::connect(&fix.socket);
    let (stdout_r, stdout_w) = common::make_pipe();
    let stdin = common::open_devnull();
    let stderr = common::open_devnull();
    let req = common::authed_request(
        "run-nul",
        "run_with_secrets",
        &fix.token,
        json!({"project": "acme", "executable": "/usr/bin/env", "argv": ["env"], "keys": ["NUL_KEY"]}),
    );
    let fds = [stdin.as_raw_fd(), stdout_w.as_raw_fd(), stderr.as_raw_fd()];
    common::send_with_fds(&mut stream, &req, &fds).unwrap();
    drop((stdout_w, stdin, stderr, stdout_r));
    let mut reader = BufReader::new(&stream);
    let resp = common::read_response(&mut reader).unwrap();
    assert!(
        !resp.ok,
        "run with NUL value must be rejected, got {resp:?}"
    );
    assert_eq!(err_code(&resp), "E_INVALID_INPUT", "got {resp:?}");
    let text = serde_json::to_string(&resp).unwrap();
    assert!(!text.contains("good-value-123"), "broker leaked secret");

    // Vault unchanged: GOOD_KEY still injects with exact bytes on disk.
    let mut s2 = common::connect(&fix.socket);
    let req2 = common::authed_request(
        "inject-good",
        "inject_file",
        &fix.token,
        json!({"project": "acme", "path": "good.env", "keys": ["GOOD_KEY"]}),
    );
    common::send_with_fds(&mut s2, &req2, &[]).unwrap();
    let mut r2 = BufReader::new(&s2);
    let ok = common::read_response(&mut r2).unwrap();
    assert!(ok.ok, "GOOD_KEY inject must still succeed, got {ok:?}");
    let path = ok.result.as_ref().unwrap()["path"]
        .as_str()
        .unwrap()
        .to_string();
    let bytes = std::fs::read(&path).unwrap();
    assert!(
        bytes
            .windows(b"good-value-123".len())
            .any(|w| w == b"good-value-123"),
        "file must carry GOOD_KEY bytes"
    );

    // NUL_KEY still present: selecting it for inject still rejects on its
    // value bytes (E_INVALID_INPUT), not E_NOT_FOUND.
    let mut s3 = common::connect(&fix.socket);
    let req3 = common::authed_request(
        "inject-nul",
        "inject_file",
        &fix.token,
        json!({"project": "acme", "path": "nul.env", "keys": ["NUL_KEY"]}),
    );
    common::send_with_fds(&mut s3, &req3, &[]).unwrap();
    let mut r3 = BufReader::new(&s3);
    let bad = common::read_response(&mut r3).unwrap();
    assert!(!bad.ok, "NUL_KEY inject must still reject, got {bad:?}");
    assert_eq!(err_code(&bad), "E_INVALID_INPUT", "got {bad:?}");
}
