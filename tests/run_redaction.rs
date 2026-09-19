//! Redaction RED tests for `run_with_secrets` (Phase 5).
//!
//! Currently RED: the op answers `E_PROTOCOL op not available`, so every
//! `assert!(started.ok, …)` below fails for the right reason.
//!
//! When green, these three grouped tests prove the broker boundary:
//! values reach the child via the passed FDs only — never wire responses,
//! errors, daemon output, or audit. Audit is structural
//! (`actor/project/keys/run_id/executable/cwd/decision/result/arg_count`)
//! and never stores a secret value or the full argv.

#[path = "common/mod.rs"]
mod common;

use std::io::{BufReader, Read};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

use serde_json::json;

fn random_trap(prefix: &str) -> String {
    let mut buf = [0u8; 9];
    let filled = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            let mut n = 0;
            while n < buf.len() {
                let k = f.read(&mut buf[n..])?;
                if k == 0 {
                    break;
                }
                n += k;
            }
            Ok::<_, std::io::Error>(())
        })
        .is_ok();
    if !filled {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((t >> (i * 5)) as u8).wrapping_add(std::process::id() as u8);
        }
    }
    let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}-{hex}")
}

/// Like `common::setup` but with caller-chosen secrets and a `run` grant.
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
    s.grant_add("human", "harness", "acme", &[Op::Run]).unwrap();
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

struct RunCapture {
    started: svault::wire::Response,
    exited: Option<svault::wire::Response>,
    stdout: String,
    stderr: String,
    wire_joined: String,
}

/// Send `run_with_secrets` with exactly three FDs (stdin=/dev/null,
/// stdout+stderr pipes). Both response lines are read on one `BufReader`.
/// A rejected run yields `None` for `exited` and empty stdio.
fn run_capture(fix: &common::Fixture, id: &str, params: serde_json::Value) -> RunCapture {
    let mut stream = common::connect(&fix.socket);
    let (stdout_r, stdout_w) = common::make_pipe();
    let (stderr_r, stderr_w) = common::make_pipe();
    let stdin = common::open_devnull();
    let req = common::authed_request(id, "run_with_secrets", &fix.token, params);
    let fds = [
        stdin.as_raw_fd(),
        stdout_w.as_raw_fd(),
        stderr_w.as_raw_fd(),
    ];
    common::send_with_fds(&mut stream, &req, &fds).unwrap();
    drop((stdout_w, stderr_w, stdin));
    let mut reader = BufReader::new(&stream);
    let started = common::read_response(&mut reader).unwrap();
    let mut wire_joined = serde_json::to_string(&started).unwrap();
    if !started.ok {
        drop((stdout_r, stderr_r));
        return RunCapture {
            started,
            exited: None,
            stdout: String::new(),
            stderr: String::new(),
            wire_joined,
        };
    }
    let exited = common::read_response(&mut reader).unwrap();
    wire_joined.push('\n');
    wire_joined.push_str(&serde_json::to_string(&exited).unwrap());
    let mut stdout = String::new();
    std::fs::File::from(stdout_r)
        .read_to_string(&mut stdout)
        .unwrap();
    let mut stderr = String::new();
    std::fs::File::from(stderr_r)
        .read_to_string(&mut stderr)
        .unwrap();
    RunCapture {
        started,
        exited: Some(exited),
        stdout,
        stderr,
        wire_joined,
    }
}

fn err_code(resp: &svault::wire::Response) -> String {
    resp.error.as_ref().unwrap().code.clone()
}

fn result_body(resp: &svault::wire::Response) -> serde_json::Value {
    resp.result.clone().unwrap_or_default()
}

fn audit_text_for(fix: &common::Fixture) -> String {
    let vault_path = fix.dir.path().join("vault.enc");
    let audit_path = svault::store::audit_path(&vault_path);
    std::fs::read_to_string(audit_path).unwrap_or_default()
}

fn parse_audit(text: &str) -> Vec<serde_json::Value> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("audit line must be JSON"))
        .collect()
}

fn find_run_entry<'a>(entries: &'a [serde_json::Value], run_id: &str) -> &'a serde_json::Value {
    entries
        .iter()
        .find(|e| {
            e.get("op").and_then(|v| v.as_str()) == Some("run_with_secrets")
                && e.get("run_id").and_then(|v| v.as_str()) == Some(run_id)
        })
        .expect("audit must contain a run_with_secrets entry with the started run_id")
}

/// Structural audit contract shared by the success paths: metadata only,
/// never values or the full argv.
fn assert_structured_run_entry(
    entry: &serde_json::Value,
    run_id: &str,
    executable: &str,
    arg_count: u64,
) {
    let actor = entry.get("actor").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        actor.starts_with("agent:"),
        "audit actor must be agent:<id>, got {entry:?}"
    );
    assert_eq!(
        entry.get("project").and_then(|v| v.as_str()),
        Some("acme"),
        "audit must record project, got {entry:?}"
    );
    let keys = entry
        .get("keys")
        .and_then(|v| v.as_array())
        .expect("audit must carry a keys array");
    assert!(
        keys.iter().any(|k| k.as_str() == Some("STRIPE_KEY")),
        "audit must record key names, got {entry:?}"
    );
    assert_eq!(
        entry.get("executable").and_then(|v| v.as_str()),
        Some(executable),
        "audit must record executable structurally, got {entry:?}"
    );
    assert_eq!(
        entry.get("arg_count").and_then(|v| v.as_u64()),
        Some(arg_count),
        "audit must record arg_count, got {entry:?}"
    );
    assert_eq!(
        entry.get("run_id").and_then(|v| v.as_str()),
        Some(run_id),
        "audit must record run_id, got {entry:?}"
    );
    let cwd = entry.get("cwd").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        cwd.contains("authorized"),
        "audit must record cwd, got {entry:?}"
    );
    assert_eq!(
        entry.get("decision").and_then(|v| v.as_str()),
        Some("allowed"),
        "audit must record decision, got {entry:?}"
    );
    assert!(
        entry.get("result").is_some() || entry.get("exit_code").is_some(),
        "audit must record result/exit_code, got {entry:?}"
    );
    assert!(
        entry.get("argv").is_none(),
        "audit must never store the full argv, got {entry:?}"
    );
}

#[test]
fn successful_run_is_structured_and_redacted_everywhere() {
    let trap_selected = random_trap("sk-trap-selected");
    let trap_decoy = random_trap("sk-trap-decoy");
    let fix = setup_with(&[
        ("STRIPE_KEY", trap_selected.as_bytes()),
        ("DECOY_KEY", trap_decoy.as_bytes()),
    ]);
    let cwd_s = fix
        .dir
        .path()
        .join("authorized")
        .to_str()
        .unwrap()
        .to_string();
    let cap = run_capture(
        &fix,
        "redact-ok",
        json!({"project": "acme", "executable": "/usr/bin/env", "argv": ["env"],
               "cwd": cwd_s, "keys": ["STRIPE_KEY"]}),
    );

    // --- wire channel: two structured lines, no values ---
    assert!(
        cap.started.ok,
        "started must succeed, got {:?}",
        cap.started
    );
    let run_id = result_body(&cap.started)
        .get("run_id")
        .and_then(|v| v.as_str())
        .expect("started run_id")
        .to_string();
    assert!(
        !cap.wire_joined.contains(&trap_selected) && !cap.wire_joined.contains(&trap_decoy),
        "wire leaked a trap value: {}",
        cap.wire_joined
    );
    let exited = cap.exited.expect("exited line must follow started");
    assert!(exited.ok, "exited must succeed, got {exited:?}");
    assert!(
        result_body(&exited).get("exit_code").is_some(),
        "exited must carry exit_code, got {exited:?}"
    );

    // --- stdio channels: only the passed FDs carry values ---
    assert!(
        cap.stdout.contains(&trap_selected) && cap.stdout.contains("STRIPE_KEY="),
        "child stdout must carry the selected secret, got {:?}",
        cap.stdout
    );
    assert!(
        !cap.stdout.contains(&trap_decoy) && !cap.stdout.contains("DECOY_KEY="),
        "unselected secret leaked to child: {:?}",
        cap.stdout
    );
    assert!(
        !cap.stderr.contains(&trap_selected) && !cap.stderr.contains(&trap_decoy),
        "stderr leaked a trap value: {:?}",
        cap.stderr
    );

    // --- audit channel: structured metadata, no values ---
    let audit_text = audit_text_for(&fix);
    assert!(
        audit_text.contains("run_with_secrets"),
        "audit must record the run"
    );
    assert!(
        audit_text.contains("STRIPE_KEY"),
        "audit must record key names"
    );
    assert!(
        !audit_text.contains(&trap_selected) && !audit_text.contains(&trap_decoy),
        "audit leaked a trap value"
    );
    let entries = parse_audit(&audit_text);
    let entry = find_run_entry(&entries, &run_id);
    assert_structured_run_entry(entry, &run_id, "/usr/bin/env", 1);
    let entry_str = serde_json::to_string(entry).unwrap();
    assert!(
        !entry_str.contains(&trap_selected) && !entry_str.contains(&trap_decoy),
        "audit entry leaked a trap value: {entry_str}"
    );
}

#[test]
fn error_responses_and_audit_denials_exclude_randomized_traps() {
    let trap_a = random_trap("sk-trap-err-a");
    let trap_b = random_trap("sk-trap-err-b");
    let fix = setup_with(&[
        ("STRIPE_KEY", trap_a.as_bytes()),
        ("DECOY_KEY", trap_b.as_bytes()),
    ]);
    let outside = fix.dir.path().to_str().unwrap().to_string();

    // --- error channel 1: missing key fails closed ---
    let missing = run_capture(
        &fix,
        "redact-err-missing",
        json!({"project": "acme", "executable": "/usr/bin/env", "argv": ["env"],
               "keys": ["NO_SUCH_KEY"]}),
    );
    assert!(
        !missing.started.ok,
        "missing key must be denied, got {:?}",
        missing.started
    );
    assert_eq!(
        err_code(&missing.started),
        "E_NOT_FOUND",
        "got {:?}",
        missing.started
    );

    // --- error channel 2: cwd outside authorized folders ---
    let bad_cwd = run_capture(
        &fix,
        "redact-err-cwd",
        json!({"project": "acme", "executable": "/bin/pwd", "argv": ["pwd"], "cwd": outside}),
    );
    assert!(
        !bad_cwd.started.ok,
        "outside cwd must be denied, got {:?}",
        bad_cwd.started
    );
    assert_eq!(
        err_code(&bad_cwd.started),
        "E_PATH_NOT_AUTHORIZED",
        "got {:?}",
        bad_cwd.started
    );

    // --- error channel 3: executable carrying a trap must not be echoed ---
    let evil_exe = format!("/nonexistent-{}", trap_a);
    let evil = run_capture(
        &fix,
        "redact-err-exe",
        json!({"project": "acme", "executable": evil_exe, "argv": ["env"]}),
    );
    assert!(
        !evil.started.ok,
        "bad executable must be denied, got {:?}",
        evil.started
    );
    assert!(
        err_code(&evil.started).starts_with("E_"),
        "error code must be a stable E_* code, got {:?}",
        evil.started
    );

    // --- scan each error response separately: no trap anywhere on wire ---
    for (label, wire) in [
        ("missing-key", missing.wire_joined.as_str()),
        ("bad-cwd", bad_cwd.wire_joined.as_str()),
        ("bad-exe", evil.wire_joined.as_str()),
    ] {
        assert!(
            !wire.contains(&trap_a) && !wire.contains(&trap_b),
            "{label} error response leaked a trap: {wire}"
        );
        assert!(
            !wire.contains(&fix.token),
            "{label} error response leaked token material: {wire}"
        );
    }

    // --- audit channel: denials recorded with codes, never values ---
    let audit_text = audit_text_for(&fix);
    assert!(
        !audit_text.contains(&trap_a) && !audit_text.contains(&trap_b),
        "audit leaked a trap value"
    );
    assert!(
        !audit_text.contains(&fix.token),
        "audit leaked token material"
    );
    let entries = parse_audit(&audit_text);
    let denied: Vec<_> = entries
        .iter()
        .filter(|e| {
            e.get("op").and_then(|v| v.as_str()) == Some("run_with_secrets")
                && e.get("decision").and_then(|v| v.as_str()) == Some("denied")
        })
        .collect();
    assert!(
        denied.len() >= 2,
        "audit must record the denials, got {audit_text}"
    );
    for entry in denied {
        let reason = entry.get("reason").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            reason.starts_with("E_"),
            "denial must carry a stable E_* reason, got {entry:?}"
        );
        assert!(
            entry.get("argv").is_none(),
            "denial must not store argv, got {entry:?}"
        );
        let entry_str = serde_json::to_string(entry).unwrap();
        assert!(
            !entry_str.contains(&trap_a) && !entry_str.contains(&trap_b),
            "audit denial leaked a trap: {entry_str}"
        );
    }
}

#[test]
fn argv_traps_and_stderr_stay_off_wire_and_audit() {
    let trap_secret = random_trap("sk-trap-argv");
    let fix = setup_with(&[("STRIPE_KEY", trap_secret.as_bytes())]);
    let cwd_s = fix
        .dir
        .path()
        .join("authorized")
        .to_str()
        .unwrap()
        .to_string();

    // --- adversarial channel: argv carries the secret value itself ---
    // Whether the broker rejects (preferred) or scrubs, neither wire nor
    // audit may repeat the value or the full argv.
    let smuggled = run_capture(
        &fix,
        "redact-argv-smuggle",
        json!({"project": "acme", "executable": "/bin/echo",
               "argv": ["echo", trap_secret], "cwd": cwd_s, "keys": ["STRIPE_KEY"]}),
    );
    assert!(
        !smuggled.wire_joined.contains(&trap_secret),
        "wire repeated an argv-carried secret: {}",
        smuggled.wire_joined
    );
    if !smuggled.started.ok {
        assert!(
            err_code(&smuggled.started).starts_with("E_"),
            "argv-smuggle denial must use a stable code, got {:?}",
            smuggled.started
        );
    } else {
        // Allowed runs emit child output only on the passed FDs, never wire.
        assert!(
            !smuggled.wire_joined.contains(&trap_secret),
            "allowed run leaked argv secret on wire"
        );
    }
    assert!(
        !smuggled.stderr.contains(&trap_secret) || smuggled.stdout.contains(&trap_secret),
        "child output must stay on the passed FDs, not wire"
    );

    // --- stdio channel: one child writes the secret to both stdout+stderr ---
    let both = run_capture(
        &fix,
        "redact-stdio-both",
        json!({"project": "acme", "executable": "/bin/sh",
               "argv": ["sh", "-c", "echo $STRIPE_KEY; echo $STRIPE_KEY >&2"],
               "cwd": cwd_s, "keys": ["STRIPE_KEY"]}),
    );
    assert!(
        both.started.ok,
        "stdio run must start, got {:?}",
        both.started
    );
    let run_id = result_body(&both.started)
        .get("run_id")
        .and_then(|v| v.as_str())
        .expect("started run_id")
        .to_string();
    let exited = both.exited.expect("exited line must follow started");
    assert!(exited.ok, "stdio run must exit ok, got {exited:?}");

    // --- scan each collected channel separately ---
    assert!(
        both.stdout.contains(&trap_secret),
        "child stdout must carry the secret via its FD, got {:?}",
        both.stdout
    );
    assert!(
        both.stderr.contains(&trap_secret),
        "child stderr must carry the secret via its FD, got {:?}",
        both.stderr
    );
    assert!(
        !both.wire_joined.contains(&trap_secret),
        "wire leaked child-emitted secret: {}",
        both.wire_joined
    );
    let audit_text = audit_text_for(&fix);
    assert!(
        !audit_text.contains(&trap_secret),
        "audit leaked a secret value"
    );
    assert!(
        !audit_text.contains("echo $STRIPE_KEY; echo $STRIPE_KEY >&2"),
        "audit must never store the full argv"
    );
    let entries = parse_audit(&audit_text);
    for entry in entries
        .iter()
        .filter(|e| e.get("op").and_then(|v| v.as_str()) == Some("run_with_secrets"))
    {
        assert!(
            entry.get("argv").is_none(),
            "no audit entry may store argv, got {entry:?}"
        );
        let entry_str = serde_json::to_string(entry).unwrap();
        assert!(
            !entry_str.contains(&trap_secret),
            "audit entry leaked a secret: {entry_str}"
        );
    }
    let entry = find_run_entry(&entries, &run_id);
    assert_structured_run_entry(entry, &run_id, "/bin/sh", 3);
}
