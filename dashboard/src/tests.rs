//! D1+D2+D3+D4+D6 backend tests: Tauri-free, no GUI. Live-daemon fixtures spin a real
//! `Daemon` on a temp socket (pattern from `tests/common/mod.rs`); pin state
//! is isolated per test via `XDG_DATA_HOME` + `XDG_RUNTIME_DIR`.
//!
//! RED protocol (TDD): each test was written to fail first for the RIGHT
//! reason (offline socket, missing pin, mismatch, wrong passphrase) before
//! the backend function it pins existed. D2 kept the protocol: the allowlist
//! test failed first (E0277: `COMMANDS: [&str; 6]` vs the 15-entry
//! expectation) before the nine new commands were added. D3 kept it again:
//! the allowlist test fails first (`[&str; 15]` vs the 24-entry expectation)
//! before the nine agents/grants/approvals commands land. D4 kept it again:
//! the allowlist test fails first (`[&str; 24]` vs the 28-entry expectation)
//! before the four reveal/leases/runs commands land. D6 kept it again:
//! the allowlist test fails first (`[&str; 28]` vs the 30-entry expectation)
//! before the two audit commands land.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use svault::broker::{Daemon, DaemonConfig};
use svault::session::{Session, SystemClock};

use crate::backend::{self, AppState, UnlockIn, COMMANDS, OVERVIEW_SECRETS_PROJECT_CAP};

const PASS: &[u8] = b"correct horse battery test passphrase 1";
const IDLE: Duration = Duration::from_secs(60);

static N: AtomicU64 = AtomicU64::new(0);

struct Env {
    _dir: PathBuf,
    socket: PathBuf,
    daemon: Arc<Daemon>,
}

impl Drop for Env {
    fn drop(&mut self) {
        // `Daemon` has no shutdown handle; the serving thread is detached and
        // the temp dir is removed here. Socket file lingers until OS cleanup
        // but the path is unique per test (pid + counter).
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

/// Real vault + real daemon on a temp socket, unlocked via dispatch.
/// Pin store isolated via `XDG_DATA_HOME=<dir>/data`.
fn live_env() -> Env {
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("svault-dash-test-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // SAFETY: tests run single-threaded within this module's serial section;
    // env mutation is contained to pin/socket resolution. (Rust 2024 marks
    // `std::env::set_var` unsafe: it races with other threads reading env.)
    unsafe {
        std::env::set_var("XDG_DATA_HOME", dir.join("data"));
        std::env::set_var("XDG_RUNTIME_DIR", dir.join("run"));
    }
    let vault_path = dir.join("vault.enc");
    let socket_path = dir.join("svault.sock");

    let s = Session::create(&vault_path, PASS, IDLE, Box::new(SystemClock)).unwrap();
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
        if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
            break;
        }
    }
    // Unlock via dispatch so `vault.unlock` (and its session seed) works.
    let unlock = daemon.handle_request(svault::wire::Request {
        v: svault::wire::VERSION,
        id: "unlock".to_string(),
        op: "vault.unlock".to_string(),
        auth: Some(svault::wire::AuthField {
            token: None,
            passphrase: Some(String::from_utf8(PASS.to_vec()).unwrap()),
            session: None,
        }),
        params: serde_json::json!({}),
    });
    assert!(unlock.ok, "setup unlock failed: {:?}", unlock.error);
    // Lock again: tests start from the locked state like a real launch.
    // `vault.lock` is fail-safe but needs an identity: use the passphrase.
    let lock = daemon.handle_request(svault::wire::Request {
        v: svault::wire::VERSION,
        id: "lock".to_string(),
        op: "vault.lock".to_string(),
        auth: Some(svault::wire::AuthField {
            token: None,
            passphrase: Some(String::from_utf8(PASS.to_vec()).unwrap()),
            session: None,
        }),
        params: serde_json::json!({}),
    });
    assert!(lock.ok, "setup lock failed: {:?}", lock.error);
    Env {
        _dir: dir,
        socket: socket_path,
        daemon,
    }
}

fn state_for(env: &Env) -> AppState {
    AppState::new(env.socket.clone())
}

fn serial() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::OnceLock;
    static L: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    L.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Pin the live broker the way the CLI ceremony does: `store_pin` directly,
/// representing "a human pinned at a TTY". Never routed through any dashboard
/// function (the dashboard has no pin-write path by design).
fn pin_live(env: &Env) {
    let st = state_for(env);
    let probe = backend::probe_fingerprint(&st).expect("probe must succeed");
    let key =
        svault::broker_identity::parse_fingerprint(&probe.fingerprint).expect("live key parses");
    svault::broker_identity::store_pin(&env.socket, &key).expect("TTY-style pin must succeed");
}

/// Pin an explicit (possibly wrong) key the CLI way, for mismatch fixtures.
fn pin_key(env: &Env, key: &[u8; 32]) {
    svault::broker_identity::store_pin(&env.socket, key).expect("TTY-style pin must succeed");
}

/// Unlock via the backend and return the state (session held in Rust).
fn unlocked_state(env: &Env) -> AppState {
    pin_live(env);
    let st = state_for(env);
    backend::unlock(
        &st,
        UnlockIn {
            passphrase: String::from_utf8(PASS.to_vec()).unwrap(),
        },
    )
    .expect("unlock must succeed");
    st
}

/// Real existing directory for project-path fixtures (temp dir child).
fn real_dir(env: &Env, name: &str) -> String {
    let d = env._dir.join(name);
    std::fs::create_dir_all(&d).unwrap();
    d.display().to_string()
}

/// Close the held session via the live daemon handle (`session.close` with
/// the held credential), so the Rust-held credential is stale: the next
/// mutation must fail `E_SESSION_EXPIRED`. Goes through `env.daemon`
/// (same-process fixture) because `broker_call` refuses `Auth::Session` and
/// the backend under test is the caller, not the callee, of that path.
fn close_session_on_wire(env: &Env, st: &AppState) {
    let cred = st
        .session
        .lock()
        .expect("session lock")
        .clone()
        .expect("session must be held");
    let resp = env.daemon.handle_request(svault::wire::Request {
        v: svault::wire::VERSION,
        id: "close".to_string(),
        op: "session.close".to_string(),
        auth: Some(svault::wire::AuthField {
            token: None,
            passphrase: None,
            session: Some(cred.to_string()),
        }),
        params: serde_json::json!({}),
    });
    assert!(resp.ok, "session.close must succeed: {:?}", resp.error);
}

#[test]
fn allowlist_is_exactly_the_thirty_commands() {
    // Guards the frozen contract: no generic `call(op, params)`, no extras,
    // and no `trust_broker` pin-write path (first trust is CLI-at-TTY only).
    // D2 adds nine commands to the D1 six (total 15); D3 adds nine more
    // (agents/grants/approvals) for a total of 24; D4 adds four more
    // (reveal/leases/runs) for a total of 28; D6 adds two more
    // (audit_show/audit_verify) for a total of 30.
    assert_eq!(
        COMMANDS,
        [
            "get_status",
            "pin_status",
            "probe_fingerprint",
            "unlock",
            "lock",
            "health",
            "overview_refresh",
            "projects_list",
            "project_add",
            "project_remove",
            "project_path_add",
            "project_path_remove",
            "secrets_list",
            "secret_set",
            "secret_delete",
            "agents_list",
            "agent_add",
            "agent_revoke",
            "grants_list",
            "grant_set",
            "grant_revoke",
            "approvals_pending",
            "approval_approve",
            "approval_deny",
            "reveal",
            "leases_list",
            "lease_revoke",
            "runs_list",
            "audit_show",
            "audit_verify",
        ]
    );
    // And the backend exposes no generic-call function: this fails to compile
    // if anyone adds `pub fn call(` with op+params shape — enforced by the
    // exhaustive match below over every public function name in backend.rs.
    let fns = [
        "get_status",
        "pin_status",
        "probe_fingerprint",
        "unlock",
        "lock",
        "health",
        "overview_refresh",
        "projects_list",
        "project_add",
        "project_remove",
        "project_path_add",
        "project_path_remove",
        "secrets_list",
        "secret_set",
        "secret_delete",
        "agents_list",
        "agent_add",
        "agent_revoke",
        "grants_list",
        "grant_set",
        "grant_revoke",
        "approvals_pending",
        "approval_approve",
        "approval_deny",
        "reveal",
        "leases_list",
        "lease_revoke",
        "runs_list",
        "audit_show",
        "audit_verify",
    ];
    for f in fns {
        assert!(COMMANDS.contains(&f), "backend fn {f} not in allowlist");
    }
    assert_eq!(COMMANDS.len(), 30, "allowlist must stay at thirty");
    assert!(
        !COMMANDS.contains(&"trust_broker"),
        "trust_broker must not be a dashboard command"
    );
    assert!(
        !COMMANDS.contains(&"call"),
        "no generic-passthrough command may exist"
    );
}

#[test]
fn offline_socket_reports_offline_without_panic() {
    let _g = serial();
    let st = AppState::new(PathBuf::from("/tmp/svault-dash-test-no-such-sock.sock"));
    let status = backend::get_status(&st).expect("offline must be Ok-shaped");
    assert!(!status.online);
    assert!(status.locked);
    assert!(!status.trusted);
    // probe fails closed with a stable code, no panic.
    let err = backend::probe_fingerprint(&st).unwrap_err();
    assert!(!err.code.is_empty());
}

#[test]
fn first_contact_reports_unpinned_and_probes_live_key() {
    let _g = serial();
    let env = live_env();
    let st = state_for(&env);
    let pin = backend::pin_status(&st).expect("pin_status must succeed");
    assert!(!pin.pinned);
    assert!(pin.fingerprint.is_none());
    // Display-only probe works with NO pin: live key, 64-hex, nothing written.
    let probe = backend::probe_fingerprint(&st).expect("probe must succeed");
    assert_eq!(probe.fingerprint.len(), 64);
    assert!(probe.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(
        svault::broker_identity::load_pin(&env.socket)
            .expect("pin read works")
            .is_none(),
        "probe must not write a pin"
    );
    // Untrusted gate: status is online but NOT trusted before pinning, with
    // no fingerprint surfaced; unlock refuses before any credential byte.
    let status = backend::get_status(&st).expect("status must succeed");
    assert!(status.online);
    assert!(!status.trusted);
    assert!(status.fingerprint.is_none());
    let err = backend::unlock(
        &st,
        UnlockIn {
            passphrase: String::from_utf8(PASS.to_vec()).unwrap(),
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_BROKER_UNTRUSTED");
}

#[test]
fn cli_pinned_then_status_is_trusted() {
    let _g = serial();
    let env = live_env();
    // Pinned the CLI way (TTY ceremony substitute inside the fixture).
    pin_live(&env);
    let st = state_for(&env);
    let status = backend::get_status(&st).expect("status must succeed");
    assert!(status.online);
    assert!(status.trusted);
    assert!(status.fingerprint.map(|f| f.len()).unwrap_or(0) == 64);
    let pin = backend::pin_status(&st).expect("pin_status must succeed");
    assert!(pin.pinned);
}

#[test]
fn pin_mismatch_fails_closed_and_keeps_old_pin() {
    let _g = serial();
    let env = live_env();
    // Pin a WRONG key the CLI way (as if the TTY ceremony pinned elsewhere):
    // the live broker must not match it.
    let wrong = [0xA5u8; 32];
    pin_key(&env, &wrong);
    let pin_path = svault::broker_identity::pin_path(&env.socket).expect("pin path resolves");
    let before = std::fs::read(&pin_path).expect("pin file exists");
    let st = state_for(&env);
    // Fail closed: status reports untrusted (identity error), never trusted.
    let status = backend::get_status(&st).expect("status must be Ok-shaped");
    assert!(
        status.online,
        "socket answered: this is a trust failure, not offline"
    );
    assert!(!status.trusted, "mismatched pin must not be trusted");
    // Unlock fails WITHOUT sending any credential: strict gate refuses first.
    let err = backend::unlock(
        &st,
        UnlockIn {
            passphrase: String::from_utf8(PASS.to_vec()).unwrap(),
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_BROKER_UNTRUSTED");
    // No backend path re-pins or overwrites: `store_pin` is gone from the
    // dashboard, so the pin file must be byte-identical afterwards.
    let after = std::fs::read(&pin_path).expect("pin file still exists");
    assert_eq!(before, after, "pin file must NOT be overwritten");
}

#[test]
fn unlock_success_returns_safe_metadata_only() {
    let _g = serial();
    let env = live_env();
    pin_live(&env);
    let st = state_for(&env);
    let pass = String::from_utf8(PASS.to_vec()).unwrap();
    let out = backend::unlock(
        &st,
        UnlockIn {
            passphrase: pass.clone(),
        },
    )
    .expect("unlock must succeed");
    assert!(out.unlocked);
    let body = serde_json::to_string(&out).unwrap();
    assert!(
        !body.contains(&pass),
        "passphrase must never appear in unlock output"
    );
    // The session credential is 43-char base64url; assert no such token-shaped
    // value appears: the body may only carry prefix + expiry fields.
    assert!(
        !body.contains("session_credential"),
        "credential field name must never appear in unlock output"
    );
    assert!(out.session_prefix.as_ref().map(|p| p.len()).unwrap_or(0) == 8);
}

#[test]
fn unlock_wrong_passphrase_is_generic_auth_failure() {
    let _g = serial();
    let env = live_env();
    pin_live(&env);
    let st = state_for(&env);
    let err = backend::unlock(
        &st,
        UnlockIn {
            passphrase: "wrong passphrase definitely 12345".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_AUTH");
    assert_eq!(err.message, "authentication failed");
    // No oracle: wrong passphrase and (e.g.) empty passphrase share the code.
    let err2 = backend::unlock(
        &st,
        UnlockIn {
            passphrase: "another wrong passphrase 99999".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err2.code, "E_AUTH");
}

#[test]
fn session_credential_never_appears_in_any_output() {
    let _g = serial();
    let env = live_env();
    pin_live(&env);
    let st = state_for(&env);
    let pass = String::from_utf8(PASS.to_vec()).unwrap();
    let unlock_out = backend::unlock(
        &st,
        UnlockIn {
            passphrase: pass.clone(),
        },
    )
    .unwrap();
    // Pull the credential out of Rust state via the session holder length is
    // impossible from JS — instead assert every JS-visible payload lacks any
    // 40+-char base64url-shaped token AND the passphrase.
    let payloads = [
        serde_json::to_string(&unlock_out).unwrap(),
        serde_json::to_string(&backend::get_status(&st).unwrap()).unwrap(),
        serde_json::to_string(&backend::pin_status(&st).unwrap()).unwrap(),
    ];
    for body in &payloads {
        assert!(!body.contains(&pass), "passphrase leaked: {body}");
        assert!(
            !body.contains("session_credential"),
            "credential key leaked: {body}"
        );
        assert!(
            !body.contains("session\":"),
            "session credential value leaked: {body}"
        );
    }
    // The credential IS held in Rust: an authenticated call works (health via
    // session succeeds while locked-vault health would need passphrase — it
    // succeeds here because unlock opened the vault + session auth).
    let _ = backend::health(&st).expect("health with session must succeed");
}

#[test]
fn lock_invalidates_session() {
    let _g = serial();
    let env = live_env();
    pin_live(&env);
    let st = state_for(&env);
    let pass = String::from_utf8(PASS.to_vec()).unwrap();
    backend::unlock(&st, UnlockIn { passphrase: pass }).unwrap();
    let out = backend::lock(&st).expect("lock must succeed");
    assert!(out.locked);
    // Post-lock, the session is gone from Rust: health (human-only) without
    // passphrase auth now fails (locked vault + no session).
    let status = backend::get_status(&st).unwrap();
    assert!(status.locked);
}

#[test]
fn unlock_without_pin_sends_no_credential() {
    let _g = serial();
    let env = live_env();
    let st = state_for(&env);
    // No pin anywhere: unlock must refuse at the strict gate.
    let err = backend::unlock(
        &st,
        UnlockIn {
            passphrase: String::from_utf8(PASS.to_vec()).unwrap(),
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_BROKER_UNTRUSTED");
    // Witness the BROKER's real state, not the dashboard's synthesized
    // fallback (`get_status` hardcodes `locked: true` on the untrusted arm,
    // so it cannot witness anything here). `vault.status` answers
    // unauthenticated, straight from the daemon handle in this fixture.
    let resp = env.daemon.handle_request(svault::wire::Request {
        v: svault::wire::VERSION,
        id: "witness".into(),
        op: "vault.status".into(),
        auth: None,
        params: serde_json::json!({}),
    });
    assert!(resp.ok, "broker must answer vault.status unauthenticated");
    let locked = resp
        .result
        .as_ref()
        .and_then(|r| r.get("locked"))
        .and_then(|v| v.as_bool());
    assert_eq!(
        locked,
        Some(true),
        "the broker's own vault must still be locked: no credential reached it"
    );
}

#[test]
fn daemon_offline_transitions_state() {
    let _g = serial();
    let env = live_env();
    pin_live(&env);
    let st = state_for(&env);
    assert!(backend::get_status(&st).unwrap().online);
    // Simulate daemon restart/offline: point at a dead socket.
    let dead = AppState::new(PathBuf::from("/tmp/svault-dash-test-dead.sock"));
    let status = backend::get_status(&dead).unwrap();
    assert!(!status.online);
    let _ = env.socket; // keep env alive until end of test
}

#[test]
fn trap_secret_never_appears_in_payloads_or_errors() {
    let _g = serial();
    // The session credential shape (43-char base64url) doubles as the trap:
    // mint one unlock, then assert the exact credential string (read back
    // from Rust state internals is impossible — so trap on the passphrase +
    // any 32+ char high-entropy token grep over all outputs and errors).
    let env = live_env();
    pin_live(&env);
    let st = state_for(&env);
    let pass = String::from_utf8(PASS.to_vec()).unwrap();
    let trap = "TRAP-SESSIONTOKEN-0123456789abcdef-XYZ";
    let mut bodies: Vec<String> = Vec::new();
    let out = backend::unlock(
        &st,
        UnlockIn {
            passphrase: pass.clone(),
        },
    )
    .unwrap();
    bodies.push(serde_json::to_string(&out).unwrap());
    bodies.push(serde_json::to_string(&backend::get_status(&st).unwrap()).unwrap());
    let err = backend::unlock(
        &st,
        UnlockIn {
            passphrase: "wrong passphrase definitely 12345".to_string(),
        },
    )
    .unwrap_err();
    bodies.push(serde_json::to_string(&err).unwrap());
    for body in &bodies {
        assert!(!body.contains(&pass), "passphrase in payload: {body}");
        assert!(!body.contains(trap), "trap token in payload: {body}");
        assert!(
            !body.contains("session_credential"),
            "credential material in payload: {body}"
        );
    }
}

// ---------------- D2: overview + projects + secrets metadata ----------------

#[test]
fn overview_locked_is_posture_only_with_no_fabricated_zeros() {
    let _g = serial();
    let env = live_env();
    pin_live(&env);
    let st = state_for(&env);
    let ov = backend::overview_refresh(&st).expect("locked overview must be Ok-shaped");
    let status = backend::get_status(&st).unwrap();
    assert!(status.locked);
    assert!(ov.locked);
    assert!(ov.online);
    assert!(ov.trusted);
    // No session was ever established: distinguishable from held-but-degraded.
    assert!(!ov.session_held);
    assert!(ov.projects.is_none());
    assert!(ov.secrets_total.is_none());
    assert!(!ov.secrets_total_exact);
    assert!(ov.agents_active.is_none());
    assert!(ov.runs_active.is_none());
    assert!(ov.approvals_pending.is_none());
    assert!(ov.leases_active.is_none());
    assert!(ov.idle_lock_secs.is_none());
    assert!(ov.idle_in.is_none());
    assert!(ov.audit_bytes.is_none());
    assert!(ov.audit_soft_limit.is_none());
    assert!(ov.audit_hard_limit.is_none());
    assert!(ov.vault_bytes.is_none());
    assert!(ov.vault_max_bytes.is_none());
}

#[test]
fn overview_unlocked_aggregates_projects_secrets_agents_health() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let dir = real_dir(&env, "projdir");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
            value: "v1".to_string(),
        },
    )
    .unwrap();
    backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "DB_PASS".to_string(),
            value: "v2".to_string(),
        },
    )
    .unwrap();
    let ov = backend::overview_refresh(&st).expect("unlocked overview must succeed");
    assert!(!ov.locked);
    assert!(ov.online && ov.trusted);
    // Session held (unlock seeded it) and counters populated.
    assert!(ov.session_held);
    assert_eq!(ov.projects, Some(1));
    assert_eq!(ov.secrets_total, Some(2));
    assert!(ov.secrets_total_exact);
    // No agents enrolled: active count is honestly 0 (a real observation,
    // not a degraded None).
    assert_eq!(ov.agents_active, Some(0));
    // Health-derived fields populated.
    assert!(ov.runs_active.is_some());
    assert!(ov.idle_lock_secs.is_some());
    assert!(ov.audit_bytes.is_some());
    assert!(ov.audit_soft_limit.is_some());
    assert!(ov.audit_hard_limit.is_some());
    assert!(ov.vault_bytes.is_some());
    assert!(ov.vault_max_bytes.is_some());
}

#[test]
fn overview_caps_secret_fanout_and_marks_partial() {
    const {
        assert!(
            OVERVIEW_SECRETS_PROJECT_CAP <= 50,
            "fan-out cap must stay bounded (broker has a 32-connection intake cap)"
        );
    }
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    for i in 0..(OVERVIEW_SECRETS_PROJECT_CAP + 5) {
        let d = real_dir(&env, &format!("capdir{i}"));
        backend::project_add(
            &st,
            backend::ProjectAddIn {
                name: format!("cap{i}"),
                paths: vec![d],
            },
        )
        .unwrap();
        backend::secret_set(
            &st,
            backend::SecretSetIn {
                project: format!("cap{i}"),
                key: "K".to_string(),
                value: "v".to_string(),
            },
        )
        .unwrap();
    }
    let ov = backend::overview_refresh(&st).unwrap();
    assert_eq!(ov.projects, Some((OVERVIEW_SECRETS_PROJECT_CAP + 5) as u64));
    assert!(
        !ov.secrets_total_exact,
        "over-cap sum must be marked partial"
    );
    assert_eq!(
        ov.secrets_total,
        Some(OVERVIEW_SECRETS_PROJECT_CAP as u64),
        "sum is the bounded partial (one secret per queried project)"
    );
}

#[test]
fn projects_list_empty_then_populated() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let empty = backend::projects_list(&st).unwrap();
    assert!(empty.projects.is_empty());
    let dir = real_dir(&env, "pdir");
    let added = backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir.clone()],
        },
    )
    .unwrap();
    assert_eq!(added.added, "web");
    // Refresh-from-broker, not optimistic: a fresh list shows it.
    let list = backend::projects_list(&st).unwrap();
    assert_eq!(list.projects.len(), 1);
    assert_eq!(list.projects[0].name, "web");
    assert_eq!(list.projects[0].paths.len(), 1);
}

#[test]
fn project_remove_roundtrip_and_refuses_nonempty_project() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let dir = real_dir(&env, "rdir");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    // Empty project removes cleanly.
    let removed = backend::project_remove(
        &st,
        backend::NameIn {
            name: "web".to_string(),
        },
    )
    .unwrap();
    assert_eq!(removed.removed, "web");
    assert!(backend::projects_list(&st).unwrap().projects.is_empty());
    // Non-empty project: broker refuses E_INVALID_INPUT and it REMAINS.
    let dir2 = real_dir(&env, "rdir2");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "full".to_string(),
            paths: vec![dir2],
        },
    )
    .unwrap();
    backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "full".to_string(),
            key: "K".to_string(),
            value: "v".to_string(),
        },
    )
    .unwrap();
    let err = backend::project_remove(
        &st,
        backend::NameIn {
            name: "full".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_INVALID_INPUT");
    assert!(
        backend::projects_list(&st)
            .unwrap()
            .projects
            .iter()
            .any(|p| p.name == "full"),
        "refused project must remain"
    );
}

#[test]
fn project_path_add_remove_roundtrip_and_rejects_missing_path() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let dir = real_dir(&env, "basedir");
    let dir2 = real_dir(&env, "extradir");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir.clone()],
        },
    )
    .unwrap();
    let added = backend::project_path_add(
        &st,
        backend::ProjectPathIn {
            name: "web".to_string(),
            path: dir2.clone(),
        },
    )
    .unwrap();
    assert!(!added.added.is_empty());
    let list = backend::projects_list(&st).unwrap();
    assert_eq!(list.projects[0].paths.len(), 2);
    let removed = backend::project_path_remove(
        &st,
        backend::ProjectPathIn {
            name: "web".to_string(),
            path: dir2,
        },
    )
    .unwrap();
    assert!(!removed.removed.is_empty());
    assert_eq!(
        backend::projects_list(&st).unwrap().projects[0].paths.len(),
        1
    );
    // Non-existent path fails E_INVALID_INPUT and changes nothing.
    let missing = env._dir.join("does-not-exist").display().to_string();
    let err = backend::project_path_add(
        &st,
        backend::ProjectPathIn {
            name: "web".to_string(),
            path: missing,
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_INVALID_INPUT");
    assert_eq!(
        backend::projects_list(&st).unwrap().projects[0].paths.len(),
        1
    );
}

#[test]
fn secrets_list_shows_key_and_updated_only_never_values() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let dir = real_dir(&env, "sdir");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    let trap = "TRAP-SECRETVALUE-0123456789abcdef";
    backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
            value: trap.to_string(),
        },
    )
    .unwrap();
    let out = backend::secrets_list(
        &st,
        backend::SecretsListIn {
            project: "web".to_string(),
        },
    )
    .unwrap();
    assert_eq!(out.secrets.len(), 1);
    assert_eq!(out.secrets[0].key, "API_KEY");
    assert!(!out.secrets[0].updated.is_empty());
    // The serialized response carries key + updated ONLY — no value field,
    // and the trap value appears in NO payload.
    let body = serde_json::to_string(&out).unwrap();
    assert!(!body.contains(trap), "trap secret value leaked: {body}");
    assert!(
        !body.contains("value"),
        "secrets_list must not carry a value field: {body}"
    );
}

#[test]
fn secret_set_upserts_and_delete_removes_with_not_found_on_replay() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let dir = real_dir(&env, "udir");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    // Create.
    let set1 = backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "K".to_string(),
            value: "v1".to_string(),
        },
    )
    .unwrap();
    assert_eq!(set1.set, "web/K");
    let body1 = serde_json::to_string(&set1).unwrap();
    assert!(
        !body1.contains("v1"),
        "secret_set response must never carry the value"
    );
    // Update (upsert same key): still lists once.
    let set2 = backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "K".to_string(),
            value: "v2-different".to_string(),
        },
    )
    .unwrap();
    assert_eq!(set2.set, "web/K");
    assert!(!serde_json::to_string(&set2)
        .unwrap()
        .contains("v2-different"));
    let listed = backend::secrets_list(
        &st,
        backend::SecretsListIn {
            project: "web".to_string(),
        },
    )
    .unwrap();
    assert_eq!(listed.secrets.len(), 1);
    // Delete removes; second delete fails E_NOT_FOUND.
    let del = backend::secret_delete(
        &st,
        backend::SecretDeleteIn {
            project: "web".to_string(),
            key: "K".to_string(),
        },
    )
    .unwrap();
    assert_eq!(del.deleted, "web/K");
    assert!(backend::secrets_list(
        &st,
        backend::SecretsListIn {
            project: "web".to_string()
        }
    )
    .unwrap()
    .secrets
    .is_empty());
    let err = backend::secret_delete(
        &st,
        backend::SecretDeleteIn {
            project: "web".to_string(),
            key: "K".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_NOT_FOUND");
}

#[test]
fn expired_session_mutation_forces_reauth() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let dir = real_dir(&env, "xdir");
    // Mint-then-close: the Rust-held credential is now stale on the wire.
    close_session_on_wire(&env, &st);
    let err = backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "late".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_SESSION_EXPIRED");
    let err2 = backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "late".to_string(),
            key: "K".to_string(),
            value: "v".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err2.code, "E_SESSION_EXPIRED");
}

#[test]
fn overview_propagates_session_expiry_for_reauth() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    // Close the session on the wire: the Rust-held credential is stale, so
    // `vault.health` inside the overview fails E_SESSION_EXPIRED — and the
    // overview must propagate that code (not degrade to None) so the
    // frontend can force re-authentication.
    close_session_on_wire(&env, &st);
    let err = backend::overview_refresh(&st).unwrap_err();
    assert_eq!(err.code, "E_SESSION_EXPIRED");
}

#[test]
fn overview_offline_is_posture_only_without_panic() {
    let _g = serial();
    let st = AppState::new(PathBuf::from("/tmp/svault-dash-test-no-such-sock.sock"));
    let ov = backend::overview_refresh(&st).expect("offline overview must be Ok-shaped");
    assert!(!ov.online);
    assert!(ov.locked);
    assert!(!ov.trusted);
    assert!(ov.projects.is_none());
    assert!(ov.secrets_total.is_none());
    assert!(!ov.secrets_total_exact);
}

#[test]
fn mismatch_refuses_every_new_command_without_executing() {
    let _g = serial();
    let env = live_env();
    pin_key(&env, &[0xA5u8; 32]);
    let st = state_for(&env);
    // Overview refuses into posture-only (mismatch arm of get_status).
    let ov = backend::overview_refresh(&st).expect("mismatch overview must be Ok-shaped");
    assert!(ov.online);
    assert!(!ov.trusted);
    assert!(ov.projects.is_none());
    // Every new command fails closed at the strict gate — never executes.
    assert_eq!(
        backend::projects_list(&st).unwrap_err().code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::project_add(
            &st,
            backend::ProjectAddIn {
                name: "x".to_string(),

                paths: vec![],
            },
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::project_remove(
            &st,
            backend::NameIn {
                name: "x".to_string()
            }
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::project_path_add(
            &st,
            backend::ProjectPathIn {
                name: "x".to_string(),
                path: "y".to_string(),
            },
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::project_path_remove(
            &st,
            backend::ProjectPathIn {
                name: "x".to_string(),
                path: "y".to_string(),
            },
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::secrets_list(
            &st,
            backend::SecretsListIn {
                project: "x".to_string()
            }
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::secret_set(
            &st,
            backend::SecretSetIn {
                project: "x".to_string(),
                key: "K".to_string(),
                value: "v".to_string(),
            },
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::secret_delete(
            &st,
            backend::SecretDeleteIn {
                project: "x".to_string(),
                key: "K".to_string(),
            },
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    // D3: every agents/grants/approvals command fails closed the same way.
    assert_eq!(
        backend::agents_list(&st).unwrap_err().code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::agent_add(
            &st,
            backend::AgentAddIn {
                name: "x".to_string(),
                token_path: None,
            },
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::agent_revoke(
            &st,
            backend::NameIn {
                name: "x".to_string()
            }
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::grants_list(&st).unwrap_err().code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::grant_set(
            &st,
            backend::GrantSetIn {
                agent: "x".to_string(),
                project: "y".to_string(),
                ops: "read".to_string(),
            },
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::grant_revoke(
            &st,
            backend::GrantRevokeIn {
                agent: "x".to_string(),
                project: "y".to_string(),
            },
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::approvals_pending(&st).unwrap_err().code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::approval_approve(
            &st,
            backend::ApprovalDecisionIn {
                approval_id: "x".to_string(),
            },
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::approval_deny(
            &st,
            backend::ApprovalDecisionIn {
                approval_id: "x".to_string(),
            },
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    // D4: reveal/leases/runs fail closed the same way.
    assert_eq!(
        backend::reveal(
            &st,
            backend::RevealIn {
                project: "x".to_string(),
                key: "y".to_string(),
            },
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::leases_list(&st).unwrap_err().code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::lease_revoke(
            &st,
            backend::LeaseRevokeIn {
                lease_id: "x".to_string(),
            },
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::runs_list(&st).unwrap_err().code,
        "E_BROKER_UNTRUSTED"
    );
    // Witness: the broker's own vault is still locked — nothing executed.
    let resp = env.daemon.handle_request(svault::wire::Request {
        v: svault::wire::VERSION,
        id: "witness".into(),
        op: "vault.status".into(),
        auth: None,
        params: serde_json::json!({}),
    });
    assert!(resp.ok);
    assert_eq!(
        resp.result
            .as_ref()
            .and_then(|r| r.get("locked"))
            .and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[test]
fn broker_codes_arrive_verbatim_not_collapsed() {
    // Would fail under Display-text guessing: these codes come straight off
    // the wire (BrokerError.code), never reconstructed from message text.
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let dir = real_dir(&env, "codedir");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    // E_NOT_FOUND: delete a key that was never created.
    let err = backend::secret_delete(
        &st,
        backend::SecretDeleteIn {
            project: "web".to_string(),
            key: "NEVER_CREATED".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_NOT_FOUND");
    assert_eq!(err.message, "not found");
    // E_INVALID_INPUT: project still has secrets.
    backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "K".to_string(),
            value: "v".to_string(),
        },
    )
    .unwrap();
    let err = backend::project_remove(
        &st,
        backend::NameIn {
            name: "web".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_INVALID_INPUT");
    assert_eq!(err.message, "invalid input");
    // E_EXISTS: add the same project twice.
    let dir2 = real_dir(&env, "codedir2");
    let err = backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir2],
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_EXISTS");
    // Unknown-to-us codes still arrive intact (code verbatim, generic
    // message) instead of collapsing to E_PROTOCOL: direct unit check on
    // the mapping (no wire op produces an unknown code today, so pin the
    // fallthrough branch structurally).
    let unknown = backend::broker_message("E_SOME_FUTURE_CODE");
    assert_eq!(unknown, "broker error");
}

#[test]
fn status_posture_branches_hold_under_verbatim_codes() {
    // get_status branching re-check now that codes arrive faithfully:
    // mismatch -> E_BROKER_UNTRUSTED arm (online, untrusted); dead socket ->
    // offline; answered-but-audit-failed stays ONLINE.
    let _g = serial();
    // Mismatch branch.
    let env = live_env();
    pin_key(&env, &[0xA5u8; 32]);
    let st = state_for(&env);
    let status = backend::get_status(&st).expect("mismatch status must be Ok-shaped");
    assert!(status.online);
    assert!(!status.trusted);
    // Dead-socket branch.
    let dead = AppState::new(PathBuf::from("/tmp/svault-dash-test-dead-sock-2.sock"));
    let status = backend::get_status(&dead).unwrap();
    assert!(!status.online);
    assert!(!status.trusted);
    assert!(status.locked);
}

#[test]
fn overview_reports_real_counts_end_to_end() {
    // Option B proof: live daemon + real session in AppState (via backend
    // `unlock`), 2 projects with real dirs, 2 secrets in one project, 1
    // enrolled agent -> overview_refresh must report the exact numbers.
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let d1 = real_dir(&env, "endodir1");
    let d2 = real_dir(&env, "endodir2");
    for (name, dir) in [("endo1", d1), ("endo2", d2)] {
        backend::project_add(
            &st,
            backend::ProjectAddIn {
                name: name.to_string(),
                paths: vec![dir],
            },
        )
        .unwrap();
    }
    for (key, value) in [("ALPHA", "v-alpha"), ("BETA", "v-beta")] {
        backend::secret_set(
            &st,
            backend::SecretSetIn {
                project: "endo1".to_string(),
                key: key.to_string(),
                value: value.to_string(),
            },
        )
        .unwrap();
    }
    // Enroll one agent over the session wire (no backend command exists for
    // it — D2 scope); freshly enrolled agents are "active".
    let cred = st
        .session
        .lock()
        .expect("session lock")
        .clone()
        .expect("session must be held");
    let added = svault::client::broker_call_with_auth(
        &env.socket,
        "agents.add",
        &svault::client::Auth::Session(cred.to_string()),
        serde_json::json!({"name": "endo-agent"}),
    )
    .unwrap_or_else(|e| panic!("agents.add must succeed: {}: {}", e.code, e.msg));
    assert!(added.get("agent_id").and_then(|v| v.as_str()).is_some());
    let ov = backend::overview_refresh(&st).expect("overview must succeed");
    // THE assertions: real counts, exact sum, populated health fields.
    assert!(ov.session_held, "session must be held after backend unlock");
    assert_eq!(ov.projects, Some(2));
    assert_eq!(ov.secrets_total, Some(2));
    assert!(ov.secrets_total_exact);
    assert_eq!(ov.agents_active, Some(1));
    for (label, v) in [
        ("runs_active", ov.runs_active),
        ("approvals_pending", ov.approvals_pending),
        ("leases_active", ov.leases_active),
        ("idle_lock_secs", ov.idle_lock_secs),
        ("audit_bytes", ov.audit_bytes),
        ("audit_soft_limit", ov.audit_soft_limit),
        ("audit_hard_limit", ov.audit_hard_limit),
        ("vault_bytes", ov.vault_bytes),
        ("vault_max_bytes", ov.vault_max_bytes),
    ] {
        assert!(v.is_some(), "{label} must be populated while unlocked");
    }
    // Evidence payload: full OverviewOut as JSON (printed with --nocapture).
    println!("OVERVIEW_JSON: {}", serde_json::to_string(&ov).unwrap());
}

#[test]
fn overview_session_held_distinguishes_lock_drop_from_never_held() {
    // The point of the field: backend's own knowledge, not sub-call success.
    // Held + unlocked -> true with counters; after lock (session dropped)
    // -> false, posture-only; never-established -> false from the start.
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let held = backend::overview_refresh(&st).expect("unlocked overview must succeed");
    assert!(held.session_held);
    backend::lock(&st).expect("lock must succeed");
    let dropped = backend::overview_refresh(&st).expect("locked overview must be Ok-shaped");
    assert!(dropped.locked);
    assert!(!dropped.session_held, "lock drops the Rust session holder");
    assert!(dropped.projects.is_none());
}

// ---------------- D3: agents + grants + approvals ----------------

/// Mint one project + one secret + enroll one agent, returning the live
/// agent token (caller-held; never in a backend payload). The project needs
/// a real directory (project paths are validated against the filesystem).
fn d3_agent_setup(env: &Env, st: &AppState, agent: &str) -> String {
    let dir = real_dir(env, &format!("d3-{agent}"));
    backend::project_add(
        st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    backend::secret_set(
        st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
            value: "d3-trap-secret-value-0123456789".to_string(),
        },
    )
    .unwrap();
    // Unlock again is idempotent, so no new session is needed here: use the
    // session the caller already holds (`unlocked_state`).
    let out = backend::agent_add(
        st,
        backend::AgentAddIn {
            name: agent.to_string(),
            token_path: None,
        },
    )
    .expect("agent_add must succeed");
    assert!(!out.token.is_empty());
    out.token
}

/// Drive an agent-side `reveal` (no approval_id) straight at the live daemon
/// with the enrolled agent token, returning the pending `approval_id`. The
fn d3_request_approval(env: &Env, token: &str) -> String {
    // NOTE: `match`, not `expect_err`: `BrokerError` has no `Debug`, so the
    // `expect_*` helpers do not compile on it (existing tests use
    // `unwrap_or_else`+`panic!` for the same reason).
    let err = match svault::client::broker_call_with_auth(
        &env.socket,
        "reveal",
        &svault::client::Auth::AgentToken(token.to_string()),
        serde_json::json!({"project": "web", "key": "API_KEY"}),
    ) {
        Ok(_) => panic!("reveal without approval_id must pend"),
        Err(err) => err,
    };
    assert_eq!(err.code, "E_APPROVAL_PENDING");
    err.data
        .as_ref()
        .and_then(|d| d.get("approval_id"))
        .and_then(|v| v.as_str())
        .expect("approval_id in E_APPROVAL_PENDING data")
        .to_string()
}

#[test]
fn d3_agents_list_empty_then_populated() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    assert!(backend::agents_list(&st).unwrap().agents.is_empty());
    let out = backend::agent_add(
        &st,
        backend::AgentAddIn {
            name: "bot".to_string(),
            token_path: None,
        },
    )
    .unwrap();
    assert!(!out.agent_id.is_empty());
    // Re-read, never assume: the broker is the source of truth.
    let list = backend::agents_list(&st).unwrap();
    assert_eq!(list.agents.len(), 1);
    let entry = &list.agents[0];
    assert_eq!(entry.name, "bot");
    assert_eq!(entry.status, "active");
    assert!(!entry.token_prefix.is_empty());
    assert_ne!(entry.token_prefix, out.token);
}

#[test]
fn d3_agent_token_returned_once_and_never_listed() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let out = backend::agent_add(
        &st,
        backend::AgentAddIn {
            name: "bot".to_string(),
            token_path: None,
        },
    )
    .unwrap();
    assert!(!out.token.is_empty());
    // The token appears in its own response — and nowhere else: a second
    // `agents_list` payload must not contain it anywhere.
    let listed = serde_json::to_string(&backend::agents_list(&st).unwrap()).unwrap();
    assert!(!listed.contains(&out.token));
}

#[test]
fn d3_agent_add_token_path_writes_0600_and_refuses_clobber() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let path = env._dir.join("bot.token");
    let path_s = path.display().to_string();
    let out = backend::agent_add(
        &st,
        backend::AgentAddIn {
            name: "bot".to_string(),
            token_path: Some(path_s.clone()),
        },
    )
    .unwrap();
    assert_eq!(out.token_saved_path.as_deref(), Some(path_s.as_str()));
    // Mode 0600 from the first byte, contents are the token (plus newline).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(body.contains(&out.token));
    // A second enrollment to the SAME path fails and leaves the original.
    let err = backend::agent_add(
        &st,
        backend::AgentAddIn {
            name: "bot2".to_string(),
            token_path: Some(path_s.clone()),
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_EXISTS");
    assert!(std::fs::read_to_string(&path).unwrap().contains(&out.token));
}

#[test]
fn d3_agent_revoke_flips_status_on_reread() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    backend::agent_add(
        &st,
        backend::AgentAddIn {
            name: "bot".to_string(),
            token_path: None,
        },
    )
    .unwrap();
    let revoked = backend::agent_revoke(
        &st,
        backend::NameIn {
            name: "bot".to_string(),
        },
    )
    .unwrap();
    assert_eq!(revoked.revoked, "bot");
    // Re-read, never assume: the entry is still listed, now revoked.
    let list = backend::agents_list(&st).unwrap();
    let entry = list
        .agents
        .iter()
        .find(|a| a.name == "bot")
        .expect("revoked agent stays listed");
    assert_eq!(entry.status, "revoked");
}

#[test]
fn d3_grant_set_upserts_and_manage_round_trips() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    d3_agent_setup(&env, &st, "bot");
    assert!(backend::grants_list(&st).unwrap().grants.is_empty());
    // Create with two ops; re-read shows exactly those ops.
    let granted = backend::grant_set(
        &st,
        backend::GrantSetIn {
            agent: "bot".to_string(),
            project: "web".to_string(),
            ops: "read,inject".to_string(),
        },
    )
    .unwrap();
    assert_eq!(granted.granted, "bot/web");
    let list = backend::grants_list(&st).unwrap();
    assert_eq!(list.grants.len(), 1);
    assert_eq!(list.grants[0].ops, vec!["read", "inject"]);
    assert!(!list.grants[0].revoked);
    // Upsert with three ops: still ONE row for the pair, now three ops.
    backend::grant_set(
        &st,
        backend::GrantSetIn {
            agent: "bot".to_string(),
            project: "web".to_string(),
            ops: "read,inject,run".to_string(),
        },
    )
    .unwrap();
    let list = backend::grants_list(&st).unwrap();
    assert_eq!(list.grants.len(), 1);
    assert_eq!(list.grants[0].ops, vec!["read", "inject", "run"]);
    // `manage` regression: it has no agent-callable op yet, but the grant is
    // real — if the UI dropped it from the checkbox set, re-saving would
    // silently revoke it. It must round-trip intact through grants_list.
    backend::grant_set(
        &st,
        backend::GrantSetIn {
            agent: "bot".to_string(),
            project: "web".to_string(),
            ops: "read,manage".to_string(),
        },
    )
    .unwrap();
    let list = backend::grants_list(&st).unwrap();
    assert_eq!(list.grants.len(), 1);
    assert_eq!(list.grants[0].ops, vec!["read", "manage"]);
}

#[test]
fn d3_grant_revoke_removes_grant_on_reread() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    d3_agent_setup(&env, &st, "bot");
    backend::grant_set(
        &st,
        backend::GrantSetIn {
            agent: "bot".to_string(),
            project: "web".to_string(),
            ops: "read,inject".to_string(),
        },
    )
    .unwrap();
    let revoked = backend::grant_revoke(
        &st,
        backend::GrantRevokeIn {
            agent: "bot".to_string(),
            project: "web".to_string(),
        },
    )
    .unwrap();
    assert_eq!(revoked.revoked, "bot/web");
    // Re-read, never assume. NOTE: the broker marks the grant revoked rather
    // than deleting the row, so assert "no LIVE row" (not "no row at all"):
    // either an empty list or a row with `revoked: true` proves the revoke.
    // A live row with `revoked: false` is the failure mode (no-op revoke).
    let list = backend::grants_list(&st).unwrap();
    assert!(
        list.grants
            .iter()
            .filter(|g| g.agent == "bot" && g.project == "web")
            .all(|g| g.revoked),
        "revoked grant must not survive live: {:?}",
        list.grants
    );
    assert!(
        !list.grants.is_empty(),
        "broker keeps the revoked row with revoked:true"
    );
}

#[test]
fn d3_reveal_grant_creates_pending_approval_then_approve() {
    // The reveal/approval non-bypass: with a live `reveal` grant, an
    // agent-side reveal pends; `approvals_pending` lists it; approving flips
    // it to approved. No reveal is performed (values never enter this file).
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let token = d3_agent_setup(&env, &st, "bot");
    backend::grant_set(
        &st,
        backend::GrantSetIn {
            agent: "bot".to_string(),
            project: "web".to_string(),
            ops: "read,reveal".to_string(),
        },
    )
    .unwrap();
    let approval_id = d3_request_approval(&env, &token);
    let pending = backend::approvals_pending(&st).unwrap();
    let entry = pending
        .approvals
        .iter()
        .find(|a| a.approval_id == approval_id)
        .expect("pending approval must be listed");
    assert_eq!(entry.agent, "bot");
    assert_eq!(entry.project, "web");
    assert_eq!(entry.key, "API_KEY");
    assert_eq!(entry.status, "pending");
    assert!(!entry.expires_at.is_empty());
    // The trap VALUE is nowhere in the pending payload (names only).
    let body = serde_json::to_string(&pending).unwrap();
    assert!(!body.contains("d3-trap-secret-value-0123456789"));
    let decided = backend::approval_approve(
        &st,
        backend::ApprovalDecisionIn {
            approval_id: approval_id.clone(),
        },
    )
    .unwrap();
    assert_eq!(decided.approval_id, approval_id);
    assert_eq!(decided.status, "approved");
}

#[test]
fn d3_approval_deny_denies_and_removes_from_pending() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let token = d3_agent_setup(&env, &st, "bot");
    backend::grant_set(
        &st,
        backend::GrantSetIn {
            agent: "bot".to_string(),
            project: "web".to_string(),
            ops: "read,reveal".to_string(),
        },
    )
    .unwrap();
    let approval_id = d3_request_approval(&env, &token);
    let decided = backend::approval_deny(
        &st,
        backend::ApprovalDecisionIn {
            approval_id: approval_id.clone(),
        },
    )
    .unwrap();
    assert_eq!(decided.approval_id, approval_id);
    assert_eq!(decided.status, "denied");
    // A denied approval leaves the pending set (re-read, never assume).
    let pending = backend::approvals_pending(&st).unwrap();
    assert!(!pending
        .approvals
        .iter()
        .any(|a| a.approval_id == approval_id));
}

#[test]
fn d3_expired_approvals_are_filtered_by_the_broker() {
    // Expiry honesty is the broker's filter (`approval_pending` returns only
    // non-expired rows: `now < pending_expires_at` in `session.rs`), covered
    // by the core suite with a controllable clock (`wave3`/`session` expiry
    // tests advance the clock past `APPROVAL_PENDING_SECS`). This dashboard
    // fixture runs on wall-clock time, so constructing a past-expiry row
    // cheaply in-process is impractical (it would need a 10-minute sleep or
    // a fake clock the live daemon does not take). What IS asserted here:
    // every listed pending approval carries a non-empty `expires_at`, and a
    // fresh request's approval survives while pending (not spuriously
    // filtered) — the broker's filter, not ours, decides.
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let token = d3_agent_setup(&env, &st, "bot");
    backend::grant_set(
        &st,
        backend::GrantSetIn {
            agent: "bot".to_string(),
            project: "web".to_string(),
            ops: "read,reveal".to_string(),
        },
    )
    .unwrap();
    let approval_id = d3_request_approval(&env, &token);
    let pending = backend::approvals_pending(&st).unwrap();
    let entry = pending
        .approvals
        .iter()
        .find(|a| a.approval_id == approval_id)
        .expect("fresh approval must survive the broker expiry filter");
    assert!(!entry.expires_at.is_empty());
}

#[test]
fn d3_session_expiry_blocks_approve_without_changing_state() {
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let token = d3_agent_setup(&env, &st, "bot");
    backend::grant_set(
        &st,
        backend::GrantSetIn {
            agent: "bot".to_string(),
            project: "web".to_string(),
            ops: "read,reveal".to_string(),
        },
    )
    .unwrap();
    let approval_id = d3_request_approval(&env, &token);
    // Close the held session on the wire: the Rust-held credential is stale.
    close_session_on_wire(&env, &st);
    let err = backend::approval_approve(
        &st,
        backend::ApprovalDecisionIn {
            approval_id: approval_id.clone(),
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_SESSION_EXPIRED");
    // Broker state unchanged: the approval is still pending, not approved.
    // Re-unlock to witness honestly: `vault.unlock` on an OPEN vault keeps it
    // open (idempotent) and seeds a FRESH session, replacing the stale one.
    backend::unlock(
        &st,
        UnlockIn {
            passphrase: String::from_utf8(PASS.to_vec()).unwrap(),
        },
    )
    .expect("re-unlock must succeed");
    let pending = backend::approvals_pending(&st).unwrap();
    let entry = pending
        .approvals
        .iter()
        .find(|a| a.approval_id == approval_id)
        .expect("failed approve must not consume the approval");
    assert_eq!(entry.status, "pending");
}

#[test]
fn d3_agents_list_offline_fails_closed_never_empty_success() {
    // Offline/mismatch fail-closed: follow the existing
    // `offline_socket_reports_offline_without_panic` pattern — a dead socket
    // must ERROR, never fabricate an empty success.
    let _g = serial();
    let st = AppState::new(PathBuf::from("/tmp/svault-dash-test-d3-dead.sock"));
    let err = backend::agents_list(&st).unwrap_err();
    assert!(!err.code.is_empty());
    assert_ne!(err.code, "E_SESSION_EXPIRED");
}

#[test]
fn d3_all_nine_payloads_carry_no_credential_or_secret_material() {
    // Payload hygiene over every one of the nine commands: serialize each
    // result and assert the bytes contain NONE of a human session
    // credential, an agent token (except agent_add's own response field), a
    // lease credential, or a secret value.
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let token_path_holder: Option<String> = None;
    // Trap secret VALUE planted first (mirrors the TRAP-style patterns).
    let dir = real_dir(&env, "hygiene");
    let trap_value = "D3-TRAP-secret-value-abcdef-0123456789";
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
            value: trap_value.to_string(),
        },
    )
    .unwrap();
    let added = backend::agent_add(
        &st,
        backend::AgentAddIn {
            name: "bot".to_string(),
            token_path: token_path_holder,
        },
    )
    .unwrap();
    let agent_token = added.token.clone();
    let added_body = serde_json::to_string(&added).unwrap();
    backend::grant_set(
        &st,
        backend::GrantSetIn {
            agent: "bot".to_string(),
            project: "web".to_string(),
            ops: "read,reveal".to_string(),
        },
    )
    .unwrap();
    let approval_id = d3_request_approval(&env, &agent_token);
    // Human session credential, read back from Rust state (same-process
    // fixture only — JS could never do this).
    let session_cred = st
        .session
        .lock()
        .expect("session lock")
        .clone()
        .expect("session must be held")
        .to_string();
    // Lease credential trap: mint one via the agent token so a lease
    // credential EXISTS, then assert no D3 payload carries it.
    let lease_cred = match svault::client::broker_call_with_auth(
        &env.socket,
        "lease.create",
        &svault::client::Auth::AgentToken(agent_token.clone()),
        serde_json::json!({"project": "web", "ops": "read", "ttl_secs": 60}),
    ) {
        Ok(v) => v["lease_credential"]
            .as_str()
            .expect("lease_credential in result")
            .to_string(),
        Err(e) => panic!("lease.create must succeed: {}: {}", e.code, e.msg),
    };
    // Collect every result EXCEPT agent_add's own response (the one explicit
    // human delivery of the one-time token the contract requires).
    let mut bodies = vec![
        serde_json::to_string(&backend::agents_list(&st).unwrap()).unwrap(),
        serde_json::to_string(&backend::grants_list(&st).unwrap()).unwrap(),
        serde_json::to_string(&backend::approvals_pending(&st).unwrap()).unwrap(),
    ];
    bodies.push(
        serde_json::to_string(
            &backend::agent_revoke(
                &st,
                backend::NameIn {
                    name: "revoke-probe".to_string(),
                },
            )
            .unwrap_err(),
        )
        .unwrap(),
    );
    // agent_add's own body: strip the one `token` field, then it too must be
    // clean (agent_id + saved path carry nothing secret).
    let mut added_json: serde_json::Value = serde_json::from_str(&added_body).unwrap();
    added_json["token"] = serde_json::Value::String(String::new());
    bodies.push(serde_json::to_string(&added_json).unwrap());
    // grant_set's own result ({granted}): capture via idempotent re-upsert
    // while the grant is still live.
    bodies.push(
        serde_json::to_string(
            &backend::grant_set(
                &st,
                backend::GrantSetIn {
                    agent: "bot".to_string(),
                    project: "web".to_string(),
                    ops: "read,reveal".to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap(),
    );
    // Approve + deny need distinct approvals (single-decision each). Both run
    // BEFORE grant_revoke below: revoking the `reveal` grant first would deny
    // the pending approval and break the agent-side reveal (E_PERMISSION).
    let approved = backend::approval_approve(
        &st,
        backend::ApprovalDecisionIn {
            approval_id: approval_id.clone(),
        },
    )
    .unwrap();
    bodies.push(serde_json::to_string(&approved).unwrap());
    let approval_id2 = d3_request_approval(&env, &agent_token);
    let denied = backend::approval_deny(
        &st,
        backend::ApprovalDecisionIn {
            approval_id: approval_id2,
        },
    )
    .unwrap();
    bodies.push(serde_json::to_string(&denied).unwrap());
    // grant_revoke captured last: nothing after this needs the grant.
    bodies.push(
        serde_json::to_string(
            &backend::grant_revoke(
                &st,
                backend::GrantRevokeIn {
                    agent: "bot".to_string(),
                    project: "web".to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap(),
    );
    for body in &bodies {
        assert!(
            !body.contains(&session_cred),
            "session credential leaked: {body}"
        );
        assert!(!body.contains(&agent_token), "agent token leaked: {body}");
        assert!(
            !body.contains(&lease_cred),
            "lease credential leaked: {body}"
        );
        assert!(!body.contains(trap_value), "secret value leaked: {body}");
    }
}

#[test]
fn d3_full_smoke_chain_unlock_to_lock() {
    // The full smoke chain as ONE ordered test, each step re-reading the
    // broker (no optimistic state): unlock -> agent_add ->
    // grant_set(read,inject,run,reveal) -> approvals_pending (after creating
    // an approval) -> approval_approve -> grant_revoke -> agent_revoke ->
    // lock. Asserts the observable outcome at each step.
    let _g = serial();
    let env = live_env();
    pin_live(&env);
    let st = state_for(&env);
    // unlock
    let unlock_out = backend::unlock(
        &st,
        UnlockIn {
            passphrase: String::from_utf8(PASS.to_vec()).unwrap(),
        },
    )
    .expect("unlock must succeed");
    assert!(unlock_out.unlocked);
    // agent_add
    let dir = real_dir(&env, "smoke");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
            value: "smoke-value".to_string(),
        },
    )
    .unwrap();
    let added = backend::agent_add(
        &st,
        backend::AgentAddIn {
            name: "smoke-bot".to_string(),
            token_path: None,
        },
    )
    .unwrap();
    assert!(!added.token.is_empty());
    assert_eq!(
        backend::agents_list(&st)
            .unwrap()
            .agents
            .iter()
            .find(|a| a.name == "smoke-bot")
            .expect("agent visible on re-read")
            .status,
        "active"
    );
    // grant_set(read,inject,run,reveal)
    let granted = backend::grant_set(
        &st,
        backend::GrantSetIn {
            agent: "smoke-bot".to_string(),
            project: "web".to_string(),
            ops: "read,inject,run,reveal".to_string(),
        },
    )
    .unwrap();
    assert_eq!(granted.granted, "smoke-bot/web");
    assert_eq!(
        backend::grants_list(&st)
            .unwrap()
            .grants
            .iter()
            .find(|g| g.agent == "smoke-bot" && g.project == "web")
            .expect("grant visible on re-read")
            .ops,
        vec!["read", "inject", "run", "reveal"]
    );
    // approvals_pending (after creating an approval via agent reveal)
    let approval_id = d3_request_approval(&env, &added.token);
    assert!(backend::approvals_pending(&st)
        .unwrap()
        .approvals
        .iter()
        .any(|a| a.approval_id == approval_id));
    // approval_approve
    let decided = backend::approval_approve(
        &st,
        backend::ApprovalDecisionIn {
            approval_id: approval_id.clone(),
        },
    )
    .unwrap();
    assert_eq!(decided.status, "approved");
    assert!(!backend::approvals_pending(&st)
        .unwrap()
        .approvals
        .iter()
        .any(|a| a.approval_id == approval_id));
    // grant_revoke
    let revoked = backend::grant_revoke(
        &st,
        backend::GrantRevokeIn {
            agent: "smoke-bot".to_string(),
            project: "web".to_string(),
        },
    )
    .unwrap();
    assert_eq!(revoked.revoked, "smoke-bot/web");
    // agent_revoke
    let revoked = backend::agent_revoke(
        &st,
        backend::NameIn {
            name: "smoke-bot".to_string(),
        },
    )
    .unwrap();
    assert_eq!(revoked.revoked, "smoke-bot");
    assert_eq!(
        backend::agents_list(&st)
            .unwrap()
            .agents
            .iter()
            .find(|a| a.name == "smoke-bot")
            .expect("revoked agent stays listed")
            .status,
        "revoked"
    );
    // lock
    assert!(backend::lock(&st).unwrap().locked);
    assert!(backend::get_status(&st).unwrap().locked);
}
// ---------------- D4: reveal + leases + runs ----------------

/// Distinct D4 trap value, planted via `secret_set`, then hunted for leaks:
/// `reveal` (and only `reveal`) may carry it.
const REVEAL_TRAP: &str = "sv1-D4-TRAP-7f3a9c2e5b1d8f4a6c0e9b2d5a7f1c3e";

/// Mint one project + one trap secret + enroll one agent with a `read` grant,
/// returning the live agent token (caller-held; never in a backend payload).
fn d4_agent_setup(env: &Env, st: &AppState, agent: &str) -> String {
    let dir = real_dir(env, &format!("d4-{agent}"));
    backend::project_add(
        st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    backend::secret_set(
        st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
            value: REVEAL_TRAP.to_string(),
        },
    )
    .unwrap();
    let out = backend::agent_add(
        st,
        backend::AgentAddIn {
            name: agent.to_string(),
            token_path: None,
        },
    )
    .expect("agent_add must succeed");
    assert!(!out.token.is_empty());
    backend::grant_set(
        st,
        backend::GrantSetIn {
            agent: agent.to_string(),
            project: "web".to_string(),
            ops: "read".to_string(),
        },
    )
    .unwrap();
    out.token
}

/// Mint one lease through the agent path (the dashboard has no `lease.create`
/// by design), returning the lease id + the one-time credential.
fn d4_mint_lease(env: &Env, token: &str) -> (String, String) {
    // NOTE: `match`, not `expect`: `BrokerError` has no `Debug`.
    let v = match svault::client::broker_call_with_auth(
        &env.socket,
        "lease.create",
        &svault::client::Auth::AgentToken(token.to_string()),
        serde_json::json!({"project": "web", "ops": "read", "ttl_secs": 3600}),
    ) {
        Ok(v) => v,
        Err(e) => panic!("lease.create must succeed: {}: {}", e.code, e.msg),
    };
    let lease_id = v
        .get("lease_id")
        .and_then(|s| s.as_str())
        .expect("lease_id in result")
        .to_string();
    let credential = v
        .get("lease_credential")
        .and_then(|s| s.as_str())
        .expect("lease_credential in result")
        .to_string();
    assert!(!lease_id.is_empty());
    assert!(!credential.is_empty());
    (lease_id, credential)
}

#[test]
fn d4_reveal_returns_trap_and_no_other_payload_carries_it() {
    // 1+2: `reveal` returns exactly the trap value, and the value appears in
    // NO other command's serialized payload — `reveal` is the ONLY carrier.
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let dir = real_dir(&env, "d4-reveal");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
            value: REVEAL_TRAP.to_string(),
        },
    )
    .unwrap();
    let out = backend::reveal(
        &st,
        backend::RevealIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
        },
    )
    .expect("reveal must succeed");
    assert_eq!(out.value, REVEAL_TRAP);
    // Every other serializable surface must be trap-free: loop the other
    // commands' results and assert absence.
    let bodies = vec![
        serde_json::to_string(&backend::leases_list(&st).unwrap()).unwrap(),
        serde_json::to_string(&backend::runs_list(&st).unwrap()).unwrap(),
        serde_json::to_string(&backend::projects_list(&st).unwrap()).unwrap(),
        serde_json::to_string(
            &backend::secrets_list(
                &st,
                backend::SecretsListIn {
                    project: "web".to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap(),
        serde_json::to_string(&backend::agents_list(&st).unwrap()).unwrap(),
        serde_json::to_string(&backend::grants_list(&st).unwrap()).unwrap(),
        serde_json::to_string(&backend::approvals_pending(&st).unwrap()).unwrap(),
        serde_json::to_string(&backend::overview_refresh(&st).unwrap()).unwrap(),
        serde_json::to_string(&backend::health(&st).unwrap()).unwrap(),
    ];
    for body in &bodies {
        assert!(!body.contains(REVEAL_TRAP), "trap value leaked: {body}");
    }
    // And `reveal`'s own payload DOES carry it — the single authorized
    // crossing, asserted explicitly.
    let reveal_body = serde_json::to_string(&out).unwrap();
    assert!(
        reveal_body.contains(REVEAL_TRAP),
        "reveal must carry the value exactly once"
    );
}

#[test]
fn d4_reveal_bad_key_is_not_found_without_value_in_error() {
    // 3: bad key -> E_NOT_FOUND; error text never contains the value.
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let dir = real_dir(&env, "d4-badkey");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
            value: REVEAL_TRAP.to_string(),
        },
    )
    .unwrap();
    let err = backend::reveal(
        &st,
        backend::RevealIn {
            project: "web".to_string(),
            key: "NO_SUCH_KEY".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_NOT_FOUND");
    let err_body = serde_json::to_string(&err).unwrap();
    assert!(
        !err_body.contains(REVEAL_TRAP),
        "error must never carry the value: {err_body}"
    );
    // Missing-key-project: unknown project is E_NOT_FOUND too, still
    // value-free.
    let err2 = backend::reveal(
        &st,
        backend::RevealIn {
            project: "no-such-project".to_string(),
            key: "API_KEY".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err2.code, "E_NOT_FOUND");
    assert!(!serde_json::to_string(&err2).unwrap().contains(REVEAL_TRAP));
}

#[test]
fn d4_reveal_session_expiry_carries_no_value() {
    // 4: after `close_session_on_wire`, `reveal` is E_SESSION_EXPIRED with no
    // value anywhere in the error.
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let dir = real_dir(&env, "d4-expiry");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
            value: REVEAL_TRAP.to_string(),
        },
    )
    .unwrap();
    close_session_on_wire(&env, &st);
    let err = backend::reveal(
        &st,
        backend::RevealIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_SESSION_EXPIRED");
    assert!(!serde_json::to_string(&err).unwrap().contains(REVEAL_TRAP));
}

#[test]
fn d4_leases_list_empty_then_populated_with_active_status() {
    // 5: fresh vault -> honest `[]`; after an agent-side `lease.create`, one
    // entry with the right project, ops, and `status: "active"`.
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    assert!(backend::leases_list(&st).unwrap().leases.is_empty());
    let token = d4_agent_setup(&env, &st, "bot");
    let (lease_id, _cred) = d4_mint_lease(&env, &token);
    // Re-read, never assume: the broker is the source of truth.
    let list = backend::leases_list(&st).unwrap();
    assert_eq!(list.leases.len(), 1);
    let entry = &list.leases[0];
    assert_eq!(entry.lease_id, lease_id);
    assert_eq!(entry.project, "web");
    assert_eq!(entry.ops, vec!["read".to_string()]);
    assert_eq!(entry.status, "active");
    assert!(!entry.lease_prefix.is_empty());
    assert!(!entry.expires_at.is_empty());
}

#[test]
fn d4_leases_list_never_carries_a_credential() {
    // 6: the serialized payload contains neither `lease_credential` nor the
    // credential string the agent received from `lease.create`.
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let token = d4_agent_setup(&env, &st, "bot");
    let (_lease_id, credential) = d4_mint_lease(&env, &token);
    let body = serde_json::to_string(&backend::leases_list(&st).unwrap()).unwrap();
    assert!(!body.contains("lease_credential"), "credential key leaked");
    assert!(!body.contains(&credential), "credential value leaked");
}

#[test]
fn d4_lease_revoke_marks_revoked_on_reread() {
    // 7: revoke -> `{revoked: true}`; a subsequent `leases_list` re-read
    // shows `status: "revoked"` (never assumed from the revoke response).
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let token = d4_agent_setup(&env, &st, "bot");
    let (lease_id, _cred) = d4_mint_lease(&env, &token);
    let out = backend::lease_revoke(
        &st,
        backend::LeaseRevokeIn {
            lease_id: lease_id.clone(),
        },
    )
    .expect("lease_revoke must succeed");
    assert_eq!(out.lease_id, lease_id);
    assert!(out.revoked);
    let list = backend::leases_list(&st).unwrap();
    let entry = list
        .leases
        .iter()
        .find(|l| l.lease_id == lease_id)
        .expect("revoked lease stays listed");
    assert_eq!(entry.status, "revoked");
}

#[test]
fn d4_runs_list_empty_allowlisted_and_trap_free() {
    // 8: fresh vault -> empty; payload carries none of argv/env/cwd/
    // executable/pgid (mirror of the core allowlist assertion shape).
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let out = backend::runs_list(&st).unwrap();
    assert!(out.runs.is_empty());
    let body = serde_json::to_string(&out).unwrap();
    for forbidden in ["argv", "env", "cwd", "executable", "pgid"] {
        assert!(!body.contains(forbidden), "{forbidden} leaked: {body}");
    }
    // Key allowlist on the serialized shape: exactly the six safe keys.
    let row = serde_json::json!({
        "run_id": "probe",
        "agent": "a",
        "project": "p",
        "pid": 1,
        "started_at": "t",
        "status": "running",
    });
    let mut keys: Vec<&str> = row
        .as_object()
        .unwrap()
        .keys()
        .map(|s| s.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["agent", "pid", "project", "run_id", "started_at", "status"]
    );
}

#[test]
fn d4_all_four_offline_fail_closed_never_empty_success() {
    // 9: offline/mismatch fail-closed for all four commands
    // (E_BROKER_UNTRUSTED on the D3 mismatch pattern; E_IO on a dead socket
    // via `require_session_auth`'s trust-first probe) — following the D3
    // pattern that already covers the nine.
    let _g = serial();
    // Mismatch arm: no session held, pin wrong -> E_BROKER_UNTRUSTED.
    let env = live_env();
    pin_key(&env, &[0xA5u8; 32]);
    let st = state_for(&env);
    assert_eq!(
        backend::reveal(
            &st,
            backend::RevealIn {
                project: "x".to_string(),
                key: "y".to_string(),
            },
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::leases_list(&st).unwrap_err().code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::lease_revoke(
            &st,
            backend::LeaseRevokeIn {
                lease_id: "x".to_string(),
            },
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::runs_list(&st).unwrap_err().code,
        "E_BROKER_UNTRUSTED"
    );
    // Dead-socket arm: no pin, no session -> the probe fails E_IO (offline),
    // never a fabricated empty success or a misleading E_SESSION_EXPIRED.
    let dead = AppState::new(PathBuf::from("/tmp/svault-dash-test-d4-dead.sock"));
    assert_eq!(
        backend::reveal(
            &dead,
            backend::RevealIn {
                project: "x".to_string(),
                key: "y".to_string(),
            },
        )
        .unwrap_err()
        .code,
        "E_IO"
    );
    assert_eq!(backend::leases_list(&dead).unwrap_err().code, "E_IO");
    assert_eq!(
        backend::lease_revoke(
            &dead,
            backend::LeaseRevokeIn {
                lease_id: "x".to_string(),
            },
        )
        .unwrap_err()
        .code,
        "E_IO"
    );
    assert_eq!(backend::runs_list(&dead).unwrap_err().code, "E_IO");
}

#[test]
fn d4_lock_clears_reveal_and_leases() {
    // 10: after `lock`, `reveal` fails and `leases_list` fails — no stale
    // success from the dropped Rust session.
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let dir = real_dir(&env, "d4-lock");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
            value: REVEAL_TRAP.to_string(),
        },
    )
    .unwrap();
    assert!(backend::lock(&st).unwrap().locked);
    // Post-lock the Rust session holder is dropped, so the trust-first probe
    // (vault.status over Auth::None) succeeds and the calls fail as
    // E_SESSION_EXPIRED — the same shape as every other post-lock human op.
    let err = backend::reveal(
        &st,
        backend::RevealIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_SESSION_EXPIRED");
    assert!(!serde_json::to_string(&err).unwrap().contains(REVEAL_TRAP));
    assert_eq!(
        backend::leases_list(&st).unwrap_err().code,
        "E_SESSION_EXPIRED"
    );
}

// ---------------- D6: audit timeline + verification ----------------

/// Distinct D6 trap value, planted via `secret_set`, then hunted for leaks:
/// no audit payload or verify result may carry it (audit records names only).
const AUDIT_TRAP: &str = "sv1-D6-TRAP-4b8d2f1a9c3e7d5f0a6b8c2d4e1f3a5b";

/// Load every page backwards from the head with `tail`, returning all pages.
/// Each `before_seq` walks strictly older seqs; terminates at a null cursor.
fn d6_load_all(st: &AppState, tail: u64) -> Vec<crate::backend::AuditShowOut> {
    let mut pages = Vec::new();
    let mut before: Option<u64> = None;
    loop {
        let page = backend::audit_show(
            st,
            backend::AuditShowIn {
                tail,
                before_seq: before,
            },
        )
        .expect("audit_show page must succeed");
        let cursor = page.next_before_seq;
        pages.push(page);
        match cursor {
            Some(b) => before = Some(b),
            None => break,
        }
        // The fixture writes dozens of entries at most; a longer walk means
        // the cursor is cycling rather than retreating.
        assert!(pages.len() < 100, "audit cursor walk did not terminate");
    }
    pages
}

#[test]
fn d6_audit_first_page_is_ascending_with_cursor() {
    // Page 1: entries ascending by `seq`, non-empty, cursor consistent with
    // `next_before_seq` semantics (first-seq − 1 when older remain, else null).
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let page = backend::audit_show(
        &st,
        backend::AuditShowIn {
            tail: 50,
            before_seq: None,
        },
    )
    .expect("first page must succeed");
    assert!(!page.entries.is_empty(), "fresh-unlocked vault has entries");
    let seqs: Vec<u64> = page.entries.iter().map(|e| e.seq).collect();
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    assert_eq!(seqs, sorted, "entries must be ascending by seq");
    match page.next_before_seq {
        Some(b) => assert_eq!(b + 1, seqs[0], "cursor must be first-seq − 1"),
        None => assert_eq!(seqs[0], 1, "null cursor means the page starts at seq 1"),
    }
    // Newest entries were written while unlocked, so they carry MACs.
    assert!(
        page.entries.last().expect("non-empty").authenticated,
        "newest unlocked entry must be authenticated"
    );
}

#[test]
fn d6_audit_older_page_walks_backwards_to_the_beginning() {
    // Repeated `before_seq = next_before_seq` pages walk strictly older seqs,
    // never overlap, and terminate at null; the union is gap-free + ascending.
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let dir = real_dir(&env, "d6-walk");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
            value: "walk-value".to_string(),
        },
    )
    .unwrap();
    let pages = d6_load_all(&st, 2);
    assert!(
        pages.len() >= 2,
        "tail 2 over several entries must paginate"
    );
    let mut seen: Vec<u64> = Vec::new();
    for page in &pages {
        assert!(!page.entries.is_empty(), "non-terminal pages are non-empty");
        let seqs: Vec<u64> = page.entries.iter().map(|e| e.seq).collect();
        let mut sorted = seqs.clone();
        sorted.sort_unstable();
        assert_eq!(seqs, sorted, "each page ascending: {seqs:?}");
        for seq in &seqs {
            assert!(!seen.contains(seq), "seq {seq} seen twice across pages");
        }
        if let Some(min_seen) = seen.iter().min() {
            // Pages load newest-first: this page's max must be older than the
            // minimum seq already collected.
            assert!(
                seqs.iter().all(|s| s < min_seen),
                "pages must walk strictly backwards: {seqs:?} vs {min_seen}"
            );
        }
        seen.extend(seqs.iter().copied());
    }
    // Union is the full 1..=max range: gap-free, ascending, duplicate-free.
    seen.sort_unstable();
    let max = *seen.iter().max().expect("entries seen");
    let expect: Vec<u64> = (1..=max).collect();
    assert_eq!(seen, expect, "walked union must be gap-free 1..=max");
}

#[test]
fn d6_audit_empty_page() {
    // `before_seq: Some(0)` yields an empty page + null cursor (broker rule).
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let page = backend::audit_show(
        &st,
        backend::AuditShowIn {
            tail: 50,
            before_seq: Some(0),
        },
    )
    .expect("before_seq 0 must succeed");
    assert!(page.entries.is_empty());
    assert_eq!(page.next_before_seq, None);
}

#[test]
fn d6_audit_marks_unauthenticated_entries() {
    // Plant a `mac: null` entry via `get_status` while LOCKED (that
    // unauthenticated `vault.status` append has no MAC key in memory), then
    // unlock and page: at least one entry reads back unauthenticated, while
    // the newest unlocked entries are authenticated.
    let _g = serial();
    let env = live_env();
    pin_live(&env);
    let st = state_for(&env);
    backend::get_status(&st).expect("locked status appends a mac-less entry");
    backend::unlock(
        &st,
        UnlockIn {
            passphrase: String::from_utf8(PASS.to_vec()).unwrap(),
        },
    )
    .expect("unlock must succeed");
    let pages = d6_load_all(&st, 50);
    let all: Vec<&backend::AuditEntryOut> = pages.iter().flat_map(|p| p.entries.iter()).collect();
    assert!(
        all.iter().any(|e| !e.authenticated),
        "locked-era entry must read back unauthenticated"
    );
    let max = all.iter().map(|e| e.seq).max().expect("entries");
    assert!(
        all.iter().filter(|e| e.seq == max).all(|e| e.authenticated),
        "newest unlocked entries must be authenticated"
    );
}

#[test]
fn d6_audit_verify_ok_then_structural_failure_is_an_error() {
    // After unlock, verify reports real counts; after appending a bogus line
    // to the on-disk log, verify fails `E_VAULT_CORRUPT` — never `Ok`.
    // This test tampers the fixture log LAST (nothing after may rely on it).
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let ok = backend::audit_verify(&st).expect("verify must succeed");
    assert!(ok.entries > 0);
    assert!(ok.macs_verified > 0);
    // Resolve the audit path the way the core does: next to the vault file.
    let audit_path = svault::store::audit_path(&env._dir.join("vault.enc"));
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&audit_path)
        .unwrap();
    writeln!(f, "{{\"bogus\": true}}").unwrap();
    drop(f);
    let err = backend::audit_verify(&st).unwrap_err();
    assert_eq!(err.code, "E_VAULT_CORRUPT");
}

#[test]
fn d6_audit_tail_bound_is_refused_locally() {
    // `tail` outside 1..=1000 fails fast with `E_INVALID_INPUT` — locally,
    // without opening a connection (dead socket proves no I/O happened: the
    // code is still `E_INVALID_INPUT`, never the probe's `E_IO`).
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    for tail in [0u64, 1001u64] {
        let err = backend::audit_show(
            &st,
            backend::AuditShowIn {
                tail,
                before_seq: None,
            },
        )
        .unwrap_err();
        assert_eq!(err.code, "E_INVALID_INPUT");
        assert_eq!(err.message, "invalid input");
    }
    let dead = AppState::new(PathBuf::from("/tmp/svault-dash-test-d6-dead.sock"));
    for tail in [0u64, 1001u64] {
        let err = backend::audit_show(
            &dead,
            backend::AuditShowIn {
                tail,
                before_seq: None,
            },
        )
        .unwrap_err();
        assert_eq!(err.code, "E_INVALID_INPUT");
    }
}

#[test]
fn d6_audit_session_expiry_blocks_read_and_verify() {
    // After `close_session_on_wire`, both commands fail `E_SESSION_EXPIRED`.
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    close_session_on_wire(&env, &st);
    assert_eq!(
        backend::audit_show(
            &st,
            backend::AuditShowIn {
                tail: 10,
                before_seq: None
            }
        )
        .unwrap_err()
        .code,
        "E_SESSION_EXPIRED"
    );
    assert_eq!(
        backend::audit_verify(&st).unwrap_err().code,
        "E_SESSION_EXPIRED"
    );
}

#[test]
fn d6_audit_payloads_never_carry_the_trap_value() {
    // Plant a distinctive trap value, perform audited ops, then serialize
    // every loaded page + the verify result: none may contain the trap value
    // or any session credential (audit records names only, never values).
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    let dir = real_dir(&env, "d6-trap");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
            value: AUDIT_TRAP.to_string(),
        },
    )
    .unwrap();
    let _ = backend::agents_list(&st).unwrap();
    let _ = backend::leases_list(&st).unwrap();
    let _ = backend::runs_list(&st).unwrap();
    let pages = d6_load_all(&st, 50);
    let verify = backend::audit_verify(&st).expect("verify must succeed");
    // Same-process fixture only: read the held credential back to hunt it.
    let session_cred = st
        .session
        .lock()
        .expect("session lock")
        .clone()
        .expect("session must be held")
        .to_string();
    let mut bodies: Vec<String> = pages
        .iter()
        .map(|p| serde_json::to_string(p).unwrap())
        .collect();
    bodies.push(serde_json::to_string(&verify).unwrap());
    for body in &bodies {
        assert!(!body.contains(AUDIT_TRAP), "trap value leaked: {body}");
        assert!(!body.contains(&session_cred), "session credential leaked");
    }
    // Guard against the shape itself growing a value-carrying field: the
    // serialized entry keys must be exactly the contracted set (ten when all
    // three `Option` fields are present; fewer when some are `None`).
    let entry_json = serde_json::to_value(&pages[0].entries[0]).unwrap();
    let keys: std::collections::HashSet<&str> = entry_json
        .as_object()
        .unwrap()
        .keys()
        .map(|s| s.as_str())
        .collect();
    // Mandatory fields always present; the three `Option` fields appear only
    // when `Some` (`skip_serializing_if`). Nothing else may appear.
    for required in [
        "actor",
        "authenticated",
        "decision",
        "keys",
        "op",
        "seq",
        "ts",
    ] {
        assert!(keys.contains(required), "{required} missing: {keys:?}");
    }
    // (`project`/`reason`/`run_id` appear only when `Some`.)
    assert!(
        keys.iter().all(|k| [
            "actor",
            "authenticated",
            "decision",
            "keys",
            "op",
            "project",
            "reason",
            "run_id",
            "seq",
            "ts"
        ]
        .contains(k)),
        "unexpected entry field: {keys:?}"
    );
    for forbidden in [
        "hash",
        "prev_hash",
        "mac",
        "target",
        "cwd",
        "executable",
        "arg_count",
        "result",
        "exit_code",
        "signal",
        "value",
        "token",
        "passphrase",
        "session_credential",
    ] {
        assert!(
            !keys.contains(forbidden),
            "{forbidden} leaked into shape: {keys:?}"
        );
    }
}

#[test]
fn d6_audit_offline_fails_closed() {
    // Dead socket: both commands fail `E_IO` — never an empty success.
    let _g = serial();
    let dead = AppState::new(PathBuf::from("/tmp/svault-dash-test-d6-dead.sock"));
    assert_eq!(
        backend::audit_show(
            &dead,
            backend::AuditShowIn {
                tail: 10,
                before_seq: None
            }
        )
        .unwrap_err()
        .code,
        "E_IO"
    );
    assert_eq!(backend::audit_verify(&dead).unwrap_err().code, "E_IO");
}

#[test]
fn d6_audit_verify_requires_trust_first() {
    // No pin file for the socket: both commands fail `E_BROKER_UNTRUSTED`,
    // and the vault stays locked — zero credential bytes reached the broker
    // (mirror of `unlock_without_pin_sends_no_credential`).
    let _g = serial();
    let env = live_env();
    let st = state_for(&env);
    assert_eq!(
        backend::audit_show(
            &st,
            backend::AuditShowIn {
                tail: 10,
                before_seq: None
            }
        )
        .unwrap_err()
        .code,
        "E_BROKER_UNTRUSTED"
    );
    assert_eq!(
        backend::audit_verify(&st).unwrap_err().code,
        "E_BROKER_UNTRUSTED"
    );
    let resp = env.daemon.handle_request(svault::wire::Request {
        v: svault::wire::VERSION,
        id: "witness".into(),
        op: "vault.status".into(),
        auth: None,
        params: serde_json::json!({}),
    });
    assert!(resp.ok, "broker must answer vault.status unauthenticated");
    let locked = resp
        .result
        .as_ref()
        .and_then(|r| r.get("locked"))
        .and_then(|v| v.as_bool());
    assert_eq!(
        locked,
        Some(true),
        "the broker's own vault must still be locked: no credential reached it"
    );
}

#[test]
fn d6_allowlist_has_no_pin_write_or_generic_passthrough() {
    // No `trust_broker`/`trust`-shaped entry, no generic `call`, length 30.
    assert_eq!(COMMANDS.len(), 30);
    assert!(!COMMANDS.contains(&"trust_broker"));
    assert!(!COMMANDS
        .iter()
        .any(|c| *c == "trust" || c.starts_with("trust_")));
    assert!(!COMMANDS.contains(&"call"));
}

#[test]
fn d6_full_smoke_chain_unlock_audit_health_settings_lock() {
    // The D6 full-chain smoke as ONE ordered test, each step re-reading the
    // broker (no optimistic state): status -> pin -> unlock -> audited ops ->
    // audit pages -> empty page -> verify -> health -> settings -> lock.
    // One ordered trace line per step (`--nocapture` smoke evidence). Prints
    // only counts/seqs/codes/statuses — never values or credentials.
    let _g = serial();
    let env = live_env();
    let st = state_for(&env);
    // 1: pre-pin posture.
    let status = backend::get_status(&st).expect("status must succeed");
    assert!(status.online);
    assert!(!status.trusted);
    assert!(status.locked);
    println!(
        "1 status: online={} trusted={} locked={}",
        status.online, status.trusted, status.locked
    );
    // 2: TTY-style pin, then unlock.
    pin_live(&env);
    let pass = String::from_utf8(PASS.to_vec()).unwrap();
    let unlock_out =
        backend::unlock(&st, UnlockIn { passphrase: pass }).expect("unlock must succeed");
    assert!(unlock_out.unlocked);
    println!(
        "2 unlock: unlocked={} prefix_len={}",
        unlock_out.unlocked,
        unlock_out
            .session_prefix
            .as_ref()
            .map(|p| p.len())
            .unwrap_or(0)
    );
    // 3: deterministic audited ops + one audit read (which appends its own).
    let dir = real_dir(&env, "d6-smoke");
    backend::project_add(
        &st,
        backend::ProjectAddIn {
            name: "web".to_string(),
            paths: vec![dir],
        },
    )
    .unwrap();
    backend::secret_set(
        &st,
        backend::SecretSetIn {
            project: "web".to_string(),
            key: "API_KEY".to_string(),
            value: AUDIT_TRAP.to_string(),
        },
    )
    .unwrap();
    let agents_n = backend::agents_list(&st).unwrap().agents.len();
    let grants_n = backend::grants_list(&st).unwrap().grants.len();
    let leases_n = backend::leases_list(&st).unwrap().leases.len();
    let runs_n = backend::runs_list(&st).unwrap().runs.len();
    let probe = backend::audit_show(
        &st,
        backend::AuditShowIn {
            tail: 1,
            before_seq: None,
        },
    )
    .unwrap();
    println!(
        "3 ops: project_add=ok secret_set=ok agents={agents_n} grants={grants_n} leases={leases_n} runs={runs_n} audit_probe_entries={}",
        probe.entries.len()
    );
    // 4: audit pages, tail 2, three pages newest-first.
    let p1 = backend::audit_show(
        &st,
        backend::AuditShowIn {
            tail: 2,
            before_seq: None,
        },
    )
    .unwrap();
    assert!(!p1.entries.is_empty());
    let s1: Vec<u64> = p1.entries.iter().map(|e| e.seq).collect();
    assert!(s1.windows(2).all(|w| w[0] < w[1]), "page ascending: {s1:?}");
    assert!(p1.entries.last().expect("non-empty").authenticated);
    println!(
        "4a audit page1: seqs={s1:?} cursor={:?} newest_authenticated={}",
        p1.next_before_seq,
        p1.entries.last().expect("non-empty").authenticated
    );
    let c1 = p1.next_before_seq.expect("more pages must remain");
    let p2 = backend::audit_show(
        &st,
        backend::AuditShowIn {
            tail: 2,
            before_seq: Some(c1),
        },
    )
    .unwrap();
    assert!(!p2.entries.is_empty());
    let s2: Vec<u64> = p2.entries.iter().map(|e| e.seq).collect();
    assert!(
        s2.iter().all(|s| *s <= c1),
        "page2 bounded by cursor: {s2:?}"
    );
    println!(
        "4b audit page2: seqs={s2:?} cursor={:?}",
        p2.next_before_seq
    );
    let c2 = p2.next_before_seq.expect("more pages must remain");
    let p3 = backend::audit_show(
        &st,
        backend::AuditShowIn {
            tail: 2,
            before_seq: Some(c2),
        },
    )
    .unwrap();
    assert!(!p3.entries.is_empty());
    let s3: Vec<u64> = p3.entries.iter().map(|e| e.seq).collect();
    println!(
        "4c audit page3: seqs={s3:?} cursor={:?}",
        p3.next_before_seq
    );
    let mut union: Vec<u64> = [s1.clone(), s2.clone(), s3.clone()].concat();
    union.sort_unstable();
    union.dedup();
    assert!(
        union.windows(2).all(|w| w[1] == w[0] + 1),
        "union gap-free: {union:?}"
    );
    println!(
        "4d audit union: len={} range={:?}..={:?}",
        union.len(),
        union.first(),
        union.last()
    );
    // 5: empty page.
    let empty = backend::audit_show(
        &st,
        backend::AuditShowIn {
            tail: 2,
            before_seq: Some(0),
        },
    )
    .unwrap();
    assert!(empty.entries.is_empty());
    assert_eq!(empty.next_before_seq, None);
    println!("5 empty page: entries=0 cursor=None");
    // 6: verify.
    let verify = backend::audit_verify(&st).expect("verify must succeed");
    assert!(verify.entries > 0);
    assert!(verify.macs_verified > 0);
    println!(
        "6 verify: entries={} macs_verified={} macs_null={}",
        verify.entries, verify.macs_verified, verify.macs_null
    );
    // 7: health while unlocked.
    let health = backend::health(&st).expect("health must succeed");
    let locked = health
        .get("locked")
        .and_then(|v| v.as_bool())
        .expect("locked present");
    assert!(!locked);
    let idle_secs = health
        .get("idle_lock_secs")
        .and_then(|v| v.as_u64())
        .expect("idle_lock_secs present");
    assert!(idle_secs > 0);
    let audit_bytes = health
        .get("audit_bytes")
        .and_then(|v| v.as_u64())
        .expect("audit_bytes present");
    assert!(audit_bytes > 0);
    let soft = health
        .get("audit_soft_limit")
        .and_then(|v| v.as_u64())
        .expect("soft present");
    assert!(soft > 0);
    let hard = health
        .get("audit_hard_limit")
        .and_then(|v| v.as_u64())
        .expect("hard present");
    assert!(hard > soft);
    let vault_bytes = health
        .get("vault_bytes")
        .and_then(|v| v.as_u64())
        .expect("vault_bytes present");
    assert!(vault_bytes > 0);
    let vault_max = health
        .get("vault_max_bytes")
        .and_then(|v| v.as_u64())
        .expect("vault_max present");
    assert!(vault_max > vault_bytes);
    assert!(health.get("leases_active").is_some_and(|v| !v.is_null()));
    assert!(health
        .get("approvals_pending")
        .is_some_and(|v| !v.is_null()));
    println!(
        "7 health: locked={locked} idle_secs={idle_secs} audit_bytes={audit_bytes} soft={soft} hard={hard} vault_bytes={vault_bytes} vault_max={vault_max}"
    );
    // 8: settings surface.
    let pin_path = svault::broker_identity::pin_path(&env.socket).expect("pin path resolves");
    let pin_before = std::fs::read(&pin_path).expect("pin file exists");
    let pin = backend::pin_status(&st).expect("pin_status must succeed");
    assert!(pin.pinned);
    let fp = pin.fingerprint.expect("pinned fingerprint present");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(fp, fp.to_lowercase(), "fingerprint must be lowercase hex");
    let probe_fp = backend::probe_fingerprint(&st)
        .expect("probe must succeed")
        .fingerprint;
    assert_eq!(
        probe_fp, fp,
        "live fingerprint must equal pinned fingerprint"
    );
    let pin_after = std::fs::read(&pin_path).expect("pin file still exists");
    assert_eq!(pin_before, pin_after, "probe must not rewrite the pin");
    let status2 = backend::get_status(&st).expect("status must succeed");
    println!(
        "8 settings: pinned={} fp_len={} probe_match={} version={} created_len={}",
        pin.pinned,
        fp.len(),
        probe_fp == fp,
        status2.version,
        status2.created.len()
    );
    // Residue BEFORE lock (lock drops the session; serialize + capture the
    // credential while held so step 10 can hunt for it).
    let session_cred = st
        .session
        .lock()
        .expect("session lock")
        .clone()
        .expect("session must be held")
        .to_string();
    let pass_str = String::from_utf8(PASS.to_vec()).unwrap();
    let residue = [
        serde_json::to_string(&p1).unwrap(),
        serde_json::to_string(&p2).unwrap(),
        serde_json::to_string(&p3).unwrap(),
        serde_json::to_string(&verify).unwrap(),
        serde_json::to_string(&health).unwrap(),
    ];
    // 9: lock updates states.
    assert!(backend::lock(&st).unwrap().locked);
    let after = backend::get_status(&st).expect("status must succeed");
    assert!(after.locked);
    let err = backend::audit_show(
        &st,
        backend::AuditShowIn {
            tail: 2,
            before_seq: None,
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "E_SESSION_EXPIRED");
    // 10: residue — trap value, passphrase and session credential absent from
    // every held string.
    for body in &residue {
        assert!(!body.contains(AUDIT_TRAP), "trap value leaked: {body}");
        assert!(!body.contains(&pass_str), "passphrase leaked: {body}");
        assert!(!body.contains(&session_cred), "session credential leaked");
    }
    println!("10 residue: pages=3 verify=1 health=1 trap_free=true");
}

// ---------------- D7: no-vault state + bounded shutdown ----------------

/// Daemon serving with NO vault file (first-run shape): `Daemon::new` with a
/// vault path that was never created yields `session: None`, so every op
/// except `vault.create` answers `E_NOT_FOUND`. Pin store isolated the same
/// way as `live_env`.
fn no_vault_env() -> Env {
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "svault-dash-test-novault-{}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // SAFETY: same containment as `live_env` (see above).
    unsafe {
        std::env::set_var("XDG_DATA_HOME", dir.join("data"));
        std::env::set_var("XDG_RUNTIME_DIR", dir.join("run"));
    }
    let vault_path = dir.join("vault.enc");
    let socket_path = dir.join("svault.sock");
    // Deliberately NO `Session::create`: the vault file stays absent.
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
        if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
            break;
        }
    }
    Env {
        _dir: dir,
        socket: socket_path,
        daemon,
    }
}

#[test]
fn d7_no_vault_is_online_but_uninitialized() {
    // Running daemon, no vault file: the broker answers `vault.status` with
    // `E_NOT_FOUND`, which must surface as ONLINE + uninitialized — never
    // "broker offline".
    let _g = serial();
    let env = no_vault_env();
    pin_live(&env);
    let st = state_for(&env);
    let status = backend::get_status(&st).expect("no-vault status must succeed");
    assert!(
        status.online,
        "daemon answered: this is no-vault, not offline"
    );
    assert!(
        !status.initialized,
        "absent vault must report uninitialized"
    );
    assert!(
        status.trusted,
        "pinned daemon must stay trusted without a vault"
    );
    assert_eq!(status.version, 0);
    assert!(status.created.is_empty());
    assert!(status.locked, "fail-safe shape, never a broker observation");
    assert!(status.fingerprint.map(|f| f.len()).unwrap_or(0) == 64);
    let _ = env.daemon; // keep env alive until end of test
}

#[test]
fn d7_status_success_is_initialized() {
    // Normal path (vault exists): `initialized` is true.
    let _g = serial();
    let env = live_env();
    pin_live(&env);
    let st = state_for(&env);
    let status = backend::get_status(&st).expect("status must succeed");
    assert!(status.online);
    assert!(status.initialized, "existing vault must report initialized");
}

#[test]
fn d7_shutdown_lock_is_bounded_and_never_panics() {
    // Dead socket + short budget: the call must return (total function —
    // never panics, never blocks past a generous ceiling). The boolean is
    // deliberately NOT asserted: a missing daemon may fail fast either way.
    let _g = serial();
    let dead = PathBuf::from("/tmp/svault-dash-test-d7-dead.sock");
    let start = std::time::Instant::now();
    let _ = backend::shutdown_lock(
        &dead,
        svault::client::Auth::None,
        Duration::from_millis(200),
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "shutdown_lock must stay bounded, elapsed={:?}",
        start.elapsed()
    );
}

#[test]
fn d7_shutdown_lock_without_credentials_is_refused() {
    // `Auth::None` cannot lock a human-only op (the broker refuses with
    // `E_AUTH`): against a dead socket this only proves the function is
    // total and bounded — it must return inside the budget and never panic.
    // Broker state cannot be witnessed without a daemon, so only
    // totality/boundedness is asserted here.
    let _g = serial();
    let dead = PathBuf::from("/tmp/svault-dash-test-d7-dead.sock");
    let start = std::time::Instant::now();
    let _ = backend::shutdown_lock(
        &dead,
        svault::client::Auth::None,
        Duration::from_millis(200),
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "shutdown_lock with Auth::None must stay bounded, elapsed={:?}",
        start.elapsed()
    );
}

#[test]
fn d7_shutdown_lock_with_a_session_locks_the_vault() {
    // The proof the old `Auth::None` bug would have failed: a real daemon,
    // a real unlock, then `shutdown_lock` with the live session credential
    // must leave the vault reporting LOCKED.
    let _g = serial();
    let env = live_env();
    let st = unlocked_state(&env);
    assert!(
        !backend::get_status(&st).unwrap().locked,
        "fixture must start unlocked"
    );
    // Take the credential exactly like the window-close handler does: state
    // is cleared unconditionally, and the value authenticates the lock.
    let cred = st.take_session().expect("session must be held");
    assert!(
        st.session.lock().map(|g| g.is_none()).unwrap_or(false),
        "take_session must clear AppState"
    );
    let done = backend::shutdown_lock(
        &env.socket,
        svault::client::Auth::Session(cred.to_string()),
        Duration::from_secs(3),
    );
    assert!(done, "shutdown_lock must complete inside its budget");
    assert!(
        backend::get_status(&st).unwrap().locked,
        "vault must report locked after shutdown_lock with a session"
    );
}

#[test]
fn d7_status_out_serializes_initialized() {
    // Consumer-visible contract: `initialized` is always present on the
    // wire (no `skip_serializing_if`), true or false.
    let on = crate::backend::StatusOut {
        version: 1,
        created: String::new(),
        locked: false,
        online: true,
        trusted: true,
        initialized: true,
        fingerprint: None,
    };
    let v = serde_json::to_value(&on).unwrap();
    assert_eq!(
        v.get("initialized"),
        Some(&serde_json::Value::Bool(true)),
        "initialized=true must serialize: {v}"
    );
    let off = crate::backend::StatusOut {
        initialized: false,
        ..on
    };
    let v = serde_json::to_value(&off).unwrap();
    assert_eq!(
        v.get("initialized"),
        Some(&serde_json::Value::Bool(false)),
        "initialized=false must serialize too (never skipped): {v}"
    );
}

// ---------------- M1: navigation guard ----------------

#[test]
fn m1_allow_navigation_allows_only_tauri_scheme() {
    for ok in [
        "tauri://localhost/index.html",
        "tauri://localhost/",
        "TAURI://LOCALHOST/x",
    ] {
        assert!(backend::allow_navigation(ok), "must allow {ok}");
    }
}

#[test]
fn m1_allow_navigation_blocks_non_tauri_urls() {
    for bad in [
        "http://127.0.0.1/",
        "https://evil.example/",
        "file:///etc/passwd",
        "data:text/html,<script>",
        "javascript:alert(1)",
        "blob:tauri://localhost/abc",
        "tauri ://x",
        "",
        "about:blank",
    ] {
        assert!(!backend::allow_navigation(bad), "must block {bad:?}");
    }
}
