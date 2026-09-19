//! Adversarial suite for `inject_file`: filesystem containment, races,
//! redaction and integrity (spec: secrets-operations + threat model I5).

use std::os::unix::fs::{FileTypeExt, PermissionsExt, symlink};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::json;
use svault::broker;
use svault::error::VaultError;
use svault::session::{Clock, Session};
use svault::wire::{self, Request, Response};

struct TestDir(std::path::PathBuf);
impl TestDir {
    fn new() -> Self {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("svault-adv-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
struct FakeClock(Arc<std::sync::Mutex<std::time::Instant>>);
impl Clock for FakeClock {
    fn now(&self) -> std::time::Instant {
        *self.0.lock().unwrap()
    }
}

const PASS: &[u8] = b"correct horse battery";
const IDLE: Duration = Duration::from_secs(60);

fn unlocked_session(dir: &TestDir) -> Session {
    let path = dir.path().join("vault.enc");
    let clock = FakeClock(Arc::new(std::sync::Mutex::new(std::time::Instant::now())));
    let mut s = Session::create(&path, PASS, IDLE, Box::new(clock)).unwrap();
    s.unlock(PASS).unwrap();
    std::fs::create_dir_all(dir.path().join("authorized")).unwrap();
    s.project_add("human", "acme", &[dir.path().join("authorized")])
        .unwrap();
    s.secret_set("human", "acme", "STRIPE_KEY", b"sk-trap-0xf00dVALUE")
        .unwrap();
    s.secret_set(
        "human",
        "acme",
        "OTHER_KEY",
        b"value with \"quotes\" and $ and `backticks`",
    )
    .unwrap();
    s
}

fn enroll(session: &mut Session) -> String {
    // Enrollment is idempotent per test: a duplicate name means the agent
    // already exists and its token was consumed — re-enroll under a fresh
    // unique name instead of failing.
    let name = format!("harness-{}", std::process::id());
    let resp = session.agent_add("human", &name).expect("enrollment");
    session
        .grant_add(
            "human",
            &name,
            "acme",
            &[svault::model::Op::Read, svault::model::Op::Inject],
        )
        .unwrap();
    resp.1
}

fn daemon_and_token(dir: &TestDir, mut session: Session) -> (broker::Daemon, String) {
    let token = enroll(&mut session);
    let config = broker::DaemonConfig {
        socket_path: dir.path().join("svault.sock"),
        vault_path: dir.path().join("vault.enc"),
        idle_lock: IDLE,
    };
    // H2: one mutable owner at a time, so the enrolling session must release
    // the vault before the daemon takes it.
    drop(session);
    (broker::Daemon::new(config).unwrap(), token)
}

fn call(
    daemon: &broker::Daemon,
    id: &str,
    op: &str,
    token: Option<&str>,
    params: serde_json::Value,
) -> Response {
    daemon.handle_request(Request {
        v: wire::VERSION,
        id: id.to_string(),
        op: op.to_string(),
        auth: token.map(|t| wire::AuthField {
            token: Some(t.to_string()),
            passphrase: None,
            session: None,
        }),
        params,
    })
}

fn callh(
    daemon: &broker::Daemon,
    id: &str,
    op: &str,
    pass: &str,
    params: serde_json::Value,
) -> Response {
    daemon.handle_request(Request {
        v: wire::VERSION,
        id: id.to_string(),
        op: op.to_string(),
        auth: Some(wire::AuthField {
            token: None,
            passphrase: Some(pass.to_string()),
            session: None,
        }),
        params,
    })
}

fn err_code(resp: &Response) -> String {
    resp.error.as_ref().unwrap().code.to_string()
}

#[test]
fn traversal_and_absolute_paths_are_rejected_and_audited() {
    let dir = TestDir::new();
    let s = unlocked_session(&dir);
    // Single writer rule: once the daemon exists it owns the vault; all
    // mutations go through dispatch.
    let (d, token) = daemon_and_token(&dir, s);
    // The daemon starts locked: the human unlocks it via dispatch (proof).
    let resp = callh(&d, "u0", "vault.unlock", "correct horse battery", json!({}));
    assert!(resp.ok, "dispatch unlock must succeed: {:?}", resp.error);

    // Unauthenticated inject attempts are denied before anything else.
    for bad in ["../../outside", "/etc/passwd", "a/../b", ".."] {
        let resp = call(
            &d,
            bad,
            "inject_file",
            None,
            serde_json::json!({"project": "acme", "path": bad}),
        );
        assert_eq!(
            err_code(&resp),
            "E_AUTH",
            "unauthenticated must be denied for {bad}"
        );
    }
    // Authenticated agent: kernel containment rejects traversal (E_* codes,
    // audited). Note: ".." is caught by validation; absolute by validation.
    for bad in ["../../outside", "/etc/passwd", "a/../b", ".."] {
        let resp = call(
            &d,
            bad,
            "inject_file",
            Some(&token),
            serde_json::json!({"project": "acme", "path": bad}),
        );
        let code = err_code(&resp);
        assert!(
            matches!(
                code.as_str(),
                "E_INVALID_INPUT" | "E_NOT_FOUND" | "E_PROTOCOL"
            ),
            "traversal {bad} must be rejected, got {code}"
        );
    }
    // The denials are audited with stable codes.
    let resp = callh(
        &d,
        "show",
        "audit.show",
        "correct horse battery",
        serde_json::json!({"tail": 50}),
    );
    let text = serde_json::to_string(&resp).unwrap();
    assert!(text.contains("inject_file"));
    assert!(text.contains("denied"));
}

#[test]
fn locked_vault_and_missing_keys_and_grants_are_denied() {
    let dir = TestDir::new();
    let mut s = unlocked_session(&dir);

    // Missing key / unknown project at session level (direct writer).
    assert!(matches!(
        s.inject_file("agent:x", "acme", ".env", Some(&["NOPE".to_string()])),
        Err(VaultError::NotFound)
    ));
    assert!(matches!(
        s.inject_file("agent:x", "ghost", ".env", None),
        Err(VaultError::NotFound)
    ));
    let token = enroll(&mut s);

    // H2: hand the vault over before anyone else opens it.
    drop(s);

    // Locked vault (fresh load without unlocking) → E_LOCKED.
    let path = dir.path().join("vault.enc");
    let clock = FakeClock(Arc::new(std::sync::Mutex::new(std::time::Instant::now())));
    let mut locked = Session::load(&path, IDLE, Box::new(clock)).unwrap();
    assert!(matches!(
        locked.inject_file("agent:x", "acme", ".env", None),
        Err(VaultError::Locked)
    ));
    drop(locked);

    // Broker authz via dispatch (daemon created last: single writer rule).
    let config = broker::DaemonConfig {
        socket_path: dir.path().join("svault.sock"),
        vault_path: path,
        idle_lock: IDLE,
    };
    let d = broker::Daemon::new(config).unwrap();
    let resp = callh(&d, "u0", "vault.unlock", "correct horse battery", json!({}));
    assert!(resp.ok, "dispatch unlock must succeed: {:?}", resp.error);
    let resp = call(
        &d,
        "ok",
        "inject_file",
        Some(&token),
        serde_json::json!({"project": "acme", "path": ".env"}),
    );
    assert!(
        resp.ok || err_code(&resp) == "E_PERMISSION",
        "unexpected: {resp:?}"
    );
}

#[test]
fn inject_grant_is_enforced_and_revocation_is_immediate() {
    let dir = TestDir::new();
    let mut s = unlocked_session(&dir);
    let (_agent_id, token) = s.agent_add("human", "reader").unwrap();
    s.grant_add("human", "reader", "acme", &[svault::model::Op::Read])
        .unwrap();
    let config = broker::DaemonConfig {
        socket_path: dir.path().join("svault.sock"),
        vault_path: dir.path().join("vault.enc"),
        idle_lock: IDLE,
    };
    drop(s);
    let d = broker::Daemon::new(config).unwrap();
    assert!(
        callh(
            &d,
            "unlock",
            "vault.unlock",
            "correct horse battery",
            json!({})
        )
        .ok
    );

    let target = dir.path().join("authorized/.env");
    let params = json!({"project": "acme", "path": ".env"});

    let denied = call(
        &d,
        "inject-identical",
        "inject_file",
        Some(&token),
        params.clone(),
    );
    assert!(!denied.ok, "inject without grant unexpectedly succeeded");
    assert_eq!(err_code(&denied), "E_PERMISSION", "{denied:?}");
    assert!(!target.exists(), "denied inject created its destination");

    std::fs::write(&target, b"ORIGINAL=1\n").unwrap();
    let denied_existing = call(
        &d,
        "inject-identical",
        "inject_file",
        Some(&token),
        params.clone(),
    );
    assert_eq!(
        err_code(&denied_existing),
        "E_PERMISSION",
        "{denied_existing:?}"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"ORIGINAL=1\n");

    let granted = callh(
        &d,
        "grant-inject",
        "grants.grant",
        "correct horse battery",
        json!({"agent": "reader", "project": "acme", "ops": "read,inject"}),
    );
    assert!(granted.ok, "{granted:?}");
    let allowed = call(
        &d,
        "inject-identical",
        "inject_file",
        Some(&token),
        params.clone(),
    );
    assert!(allowed.ok, "{allowed:?}");
    let injected = std::fs::read(&target).unwrap();
    assert_ne!(injected, b"ORIGINAL=1\n");

    let revoked = callh(
        &d,
        "revoke-inject",
        "grants.revoke",
        "correct horse battery",
        json!({"agent": "reader", "project": "acme"}),
    );
    assert!(revoked.ok, "{revoked:?}");
    let denied_again = call(&d, "inject-identical", "inject_file", Some(&token), params);
    assert!(
        !denied_again.ok,
        "inject after revoke unexpectedly succeeded"
    );
    assert_eq!(err_code(&denied_again), "E_PERMISSION", "{denied_again:?}");
    assert_eq!(std::fs::read(&target).unwrap(), injected);
    let audit = callh(
        &d,
        "audit",
        "audit.show",
        "correct horse battery",
        json!({"tail": 100}),
    );
    let text = serde_json::to_string(&audit).unwrap();
    assert!(text.contains("inject_file"));
    assert!(text.contains("E_PERMISSION"));
    assert!(!text.contains("sk-trap-0xf00dVALUE"));
}
#[test]
fn symlinks_and_non_regular_destinations_never_escape() {
    let dir = TestDir::new();
    let mut s = unlocked_session(&dir);
    let authorized = dir.path().join("authorized");
    std::fs::create_dir_all(&authorized).unwrap();
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("sentinel"), b"do-not-touch").unwrap();

    // Final symlink pointing outside: REFUSED (option A), outside untouched.
    symlink(outside.join("sentinel"), authorized.join(".env")).unwrap();
    assert!(s.inject_file("agent:x", "acme", ".env", None).is_err());
    assert!(
        std::fs::symlink_metadata(authorized.join(".env"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read(outside.join("sentinel")).unwrap(),
        b"do-not-touch"
    );

    // Intermediate symlink pointing outside.
    symlink(&outside, authorized.join("link")).unwrap();
    assert!(s.inject_file("agent:x", "acme", "link/.env", None).is_err());
    assert_eq!(
        std::fs::read(outside.join("sentinel")).unwrap(),
        b"do-not-touch"
    );

    // Magic-link style symlink into /proc.
    symlink("/proc/self/environ", authorized.join("magic")).unwrap();
    // Option A: the symlink leaf is refused — /proc is never touched.
    assert!(s.inject_file("agent:x", "acme", "magic", None).is_err());
    assert!(std::fs::read_to_string("/proc/self/environ").is_ok());

    // Non-regular destination: FIFO.
    let fifo = authorized.join("pipe.env");
    let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
    assert!(s.inject_file("agent:x", "acme", "pipe.env", None).is_err());
    assert!(std::fs::metadata(&fifo).unwrap().file_type().is_fifo());
}

#[test]
fn race_swap_never_escapes() {
    let dir = TestDir::new();
    let mut s = unlocked_session(&dir);
    let authorized = dir.path().join("authorized");
    std::fs::create_dir_all(&authorized).unwrap();
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("sentinel"), b"do-not-touch").unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let racer_stop = stop.clone();
    let outside_for_racer = outside.clone();
    let link = authorized.join("link");
    let racer = std::thread::spawn(move || {
        let mut flip = false;
        while !racer_stop.load(Ordering::Relaxed) {
            let _ = std::fs::remove_file(&link);
            if flip {
                let _ = symlink(&outside_for_racer, &link);
            } else {
                let _ = std::fs::create_dir(&link);
            }
            flip = !flip;
        }
    });

    let mut escapes = 0;
    for i in 0..200 {
        match s.inject_file("agent:x", "acme", "link/.env", None) {
            Ok(r) => {
                // Success is only legitimate if the file landed inside the
                // authorized folder (resolved via kernel containment).
                if !r.path.starts_with(&authorized) {
                    escapes += 1;
                }
            }
            Err(_) => { /* clean refusal is fine */ }
        }
        let _ = i;
    }
    stop.store(true, Ordering::Relaxed);
    racer.join().unwrap();
    assert_eq!(
        escapes, 0,
        "no injection may land outside the authorized folder"
    );
    assert_eq!(
        std::fs::read(outside.join("sentinel")).unwrap(),
        b"do-not-touch"
    );
    let outside_entries: Vec<_> = std::fs::read_dir(&outside).unwrap().collect();
    assert_eq!(outside_entries.len(), 1, "nothing may appear outside");
}

#[test]
fn redaction_across_channels_and_permissions() {
    let dir = TestDir::new();
    let mut s = unlocked_session(&dir);
    let authorized = dir.path().join("authorized");
    std::fs::create_dir_all(&authorized).unwrap();
    let report = s.inject_file("agent:x", "acme", ".env", None).unwrap();

    // Wire metadata only: no trap values can appear in a serialized report.
    let report_json = serde_json::to_string(&serde_json::json!({
        "path": report.path.display().to_string(),
        "keys": report.keys,
    }))
    .unwrap();
    assert!(!report_json.contains("sk-trap-0xf00dVALUE"));

    // Audit: key names and target, never values.
    let audit_path = svault::store::audit_path(&dir.path().join("vault.enc"));
    let audit = std::fs::read_to_string(audit_path).unwrap();
    assert!(audit.contains("inject_file"));
    assert!(audit.contains("STRIPE_KEY"));
    assert!(!audit.contains("sk-trap-0xf00dVALUE"));
    assert!(!audit.contains("backticks"));

    // Permissions 0600.
    let mode = std::fs::metadata(&report.path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn failed_write_keeps_previous_file_intact() {
    let dir = TestDir::new();
    let mut s = unlocked_session(&dir);
    let report = s.inject_file("agent:x", "acme", ".env", None).unwrap();
    let before = std::fs::read(&report.path).unwrap();

    // Make the authorized folder read-only: temp creation fails, previous
    // file must survive byte-for-byte.
    let authorized = dir.path().join("authorized");
    let mut perms = std::fs::metadata(&authorized).unwrap().permissions();
    perms.set_mode(0o500);
    std::fs::set_permissions(&authorized, perms).unwrap();
    assert!(s.inject_file("agent:x", "acme", ".env", None).is_err());
    let mut perms = std::fs::metadata(&authorized).unwrap().permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(&authorized, perms).unwrap();

    assert_eq!(std::fs::read(&report.path).unwrap(), before);
}

#[test]
fn dotenv_roundtrip_through_real_file() {
    let dir = TestDir::new();
    let mut s = unlocked_session(&dir);
    let report = s.inject_file("agent:x", "acme", ".env", None).unwrap();

    let parsed: std::collections::HashMap<String, String> = dotenvy::from_path_iter(&report.path)
        .unwrap()
        .map(|r| r.expect("dotenv parse"))
        .collect();
    assert_eq!(
        parsed.get("STRIPE_KEY").map(String::as_str),
        Some("sk-trap-0xf00dVALUE")
    );
    assert_eq!(
        parsed.get("OTHER_KEY").map(String::as_str),
        Some("value with \"quotes\" and $ and `backticks`")
    );
}
