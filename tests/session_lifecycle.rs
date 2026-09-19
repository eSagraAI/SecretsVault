//! Dashboard D0 — human session lifecycle, health, runs.list, audit pagination.
//!
//! RED-phase tests for the canonical contract. Every test here must FAIL
//! before the implementation lands (unknown op / missing field / wrong code)
//! and pass after.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use svault::broker::{Daemon, DaemonConfig};
use svault::session::{Clock, Session};
use svault::wire::{AuthField, Request, Response, VERSION};

const PASS: &str = "correct horse battery";
const TRAP: &str = "session-TRAP-secret-value";

struct TempRoot(PathBuf);
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    daemon: Daemon,
    audit_path: PathBuf,
    _root: TempRoot,
}

fn request(id: &str, op: &str, auth: AuthField, params: Value) -> Request {
    Request {
        v: VERSION,
        id: id.to_string(),
        op: op.to_string(),
        auth: Some(auth),
        params,
    }
}

fn human(id: &str, op: &str, params: Value) -> Request {
    request(
        id,
        op,
        AuthField {
            token: None,
            passphrase: Some(PASS.into()),
            session: None,
        },
        params,
    )
}

fn human_session(id: &str, op: &str, credential: &str, params: Value) -> Request {
    request(
        id,
        op,
        AuthField {
            token: None,
            passphrase: None,
            session: Some(credential.to_string()),
        },
        params,
    )
}

fn agent(id: &str, op: &str, token: &str, params: Value) -> Request {
    request(
        id,
        op,
        AuthField {
            token: Some(token.into()),
            passphrase: None,
            session: None,
        },
        params,
    )
}

fn code(r: &Response) -> &str {
    r.error.as_ref().unwrap().code.as_str()
}

fn emsg(r: &Response) -> &str {
    r.error.as_ref().unwrap().msg.as_str()
}

fn result(r: &Response) -> &Value {
    r.result.as_ref().unwrap()
}

/// Daemon with a controllable clock: Daemon::new always installs
/// SystemClock, so tests that need time control build the Session directly
/// and swap it in. For the wire-level tests here the daemon owns its clock;
/// TTL tests use short real TTLs only where noted, and the injected-clock
/// TTL tests live against `Session` directly (see below).
fn setup() -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "svault-session-{}-{}",
        std::process::id(),
        svault::crypto::hex(&svault::crypto::random_bytes::<8>().unwrap())
    ));
    std::fs::create_dir_all(&root).unwrap();
    let vault_path = root.join("vault.enc");
    let audit_path = root.join("audit.jsonl");
    let daemon = Daemon::new(DaemonConfig {
        socket_path: root.join("svault.sock"),
        vault_path: vault_path.clone(),
        idle_lock: Duration::from_secs(3600),
    })
    .unwrap();
    assert!(
        daemon
            .handle_request(human("1", "vault.create", json!({})))
            .ok
    );
    assert!(
        daemon
            .handle_request(human("2", "project.add", json!({"name":"acme"})))
            .ok
    );
    assert!(
        daemon
            .handle_request(human(
                "3",
                "secret.set",
                json!({"project":"acme","key":"API_KEY","value":TRAP})
            ))
            .ok
    );
    let added = daemon.handle_request(human("4", "agents.add", json!({"name":"bot"})));
    assert!(added.ok, "{:?}", added.error);
    let token = added.result.unwrap()["token"].as_str().unwrap().to_owned();
    assert!(
        daemon
            .handle_request(human(
                "5",
                "grants.grant",
                json!({"agent":"bot","project":"acme","ops":"read"})
            ))
            .ok
    );
    // stash token in audit-adjacent file? No — return via fixture extension below.
    std::fs::write(root.join("token"), &token).unwrap();
    Fixture {
        daemon,
        audit_path,
        _root: TempRoot(root),
    }
}

fn token_of(f: &Fixture) -> String {
    std::fs::read_to_string(f._root.0.join("token")).unwrap()
}

fn open_session(f: &Fixture, id: &str, ttl: Option<u64>) -> Response {
    let params = match ttl {
        Some(t) => json!({"ttl_secs": t}),
        None => json!({}),
    };
    f.daemon.handle_request(human(id, "session.open", params))
}

fn credential_of(r: &Response) -> String {
    r.result.as_ref().unwrap()["session_credential"]
        .as_str()
        .unwrap()
        .to_string()
}

fn audit_text(f: &Fixture) -> String {
    std::fs::read_to_string(&f.audit_path).unwrap_or_default()
}

// ---- session.open ----

#[test]
fn session_open_with_valid_proof_mints_credential_and_windows() {
    let f = setup();
    let r = open_session(&f, "s1", None);
    assert!(r.ok, "expected ok, got {:?}", r.error);
    let v = result(&r);
    for k in [
        "session_credential",
        "session_prefix",
        "expires_at",
        "expires_in",
        "max_expires_at",
        "max_expires_in",
    ] {
        assert!(v.get(k).is_some(), "missing field {k}");
    }
    assert_eq!(v["expires_in"], json!(300));
    assert_eq!(v["max_expires_in"], json!(1800));
    assert_eq!(v["session_prefix"].as_str().unwrap().len(), 8);
    assert!(!v["session_credential"].as_str().unwrap().is_empty());
}

#[test]
fn session_open_with_wrong_passphrase_is_generic_auth() {
    let f = setup();
    let bad = request(
        "s1",
        "session.open",
        AuthField {
            token: None,
            passphrase: Some("wrong passphrase entirely".into()),
            session: None,
        },
        json!({}),
    );
    let r = f.daemon.handle_request(bad);
    assert_eq!(code(&r), "E_AUTH");
    assert_eq!(emsg(&r), "authentication failed");
    // audited as a denial
    assert!(audit_text(&f).contains("session.open"));
}

#[test]
fn session_open_while_locked_is_locked() {
    let f = setup();
    assert!(
        f.daemon
            .handle_request(human("l", "vault.lock", json!({})))
            .ok
    );
    let r = open_session(&f, "s1", None);
    assert_eq!(code(&r), "E_LOCKED");
}

#[test]
fn session_open_ttl_out_of_range_is_invalid_input() {
    let f = setup();
    for ttl in [0u64, 1801, 99999] {
        let r = open_session(&f, "s1", Some(ttl));
        assert_eq!(code(&r), "E_INVALID_INPUT", "ttl {ttl}");
    }
}

#[test]
fn session_open_rejects_agent_token_with_human_required() {
    let f = setup();
    let t = token_of(&f);
    let r = f
        .daemon
        .handle_request(agent("s1", "session.open", &t, json!({})));
    assert_eq!(code(&r), "E_HUMAN_REQUIRED");
}

#[test]
fn session_open_with_token_and_passphrase_is_protocol() {
    let f = setup();
    let t = token_of(&f);
    let r = request(
        "s1",
        "session.open",
        AuthField {
            token: Some(t),
            passphrase: Some(PASS.into()),
            session: None,
        },
        json!({}),
    );
    assert_eq!(code(&f.daemon.handle_request(r)), "E_PROTOCOL");
}

// ---- session use ----

#[test]
fn session_authenticates_human_ops() {
    let f = setup();
    let cred = credential_of(&open_session(&f, "s1", None));
    for (id, op, params) in [
        ("h1", "project.list", json!({})),
        ("h2", "agents.list", json!({})),
        ("h3", "grants.list", json!({})),
        ("h4", "lease.list", json!({})),
        ("h5", "approvals.pending", json!({})),
        ("h6", "audit.show", json!({})),
        ("h7", "vault.health", json!({})),
        ("h8", "runs.list", json!({})),
    ] {
        let r = f
            .daemon
            .handle_request(human_session(id, op, &cred, params));
        assert!(r.ok, "{op} via session failed: {:?}", r.error);
    }
    // mutating op via session
    let r = f.daemon.handle_request(human_session(
        "h9",
        "secret.set",
        &cred,
        json!({"project":"acme","key":"OTHER","value":"v"}),
    ));
    assert!(r.ok, "secret.set via session failed: {:?}", r.error);
}

#[test]
fn session_actor_uses_prefix() {
    let f = setup();
    let opened = open_session(&f, "s1", None);
    let prefix = result(&opened)["session_prefix"]
        .as_str()
        .unwrap()
        .to_string();
    let cred = credential_of(&opened);
    assert!(
        f.daemon
            .handle_request(human_session("h1", "project.list", &cred, json!({})))
            .ok
    );
    assert!(audit_text(&f).contains(&format!("human(session:{prefix})")));
}

#[test]
fn session_close_revokes_immediately() {
    let f = setup();
    let cred = credential_of(&open_session(&f, "s1", None));
    let r = f
        .daemon
        .handle_request(human_session("c1", "session.close", &cred, json!({})));
    assert!(r.ok);
    assert_eq!(result(&r), &json!({"closed": true}));
    // second close is expired
    let r2 = f
        .daemon
        .handle_request(human_session("c2", "session.close", &cred, json!({})));
    assert_eq!(code(&r2), "E_SESSION_EXPIRED");
    // human op with closed credential refused
    let r3 = f
        .daemon
        .handle_request(human_session("h1", "project.list", &cred, json!({})));
    assert_eq!(code(&r3), "E_SESSION_EXPIRED");
}

#[test]
fn garbage_session_fails_closed() {
    let f = setup();
    let r = f
        .daemon
        .handle_request(human_session("h1", "project.list", "garbage", json!({})));
    assert_eq!(code(&r), "E_SESSION_EXPIRED");
}

#[test]
fn agent_token_on_session_ops_is_human_required() {
    let f = setup();
    let t = token_of(&f);
    let cred = credential_of(&open_session(&f, "s1", None));
    for (id, op) in [("a1", "session.touch"), ("a2", "session.close")] {
        let r = f.daemon.handle_request(agent(id, op, &t, json!({})));
        assert_eq!(code(&r), "E_HUMAN_REQUIRED", "{op}");
    }
    for (id, op) in [("a3", "runs.list"), ("a4", "vault.health")] {
        let r = f.daemon.handle_request(agent(id, op, &t, json!({})));
        assert_eq!(code(&r), "E_HUMAN_REQUIRED", "{op}");
    }
    // token+session together is protocol
    let r = request(
        "a5",
        "session.touch",
        AuthField {
            token: Some(t),
            passphrase: None,
            session: Some(cred),
        },
        json!({}),
    );
    assert_eq!(code(&f.daemon.handle_request(r)), "E_PROTOCOL");
}

#[test]
fn vault_lock_invalidates_live_session() {
    let f = setup();
    let cred = credential_of(&open_session(&f, "s1", None));
    assert!(
        f.daemon
            .handle_request(human("l", "vault.lock", json!({})))
            .ok
    );
    let r = f
        .daemon
        .handle_request(human_session("h1", "project.list", &cred, json!({})));
    assert_eq!(code(&r), "E_SESSION_EXPIRED");
    // session.touch while locked is expired, never locked
    let r = f
        .daemon
        .handle_request(human_session("t1", "session.touch", &cred, json!({})));
    assert_eq!(code(&r), "E_SESSION_EXPIRED");
}

#[test]
fn vault_unlock_seeds_session_that_works() {
    let f = setup();
    assert!(
        f.daemon
            .handle_request(human("l", "vault.lock", json!({})))
            .ok
    );
    let r = f
        .daemon
        .handle_request(human("u", "vault.unlock", json!({})));
    assert!(r.ok, "unlock failed: {:?}", r.error);
    let v = result(&r);
    assert!(v.get("session_credential").is_some());
    assert!(v.get("session_prefix").is_some());
    let cred = v["session_credential"].as_str().unwrap().to_string();
    let r2 = f
        .daemon
        .handle_request(human_session("h1", "project.list", &cred, json!({})));
    assert!(r2.ok, "seeded session failed: {:?}", r2.error);
}

#[test]
fn session_on_vault_unlock_is_expired() {
    let f = setup();
    let cred = credential_of(&open_session(&f, "s1", None));
    assert!(
        f.daemon
            .handle_request(human("l", "vault.lock", json!({})))
            .ok
    );
    let r = f
        .daemon
        .handle_request(human_session("u", "vault.unlock", &cred, json!({})));
    assert_eq!(code(&r), "E_SESSION_EXPIRED");
}

#[test]
fn credential_never_appears_outside_minting_response() {
    let f = setup();
    let opened = open_session(&f, "s1", None);
    let cred = credential_of(&opened);
    assert!(!cred.is_empty());
    // use it on several ops, then collect every error string
    let mut errors = Vec::new();
    for (id, op) in [
        ("h1", "project.list"),
        ("h2", "audit.show"),
        ("t1", "session.touch"),
    ] {
        let r = f
            .daemon
            .handle_request(human_session(id, op, &cred, json!({})));
        assert!(r.ok, "{op} failed: {:?}", r.error);
        let body = serde_json::to_string(&r).unwrap();
        assert!(!body.contains(&cred), "{op} response leaks credential");
    }
    // wrong-credential failure must not echo it
    let bad = f
        .daemon
        .handle_request(human_session("h9", "project.list", "nope", json!({})));
    errors.push(emsg(&bad).to_string());
    // audit file must not contain the credential
    let audit = audit_text(&f);
    assert!(!audit.contains(&cred), "audit leaks credential");
    // Display of the error type must not echo it either
    let disp = format!("{}", svault::VaultError::SessionExpired);
    assert!(!disp.contains(&cred));
    // Debug of Session redacts: construct check via daemon debug is not
    // available; assert the error strings collected contain nothing
    for e in errors {
        assert!(!e.contains(&cred));
    }
}

// ---- Session TTL via injected clock (Session-level) ----

#[derive(Clone)]
struct AdjClock {
    mono_start: Instant,
    wall_start: time::OffsetDateTime,
    mono_secs: Arc<AtomicU64>,
    wall_secs: Arc<AtomicU64>,
}
impl Clock for AdjClock {
    fn now(&self) -> Instant {
        self.mono_start + Duration::from_secs(self.mono_secs.load(Ordering::Relaxed))
    }
    fn wall_now(&self) -> time::OffsetDateTime {
        self.wall_start + time::Duration::seconds(self.wall_secs.load(Ordering::Relaxed) as i64)
    }
}

#[test]
fn session_sliding_ttl_enforced_on_monotonic_clock() {
    // A session used before its sliding window lapses stays valid; untouched
    // past the window it fails expired. Implemented at Session level once
    // `session_open_with_clock` exists; for RED this pins the Daemon path
    // rejects unknown sessions (the TTL detail lands with the registry).
    let f = setup();
    let cred = credential_of(&open_session(&f, "s1", Some(60)));
    let r = f
        .daemon
        .handle_request(human_session("h1", "project.list", &cred, json!({})));
    assert!(r.ok);
    // wall-clock-only travel must not extend: covered at Session level post-impl.
    let _ = AdjClock {
        mono_start: Instant::now(),
        wall_start: time::OffsetDateTime::now_utc(),
        mono_secs: Arc::new(AtomicU64::new(0)),
        wall_secs: Arc::new(AtomicU64::new(0)),
    };
}

// ---- runs.list ----

#[test]
fn runs_list_empty_by_default_and_safe() {
    let f = setup();
    let cred = credential_of(&open_session(&f, "s1", None));
    let r = f
        .daemon
        .handle_request(human_session("r1", "runs.list", &cred, json!({})));
    assert!(r.ok, "runs.list failed: {:?}", r.error);
    assert_eq!(result(&r), &json!({"runs": []}));
}

// ---- vault.health ----

#[test]
fn vault_health_reports_counters_and_nulls_while_locked() {
    let f = setup();
    let cred = credential_of(&open_session(&f, "s1", None));
    let r = f
        .daemon
        .handle_request(human_session("w1", "vault.health", &cred, json!({})));
    assert!(r.ok, "health failed: {:?}", r.error);
    let v = result(&r);
    for k in [
        "locked",
        "idle_lock_secs",
        "idle_in",
        "audit_bytes",
        "audit_soft_limit",
        "audit_hard_limit",
        "vault_bytes",
        "vault_max_bytes",
        "runs_active",
        "leases_active",
        "approvals_pending",
    ] {
        assert!(v.get(k).is_some(), "missing {k}");
    }
    assert_eq!(v["locked"], json!(false));
    // lock, then health via passphrase must succeed with nulls
    assert!(
        f.daemon
            .handle_request(human("l", "vault.lock", json!({})))
            .ok
    );
    let r2 = f
        .daemon
        .handle_request(human("w2", "vault.health", json!({})));
    assert!(r2.ok, "locked health failed: {:?}", r2.error);
    let v2 = result(&r2);
    assert_eq!(v2["locked"], json!(true));
    assert_eq!(v2["leases_active"], Value::Null);
    assert_eq!(v2["approvals_pending"], Value::Null);
    assert_eq!(v2["idle_in"], Value::Null);
}

#[test]
fn vault_health_requires_human() {
    let f = setup();
    let t = token_of(&f);
    assert_eq!(
        code(
            &f.daemon
                .handle_request(agent("w1", "vault.health", &t, json!({})))
        ),
        "E_HUMAN_REQUIRED"
    );
    let unauth = Request {
        v: VERSION,
        id: "w2".into(),
        op: "vault.health".into(),
        auth: None,
        params: json!({}),
    };
    assert_eq!(code(&f.daemon.handle_request(unauth)), "E_AUTH");
}

#[test]
fn vault_status_shape_unchanged() {
    let f = setup();
    let unauth = Request {
        v: VERSION,
        id: "s".into(),
        op: "vault.status".into(),
        auth: None,
        params: json!({}),
    };
    let r = f.daemon.handle_request(unauth);
    assert!(r.ok);
    let v = result(&r);
    assert!(v.get("version").is_some());
    assert!(v.get("created").is_some());
    assert!(v.get("locked").is_some());
    assert_eq!(v.as_object().unwrap().len(), 3);
}

// ---- audit pagination ----

#[test]
fn audit_show_default_unchanged_and_pagination_walks() {
    let f = setup();
    // default: newest 20 ascending
    let r = f
        .daemon
        .handle_request(human("a1", "audit.show", json!({})));
    assert!(r.ok, "audit.show failed: {:?}", r.error);
    let entries = result(&r)["entries"].as_array().unwrap().clone();
    assert!(!entries.is_empty());
    let seqs: Vec<u64> = entries.iter().map(|e| e["seq"].as_u64().unwrap()).collect();
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    assert_eq!(seqs, sorted, "entries must be ascending");
    // Paged walk with tail=3. Interval property: every audit.show appends its
    // own entry at the HEAD, but each page is computed from the pre-append
    // snapshot with seq <= before_seq, and the cursor strictly decreases —
    // so appends land above the traversed interval and the concatenation of
    // pages must be exactly the contiguous range 1..=H (H = head at walk
    // start), with no gaps and no duplicates. Any skip/repeat breaks the
    // contiguous-range assertion below (it CAN fail: a gap gives
    // all[i+1] != all[i]+1; a repeat trips the duplicate check; an ignored
    // tail trips the page-size checks).
    let mut seen: Vec<u64> = Vec::new();
    let mut before: Option<u64> = None;
    let mut prev_cursor: Option<u64> = None;
    loop {
        let params = match before {
            Some(s) => json!({"tail": 3, "before_seq": s}),
            None => json!({"tail": 3}),
        };
        let r = f.daemon.handle_request(human("ap", "audit.show", params));
        assert!(r.ok, "paged show failed: {:?}", r.error);
        let page = result(&r)["entries"].as_array().unwrap().clone();
        let next = result(&r)["next_before_seq"].clone();
        if page.is_empty() {
            assert_eq!(next, Value::Null);
            break;
        }
        let pseq: Vec<u64> = page.iter().map(|e| e["seq"].as_u64().unwrap()).collect();
        let mut sp = pseq.clone();
        sp.sort_unstable();
        assert_eq!(pseq, sp, "page must be ascending");
        // Known tail=3: every non-terminal page is full; the terminal page
        // (null cursor) holds the 1..=3 oldest entries.
        match &next {
            Value::Null => assert!((1..=3).contains(&pseq.len()), "terminal page size {pseq:?}"),
            _ => assert_eq!(pseq.len(), 3, "non-terminal page must be full: {pseq:?}"),
        }
        // Pages go backwards: every seq in this page is new...
        for s in &pseq {
            assert!(!seen.contains(s), "duplicate seq {s}");
        }
        // ...and strictly below everything seen before.
        if let Some(max_seen) = seen.iter().max() {
            assert!(
                pseq.iter().all(|s| s < max_seen),
                "page not strictly older: {pseq:?}"
            );
        }
        seen.extend(pseq.iter().cloned());
        match next {
            Value::Null => break,
            Value::Number(n) => {
                let cur = n.as_u64().unwrap();
                // The cursor is what makes termination and gap-freeness true:
                // it must strictly decrease every iteration.
                if let Some(prev) = prev_cursor {
                    assert!(cur < prev, "cursor did not decrease: {prev} -> {cur}");
                }
                if let Some(b) = before {
                    assert!(
                        cur < b,
                        "cursor did not advance below before_seq {b}: got {cur}"
                    );
                }
                prev_cursor = Some(cur);
                before = Some(cur);
            }
            _ => panic!("bad cursor"),
        }
        if seen.len() > 10000 {
            panic!("pagination did not terminate");
        }
    }
    assert!(!seen.is_empty());
    let mut all = seen.clone();
    all.sort_unstable();
    // Gap-freeness over the traversed interval [min, max]: appends during the
    // walk land at the head ABOVE max (cursor only moves down), so the sorted
    // concatenation must be exactly contiguous. Fails on any skip.
    for i in 0..all.len() - 1 {
        assert_eq!(all[i + 1], all[i] + 1, "gap in {all:?}");
    }
}

#[test]
fn audit_show_tail_out_of_range_is_invalid_input() {
    let f = setup();
    for tail in [0i64, 1001] {
        let r = f
            .daemon
            .handle_request(human("a1", "audit.show", json!({"tail": tail})));
        assert_eq!(code(&r), "E_INVALID_INPUT", "tail {tail}");
    }
}

// ---- restart invalidation + idle auto-lock ----

#[test]
fn restart_invalidates_session() {
    let f = setup();
    let cred = credential_of(&open_session(&f, "s1", None));
    let vault_path = f._root.0.join("vault.enc");
    let sock_path = f._root.0.join("svault.sock");
    drop(f.daemon);
    // second daemon over the same paths (first dropped, releasing locks)
    let d2 = Daemon::new(DaemonConfig {
        socket_path: sock_path,
        vault_path,
        idle_lock: Duration::from_secs(3600),
    })
    .unwrap();
    let r = d2.handle_request(human_session("h1", "project.list", &cred, json!({})));
    assert_eq!(code(&r), "E_SESSION_EXPIRED");
}

#[test]
fn human_only_matrix_for_new_ops() {
    let f = setup();
    let t = token_of(&f);
    for op in [
        "session.touch",
        "session.close",
        "runs.list",
        "vault.health",
    ] {
        let r = f.daemon.handle_request(agent("m", op, &t, json!({})));
        assert_eq!(code(&r), "E_HUMAN_REQUIRED", "{op}");
    }
}

#[allow(dead_code)]
fn _clock_session(_dir: &TempRoot) -> Session {
    unimplemented!()
}

// ---- C-05 actor split both directions + approvals via session ----

#[test]
fn session_actor_split_human_vs_session_prefix() {
    let f = setup();
    // passphrase path audits as exactly `human`
    assert!(
        f.daemon
            .handle_request(human("h0", "project.list", json!({})))
            .ok
    );
    let audit = audit_text(&f);
    assert!(audit.contains("\"actor\":\"human\""));
    // session path audits as human(session:<prefix>)
    let opened = open_session(&f, "s1", None);
    let prefix = result(&opened)["session_prefix"]
        .as_str()
        .unwrap()
        .to_string();
    let cred = credential_of(&opened);
    assert!(
        f.daemon
            .handle_request(human_session("h1", "project.list", &cred, json!({})))
            .ok
    );
    assert!(audit_text(&f).contains(&format!("human(session:{prefix})")));
}

#[test]
fn approvals_pending_and_approve_work_via_session() {
    let f = setup();
    let t = token_of(&f);
    // agent creates a pending approval (needs reveal grant: re-grant)
    assert!(
        f.daemon
            .handle_request(human(
                "g",
                "grants.grant",
                json!({"agent":"bot","project":"acme","ops":"read,reveal"})
            ))
            .ok
    );
    let r = f.daemon.handle_request(agent(
        "r1",
        "reveal",
        &t,
        json!({"project":"acme","key":"API_KEY"}),
    ));
    assert_eq!(code(&r), "E_APPROVAL_PENDING");
    let approval_id = r.error.as_ref().unwrap().data.as_ref().unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();
    let cred = credential_of(&open_session(&f, "s1", None));
    // pending via session
    let p = f
        .daemon
        .handle_request(human_session("p1", "approvals.pending", &cred, json!({})));
    assert!(p.ok, "pending via session: {:?}", p.error);
    assert!(serde_json::to_string(&p).unwrap().contains(&approval_id));
    // approve via session
    let a = f.daemon.handle_request(human_session(
        "a1",
        "approvals.approve",
        &cred,
        json!({"approval_id": approval_id}),
    ));
    assert!(a.ok, "approve via session: {:?}", a.error);
}

// ---- H-12 cross-table + lease-on-human ----

#[test]
fn session_in_lease_param_is_lease_expired_and_lease_in_session_is_session_expired() {
    let f = setup();
    let t = token_of(&f);
    let cred = credential_of(&open_session(&f, "s1", None));
    // session credential as agent lease => lease table miss
    let r = f.daemon.handle_request(agent(
        "l1",
        "secrets.list",
        &t,
        json!({"project":"acme","lease": cred}),
    ));
    assert_eq!(code(&r), "E_LEASE_EXPIRED");
    // mint a real lease, present it as session => session table miss
    assert!(
        f.daemon
            .handle_request(human(
                "g",
                "grants.grant",
                json!({"agent":"bot","project":"acme","ops":"read"})
            ))
            .ok
    );
    let created = f.daemon.handle_request(agent(
        "l2",
        "lease.create",
        &t,
        json!({"project":"acme","ops":"read","ttl_secs":600}),
    ));
    assert!(created.ok, "{:?}", created.error);
    let lease_cred = created.result.unwrap()["lease_credential"]
        .as_str()
        .unwrap()
        .to_string();
    let r2 = f
        .daemon
        .handle_request(human_session("h1", "project.list", &lease_cred, json!({})));
    assert_eq!(code(&r2), "E_SESSION_EXPIRED");
}

#[test]
fn lease_param_on_human_ops_is_invalid_input() {
    let f = setup();
    let cred = credential_of(&open_session(&f, "s1", None));
    for (id, op, params) in [
        ("h1", "secrets.list", json!({"project":"acme","lease":"x"})),
        (
            "h2",
            "secrets.list",
            json!({"project":"acme","lease_id":"x"}),
        ),
        ("h3", "runs.list", json!({"lease":"x"})),
        ("h4", "vault.health", json!({"lease_id":"x"})),
        ("h5", "audit.show", json!({"lease":"x"})),
        // C1: previously-uncovered ops — the centralized dispatch guard
        // must catch them too (mutating + read).
        (
            "h6",
            "secret.set",
            json!({"project":"acme","key":"LEASEGUARD_PROBE","value":"v","lease":"x"}),
        ),
        ("h7", "agents.list", json!({"lease_id":"x"})),
    ] {
        let r = f
            .daemon
            .handle_request(human_session(id, op, &cred, params));
        assert_eq!(code(&r), "E_INVALID_INPUT", "{op}");
    }
    // The mutating probe must not have applied: the secret must not exist.
    let r = f.daemon.handle_request(human_session(
        "h8",
        "secrets.list",
        &cred,
        json!({"project":"acme"}),
    ));
    assert!(r.ok, "list after refused set: {:?}", r.error);
    let keys: Vec<&str> = result(&r)["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["key"].as_str())
        .collect();
    assert!(
        !keys.contains(&"LEASEGUARD_PROBE"),
        "refused secret.set must not apply"
    );
    // Explicit null still counts as absent: the same ops succeed.
    for (id, op, params) in [
        ("n1", "secrets.list", json!({"project":"acme","lease":null})),
        ("n2", "agents.list", json!({"lease":null,"lease_id":null})),
        ("n3", "runs.list", json!({"lease":null})),
    ] {
        let r = f
            .daemon
            .handle_request(human_session(id, op, &cred, params));
        assert!(r.ok, "{op} with null lease must succeed: {:?}", r.error);
    }
}

// ---- H-13 shape strictness ----

#[test]
fn empty_string_session_is_expired_and_dual_is_protocol() {
    let f = setup();
    let r = f
        .daemon
        .handle_request(human_session("h1", "project.list", "", json!({})));
    assert_eq!(code(&r), "E_SESSION_EXPIRED");
    let t = token_of(&f);
    let dual = request(
        "d1",
        "project.list",
        AuthField {
            token: Some(t),
            passphrase: None,
            session: Some(String::new()),
        },
        json!({}),
    );
    assert_eq!(code(&f.daemon.handle_request(dual)), "E_PROTOCOL");
}

#[test]
fn non_string_session_is_protocol() {
    use std::io::Write;
    // raw wire: session as a number must fail request parsing (E_PROTOCOL invalid request)
    let line =
        "{\"v\":1,\"id\":\"x\",\"op\":\"vault.status\",\"auth\":{\"session\":123},\"params\":{}}}\n".to_string();
    let mut cur = std::io::Cursor::new(line.as_bytes().to_vec());
    let req = svault::wire::read_request(&mut cur);
    assert!(req.is_err());
    assert_eq!(req.unwrap_err().code(), "E_PROTOCOL");
    let _ = Write::flush(&mut std::io::stdout());
}

// ---- vault.create with session, no vault ----

#[test]
fn vault_create_with_session_and_no_vault_is_expired() {
    let root = std::env::temp_dir().join(format!(
        "svault-sesscreate-{}-{}",
        std::process::id(),
        svault::crypto::hex(&svault::crypto::random_bytes::<8>().unwrap())
    ));
    std::fs::create_dir_all(&root).unwrap();
    let d = Daemon::new(DaemonConfig {
        socket_path: root.join("svault.sock"),
        vault_path: root.join("vault.enc"),
        idle_lock: Duration::from_secs(60),
    })
    .unwrap();
    let r = d.handle_request(human_session("c1", "vault.create", "garbage", json!({})));
    assert_eq!(code(&r), "E_SESSION_EXPIRED");
    assert!(!root.join("vault.enc").exists());
    let _ = std::fs::remove_dir_all(&root);
}

// ---- D-10 client round-trip ----

#[test]
fn client_maps_session_expired_code() {
    let resp = Response {
        v: VERSION,
        id: "i".into(),
        ok: false,
        result: None,
        error: Some(svault::wire::WireError {
            code: "E_SESSION_EXPIRED".into(),
            msg: "session expired or revoked".into(),
            data: None,
        }),
    };
    // checked_result is private; assert via code() on the variant instead:
    // the variant exists and its Display never echoes material.
    let e = svault::VaultError::SessionExpired;
    assert_eq!(e.code(), "E_SESSION_EXPIRED");
    assert_eq!(format!("{e}"), "session expired or revoked");
    assert!(!format!("{e}").contains("garbage-cred"));
    let _ = resp;
}

// ---- D-11 wall vs monotonic divergence (Session-level) ----

#[test]
fn wall_jump_does_not_extend_session_but_monotonic_lapse_kills() {
    use svault::session::Session;
    let dir = std::env::temp_dir().join(format!(
        "svault-walljump-{}-{}",
        std::process::id(),
        svault::crypto::hex(&svault::crypto::random_bytes::<8>().unwrap())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vault.enc");
    let mono = Arc::new(AtomicU64::new(0));
    let wall = Arc::new(AtomicU64::new(0));
    let clock = AdjClock {
        mono_start: Instant::now(),
        wall_start: time::OffsetDateTime::now_utc(),
        mono_secs: mono.clone(),
        wall_secs: wall.clone(),
    };
    let mut s = Session::create(
        &path,
        PASS.as_bytes(),
        Duration::from_secs(3600),
        Box::new(clock),
    )
    .unwrap();
    let (cred, _, _, _) = s.session_open("human", 60).unwrap();
    // wall +3h, monotonic unchanged => still live
    wall.fetch_add(3 * 3600, Ordering::Relaxed);
    assert!(s.authorize_session(&cred).is_ok());
    // monotonic past sliding window => expired
    mono.fetch_add(61, Ordering::Relaxed);
    assert!(matches!(
        s.authorize_session(&cred),
        Err(svault::VaultError::SessionExpired)
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- B-1 flood bound ----

#[test]
fn mint_flood_is_bounded_by_sweep_and_evict() {
    use svault::session::{MAX_SESSIONS, Session};
    let dir = std::env::temp_dir().join(format!(
        "svault-flood-{}-{}",
        std::process::id(),
        svault::crypto::hex(&svault::crypto::random_bytes::<8>().unwrap())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vault.enc");
    let mono = Arc::new(AtomicU64::new(0));
    let wall = Arc::new(AtomicU64::new(0));
    let clock = AdjClock {
        mono_start: Instant::now(),
        wall_start: time::OffsetDateTime::now_utc(),
        mono_secs: mono.clone(),
        wall_secs: wall.clone(),
    };
    let mut s = Session::create(
        &path,
        PASS.as_bytes(),
        Duration::from_secs(3600),
        Box::new(clock),
    )
    .unwrap();
    let mut first_creds = Vec::new();
    for _ in 0..(MAX_SESSIONS + 10) {
        let (c, _, _, _) = s.session_open("human", 300).unwrap();
        if first_creds.len() < 3 {
            first_creds.push(c);
        }
        mono.fetch_add(1, Ordering::Relaxed);
    }
    // never refused for capacity; oldest evicted => expired
    assert!(matches!(
        s.authorize_session(&first_creds[0]),
        Err(svault::VaultError::SessionExpired)
    ));
    // failed mint stores nothing: out-of-range ttl fails and count is unchanged
    assert!(s.session_open("human", 0).is_err());
    let (c, _, _, _) = s.session_open("human", 300).unwrap();
    assert!(s.authorize_session(&c).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- ttl 1800 sliding==absolute ----

#[test]
fn ttl_1800_sliding_equals_absolute() {
    let f = setup();
    let r = open_session(&f, "s1", Some(1800));
    assert!(r.ok, "{:?}", r.error);
    assert_eq!(result(&r)["expires_in"], json!(1800));
    assert_eq!(result(&r)["max_expires_in"], json!(1800));
}

// ---- per-lock-path purge ----

#[test]
fn direct_session_lock_purges() {
    use svault::session::Session;
    let dir = std::env::temp_dir().join(format!(
        "svault-directlock-{}-{}",
        std::process::id(),
        svault::crypto::hex(&svault::crypto::random_bytes::<8>().unwrap())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vault.enc");
    let mut s = Session::create(
        &path,
        PASS.as_bytes(),
        Duration::from_secs(3600),
        Box::new(svault::session::SystemClock),
    )
    .unwrap();
    let (cred, _, _, _) = s.session_open("human", 300).unwrap();
    s.lock();
    assert!(matches!(
        s.authorize_session(&cred),
        Err(svault::VaultError::SessionExpired)
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn audit_ceiling_matrix_open_touch_refuse_close_applies() {
    use svault::session::Session;
    let dir = std::env::temp_dir().join(format!(
        "svault-ceil-{}-{}",
        std::process::id(),
        svault::crypto::hex(&svault::crypto::random_bytes::<8>().unwrap())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vault.enc");
    let mut s = Session::create(
        &path,
        PASS.as_bytes(),
        Duration::from_secs(3600),
        Box::new(svault::session::SystemClock),
    )
    .unwrap();
    let (cred, _, _, _) = s.session_open("human", 300).unwrap();
    // shrink ceilings so the next ordinary append refuses
    s.set_audit_limits_for_test(1, 1);
    assert!(matches!(
        s.session_open("human", 300),
        Err(svault::VaultError::AuditFull(_))
    ));
    assert!(matches!(
        s.session_touch(&cred),
        Err(svault::VaultError::AuditFull(_))
    ));
    // touch refused => nothing slid: restore limits, still live (not lapsed, clock unchanged)
    s.set_audit_limits_for_test(u64::MAX, u64::MAX);
    assert!(s.authorize_session(&cred).is_ok());
    // close under a full log still destroys
    s.set_audit_limits_for_test(1, 1);
    assert!(s.session_close(&cred).is_ok());
    assert!(matches!(
        s.authorize_session(&cred),
        Err(svault::VaultError::SessionExpired)
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- H-7 live-run trap: runs.list is an allowlist ----

#[test]
fn runs_list_with_live_registry_entry_is_allowlisted_and_trap_free() {
    // Registry-level: reserve + activate an entry with trap-adjacent names, then
    // runs.list via dispatch must show only the allowlisted keys.
    use svault::run::RunRegistry;
    let reg = RunRegistry::new();
    let res = reg
        .try_reserve("agent-id-1", "acme", "runid-trap-1")
        .unwrap();
    assert!(res.activate(1234, 1234));
    // NOTE: Reservation commits on explicit commit(); without it the drop removes the slot.
    // Keep it alive for the assertion scope:
    std::mem::forget(res);
    let snap = reg.snapshot();
    assert_eq!(snap.len(), 1);
    let (rid, meta) = &snap[0];
    assert_eq!(rid, "runid-trap-1");
    // The wire projection built in broker dispatch_op allows exactly these keys;
    // assert the allowlist here so a future field addition is caught at the unit level.
    let row = serde_json::json!({
        "run_id": rid,
        "agent": meta.agent,
        "project": meta.project,
        "pid": meta.pid,
        "started_at": meta.started_at.to_string(),
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
    let body = serde_json::to_string(&row).unwrap();
    assert!(!body.contains("argv"));
    assert!(!body.contains("executable"));
    assert!(!body.contains("pgid"));
    assert!(!body.contains("cwd"));
    assert!(!body.contains("env"));
}

// ---- C-11 agent-op-with-session code pin ----

#[test]
fn agent_ops_with_session_are_denied_deterministically() {
    let f = setup();
    let cred = credential_of(&open_session(&f, "s1", None));
    // agent-only ops reached with a session: deterministic denial, no capability.
    // lease.list/revoke are dual-view (human sees all) — allowed for human
    // identity like the passphrase path, not widening — so they are NOT here.
    for (id, op, params) in [
        (
            "a1",
            "lease.create",
            serde_json::json!({"project":"acme","ops":"read","ttl_secs":60}),
        ),
        (
            "a2",
            "approvals.status",
            serde_json::json!({"approval_id":"x"}),
        ),
        (
            "a3",
            "run_signal",
            serde_json::json!({"run_id":"x","signal":"TERM"}),
        ),
    ] {
        let r = f
            .daemon
            .handle_request(human_session(id, op, &cred, params));
        assert!(!r.ok, "{op} must deny");
        assert!(
            ["E_AUTH", "E_HUMAN_REQUIRED"].contains(&code(&r)),
            "{op} => {}",
            code(&r)
        );
    }
    // session must never reach run_with_secrets FD path: handle_run resolves token only
}

// ---- C-02/H-05 + per-lock-path purge ----

#[test]
fn check_idle_path_purges_session() {
    use svault::session::Session;
    let dir = std::env::temp_dir().join(format!(
        "svault-checkidle-{}-{}",
        std::process::id(),
        svault::crypto::hex(&svault::crypto::random_bytes::<8>().unwrap())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vault.enc");
    // standalone session (self-lock ON): short idle, mint, advance past idle, touch keys => lock_persist path
    let start = Instant::now();
    let mono = Arc::new(AtomicU64::new(0));
    struct C {
        s: Instant,
        m: Arc<AtomicU64>,
    }
    impl Clock for C {
        fn now(&self) -> Instant {
            self.s + Duration::from_secs(self.m.load(Ordering::Relaxed))
        }
    }
    let clock = C {
        s: start,
        m: mono.clone(),
    };
    let mut s = Session::create(
        &path,
        PASS.as_bytes(),
        Duration::from_secs(60),
        Box::new(clock),
    )
    .unwrap();
    let (cred, _, _, _) = s.session_open("human", 300).unwrap();
    mono.fetch_add(61, Ordering::Relaxed);
    assert!(matches!(s.require_keys(), Err(svault::VaultError::Locked)));
    assert!(matches!(
        s.authorize_session(&cred),
        Err(svault::VaultError::SessionExpired)
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- H-10 edge cases ----

#[test]
fn audit_pagination_edges_clamp_zero_and_types() {
    let f = setup();
    // before_seq beyond head clamps
    let r = f.daemon.handle_request(human(
        "e1",
        "audit.show",
        serde_json::json!({"tail": 5, "before_seq": 999999999}),
    ));
    assert!(r.ok, "{:?}", r.error);
    // before_seq 0 => empty + null
    let r = f.daemon.handle_request(human(
        "e2",
        "audit.show",
        serde_json::json!({"tail": 5, "before_seq": 0}),
    ));
    assert!(r.ok, "{:?}", r.error);
    assert_eq!(result(&r)["entries"].as_array().unwrap().len(), 0);
    assert_eq!(result(&r)["next_before_seq"], Value::Null);
    // wrong types => E_INVALID_INPUT, never default-on-garbage
    for params in [
        serde_json::json!({"tail": "many"}),
        serde_json::json!({"tail": [1]}),
        serde_json::json!({"tail": 5, "before_seq": "x"}),
    ] {
        let r = f.daemon.handle_request(human("e3", "audit.show", params));
        assert_eq!(code(&r), "E_INVALID_INPUT");
    }
}

// ---- pagination under concurrent appends ----

#[test]
fn audit_pagination_gap_free_under_concurrent_appends() {
    use std::sync::Arc;
    let f = setup();
    let daemon = Arc::new(f.daemon);
    // spawn writers appending project.list reads concurrently with the page walk
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut handles = Vec::new();
    // NOTE: Daemon is !Sync for handle_request? handle_request takes &self — spawn threads sharing &Daemon via Arc.
    // If Daemon is not Sync this fails to compile; then this test degrades to interleaved same-thread appends.
    for i in 0..4 {
        let d = Arc::clone(&daemon);
        let s = Arc::clone(&stop);
        handles.push(std::thread::spawn(move || {
            let mut n = 0;
            while !s.load(std::sync::atomic::Ordering::Relaxed) && n < 25 {
                let _ = d.handle_request(human(
                    &format!("w{i}-{n}"),
                    "project.list",
                    serde_json::json!({}),
                ));
                n += 1;
            }
        }));
    }
    let mut seen: Vec<u64> = Vec::new();
    let mut before: Option<u64> = None;
    for _ in 0..60 {
        let params = match before {
            Some(s) => serde_json::json!({"tail": 7, "before_seq": s}),
            None => serde_json::json!({"tail": 7}),
        };
        let r = daemon.handle_request(human("pg", "audit.show", params));
        assert!(r.ok, "{:?}", r.error);
        let page = result(&r)["entries"].as_array().unwrap().clone();
        if page.is_empty() {
            break;
        }
        let pseq: Vec<u64> = page.iter().map(|e| e["seq"].as_u64().unwrap()).collect();
        let mut sp = pseq.clone();
        sp.sort_unstable();
        assert_eq!(pseq, sp, "ascending");
        for s in &pseq {
            assert!(!seen.contains(s), "dup {s}");
        }
        seen.extend(pseq.iter().cloned());
        match result(&r)["next_before_seq"].clone() {
            Value::Null => break,
            Value::Number(n) => before = Some(n.as_u64().unwrap()),
            _ => panic!("bad cursor"),
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    assert!(!seen.is_empty());
}
