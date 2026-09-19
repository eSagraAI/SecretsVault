//! Wave 3 (M4) — the audit invariant's exact scope.
//!
//! **Scope, stated precisely:** every request that reaches dispatch with a
//! request id and an op name is audited — allowed or denied — *provided* the
//! broker can attribute it to an identity it actually established. Two
//! exclusions, both deliberate:
//!
//! * traffic that never becomes a request (framing errors, oversize messages,
//!   peer-UID failures) has no id/op and no identity to record, so inventing
//!   one would fabricate attribution;
//! * a wrong passphrase cannot be attributed to an actor either (the whole
//!   point of the generic `E_AUTH`), so it is recorded under the fixed
//!   `unauthenticated` actor.
//!
//! What the tests below pin is that an op the broker *understands well enough
//! to reject* never disappears silently — including the ones that fall through
//! to "unknown op" and the structural-validation denials.

#[path = "common/mod.rs"]
mod common;

use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;

use svault::broker::{Daemon, DaemonConfig};
use svault::session::{Session, SystemClock};
use svault::wire::{AuthField, Request, Response, VERSION};

const PASS: &[u8] = b"correct horse battery";
const IDLE: Duration = Duration::from_secs(60);

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("svault-wave3-audit-{tag}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn audit(&self) -> String {
        std::fs::read_to_string(self.0.join("audit.jsonl")).unwrap_or_default()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture(dir: &Dir) -> String {
    let authorized = dir.0.join("authorized");
    std::fs::create_dir_all(&authorized).unwrap();
    let mut s =
        Session::create(&dir.0.join("vault.enc"), PASS, IDLE, Box::new(SystemClock)).unwrap();
    s.project_add("human", "acme", &[authorized]).unwrap();
    s.secret_set("human", "acme", "ALPHA", b"alpha-value")
        .unwrap();
    let (_id, token) = s.agent_add("human", "bot").unwrap();
    s.grant_add("human", "bot", "acme", &[svault::model::Op::Read])
        .unwrap();
    drop(s);
    token
}

fn daemon_on(dir: &Dir) -> std::sync::Arc<Daemon> {
    std::sync::Arc::new(
        Daemon::new(DaemonConfig {
            socket_path: dir.0.join("svault.sock"),
            vault_path: dir.0.join("vault.enc"),
            idle_lock: IDLE,
        })
        .unwrap(),
    )
}

fn human(id: &str, op: &str, params: serde_json::Value) -> Request {
    Request {
        v: VERSION,
        id: id.into(),
        op: op.into(),
        auth: Some(AuthField {
            token: None,
            passphrase: Some(String::from_utf8_lossy(PASS).into_owned()),
            session: None,
        }),
        params,
    }
}

fn agent(id: &str, op: &str, token: &str, params: serde_json::Value) -> Request {
    Request {
        v: VERSION,
        id: id.into(),
        op: op.into(),
        auth: Some(AuthField {
            token: Some(token.to_string()),
            passphrase: None,
            session: None,
        }),
        params,
    }
}

fn code(resp: &Response) -> String {
    resp.error
        .as_ref()
        .map(|e| e.code.clone())
        .unwrap_or_else(|| "<ok>".to_string())
}

/// The last audited event whose `op` is exactly `op`.
fn last_event(audit: &str, op: &str) -> serde_json::Value {
    audit
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .rfind(|v| v.get("op").and_then(|o| o.as_str()) == Some(op))
        .unwrap_or_else(|| panic!("no audited event for op {op}"))
}

/// Count audit lines whose `op` field is exactly `op`.
fn audit_events(audit: &str, op: &str) -> usize {
    audit
        .lines()
        .filter(|l| !l.is_empty())
        .filter(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .and_then(|v| v.get("op").and_then(|o| o.as_str()).map(str::to_string))
                .as_deref()
                == Some(op)
        })
        .count()
}

// ---------------------------------------------------------------------------
// Unknown op
// ---------------------------------------------------------------------------

/// An op the broker does not implement must land in the audit log as a denial,
/// not vanish. `E_PROTOCOL` is a decision like any other.
#[test]
fn m4_unknown_op_is_audited_as_denied() {
    let dir = Dir::new("unknown-op");
    let token = fixture(&dir);
    let daemon = daemon_on(&dir);
    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    let before = audit_events(&dir.audit(), "not.an.op");
    let resp = daemon.handle_request(agent("x", "not.an.op", &token, json!({})));
    assert_eq!(code(&resp), "E_PROTOCOL", "resp: {resp:?}");
    let after = audit_events(&dir.audit(), "not.an.op");
    assert_eq!(
        after,
        before + 1,
        "M4 REGRESSION: an unknown op must be audited as denied"
    );

    // The entry must carry the rejection, attributed to the caller.
    let ev = last_event(&dir.audit(), "not.an.op");
    assert_eq!(ev["decision"], "denied");
    assert_eq!(ev["reason"], "E_PROTOCOL");
    // Attributed to the real caller (agent ids are derived, not sequential).
    assert!(
        ev["actor"]
            .as_str()
            .is_some_and(|a| a.starts_with("agent:") && a.len() > "agent:".len()),
        "attributed to the caller: {ev}"
    );
}

/// An unauthenticated unknown op is still identifiable enough to record: the
/// broker knows it refused an anonymous caller, which is exactly what the
/// audit trail is for.
#[test]
fn m4_unknown_op_without_credentials_is_audited() {
    let dir = Dir::new("unknown-anon");
    let _token = fixture(&dir);
    let daemon = daemon_on(&dir);
    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    let resp = daemon.handle_request(Request {
        v: VERSION,
        id: "anon".into(),
        op: "not.an.op".into(),
        auth: None,
        params: json!({}),
    });
    assert_eq!(code(&resp), "E_AUTH", "resp: {resp:?}");
    assert!(
        audit_events(&dir.audit(), "not.an.op") >= 1,
        "M4 REGRESSION: an anonymous unknown op must still be audited"
    );
}

// ---------------------------------------------------------------------------
// Structural denials
// ---------------------------------------------------------------------------

/// A structurally invalid request the broker can attribute must be audited as
/// denied. `inject_file` without a project is the cheapest example.
#[test]
fn m4_structural_denial_is_audited() {
    let dir = Dir::new("structural");
    let token = fixture(&dir);
    let daemon = daemon_on(&dir);
    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    let before = audit_events(&dir.audit(), "inject_file");
    let resp = daemon.handle_request(agent("s", "inject_file", &token, json!({"path": ".env"})));
    assert_eq!(code(&resp), "E_INVALID_INPUT", "resp: {resp:?}");
    let after = audit_events(&dir.audit(), "inject_file");
    assert_eq!(
        after,
        before + 1,
        "M4 REGRESSION: an attributed structural denial must be audited"
    );
}

/// A refusal that the op already audited must not be recorded twice: the
/// boundary only fills gaps.
#[test]
fn m4_no_duplicate_entry_when_the_op_already_audited() {
    let dir = Dir::new("no-dup");
    let token = fixture(&dir);
    let daemon = daemon_on(&dir);
    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    // `inject_file` on a locked vault audits its own denial.
    let lock = daemon.handle_request(human("l", "vault.lock", json!({})));
    assert!(lock.ok, "lock: {:?}", lock.error);
    let before = audit_events(&dir.audit(), "inject_file");
    let resp = daemon.handle_request(agent(
        "x",
        "inject_file",
        &token,
        json!({"project": "acme", "path": ".env", "keys": ["ALPHA"]}),
    ));
    assert_eq!(code(&resp), "E_LOCKED", "resp: {resp:?}");
    assert_eq!(
        audit_events(&dir.audit(), "inject_file"),
        before + 1,
        "M4: the denial must be recorded exactly once"
    );
}

/// Human-only enforcement is a decision and is already audited — pinned so it
/// cannot silently regress.
#[test]
fn m4_human_only_denial_is_audited() {
    let dir = Dir::new("human-only");
    let token = fixture(&dir);
    let daemon = daemon_on(&dir);
    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    let before = audit_events(&dir.audit(), "grants.grant");
    let resp = daemon.handle_request(agent(
        "g",
        "grants.grant",
        &token,
        json!({"agent": "bot", "project": "acme", "ops": "read"}),
    ));
    assert_eq!(code(&resp), "E_HUMAN_REQUIRED", "resp: {resp:?}");
    assert_eq!(
        audit_events(&dir.audit(), "grants.grant"),
        before + 1,
        "M4 REGRESSION: a human-only denial must be audited"
    );
}

// ---------------------------------------------------------------------------
// The honest exclusions
// ---------------------------------------------------------------------------

/// A wrong passphrase is not attributable to an actor, so it is recorded under
/// the fixed `unauthenticated` actor rather than inventing one.
#[test]
fn m4_wrong_passphrase_is_audited_without_inventing_identity() {
    let dir = Dir::new("wrong-pass");
    let _token = fixture(&dir);
    let daemon = daemon_on(&dir);
    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    let before = audit_events(&dir.audit(), "vault.lock");
    let resp = daemon.handle_request(Request {
        v: VERSION,
        id: "w".into(),
        op: "vault.lock".into(),
        auth: Some(AuthField {
            token: None,
            passphrase: Some("wrong passphrase entirely".into()),
            session: None,
        }),
        params: json!({}),
    });
    assert_eq!(code(&resp), "E_AUTH", "resp: {resp:?}");
    assert_eq!(
        audit_events(&dir.audit(), "vault.lock"),
        before + 1,
        "M4 REGRESSION: a failed human proof must still be recorded"
    );
    let ev = last_event(&dir.audit(), "vault.lock");
    assert_eq!(ev["decision"], "denied");
    assert_eq!(
        ev["actor"], "unauthenticated",
        "no fabricated identity: {ev}"
    );
    // The attempted passphrase must never be recorded.
    assert!(!dir.audit().contains("wrong passphrase entirely"));
}

/// A request that arrives with no op at all carries no operation to record and
/// no established identity to attribute it to, so it must not fabricate an
/// audit entry. (Boundary of the invariant: `""` is not an op the broker
/// refused, it is the absence of one.)
#[test]
fn m4_request_without_an_op_fabricates_nothing() {
    let dir = Dir::new("no-op");
    let _token = fixture(&dir);
    let daemon = daemon_on(&dir);
    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    let before = dir.audit().lines().filter(|l| !l.is_empty()).count();
    let resp = daemon.handle_request(Request {
        v: VERSION,
        id: "e".into(),
        op: String::new(),
        auth: None,
        params: json!({}),
    });
    assert!(!resp.ok, "an empty op must be refused: {resp:?}");
    let after = dir.audit().lines().filter(|l| !l.is_empty()).count();
    assert_eq!(
        after, before,
        "M4: an empty op carries no identity or operation, so nothing is recorded"
    );
}
