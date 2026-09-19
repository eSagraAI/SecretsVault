//! Wave 3 (M1/M2) — strict param shapes and no silent widening.
//!
//! * **M1** — `inject_file.keys` with a non-array shape (a string, an object,
//!   a number) was read with `as_array()`, which yields `None` — and `None`
//!   means *every secret in the project*. A shape error therefore silently
//!   expanded a narrow request into a full dump of the project's secrets.
//! * **M2** — a lease was documented as resolvable by its public `lease_id`
//!   handle, but the broker ignored that field: a caller who meant to narrow
//!   the call with a lease got the full grant instead.
//!
//! Both are the same failure mode: a request the caller *intended* to narrow
//! being silently widened. The fix is fail-closed shape validation at the
//! broker boundary — the MCP adapter's substitution is a separate layer (H3)
//! and cannot be the only defence.

#[path = "common/mod.rs"]
mod common;

use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
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
        let p = std::env::temp_dir().join(format!("svault-wave3-shapes-{tag}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Two secrets so "select nothing" and "select all" are distinguishable.
fn fixture(dir: &Dir, ops: &str) -> String {
    let authorized = dir.0.join("authorized");
    std::fs::create_dir_all(&authorized).unwrap();
    let mut s =
        Session::create(&dir.0.join("vault.enc"), PASS, IDLE, Box::new(SystemClock)).unwrap();
    s.project_add("human", "acme", &[authorized]).unwrap();
    s.secret_set("human", "acme", "ALPHA", b"alpha-value")
        .unwrap();
    s.secret_set("human", "acme", "BETA", b"beta-value")
        .unwrap();
    let (_id, token) = s.agent_add("human", "bot").unwrap();
    s.grant_add(
        "human",
        "bot",
        "acme",
        &[svault::model::Op::Read, svault::model::Op::Inject],
    )
    .unwrap();
    drop(s);
    let _ = ops;
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

fn code(resp: &Response) -> String {
    resp.error
        .as_ref()
        .map(|e| e.code.clone())
        .unwrap_or_else(|| "<ok>".to_string())
}

fn read_injected(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// M1 — keys shape
// ---------------------------------------------------------------------------

/// A `keys` value that is not an array must be refused, never reinterpreted as
/// "all secrets". Each of these shapes previously widened the call.
#[test]
fn m1_non_array_keys_is_refused_not_widened() {
    let dir = Dir::new("keys-shape");
    let token = fixture(&dir, "");
    let daemon = daemon_on(&dir);

    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    for (label, bad) in [
        ("string", json!("ALPHA")),
        ("object", json!({"k": "ALPHA"})),
        ("number", json!(7)),
        ("bool", json!(true)),
        ("array-of-nonstrings", json!([1, 2])),
        ("array-with-null", json!(["ALPHA", null])),
    ] {
        let resp = daemon.handle_request(agent(
            "inj",
            "inject_file",
            &token,
            json!({"project": "acme", "path": ".env", "keys": bad}),
        ));
        assert_eq!(
            code(&resp),
            "E_INVALID_INPUT",
            "M1 REGRESSION: keys={label} must fail closed, got {resp:?}"
        );
        // And nothing may have been written: a refused request must not leak
        // the project's secrets into a file.
        assert!(
            read_injected(&dir.0.join("authorized").join(".env")).is_empty(),
            "M1 REGRESSION: keys={label} was refused but still wrote a file"
        );
    }
}

/// `keys` omitted or explicitly null keeps meaning "all secrets": that is the
/// documented convenience and must not regress into an error.
#[test]
fn m1_omitted_or_null_keys_still_means_all() {
    let dir = Dir::new("keys-absent");
    let token = fixture(&dir, "");
    let daemon = daemon_on(&dir);

    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    for (label, params) in [
        ("omitted", json!({"project": "acme", "path": ".env.all"})),
        (
            "null",
            json!({"project": "acme", "path": ".env.null", "keys": null}),
        ),
    ] {
        let resp = daemon.handle_request(agent("inj", "inject_file", &token, params));
        assert!(resp.ok, "keys={label} must keep meaning all: {resp:?}");
        let path = dir.0.join("authorized").join(if label == "omitted" {
            ".env.all"
        } else {
            ".env.null"
        });
        let body = read_injected(&path);
        assert!(
            body.contains("ALPHA") && body.contains("BETA"),
            "keys={label} must inject every secret, got: {body}"
        );
    }
}

/// An explicit empty array selects zero keys. The existing implementation
/// refuses it ("no secrets to inject"); what matters for M1 is the invariant
/// and not the exact code: it must never widen into "all secrets".
#[test]
fn m1_empty_array_never_widens_to_all() {
    let dir = Dir::new("keys-empty");
    let token = fixture(&dir, "");
    let daemon = daemon_on(&dir);

    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    let resp = daemon.handle_request(agent(
        "inj",
        "inject_file",
        &token,
        json!({"project": "acme", "path": ".env", "keys": []}),
    ));
    let body = read_injected(&dir.0.join("authorized").join(".env"));
    assert!(
        !body.contains("ALPHA") && !body.contains("BETA"),
        "M1 REGRESSION: an empty keys array injected secrets ({resp:?}): {body}"
    );
}

// ---------------------------------------------------------------------------
// M2 — lease fields must not be ignored
// ---------------------------------------------------------------------------

/// A lease handle presented where the broker expects a credential must fail
/// closed. `lease_id` is a public handle: it authorizes nothing, and silently
/// dropping it would widen the call to the caller's full grant.
#[test]
fn m2_lease_id_alone_is_not_a_capability() {
    let dir = Dir::new("lease-id");
    let token = fixture(&dir, "");
    let daemon = daemon_on(&dir);

    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    // Mint a real lease so the handle is a genuine one.
    let created = daemon.handle_request(agent(
        "lc",
        "lease.create",
        &token,
        json!({"project": "acme", "ops": "read", "ttl_secs": 3600}),
    ));
    assert!(created.ok, "lease.create: {:?}", created.error);
    let handle = created
        .result
        .as_ref()
        .and_then(|r| r.get("lease_id"))
        .and_then(|v| v.as_str())
        .expect("lease_id")
        .to_string();

    let resp = daemon.handle_request(agent(
        "ls",
        "secrets.list",
        &token,
        json!({"project": "acme", "lease_id": handle}),
    ));
    assert_eq!(
        code(&resp),
        "E_INVALID_INPUT",
        "M2 REGRESSION: a public handle must never be mistaken for a credential, got {resp:?}"
    );
}

/// An unknown/other lease field must fail closed rather than being dropped on
/// the floor (which would silently run with the full grant).
#[test]
fn m2_unknown_lease_shaped_params_fail_closed() {
    let dir = Dir::new("lease-unknown");
    let token = fixture(&dir, "");
    let daemon = daemon_on(&dir);

    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    for (label, params) in [
        ("non-string lease", json!({"project": "acme", "lease": 42})),
        (
            "object lease",
            json!({"project": "acme", "lease": {"credential": "x"}}),
        ),
        (
            "empty-string lease",
            json!({"project": "acme", "lease": ""}),
        ),
    ] {
        let resp = daemon.handle_request(agent("ls", "secrets.list", &token, params));
        // Every one of these must fail closed. An unusable credential may
        // surface as a shape error or as the generic lease failure; what must
        // never happen is falling back to the caller's full grant.
        assert!(
            matches!(code(&resp).as_str(), "E_INVALID_INPUT" | "E_LEASE_EXPIRED"),
            "M2 REGRESSION: {label} must fail closed, got {resp:?}"
        );
        assert!(
            resp.result.is_none(),
            "M2 REGRESSION: {label} returned data instead of failing: {resp:?}"
        );
    }
}

/// A request that names no lease must still work off the plain grant: the
/// strictness above must not break the ordinary path.
#[test]
fn m2_plain_grant_path_still_works() {
    let dir = Dir::new("lease-plain");
    let token = fixture(&dir, "");
    let daemon = daemon_on(&dir);

    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    let resp = daemon.handle_request(agent(
        "ls",
        "secrets.list",
        &token,
        json!({"project": "acme"}),
    ));
    assert!(resp.ok, "plain grant read must succeed: {resp:?}");
}

/// A real lease credential still narrows successfully — the strictness must
/// not reject the legitimate mechanism.
#[test]
fn m2_real_credential_still_authorizes() {
    let dir = Dir::new("lease-real");
    let token = fixture(&dir, "");
    let daemon = daemon_on(&dir);

    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    let created = daemon.handle_request(agent(
        "lc",
        "lease.create",
        &token,
        json!({"project": "acme", "ops": "read", "ttl_secs": 3600}),
    ));
    let credential = created
        .result
        .as_ref()
        .and_then(|r| r.get("lease_credential"))
        .and_then(|v| v.as_str())
        .expect("lease_credential")
        .to_string();

    let resp = daemon.handle_request(agent(
        "ls",
        "secrets.list",
        &token,
        json!({"project": "acme", "lease": credential}),
    ));
    assert!(resp.ok, "a real credential must authorize: {resp:?}");
}

/// Belt and braces on the injected file's own permissions: the write is a
/// credential-bearing artifact.
#[test]
fn m1_injected_file_is_private() {
    let dir = Dir::new("keys-mode");
    let token = fixture(&dir, "");
    let daemon = daemon_on(&dir);

    let unlock = daemon.handle_request(human("u", "vault.unlock", json!({})));
    assert!(unlock.ok, "unlock: {:?}", unlock.error);

    let resp = daemon.handle_request(agent(
        "inj",
        "inject_file",
        &token,
        json!({"project": "acme", "path": ".env", "keys": ["ALPHA"]}),
    ));
    assert!(resp.ok, "inject must succeed: {resp:?}");
    let mode = std::fs::metadata(dir.0.join("authorized").join(".env"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "injected file must be 0600, got {mode:o}");
}

/// Keep the unused-import checker honest: `BufReader` backs the shared wire
/// helpers exercised by the daemon fixture above.
#[allow(dead_code)]
fn _wire_reader_used(s: std::os::unix::net::UnixStream) {
    let _ = BufReader::new(s);
}
