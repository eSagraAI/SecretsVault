use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};
use svault::broker::{Daemon, DaemonConfig};
use svault::wire::{AuthField, Request, Response, VERSION};

const PASS: &str = "correct horse battery";
const TRAP: &str = "phase6-TRAP-secret-value";
const OTHER_TRAP: &str = "phase6-OTHER-secret-value";

struct Fixture {
    daemon: Daemon,
    token: String,
    audit_path: PathBuf,
    vault_path: PathBuf,
    /// L3: the temp root, removed on drop so a test run leaves no residue —
    /// including when an assertion panics (Drop still runs while unwinding).
    _root: TempRoot,
}

/// A temporary directory removed on drop, panics included.
struct TempRoot(PathBuf);

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request(id: &str, op: &str, auth: AuthField, params: Value) -> Request {
    Request {
        v: VERSION,
        id: id.into(),
        op: op.into(),
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

fn code(response: &Response) -> &str {
    response.error.as_ref().unwrap().code.as_str()
}

fn emsg(response: &Response) -> &str {
    response.error.as_ref().unwrap().msg.as_str()
}

fn edata(response: &Response) -> Value {
    *response
        .error
        .as_ref()
        .unwrap()
        .data
        .clone()
        .expect("error data must be present")
}

fn approval_id_of(pending: &Response) -> String {
    assert_eq!(code(pending), "E_APPROVAL_PENDING", "{pending:?}");
    edata(pending)["approval_id"]
        .as_str()
        .expect("approval_id in error data")
        .to_owned()
}

/// The one-time lease credential returned by `lease.create`, which is what
/// requests must present (the `lease_id` handle authorizes nothing).
fn lease_credential_of(created: &Response) -> String {
    assert!(created.ok, "{:?}", created.error);
    created.result.as_ref().unwrap()["lease_credential"]
        .as_str()
        .expect("lease_credential in result")
        .to_owned()
}

fn lease_handle_of(created: &Response) -> String {
    created.result.as_ref().unwrap()["lease_id"]
        .as_str()
        .expect("lease_id in result")
        .to_owned()
}

fn audit_text(f: &Fixture) -> String {
    std::fs::read_to_string(&f.audit_path).unwrap_or_default()
}

fn setup(ops: &str) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "svault-phase6-{}-{}",
        std::process::id(),
        svault::crypto::hex(&svault::crypto::random_bytes::<8>().unwrap())
    ));
    std::fs::create_dir_all(&root).unwrap();
    let vault_path = root.join("vault.enc");
    let audit_path = vault_path.with_file_name("audit.jsonl");
    let daemon = Daemon::new(DaemonConfig {
        socket_path: root.join("svault.sock"),
        vault_path: vault_path.clone(),
        idle_lock: Duration::from_secs(60),
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
    assert!(
        daemon
            .handle_request(human(
                "3b",
                "secret.set",
                json!({"project":"acme","key":"OTHER_KEY","value":OTHER_TRAP})
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
                json!({"agent":"bot","project":"acme","ops":ops})
            ))
            .ok
    );
    Fixture {
        daemon,
        token,
        audit_path,
        vault_path,
        _root: TempRoot(root),
    }
}

fn enroll(f: &Fixture, id: &str, name: &str, ops: &str) -> String {
    let added = f.daemon.handle_request(human(
        &format!("{id}-add"),
        "agents.add",
        json!({"name":name}),
    ));
    assert!(added.ok, "{:?}", added.error);
    let token = added.result.unwrap()["token"].as_str().unwrap().to_owned();
    assert!(
        f.daemon
            .handle_request(human(
                &format!("{id}-grant"),
                "grants.grant",
                json!({"agent":name,"project":"acme","ops":ops})
            ))
            .ok
    );
    token
}

#[test]
fn lease_is_a_revocable_non_escalating_grant_subset() {
    let f = setup("read,inject");
    let created = f.daemon.handle_request(agent(
        "6",
        "lease.create",
        &f.token,
        json!({"project":"acme","ops":"read","ttl_secs":60}),
    ));
    let credential = lease_credential_of(&created);
    let lease_id = lease_handle_of(&created);
    assert!(
        f.daemon
            .handle_request(agent(
                "7",
                "secrets.list",
                &f.token,
                json!({"project":"acme","lease":credential})
            ))
            .ok
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "8",
            "inject_file",
            &f.token,
            json!({"project":"acme","path":".env","lease":credential})
        ))),
        "E_PERMISSION"
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "9",
            "lease.create",
            &f.token,
            json!({"project":"acme","ops":"reveal","ttl_secs":60})
        ))),
        "E_PERMISSION"
    );
    assert!(
        f.daemon
            .handle_request(agent(
                "10",
                "lease.revoke",
                &f.token,
                json!({"lease_id":lease_id})
            ))
            .ok
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "11",
            "secrets.list",
            &f.token,
            json!({"project":"acme","lease":credential})
        ))),
        "E_LEASE_EXPIRED"
    );
}

#[test]
fn lease_ttl_expiry_is_enforced() {
    let f = setup("read,inject");
    let created = f.daemon.handle_request(agent(
        "6",
        "lease.create",
        &f.token,
        json!({"project":"acme","ops":"read","ttl_secs":1}),
    ));
    let credential = lease_credential_of(&created);
    assert!(
        f.daemon
            .handle_request(agent(
                "7",
                "secrets.list",
                &f.token,
                json!({"project":"acme","lease":credential})
            ))
            .ok
    );
    std::thread::sleep(Duration::from_millis(1500));
    let expired = f.daemon.handle_request(agent(
        "8",
        "secrets.list",
        &f.token,
        json!({"project":"acme","lease":credential}),
    ));
    assert_eq!(code(&expired), "E_LEASE_EXPIRED");
    assert!(!emsg(&expired).contains(TRAP));
}

#[test]
fn lease_list_shows_own_to_agent_and_all_to_human() {
    let f = setup("read,inject");
    let created = f.daemon.handle_request(agent(
        "6",
        "lease.create",
        &f.token,
        json!({"project":"acme","ops":"read","ttl_secs":60}),
    ));
    let credential = lease_credential_of(&created);
    let lease_id = lease_handle_of(&created);
    let mine = f
        .daemon
        .handle_request(agent("7", "lease.list", &f.token, json!({})));
    assert!(mine.ok, "{:?}", mine.error);
    let leases = mine.result.unwrap()["leases"]
        .as_array()
        .unwrap()
        .to_owned();
    assert!(
        leases
            .iter()
            .any(|l| l["lease_id"].as_str() == Some(lease_id.as_str()))
    );
    let blob = serde_json::to_string(&leases).unwrap();
    assert!(!blob.contains(TRAP));
    // A listing exposes the handle and the display prefix, never the
    // credential: a leaked listing is not a usable capability.
    assert!(!blob.contains(&credential), "{blob}");
    assert!(
        leases
            .iter()
            .any(|l| l["lease_prefix"].as_str().is_some_and(|p| !p.is_empty())),
        "listing should carry the credential prefix: {blob}"
    );
    let all = f.daemon.handle_request(human("8", "lease.list", json!({})));
    assert!(all.ok, "{:?}", all.error);
    let leases = all.result.unwrap()["leases"].as_array().unwrap().to_owned();
    assert!(
        leases
            .iter()
            .any(|l| l["lease_id"].as_str() == Some(lease_id.as_str()))
    );
    assert!(
        !serde_json::to_string(&leases)
            .unwrap()
            .contains(&credential)
    );
}

#[test]
fn lease_revoke_by_human_succeeds_and_the_lease_dies() {
    // `docs/protocol.md`: `lease.revoke` is "agent (own) / human (any)". The
    // human arm passes `owner = None` (no ownership filter) and reads
    // `params.lease_id` as the TARGET handle, not as a credential — so the
    // H-12(b) guard must not reject it. Regression: the guard used to block
    // every `params.lease_id` on a human request, making the documented human
    // revoke path unreachable (E_INVALID_INPUT) while `lease.list` worked.
    let f = setup("read,inject");
    let created = f.daemon.handle_request(agent(
        "6",
        "lease.create",
        &f.token,
        json!({"project":"acme","ops":"read","ttl_secs":60}),
    ));
    let credential = lease_credential_of(&created);
    let lease_id = lease_handle_of(&created);

    let revoked =
        f.daemon
            .handle_request(human("7", "lease.revoke", json!({"lease_id": lease_id})));
    assert!(
        revoked.ok,
        "a human must be able to revoke any lease: {:?}",
        revoked.error
    );
    assert_eq!(revoked.result.unwrap()["revoked"], json!(true));

    // The credential is dead: its use is refused as an expired lease.
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "8",
            "secrets.list",
            &f.token,
            json!({"project":"acme","lease":credential.clone()})
        ))),
        "E_LEASE_EXPIRED"
    );
}

#[test]
fn human_ops_still_reject_a_caller_named_lease_credential() {
    // The H-12(b) exemption is per-KEY: only the `lease_id` TARGET handle is
    // allowed on `lease.revoke`. `params.lease` (the credential form) stays
    // refused everywhere for a human — no arm reads it there, and silently
    // ignoring a caller-named capability is what the guard exists to prevent.
    let f = setup("read,inject");
    let created = f.daemon.handle_request(agent(
        "6",
        "lease.create",
        &f.token,
        json!({"project":"acme","ops":"read","ttl_secs":60}),
    ));
    let credential = lease_credential_of(&created);

    for (id, op, params) in [
        (
            "7",
            "lease.revoke",
            json!({"lease_id": "x", "lease": credential.clone()}),
        ),
        ("8", "lease.list", json!({"lease": credential.clone()})),
        ("9", "runs.list", json!({"lease_id": "x"})),
    ] {
        assert_eq!(
            code(&f.daemon.handle_request(human(id, op, params))),
            "E_INVALID_INPUT",
            "{op} must still refuse a caller-named lease"
        );
    }
}

#[test]
fn grant_reduction_invalidates_existing_lease() {
    let f = setup("read,inject");
    let created = f.daemon.handle_request(agent(
        "6",
        "lease.create",
        &f.token,
        json!({"project":"acme","ops":"read,inject","ttl_secs":60}),
    ));
    let credential = lease_credential_of(&created);
    assert!(
        f.daemon
            .handle_request(human(
                "7",
                "grants.grant",
                json!({"agent":"bot","project":"acme","ops":"inject"})
            ))
            .ok
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "8",
            "secrets.list",
            &f.token,
            json!({"project":"acme","lease":credential})
        ))),
        "E_LEASE_EXPIRED"
    );
}

#[test]
fn grant_revoke_invalidates_lease() {
    let f = setup("read,inject");
    let created = f.daemon.handle_request(agent(
        "6",
        "lease.create",
        &f.token,
        json!({"project":"acme","ops":"read","ttl_secs":60}),
    ));
    let credential = lease_credential_of(&created);
    assert!(
        f.daemon
            .handle_request(human(
                "7",
                "grants.revoke",
                json!({"agent":"bot","project":"acme"})
            ))
            .ok
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "8",
            "secrets.list",
            &f.token,
            json!({"project":"acme","lease":credential})
        ))),
        "E_LEASE_EXPIRED"
    );
}

#[test]
fn agent_revoke_invalidates_lease_token() {
    let f = setup("read,inject");
    let created = f.daemon.handle_request(agent(
        "6",
        "lease.create",
        &f.token,
        json!({"project":"acme","ops":"read","ttl_secs":60}),
    ));
    let credential = lease_credential_of(&created);
    assert!(
        f.daemon
            .handle_request(human("7", "agents.revoke", json!({"name":"bot"})))
            .ok
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "8",
            "secrets.list",
            &f.token,
            json!({"project":"acme","lease":credential})
        ))),
        "E_AUTH"
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "9",
            "secrets.list",
            &f.token,
            json!({"project":"acme"})
        ))),
        "E_AUTH"
    );
}

#[test]
fn lock_blocks_leased_use() {
    let f = setup("read,inject");
    let created = f.daemon.handle_request(agent(
        "6",
        "lease.create",
        &f.token,
        json!({"project":"acme","ops":"read","ttl_secs":60}),
    ));
    let credential = lease_credential_of(&created);
    assert!(
        f.daemon
            .handle_request(human("7", "vault.lock", json!({})))
            .ok
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "8",
            "secrets.list",
            &f.token,
            json!({"project":"acme","lease":credential})
        ))),
        "E_LOCKED"
    );
}

#[test]
fn lease_handle_alone_authorizes_nothing() {
    let f = setup("read,inject");
    let created = f.daemon.handle_request(agent(
        "H1",
        "lease.create",
        &f.token,
        json!({"project":"acme","ops":"read","ttl_secs":60}),
    ));
    let credential = lease_credential_of(&created);
    let handle = lease_handle_of(&created);
    assert_ne!(credential, handle);
    // The public handle is 64 bits of display identity, not a capability;
    // presenting it as a lease must fail closed.
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "H2",
            "secrets.list",
            &f.token,
            json!({"project":"acme","lease":handle})
        ))),
        "E_LEASE_EXPIRED"
    );
    // A substituted credential is likewise indistinguishable from a revoked
    // one — same code, no oracle.
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "H3",
            "secrets.list",
            &f.token,
            json!({"project":"acme","lease":"not-a-real-credential"})
        ))),
        "E_LEASE_EXPIRED"
    );
    assert!(
        f.daemon
            .handle_request(agent(
                "H4",
                "secrets.list",
                &f.token,
                json!({"project":"acme","lease":credential})
            ))
            .ok
    );
}

#[test]
fn lease_credential_has_entropy_and_is_not_persisted_in_cleartext() {
    let f = setup("read,inject");
    let created = f.daemon.handle_request(agent(
        "E1",
        "lease.create",
        &f.token,
        json!({"project":"acme","ops":"read","ttl_secs":60}),
    ));
    let credential = lease_credential_of(&created);
    let handle = lease_handle_of(&created);

    // 256 bits base64url ≈ 43 chars; the handle is a 16-hex-char id.
    assert!(credential.len() >= 42, "credential too short: {credential}");
    assert_eq!(handle.len(), 16);

    // Distinct runs must not collide.
    let second = f.daemon.handle_request(agent(
        "E2",
        "lease.create",
        &f.token,
        json!({"project":"acme","ops":"read","ttl_secs":60}),
    ));
    assert_ne!(lease_credential_of(&second), credential);

    // Use the lease so the audit records its actor and prefix.
    assert!(
        f.daemon
            .handle_request(agent(
                "E3",
                "secrets.list",
                &f.token,
                json!({"project":"acme","lease":credential})
            ))
            .ok
    );

    // Nothing on disk repeats the credential: neither the audit log nor the
    // sealed vault document.
    let audit = audit_text(&f);
    assert!(!audit.contains(&credential), "credential leaked into audit");
    let vault = std::fs::read(&f.vault_path).unwrap();
    assert!(
        !vault
            .windows(credential.len())
            .any(|w| w == credential.as_bytes()),
        "credential written to the vault file"
    );
    // The audit records the safe public handle and the display prefix only.
    assert!(audit.contains(&handle), "handle should be audited as actor");
    assert!(
        audit.contains(&format!("lease:{handle}")),
        "lease actor should be the public handle"
    );
    let prefix = created.result.as_ref().unwrap()["lease_prefix"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(prefix.len(), 8, "prefix is 4 digest bytes in hex");
    // The prefix is display-only and cannot authorize anything.
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "E4",
            "secrets.list",
            &f.token,
            json!({"project":"acme","lease":prefix})
        ))),
        "E_LEASE_EXPIRED"
    );
}

#[test]
fn lease_credential_never_appears_in_errors_or_audit() {
    let f = setup("read,inject");
    let created = f.daemon.handle_request(agent(
        "T1",
        "lease.create",
        &f.token,
        json!({"project":"acme","ops":"read","ttl_secs":60}),
    ));
    let credential = lease_credential_of(&created);
    let handle = lease_handle_of(&created);

    // Exercise both the allowed and denied paths with the credential present.
    assert!(
        f.daemon
            .handle_request(agent(
                "T2",
                "secrets.list",
                &f.token,
                json!({"project":"acme","lease":credential})
            ))
            .ok
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "T3",
            "inject_file",
            &f.token,
            json!({"project":"acme","path":".env","lease":credential})
        ))),
        "E_PERMISSION"
    );
    assert!(
        f.daemon
            .handle_request(agent(
                "T4",
                "lease.revoke",
                &f.token,
                json!({"lease_id":handle})
            ))
            .ok
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "T5",
            "secrets.list",
            &f.token,
            json!({"project":"acme","lease":credential})
        ))),
        "E_LEASE_EXPIRED"
    );

    let audit = audit_text(&f);
    assert!(
        !audit.contains(&credential),
        "credential leaked into audit: {audit}"
    );
    assert!(!audit.contains(TRAP));
    assert!(!audit.contains(OTHER_TRAP));
}

#[test]
fn reveal_approval_is_bound_single_use_and_revalidated_at_claim() {
    let f = setup("reveal");
    let pending = f.daemon.handle_request(agent(
        "6",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY"}),
    ));
    let approval_id = approval_id_of(&pending);
    assert_eq!(
        f.daemon
            .handle_request(agent(
                "7",
                "approvals.status",
                &f.token,
                json!({"approval_id":approval_id})
            ))
            .result
            .unwrap()["status"],
        "pending"
    );
    assert!(
        f.daemon
            .handle_request(human(
                "8",
                "approvals.approve",
                json!({"approval_id":approval_id})
            ))
            .ok
    );
    let claim = f.daemon.handle_request(agent(
        "9",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY","approval_id":approval_id}),
    ));
    assert_eq!(claim.result.unwrap()["value"], TRAP);
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "10",
            "reveal",
            &f.token,
            json!({"project":"acme","key":"API_KEY","approval_id":approval_id})
        ))),
        "E_APPROVAL_CONSUMED"
    );
    let audit = audit_text(&f);
    assert!(!audit.contains(TRAP));
    assert!(!audit.contains(OTHER_TRAP));
}

#[test]
fn pending_approval_is_nonblocking_and_advertises_expiry() {
    let f = setup("reveal");
    let first = f.daemon.handle_request(agent(
        "6",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY"}),
    ));
    let id1 = approval_id_of(&first);
    let exp1 = edata(&first)["expires_in"].as_u64().unwrap();
    assert!(exp1 > 0);
    assert!(!emsg(&first).contains(TRAP));
    let second = f.daemon.handle_request(agent(
        "7",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY"}),
    ));
    let id2 = approval_id_of(&second);
    assert_ne!(id1, id2);
    let status = f.daemon.handle_request(agent(
        "8",
        "approvals.status",
        &f.token,
        json!({"approval_id":id1}),
    ));
    assert!(status.ok, "{:?}", status.error);
    let body = status.result.unwrap();
    assert_eq!(body["status"], "pending");
    assert_eq!(body["project"], "acme");
    assert_eq!(body["key"], "API_KEY");
    assert!(body["expires_in"].as_u64().unwrap() > 0);
    assert!(!serde_json::to_string(&body).unwrap().contains(TRAP));
    let pending = f
        .daemon
        .handle_request(human("9", "approvals.pending", json!({})));
    assert!(pending.ok, "{:?}", pending.error);
    let list = serde_json::to_string(&pending.result.unwrap()).unwrap();
    assert!(list.contains(&id1));
    assert!(!list.contains(TRAP));
    std::thread::sleep(Duration::from_millis(1100));
    let again = f.daemon.handle_request(agent(
        "10",
        "approvals.status",
        &f.token,
        json!({"approval_id":id1}),
    ));
    assert_eq!(again.result.unwrap()["status"], "pending");
}

#[test]
fn deny_and_permission_revoke_invalidate_approvals() {
    let f = setup("reveal");
    let pending = f.daemon.handle_request(agent(
        "6",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY"}),
    ));
    let approval_id = approval_id_of(&pending);
    assert!(
        f.daemon
            .handle_request(human(
                "7",
                "approvals.deny",
                json!({"approval_id":approval_id})
            ))
            .ok
    );
    let status = f.daemon.handle_request(agent(
        "7b",
        "approvals.status",
        &f.token,
        json!({"approval_id":approval_id}),
    ));
    assert_eq!(status.result.unwrap()["status"], "denied");
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "8",
            "reveal",
            &f.token,
            json!({"project":"acme","key":"API_KEY","approval_id":approval_id})
        ))),
        "E_APPROVAL_DENIED"
    );
    let pending = f.daemon.handle_request(agent(
        "9",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY"}),
    ));
    let approval_id = approval_id_of(&pending);
    assert!(
        f.daemon
            .handle_request(human(
                "10",
                "approvals.approve",
                json!({"approval_id":approval_id})
            ))
            .ok
    );
    assert!(
        f.daemon
            .handle_request(human(
                "11",
                "grants.revoke",
                json!({"agent":"bot","project":"acme"})
            ))
            .ok
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "12",
            "reveal",
            &f.token,
            json!({"project":"acme","key":"API_KEY","approval_id":approval_id})
        ))),
        "E_PERMISSION"
    );
}

#[test]
fn approval_binding_across_agent_key_project() {
    let f = setup("reveal");
    let bot2 = enroll(&f, "b2", "bot2", "reveal");
    assert!(
        f.daemon
            .handle_request(human("p1", "project.add", json!({"name":"beta"})))
            .ok
    );
    assert!(
        f.daemon
            .handle_request(human(
                "p2",
                "secret.set",
                json!({"project":"beta","key":"API_KEY","value":"beta-value"})
            ))
            .ok
    );
    assert!(
        f.daemon
            .handle_request(human(
                "p3",
                "grants.grant",
                json!({"agent":"bot","project":"beta","ops":"reveal"})
            ))
            .ok
    );
    assert!(
        f.daemon
            .handle_request(human(
                "p4",
                "grants.grant",
                json!({"agent":"bot2","project":"acme","ops":"reveal"})
            ))
            .ok
    );
    let pending = f.daemon.handle_request(agent(
        "6",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY"}),
    ));
    let approval_id = approval_id_of(&pending);
    assert!(
        f.daemon
            .handle_request(human(
                "7",
                "approvals.approve",
                json!({"approval_id":approval_id})
            ))
            .ok
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "8",
            "reveal",
            &bot2,
            json!({"project":"acme","key":"API_KEY","approval_id":approval_id})
        ))),
        "E_PERMISSION"
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "9",
            "reveal",
            &f.token,
            json!({"project":"acme","key":"OTHER_KEY","approval_id":approval_id})
        ))),
        "E_PERMISSION"
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "10",
            "reveal",
            &f.token,
            json!({"project":"beta","key":"API_KEY","approval_id":approval_id})
        ))),
        "E_PERMISSION"
    );
    let claim = f.daemon.handle_request(agent(
        "11",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY","approval_id":approval_id}),
    ));
    assert_eq!(claim.result.unwrap()["value"], TRAP);
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "12",
            "reveal",
            &f.token,
            json!({"project":"acme","key":"API_KEY","approval_id":approval_id})
        ))),
        "E_APPROVAL_CONSUMED"
    );
}

#[test]
fn approved_claim_window_is_advertised_and_single_use() {
    let f = setup("reveal");
    let pending = f.daemon.handle_request(agent(
        "6",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY"}),
    ));
    let approval_id = approval_id_of(&pending);
    assert!(
        f.daemon
            .handle_request(human(
                "7",
                "approvals.approve",
                json!({"approval_id":approval_id})
            ))
            .ok
    );
    let status = f.daemon.handle_request(agent(
        "8",
        "approvals.status",
        &f.token,
        json!({"approval_id":approval_id}),
    ));
    let body = status.result.unwrap();
    assert_eq!(body["status"], "approved");
    assert!(body["expires_in"].as_u64().unwrap() > 0);
    std::thread::sleep(Duration::from_millis(1100));
    let claim = f.daemon.handle_request(agent(
        "9",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY","approval_id":approval_id}),
    ));
    assert_eq!(claim.result.unwrap()["value"], TRAP);
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "10",
            "reveal",
            &f.token,
            json!({"project":"acme","key":"API_KEY","approval_id":approval_id})
        ))),
        "E_APPROVAL_CONSUMED"
    );
    let status = f.daemon.handle_request(agent(
        "11",
        "approvals.status",
        &f.token,
        json!({"approval_id":approval_id}),
    ));
    assert_eq!(status.result.unwrap()["status"], "consumed");
}

#[test]
fn agent_revoke_invalidates_approval() {
    let f = setup("reveal");
    let pending = f.daemon.handle_request(agent(
        "6",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY"}),
    ));
    let approval_id = approval_id_of(&pending);
    assert!(
        f.daemon
            .handle_request(human(
                "7",
                "approvals.approve",
                json!({"approval_id":approval_id})
            ))
            .ok
    );
    assert!(
        f.daemon
            .handle_request(human("8", "agents.revoke", json!({"name":"bot"})))
            .ok
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "9",
            "reveal",
            &f.token,
            json!({"project":"acme","key":"API_KEY","approval_id":approval_id})
        ))),
        "E_AUTH"
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "10",
            "approvals.status",
            &f.token,
            json!({"approval_id":approval_id})
        ))),
        "E_AUTH"
    );
}

#[test]
fn lock_blocks_approval_claim() {
    let f = setup("reveal");
    let pending = f.daemon.handle_request(agent(
        "6",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY"}),
    ));
    let approval_id = approval_id_of(&pending);
    assert!(
        f.daemon
            .handle_request(human(
                "7",
                "approvals.approve",
                json!({"approval_id":approval_id})
            ))
            .ok
    );
    assert!(
        f.daemon
            .handle_request(human("8", "vault.lock", json!({})))
            .ok
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "9",
            "reveal",
            &f.token,
            json!({"project":"acme","key":"API_KEY","approval_id":approval_id})
        ))),
        "E_LOCKED"
    );
    assert_eq!(
        code(&f.daemon.handle_request(agent(
            "10",
            "approvals.status",
            &f.token,
            json!({"approval_id":approval_id})
        ))),
        "E_LOCKED"
    );
}

#[test]
fn secret_never_appears_in_errors_or_audit() {
    let f = setup("read,reveal");
    for resp in [
        f.daemon.handle_request(agent(
            "e1",
            "reveal",
            &f.token,
            json!({"project":"acme","key":"API_KEY"}),
        )),
        f.daemon.handle_request(agent(
            "e2",
            "secrets.list",
            &f.token,
            json!({"project":"nope"}),
        )),
        f.daemon.handle_request(agent(
            "e3",
            "lease.create",
            &f.token,
            json!({"project":"acme","ops":"run","ttl_secs":60}),
        )),
    ] {
        let blob = serde_json::to_string(&resp.error).unwrap();
        assert!(!blob.contains(TRAP), "{blob}");
        assert!(!blob.contains(OTHER_TRAP), "{blob}");
    }
    let list = f.daemon.handle_request(agent(
        "e4",
        "secrets.list",
        &f.token,
        json!({"project":"acme"}),
    ));
    assert!(list.ok, "{:?}", list.error);
    let blob = serde_json::to_string(&list.result).unwrap();
    assert!(blob.contains("API_KEY"));
    assert!(!blob.contains(TRAP));
    assert!(!blob.contains(OTHER_TRAP));
    let pending = f.daemon.handle_request(agent(
        "e5",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY"}),
    ));
    let approval_id = approval_id_of(&pending);
    assert!(
        f.daemon
            .handle_request(human(
                "e6",
                "approvals.approve",
                json!({"approval_id":approval_id})
            ))
            .ok
    );
    let direct = f.daemon.handle_request(human(
        "e7",
        "reveal",
        json!({"project":"acme","key":"API_KEY"}),
    ));
    assert!(direct.ok, "{:?}", direct.error);
    assert_eq!(direct.result.unwrap()["value"], TRAP);
    let shown = f
        .daemon
        .handle_request(human("e8", "audit.show", json!({"tail":100})));
    assert!(shown.ok, "{:?}", shown.error);
    let blob = serde_json::to_string(&shown.result).unwrap();
    assert!(!blob.contains(TRAP), "{blob}");
    assert!(!blob.contains(OTHER_TRAP), "{blob}");
    assert!(!audit_text(&f).contains(TRAP));
    assert!(!audit_text(&f).contains(OTHER_TRAP));
}

#[test]
fn leased_reveal_audit_uses_lease_actor() {
    let f = setup("reveal");
    let created = f.daemon.handle_request(agent(
        "L1",
        "lease.create",
        &f.token,
        json!({"project":"acme","ops":"reveal","ttl_secs":60}),
    ));
    let credential = lease_credential_of(&created);
    let lease_id = lease_handle_of(&created);
    let leased_actor = format!("lease:{lease_id}");
    let pending = f.daemon.handle_request(agent(
        "L2",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY","lease":credential}),
    ));
    let approval_id = approval_id_of(&pending);
    assert!(
        f.daemon
            .handle_request(human(
                "L3",
                "approvals.approve",
                json!({"approval_id":approval_id})
            ))
            .ok
    );
    let claim = f.daemon.handle_request(agent(
        "L4",
        "reveal",
        &f.token,
        json!({"project":"acme","key":"API_KEY","approval_id":approval_id,"lease":credential}),
    ));
    assert_eq!(claim.result.unwrap()["value"], TRAP);
    let audit = audit_text(&f);
    assert!(!audit.contains(TRAP));
    assert!(!audit.contains(OTHER_TRAP));
    let mut saw_request = false;
    let mut saw_reveal = false;
    for line in audit.lines() {
        let v: Value = serde_json::from_str(line).expect("audit line is JSON");
        match v.get("op").and_then(|o| o.as_str()) {
            Some("approval.request") => {
                assert_eq!(
                    v.get("actor").and_then(|a| a.as_str()),
                    Some(leased_actor.as_str()),
                    "{line}"
                );
                saw_request = true;
            }
            Some("reveal") if v.get("decision").and_then(|d| d.as_str()) == Some("allowed") => {
                assert_eq!(
                    v.get("actor").and_then(|a| a.as_str()),
                    Some(leased_actor.as_str()),
                    "{line}"
                );
                saw_reveal = true;
            }
            _ => {}
        }
    }
    assert!(saw_request, "missing leased approval.request entry");
    assert!(saw_reveal, "missing leased reveal entry");
}
