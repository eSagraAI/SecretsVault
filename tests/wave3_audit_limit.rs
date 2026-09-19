//! Wave 3 follow-up — `MAX_AUDIT_LEN` vs. the vault lifecycle.
//!
//! Two states the audit ceiling must never create:
//!
//! 1. **vault committed, audit missing.** `commit` used to reseal and persist
//!    `vault.enc` *before* appending the audit entry, and the checkpoint
//!    embeds `{seq, hash}` of that entry. If the append then failed, the vault
//!    on disk referenced an event that does not exist: `check_checkpoint`
//!    fails and the vault can never be unlocked again. The ceiling made this
//!    reachable by a *predictable* condition rather than a disk failure.
//! 2. **the vault cannot be locked.** `lock_and_drain` and `lock_persist`
//!    propagated an audit error with `?` *before* terminating runs, revoking
//!    capabilities and zeroizing keys — so a full audit log would block the
//!    lock, the idle auto-lock, revocation and key destruction. That inverts
//!    the point of the lock.
//!
//! Design: a soft operational limit for ordinary operations (they preflight
//! and fail closed with `E_AUDIT_FULL` *before* touching the vault), reserved
//! headroom that only lifecycle events may spend, and `MAX_AUDIT_LEN` kept as
//! the absolute hard cap. Appends happen before the vault is replaced, so the
//! dangerous ordering is gone by construction.
//!
//! These tests shrink the ceilings through a test seam so the boundary is
//! reached deterministically — writing 16 MiB of real history would make them
//! quadratically slow for no extra coverage.

use std::path::PathBuf;
use std::time::Duration;

use svault::audit::MAX_AUDIT_LEN;
use svault::session::{Session, SystemClock};

const PASS: &[u8] = b"correct horse battery";
const IDLE: Duration = Duration::from_secs(300);

/// Room for a handful of ~400-byte entries: enough to reach the boundary with
/// a handful of real mutations, far below the production ceilings.
const TEST_SOFT: u64 = 8 * 1024;
const TEST_HARD: u64 = 16 * 1024;

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("svault-wave3b-{tag}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn vault(dir: &Dir) -> PathBuf {
    dir.path().join("vault.enc")
}

fn audit(dir: &Dir) -> PathBuf {
    dir.path().join("audit.jsonl")
}

/// `std::fs::set_permissions` consumes the `Permissions` value, which makes
/// multi-step permission juggling awkward; this keeps the tests readable.
fn chmod(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms).unwrap();
}

/// A session with the ceilings shrunk so the boundary is reachable.
fn session(tag: &str) -> (Dir, Session) {
    let dir = Dir::new(tag);
    let path = vault(&dir);
    let mut s = Session::create(&path, PASS, IDLE, Box::new(SystemClock)).unwrap();
    s.set_audit_limits_for_test(TEST_SOFT, TEST_HARD);
    s.project_add("human", "acme", &[]).unwrap();
    (dir, s)
}

/// Write ordinary mutations until one is refused by the soft limit.
fn fill_to_soft_limit(s: &mut Session) -> svault::VaultError {
    for i in 0..10_000 {
        match s.secret_set("human", "acme", "K", format!("value-{i}").as_bytes()) {
            Ok(()) => continue,
            Err(e) => return e,
        }
    }
    panic!("the soft limit was never reached");
}

// ---------------------------------------------------------------------------
// 1. A mutation that cannot be audited is never committed
// ---------------------------------------------------------------------------

/// At the soft limit, an ordinary mutation must fail **before** touching
/// `vault.enc`, with a stable code, leaving the stored vault byte-identical
/// and the session's document unchanged.
#[test]
fn audit_full_refuses_the_mutation_before_the_vault_is_touched() {
    let (dir, mut s) = session("preflight");
    let err = fill_to_soft_limit(&mut s);
    assert_eq!(
        err.code(),
        "E_AUDIT_FULL",
        "a predictable ceiling must refuse with a stable code, got {err}"
    );

    let before_vault = std::fs::read(vault(&dir)).unwrap();
    let before_audit = std::fs::metadata(audit(&dir)).unwrap().len();
    let before_doc = s.document().cloned();

    // Further attempts keep failing, and change nothing.
    for i in 0..3 {
        let e = s
            .secret_set("human", "acme", "K", format!("rejected-{i}").as_bytes())
            .expect_err("still full");
        assert_eq!(e.code(), "E_AUDIT_FULL");
    }

    assert_eq!(
        std::fs::read(vault(&dir)).unwrap(),
        before_vault,
        "vault.enc must be byte-identical: no committed-but-unaudited state"
    );
    assert_eq!(
        std::fs::metadata(audit(&dir)).unwrap().len(),
        before_audit,
        "the refused entries must not have been written"
    );
    assert_eq!(
        s.document().cloned(),
        before_doc,
        "the in-memory document must not advance past a refused commit"
    );
}

/// The vault must still be loadable and its checkpoint valid after refusals.
#[test]
fn vault_stays_loadable_and_checkpoint_coherent_after_refusals() {
    let (dir, mut s) = session("coherent");
    let _ = fill_to_soft_limit(&mut s);
    drop(s);

    let mut reopened = Session::load(&vault(&dir), IDLE, Box::new(SystemClock)).unwrap();
    reopened
        .unlock(PASS)
        .expect("the vault must remain loadable and unlockable");
    assert!(reopened.document().is_some());
    // The audit log still verifies against the vault checkpoint.
    let report = reopened.audit_verify().expect("audit must still verify");
    assert!(report.macs_verified > 0, "{report:?}");
}

/// The exact dangerous window, reached without any ceiling: the audit entry is
/// staged fine, the vault is written, and only then does the *append* fail
/// (here: the log is not writable). With the old ordering this leaves the
/// stored vault naming an entry that does not exist, and every later unlock
/// fails `check_checkpoint` — permanently. The append-before-save ordering
/// makes the vault untouched instead.
#[test]
fn a_failed_append_leaves_the_vault_untouched_and_loadable() {
    let dir = Dir::new("append-fails");
    let path = vault(&dir);
    let mut s = Session::create(&path, PASS, IDLE, Box::new(SystemClock)).unwrap();
    s.project_add("human", "acme", &[]).unwrap();
    s.secret_set("human", "acme", "K", b"v").unwrap();

    let before_vault = std::fs::read(&path).unwrap();
    let before_doc = s.document().cloned();

    // The log becomes unwritable: `stage` still succeeds (it only reads), the
    // append cannot.
    chmod(&audit(&dir), 0o400);

    let err = s
        .secret_set("human", "acme", "K", b"rejected")
        .expect_err("a mutation whose audit entry cannot be written must fail");

    // Restore permissions before asserting on disk state.
    chmod(&audit(&dir), 0o600);

    assert!(
        matches!(err.code(), "E_AUDIT_WRITE" | "E_AUDIT_FULL"),
        "stable code expected, got {}: {err}",
        err.code()
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before_vault,
        "the vault must not be committed when its audit entry could not be written"
    );
    assert_eq!(
        s.document().cloned(),
        before_doc,
        "session must not diverge"
    );

    // The decisive property: the vault still unlocks (no missing checkpoint).
    drop(s);
    let mut reopened = Session::load(&path, IDLE, Box::new(SystemClock)).unwrap();
    reopened
        .unlock(PASS)
        .expect("the vault must remain loadable — no committed-but-unaudited state");
}

/// The same invariant at the other entry point: `create` must not leave a
/// vault on disk when its creation event could not be recorded, or the brand
/// new vault would fail `check_checkpoint` on first unlock.
#[test]
fn a_failed_creation_audit_leaves_no_vault() {
    let dir = Dir::new("create-audit-fails");
    let path = vault(&dir);
    let audit_path = audit(&dir);

    // An audit log that exists but cannot be appended to.
    std::fs::write(&audit_path, b"").unwrap();
    chmod(&audit_path, 0o400);

    let result = Session::create(&path, PASS, IDLE, Box::new(SystemClock));
    let created = result.is_ok();

    // Restore permissions before asserting.
    chmod(&audit_path, 0o600);

    if created {
        // If creation succeeded, the audit entry must exist and the vault must
        // open: no committed-but-unaudited state.
        let mut s = Session::load(&path, IDLE, Box::new(SystemClock)).unwrap();
        s.unlock(PASS)
            .expect("a created vault must always be openable");
    } else {
        assert!(
            !path.exists(),
            "a failed creation must not leave a half-created vault on disk"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. The lock path survives a full audit log
// ---------------------------------------------------------------------------

/// `lock_persist` must still lock, revoke capabilities, persist and zeroize
/// with the log at its ceiling.
#[test]
fn lock_still_locks_and_revokes_with_a_full_audit_log() {
    let (dir, mut s) = session("lock-full");
    let (agent_id, _token) = s.agent_add("human", "bot").unwrap();
    s.grant_add("human", "bot", "acme", &[svault::model::Op::Read])
        .unwrap();
    let (lease, credential) = s
        .lease_create(
            "agent:bot",
            &agent_id,
            "acme",
            &[svault::model::Op::Read],
            3600,
        )
        .unwrap();
    let _ = fill_to_soft_limit(&mut s);
    // Spend the reserve too, so the lock runs with nothing left.
    for i in 0..200 {
        s.set_audit_limits_for_test(1, 1);
        let _ = s.secret_set("human", "acme", "K", format!("x{i}").as_bytes());
    }
    s.set_audit_limits_for_test(TEST_SOFT, TEST_HARD);

    s.lock_persist()
        .expect("the lock must never be blocked by a full audit log");
    assert!(s.is_locked(), "key material must be dropped");

    drop(s);
    let mut reopened = Session::load(&vault(&dir), IDLE, Box::new(SystemClock)).unwrap();
    reopened.unlock(PASS).expect("vault must still unlock");
    let doc = reopened.document().unwrap();
    if let Some(stored) = doc.leases.iter().find(|l| l.id == lease.id) {
        assert!(
            stored.revoked_at.is_some(),
            "the lock must have revoked the lease"
        );
    }
    let _ = credential;
}

/// Past the hard cap — the most hostile state, where not even a lifecycle
/// entry can be written — locking must still lock, revoke and zeroize, and the
/// vault must stay loadable: the checkpoint simply keeps naming the last entry
/// that really exists.
#[test]
fn lock_at_the_hard_cap_still_locks_revokes_and_stays_loadable() {
    let (dir, mut s) = session("lock-hardcap");
    let (agent_id, _token) = s.agent_add("human", "bot").unwrap();
    s.grant_add("human", "bot", "acme", &[svault::model::Op::Read])
        .unwrap();
    let (lease, _credential) = s
        .lease_create(
            "agent:bot",
            &agent_id,
            "acme",
            &[svault::model::Op::Read],
            3600,
        )
        .unwrap();

    s.set_audit_limits_for_test(1, 1);
    s.lock_persist()
        .expect("nothing may block the lock, not even a hard-capped log");
    assert!(
        s.is_locked(),
        "key material must be dropped regardless of the audit state"
    );

    drop(s);
    let mut reopened = Session::load(&vault(&dir), IDLE, Box::new(SystemClock)).unwrap();
    reopened.unlock(PASS).expect("vault must still unlock");
    let doc = reopened.document().unwrap();
    let stored = doc
        .leases
        .iter()
        .find(|l| l.id == lease.id)
        .expect("the lease row must survive the lock");
    assert!(
        stored.revoked_at.is_some(),
        "the lock must have revoked the lease even unaudited"
    );
    let report = reopened.audit_verify().expect("audit must still verify");
    assert!(report.entries > 0, "{report:?}");
}

// ---------------------------------------------------------------------------
// 2b. Revocations are authority-reducing: they must apply even unaudited
// ---------------------------------------------------------------------------

/// `agents.revoke`, `grants.revoke` and `lease.revoke` change persisted state
/// that *removes* authority. Refusing them because the log is full would leave
/// the capability alive — strictly worse than a missing audit line. So at the
/// hard cap they still take effect, the checkpoint does not move (it must keep
/// naming an entry that exists), and the vault stays coherent.
#[test]
fn revocations_at_the_hard_cap_still_take_effect() {
    let (dir, mut s) = session("revoke-hardcap");
    let (agent_id, _token) = s.agent_add("human", "bot").unwrap();
    s.grant_add("human", "bot", "acme", &[svault::model::Op::Read])
        .unwrap();
    let (lease, credential) = s
        .lease_create(
            "agent:bot",
            &agent_id,
            "acme",
            &[svault::model::Op::Read],
            3600,
        )
        .unwrap();
    let before_head = s.document().unwrap().audit_head.clone();

    // Nothing can be recorded from here on: not even a lifecycle entry.
    s.set_audit_limits_for_test(1, 1);

    s.lease_revoke("human", None, &lease.id)
        .expect("lease revocation must not be blocked by a full log");
    s.grant_revoke("human", "bot", "acme")
        .expect("grant revocation must not be blocked by a full log");
    s.agent_revoke("human", "bot")
        .expect("agent revocation must not be blocked by a full log");

    // The checkpoint must not have moved to an entry that was never written.
    assert_eq!(
        s.document().unwrap().audit_head,
        before_head,
        "an unrecorded change must leave the checkpoint on the last real entry"
    );

    // Authority is genuinely gone, not merely marked in memory.
    assert!(
        s.authorize_lease(
            &agent_id,
            "acme",
            svault::model::Op::Read,
            Some(&credential)
        )
        .is_err(),
        "the revoked lease must no longer authorize"
    );
    let doc = s.document().unwrap();
    assert!(
        doc.leases.iter().all(|l| l.revoked_at.is_some()),
        "every lease of a revoked agent must be revoked"
    );
    let project_id = doc.project_by_name("acme").unwrap().id.clone();
    assert!(
        doc.active_grant(&agent_id, &project_id).is_none(),
        "no active grant may survive revocation"
    );
    assert_eq!(
        doc.agents.iter().find(|a| a.id == agent_id).unwrap().status,
        svault::model::AgentStatus::Revoked
    );

    drop(s);
    // Coherence: the checkpoint still names an existing entry, so unlock and
    // verification are untouched by the unrecorded revocations.
    let mut reopened = Session::load(&vault(&dir), IDLE, Box::new(SystemClock)).unwrap();
    reopened
        .unlock(PASS)
        .expect("revocations must not break the vault↔audit checkpoint");
    let doc = reopened.document().unwrap();
    assert_eq!(
        doc.audit_head, before_head,
        "the persisted checkpoint must still name the last recorded entry"
    );
    assert_eq!(
        doc.agents.iter().find(|a| a.id == agent_id).unwrap().status,
        svault::model::AgentStatus::Revoked,
        "the revocation must have reached disk"
    );
    reopened.audit_verify().expect("audit must still verify");
}

/// A *narrowing* `grants.grant` also removes authority, so it must apply at the
/// cap; a widening one must not, because the agent simply does not gain.
#[test]
fn a_narrowing_grant_applies_at_the_hard_cap_but_a_widening_one_does_not() {
    let (_dir, mut s) = session("grant-hardcap");
    let (agent_id, _token) = s.agent_add("human", "bot").unwrap();
    s.grant_add(
        "human",
        "bot",
        "acme",
        &[svault::model::Op::Read, svault::model::Op::Inject],
    )
    .unwrap();

    let project_id = s
        .document()
        .unwrap()
        .project_by_name("acme")
        .unwrap()
        .id
        .clone();
    s.set_audit_limits_for_test(1, 1);
    // Narrowing: must apply.
    s.grant_add("human", "bot", "acme", &[svault::model::Op::Read])
        .expect("a narrowing grant must not be blocked by a full log");
    assert_eq!(
        s.document()
            .unwrap()
            .active_grant(&agent_id, &project_id)
            .unwrap()
            .ops,
        vec![svault::model::Op::Read],
        "the narrowed grant must have taken effect"
    );
    // Widening: fails closed, the agent does not gain.
    assert!(
        s.grant_add(
            "human",
            "bot",
            "acme",
            &[svault::model::Op::Read, svault::model::Op::Reveal]
        )
        .is_err(),
        "a widening grant must fail closed rather than apply unaudited"
    );
    assert_eq!(
        s.document()
            .unwrap()
            .active_grant(&agent_id, &project_id)
            .unwrap()
            .ops,
        vec![svault::model::Op::Read],
        "the refused widening must not have leaked any authority"
    );
}

// ---------------------------------------------------------------------------
// 2c. The other side of the ordering: the append happened, the save did not
// ---------------------------------------------------------------------------

/// `append` succeeds, `save_atomic` fails. The stored vault must be untouched
/// and still openable; the log carries one entry beyond the checkpoint. That
/// entry describes a change that was **never committed** — it must be treated
/// as an unconfirmed record, never as a mutation that happened.
#[test]
fn a_failed_vault_save_after_a_successful_append_leaves_the_previous_vault() {
    let dir = Dir::new("save-fails");
    let path = vault(&dir);
    let mut s = Session::create(&path, PASS, IDLE, Box::new(SystemClock)).unwrap();
    s.project_add("human", "acme", &[]).unwrap();
    s.secret_set("human", "acme", "K", b"v").unwrap();

    let before_vault = std::fs::read(&path).unwrap();
    let before_head = s.document().unwrap().audit_head.clone();
    let before_log = std::fs::read_to_string(audit(&dir)).unwrap();

    // The vault file becomes read-only *for the rename target's directory*: a
    // durable write failure with the shape of a read-only mount. The audit log
    // is a separate file and stays writable, so the append can succeed and the
    // save cannot.
    chmod(&path, 0o400);
    chmod(dir.path(), 0o500);

    let err = s
        .secret_set("human", "acme", "K", b"rejected")
        .expect_err("the save must fail, so the mutation must not be reported as applied");
    assert_eq!(
        err.code(),
        "E_IO",
        "the failure is the vault write, got {err}"
    );

    chmod(dir.path(), 0o700);
    chmod(&path, 0o600);

    // The previous vault — and therefore its checkpoint — is intact.
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before_vault,
        "the stored vault must be byte-identical when the save failed"
    );
    // The log is ahead of the checkpoint: exactly one unconfirmed entry.
    let after_log = std::fs::read_to_string(audit(&dir)).unwrap();
    let added = after_log.lines().count() - before_log.lines().count();
    assert_eq!(
        added, 1,
        "exactly one orphan entry must exist beyond the checkpoint"
    );
    assert!(
        after_log.starts_with(&before_log),
        "the existing history must be untouched"
    );

    // And the vault still opens: an entry with no vault is harmless.
    drop(s);
    let mut reopened = Session::load(&path, IDLE, Box::new(SystemClock)).unwrap();
    reopened
        .unlock(PASS)
        .expect("an uncommitted orphan entry must not break unlock");
    let doc = reopened.document().unwrap();
    assert_eq!(
        doc.audit_head, before_head,
        "the checkpoint must still name the last committed mutation"
    );
    // The uncommitted change is not visible in the vault.
    let project_id = doc.project_by_name("acme").unwrap().id.clone();
    assert_eq!(
        doc.secret(&project_id, "K").unwrap().value.0.to_vec(),
        b"v".to_vec(),
        "the value from the failed save must not appear"
    );
    reopened.audit_verify().expect("audit must still verify");
}

/// The same class of defect on the way in: once `do_unlock` has succeeded the
/// vault is open in memory, so a full log must not turn that into a reported
/// failure; and an unwritable log must not replace `E_AUTH` with an audit
/// error (which would both mask the real result and become an oracle).
#[test]
fn unlock_at_the_hard_cap_reports_the_real_result() {
    let (_dir, mut s) = session("unlock-hardcap");
    s.set_audit_limits_for_test(1, 1);

    // Wrong passphrase: the answer is E_AUTH, not an audit failure.
    assert_eq!(
        s.unlock(b"wrong horse battery")
            .expect_err("bad passphrase")
            .code(),
        "E_AUTH",
        "an unwritable audit log must not mask the authentication result"
    );

    // Correct passphrase on a locked session: unlock must still succeed.
    s.lock_persist().expect("locking is unaffected");
    assert!(s.is_locked());
    s.unlock(PASS)
        .expect("a full audit log must not block unlocking");
    assert!(!s.is_locked(), "the vault must actually be open");
    assert!(s.document().is_some(), "the document must be available");
}

// ---------------------------------------------------------------------------
// 3. Headroom: lifecycle may spend it, ordinary operations may not
// ---------------------------------------------------------------------------

/// With the log at the soft limit, ordinary mutations are refused while a
/// lifecycle event still records — the reserve is what keeps the lock alive.
#[test]
fn the_soft_limit_reserves_headroom_for_lifecycle_events() {
    // Compile-time invariants: the reserve sits inside the hard cap.
    const {
        assert!(svault::audit::AUDIT_SOFT_LIMIT < MAX_AUDIT_LEN);
        assert!(svault::audit::AUDIT_SOFT_LIMIT + svault::audit::AUDIT_HEADROOM == MAX_AUDIT_LEN);
    }

    let (dir, mut s) = session("headroom");
    let _ = fill_to_soft_limit(&mut s);
    let len_at_soft = std::fs::metadata(audit(&dir)).unwrap().len();

    // Lifecycle still works and writes past the soft limit, within the cap.
    s.lock_persist().expect("lifecycle may spend the reserve");
    assert!(s.is_locked());
    let len_after = std::fs::metadata(audit(&dir)).unwrap().len();
    assert!(
        len_after <= TEST_HARD,
        "the hard cap must still bound the log: {len_after} > {TEST_HARD}"
    );
    let _ = len_at_soft;
}

/// The hard cap bounds everything, including lifecycle events.
#[test]
fn nothing_grows_the_log_past_the_hard_cap() {
    let (dir, mut s) = session("hard-cap");
    s.set_audit_limits_for_test(1, 1);
    for i in 0..50 {
        let _ = s.secret_set("human", "acme", "K", format!("v{i}").as_bytes());
        let _ = s.lock_persist();
        if i % 10 == 0 {
            let _ = s.unlock(PASS);
        }
    }
    let len = std::fs::metadata(audit(&dir)).unwrap().len();
    assert!(
        len <= TEST_HARD,
        "the hard cap must bound total growth, got {len} > {TEST_HARD}"
    );
}

// ---------------------------------------------------------------------------
// 4. Healthy logs are unaffected
// ---------------------------------------------------------------------------

/// Production ceilings are untouched by any of this: normal use never sees
/// `E_AUDIT_FULL`.
#[test]
fn healthy_logs_are_unaffected() {
    let dir = Dir::new("healthy");
    let path = vault(&dir);
    let mut s = Session::create(&path, PASS, IDLE, Box::new(SystemClock)).unwrap();
    s.project_add("human", "acme", &[]).unwrap();
    for i in 0..60 {
        s.secret_set("human", "acme", "K", format!("v{i}").as_bytes())
            .expect("normal mutations must keep working");
    }
    s.lock_persist().expect("normal lock must keep working");
    drop(s);

    let mut reopened = Session::load(&path, IDLE, Box::new(SystemClock)).unwrap();
    reopened.unlock(PASS).unwrap();
    let report = reopened.audit_verify().unwrap();
    assert!(report.macs_verified > 0, "{report:?}");

    // The production headroom is a sane fraction of the cap.
    const {
        assert!(MAX_AUDIT_LEN >= 1024 * 1024);
        assert!(svault::audit::AUDIT_HEADROOM < MAX_AUDIT_LEN / 2);
    }
}

/// A crash *between* the append and the vault save must not strand the vault:
/// the entry is an orphan beyond the checkpoint, which is harmless.
#[test]
fn an_orphan_audit_entry_never_breaks_unlock() {
    let dir = Dir::new("orphan");
    let path = vault(&dir);
    {
        let mut s = Session::create(&path, PASS, IDLE, Box::new(SystemClock)).unwrap();
        s.project_add("human", "acme", &[]).unwrap();
        s.secret_set("human", "acme", "K", b"v").unwrap();
    }
    // Simulate the ordering the fix guarantees: the audit log is *ahead* of
    // the vault checkpoint. Unlock must still succeed — extra trailing entries
    // are legitimate (they are how reads and denials are recorded too).
    let audit_path = audit(&dir);
    let mut bytes = std::fs::read_to_string(&audit_path).unwrap();
    bytes.push('\n');
    std::fs::write(&audit_path, bytes).unwrap();

    let mut s = Session::load(&path, IDLE, Box::new(SystemClock)).unwrap();
    s.unlock(PASS)
        .expect("trailing audit entries beyond the checkpoint must not break unlock");
}
