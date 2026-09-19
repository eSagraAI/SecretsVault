//! Wave 3 (L1) — terminal leases and approvals must not occupy the caps
//! forever.
//!
//! `MAX_LEASES` / `MAX_APPROVALS` bound a security-relevant collection, but a
//! revoked, expired, consumed or denied entry is inert: it authorizes nothing.
//! Because nothing ever removed them, a long-lived vault filled up with dead
//! entries and then refused *new* leases and approvals — a self-inflicted
//! denial of service, and one an agent can trigger deliberately (mint, let
//! expire, repeat).
//!
//! The GC must be safe as well as effective: capabilities are identified by a
//! digest (never the credential), removal must not resurrect anything, and
//! history stays in the audit log rather than in the live document.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use svault::model::{MAX_LEASES, Op, VaultDocument};
use svault::session::{Clock, Session};

const PASS: &[u8] = b"correct horse battery";

/// Unique tempdir, removed on drop (panics included).
struct Dir(PathBuf);

impl Dir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }

    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("svault-wave3-gc-{tag}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Clock the test drives by hand, so windows are tested without sleeping.
/// Lease/approval windows are wall-clock based, so both clocks advance
/// together.
#[derive(Clone)]
struct FakeClock {
    monotonic_start: std::time::Instant,
    wall_start: time::OffsetDateTime,
    secs: Arc<AtomicU64>,
}

impl FakeClock {
    fn new() -> Self {
        Self {
            monotonic_start: std::time::Instant::now(),
            wall_start: time::OffsetDateTime::now_utc(),
            secs: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Clock for FakeClock {
    fn now(&self) -> std::time::Instant {
        self.monotonic_start + Duration::from_secs(self.secs.load(Ordering::Relaxed))
    }

    fn wall_now(&self) -> time::OffsetDateTime {
        self.wall_start + time::Duration::seconds(self.secs.load(Ordering::Relaxed) as i64)
    }
}

/// Advance the shared clock by `d`.
fn advance(clock: &FakeClock, d: Duration) {
    clock.secs.fetch_add(d.as_secs(), Ordering::Relaxed);
}

struct Fixture {
    _dir: Dir,
    session: Session,
    clock: FakeClock,
    /// The derived agent id, which is what the lease/approval APIs take.
    agent: String,
}

fn setup(tag: &str) -> Fixture {
    let dir = Dir::new(tag);
    let clock = FakeClock::new();
    let mut session = Session::create(
        &dir.path().join("vault.enc"),
        PASS,
        Duration::from_secs(3600),
        Box::new(clock.clone()),
    )
    .unwrap();
    session.unlock(PASS).unwrap();
    session.project_add("human", "acme", &[]).unwrap();
    session.secret_set("human", "acme", "K", b"v").unwrap();
    let (agent_id, _token) = session.agent_add("human", "bot").unwrap();
    session
        .grant_add("human", "bot", "acme", &[Op::Read, Op::Reveal])
        .unwrap();
    Fixture {
        _dir: dir,
        session,
        clock,
        agent: agent_id,
    }
}

fn lease_count(s: &Session) -> usize {
    s.document()
        .map(|d: &VaultDocument| d.leases.len())
        .unwrap_or(0)
}

fn approval_count(s: &Session) -> usize {
    s.document()
        .map(|d: &VaultDocument| d.approvals.len())
        .unwrap_or(0)
}

/// Expired leases must be collected, so the cap cannot be filled by dead
/// entries.
#[test]
fn l1_expired_leases_are_collected() {
    let mut f = setup("x");
    // Fill a chunk of the cap with short-lived leases.
    for _ in 0..64 {
        f.session
            .lease_create("agent:bot", &f.agent, "acme", &[Op::Read], 60)
            .unwrap();
    }
    assert_eq!(lease_count(&f.session), 64, "leases were minted");

    // Past every one of those windows.
    advance(&f.clock, Duration::from_secs(61));
    let removed = f.session.gc_terminal_credentials();
    assert!(removed.leases >= 64, "expired leases must be collected");
    assert_eq!(
        lease_count(&f.session),
        0,
        "no expired lease may remain in the live document"
    );
}

/// Revoked leases must be collected too: they are inert by construction.
#[test]
fn l1_revoked_leases_are_collected() {
    let mut f = setup("x");
    let (lease, _cred) = f
        .session
        .lease_create("agent:bot", &f.agent, "acme", &[Op::Read], 3600)
        .unwrap();
    f.session
        .lease_revoke("agent:bot", Some(&f.agent), &lease.id)
        .unwrap();
    assert_eq!(lease_count(&f.session), 1, "revoked lease still stored");

    let removed = f.session.gc_terminal_credentials();
    assert!(removed.leases >= 1, "revoked leases must be collected");
    assert_eq!(lease_count(&f.session), 0);
}

/// Active leases must survive — the GC is not a blanket wipe.
#[test]
fn l1_active_leases_survive_gc() {
    let mut f = setup("x");
    let (live, cred) = f
        .session
        .lease_create("agent:bot", &f.agent, "acme", &[Op::Read], 3600)
        .unwrap();

    let removed = f.session.gc_terminal_credentials();
    assert_eq!(removed.leases, 0, "an active lease must not be collected");
    assert_eq!(lease_count(&f.session), 1);

    // And it still authorizes after the sweep.
    let actor = f
        .session
        .authorize_lease(&f.agent, "acme", Op::Read, Some(&cred))
        .expect("the surviving lease must still authorize");
    assert_eq!(actor, format!("lease:{}", live.id));
}

/// Consumed approvals must be collected; the single-use guarantee lives in the
/// audit trail, not in the live collection.
#[test]
fn l1_consumed_approvals_are_collected() {
    let mut f = setup("x");
    let pending = f
        .session
        .approval_request("agent:bot", &f.agent, "acme", "K")
        .unwrap();
    f.session
        .approval_decide("human", &pending.id, true)
        .unwrap();
    f.session
        .reveal_claim("agent:bot", &f.agent, "acme", "K", &pending.id)
        .unwrap();
    assert_eq!(approval_count(&f.session), 1, "consumed approval stored");

    let removed = f.session.gc_terminal_credentials();
    assert!(
        removed.approvals >= 1,
        "consumed approvals must be collected"
    );
    assert_eq!(approval_count(&f.session), 0);
}

/// Expired pending approvals must be collected.
#[test]
fn l1_expired_approvals_are_collected() {
    let mut f = setup("x");
    f.session
        .approval_request("agent:bot", &f.agent, "acme", "K")
        .unwrap();
    // Past the pending window.
    advance(&f.clock, Duration::from_secs(3600));
    let removed = f.session.gc_terminal_credentials();
    assert!(
        removed.approvals >= 1,
        "expired approvals must be collected"
    );
    assert_eq!(approval_count(&f.session), 0);
}

/// Denied approvals must be collected.
#[test]
fn l1_denied_approvals_are_collected() {
    let mut f = setup("x");
    let pending = f
        .session
        .approval_request("agent:bot", &f.agent, "acme", "K")
        .unwrap();
    f.session
        .approval_decide("human", &pending.id, false)
        .unwrap();
    let removed = f.session.gc_terminal_credentials();
    assert!(removed.approvals >= 1, "denied approvals must be collected");
    assert_eq!(approval_count(&f.session), 0);
}

/// A pending approval must survive: it is still live state.
#[test]
fn l1_live_approvals_survive_gc() {
    let mut f = setup("x");
    let pending = f
        .session
        .approval_request("agent:bot", &f.agent, "acme", "K")
        .unwrap();
    let removed = f.session.gc_terminal_credentials();
    assert_eq!(removed.approvals, 0, "a pending approval must not be swept");
    assert_eq!(approval_count(&f.session), 1);

    // Still usable end to end.
    f.session
        .approval_decide("human", &pending.id, true)
        .unwrap();
    let claimed = f
        .session
        .reveal_claim("agent:bot", &f.agent, "acme", "K", &pending.id)
        .unwrap();
    assert_eq!(claimed.as_slice(), b"v");
}

/// The cap must bound *live* credentials, not an ever-growing junk pile: with
/// the collection full of expired leases, issuing a new one must succeed — the
/// cap check reclaims before refusing, with no explicit GC call.
#[test]
fn l1_cap_reclaims_inert_rows_before_refusing() {
    let mut f = setup("cap-usable");
    // Fill the cap with leases that will expire.
    for _ in 0..MAX_LEASES {
        f.session
            .lease_create("agent:bot", &f.agent, "acme", &[Op::Read], 30)
            .unwrap();
    }
    // At the cap with everything still live: a further lease is refused.
    let refused = f
        .session
        .lease_create("agent:bot", &f.agent, "acme", &[Op::Read], 30)
        .expect_err("a full collection of live leases must refuse");
    assert_eq!(
        refused.code(),
        "E_INVALID_INPUT",
        "expected the cap refusal, got {refused}"
    );

    // Expire them all; the next create must reclaim and succeed.
    advance(&f.clock, Duration::from_secs(31));
    f.session
        .lease_create("agent:bot", &f.agent, "acme", &[Op::Read], 3600)
        .expect("expired leases must be reclaimed so the cap stays usable");

    // Only the fresh, live lease remains.
    assert_eq!(
        lease_count(&f.session),
        1,
        "the whole expired generation must be gone"
    );
}
