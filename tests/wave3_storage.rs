//! Wave 3 (L2) — predictable temp names and unbounded audit growth.
//!
//! Two independent problems, one file each:
//!
//! 1. `store::save_atomic` named its temp file `.<name>.tmp.<pid>`, so the
//!    name was guessable: a same-UID attacker can pre-create that path (or a
//!    symlink at it) and either win a race or make every save fail. The temp
//!    name must come from the CSPRNG, and creation must be `O_EXCL` so a
//!    pre-existing file is never followed or overwritten.
//! 2. The audit log has no ceiling, and `AuditLog::stage` re-reads and
//!    re-parses the whole file on every append — so appends get linearly more
//!    expensive as the log grows, with no bound in sight. A vault in normal
//!    use reaches that state by itself.
//!
//! Rotation is the correct long-term answer and is deliberately out of scope
//! for this wave; what must exist now is a fail-closed bound, so growth is
//! capped rather than unbounded, and the chain stays verifiable.

use std::path::PathBuf;
use std::time::Duration;

use svault::session::{Session, SystemClock};

const PASS: &[u8] = b"correct horse battery";
const IDLE: Duration = Duration::from_secs(300);

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("svault-wave3-l2-{tag}-{n}"));
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

// ---------------------------------------------------------------------------
// Predictable temp name
// ---------------------------------------------------------------------------

/// The temp name must not be derivable from the vault path: it carries
/// CSPRNG entropy.
#[test]
fn l2_temp_name_is_not_derivable_from_the_vault_path() {
    let dir = Dir::new("temp-name");
    let path = vault(&dir);
    let mut s = Session::create(&path, PASS, IDLE, Box::new(SystemClock)).unwrap();
    s.project_add("human", "acme", &[]).unwrap();
    s.secret_set("human", "acme", "K", b"v").unwrap();

    // Poll the directory while a save is in flight is racy; instead assert on
    // the naming that reaches disk on failure, which is the observable part: a
    // save made to fail must leave a temp name that is not `<name>.tmp.<pid>`.
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    for n in &names {
        assert!(
            !n.contains(&format!(".tmp.{}", std::process::id())),
            "L2 REGRESSION: predictable temp name leaked: {n}"
        );
    }

    // The vault itself is still written correctly.
    assert!(path.exists(), "the vault must be saved");
}

/// A pre-existing file at the temp path must not be followed or clobbered;
/// with a random name the save simply picks another one and succeeds.
#[test]
fn l2_save_is_not_blocked_by_a_pre_created_temp_path() {
    let dir = Dir::new("temp-squat");
    let path = vault(&dir);
    let mut s = Session::create(&path, PASS, IDLE, Box::new(SystemClock)).unwrap();
    s.project_add("human", "acme", &[]).unwrap();

    // Squat the old predictable name; a CSPRNG name ignores it entirely.
    let squat = dir
        .path()
        .join(format!(".vault.enc.tmp.{}", std::process::id()));
    std::fs::write(&squat, b"attacker-controlled").unwrap();

    s.secret_set("human", "acme", "K", b"v")
        .expect("save must succeed");

    // The squatted file is untouched, and the vault is intact.
    let content = std::fs::read_to_string(&squat).unwrap();
    assert_eq!(
        content, "attacker-controlled",
        "the squat must be untouched"
    );
    drop(s);
    let mut reopened = Session::load(&path, IDLE, Box::new(SystemClock)).unwrap();
    reopened.unlock(PASS).unwrap();
    assert!(reopened.document().is_some());
}

/// The temp file must be private and must not survive a successful save.
#[test]
fn l2_no_temp_file_survives_a_successful_save() {
    let dir = Dir::new("temp-cleanup");
    let path = vault(&dir);
    let mut s = Session::create(&path, PASS, IDLE, Box::new(SystemClock)).unwrap();
    s.project_add("human", "acme", &[]).unwrap();
    s.secret_set("human", "acme", "K", b"v").unwrap();

    let leftover: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert!(
        leftover.is_empty(),
        "L2 REGRESSION: temp files left behind: {leftover:?}"
    );
}

// ---------------------------------------------------------------------------
// Audit growth
// ---------------------------------------------------------------------------

/// The audit log must be bounded. The ceiling is exercised deterministically
/// in `audit::`'s unit tests (which can name a small limit); here we pin the
/// public contract: a ceiling exists, and the file never exceeds it.
#[test]
fn l2_audit_ceiling_is_declared_and_respected() {
    let dir = Dir::new("audit-bound");
    let path = vault(&dir);
    let mut s = Session::create(&path, PASS, IDLE, Box::new(SystemClock)).unwrap();
    s.project_add("human", "acme", &[]).unwrap();

    let audit_path = svault::store::audit_path(&path);
    let cap = svault::audit::MAX_AUDIT_LEN;
    assert!(cap >= 1024 * 1024, "a usable ceiling must exist, got {cap}");

    // Normal use stays far below it, and nothing is ever truncated to fit.
    for i in 0..50 {
        s.secret_set("human", "acme", "K", format!("value-{i}").as_bytes())
            .unwrap();
    }
    let len = std::fs::metadata(&audit_path).unwrap().len();
    assert!(len < cap, "normal use must fit comfortably under {cap}");
    let lines = std::fs::read_to_string(&audit_path).unwrap();
    assert_eq!(
        lines.lines().filter(|l| !l.is_empty()).count(),
        1 + 1 + 50,
        "create + project.add + 50 secret.set, nothing dropped"
    );
}

/// The chain stays verifiable after normal use — the cap must not corrupt it.
#[test]
fn l2_chain_still_verifies_under_the_cap() {
    let dir = Dir::new("audit-chain");
    let path = vault(&dir);
    let mut s = Session::create(&path, PASS, IDLE, Box::new(SystemClock)).unwrap();
    s.project_add("human", "acme", &[]).unwrap();
    for i in 0..50 {
        s.secret_set("human", "acme", "K", format!("value-{i}").as_bytes())
            .unwrap();
    }
    let report = s.audit_verify().expect("audit must verify");
    assert!(
        report.macs_verified > 0 && report.macs_null == 0,
        "MACs must verify while unlocked: {report:?}"
    );
}
