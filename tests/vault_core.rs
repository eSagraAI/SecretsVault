//! Vault lifecycle integration tests: full lifecycle through the public API.
//! Contract: `docs/architecture.md`, `docs/threat-model.md`.

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use svault::VaultError;
use svault::session::{Clock, Session, VaultDocument};

struct TestDir(std::path::PathBuf);

impl TestDir {
    fn new() -> Self {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("svault-it-{}-{}", std::process::id(), n));
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
struct FakeClock(Arc<Mutex<Instant>>);

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }
}

const PASS: &[u8] = b"correct horse battery";
const IDLE: Duration = Duration::from_secs(60);

fn clock() -> FakeClock {
    FakeClock(Arc::new(Mutex::new(Instant::now())))
}

#[test]
fn full_lifecycle_create_lock_unlock_save_reload() {
    let dir = TestDir::new();
    let path = dir.path().join("vault.enc");

    let created = Session::create(&path, PASS, IDLE, Box::new(clock())).unwrap();
    let created_doc = created.document().cloned().unwrap();
    // H2: one mutable owner at a time — release before reopening.
    drop(created);
    // The vault file lands with private permissions.
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    // A fresh load is locked (spec: create → status reports locked).
    let mut s = Session::load(&path, IDLE, Box::new(clock())).unwrap();
    assert!(s.status().locked);
    assert!(matches!(s.require_keys(), Err(VaultError::Locked)));

    // Unlock, re-seal, persist.
    s.unlock(PASS).unwrap();
    assert!(!s.status().locked);
    s.save().unwrap();

    drop(s);
    // Reload and verify the document survived a full seal cycle.
    let mut s2 = Session::load(&path, IDLE, Box::new(clock())).unwrap();
    s2.unlock(PASS).unwrap();
    let doc: &VaultDocument = s2.document().unwrap();
    assert_eq!(doc, &created_doc);
    assert_eq!(doc.v, 1);
}

#[test]
fn on_disk_tampering_fails_closed() {
    let dir = TestDir::new();
    let path = dir.path().join("vault.enc");
    Session::create(&path, PASS, IDLE, Box::new(clock())).unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&path, &bytes).unwrap();

    let mut s = Session::load(&path, IDLE, Box::new(clock())).unwrap();
    // The document seal includes the header as AAD; a flipped document byte
    // must fail closed (never return plaintext).
    assert!(matches!(s.unlock(PASS), Err(VaultError::Corrupt(_))));
}

#[test]
fn wrong_passphrase_on_persisted_vault_is_generic_auth() {
    let dir = TestDir::new();
    let path = dir.path().join("vault.enc");
    Session::create(&path, PASS, IDLE, Box::new(clock())).unwrap();

    let mut s = Session::load(&path, IDLE, Box::new(clock())).unwrap();
    let e1 = s.unlock(b"one wrong guess").unwrap_err();
    let e2 = s.unlock(b"another wrong guess").unwrap_err();
    assert!(matches!(e1, VaultError::Auth));
    assert_eq!(e1.to_string(), e2.to_string());
}
