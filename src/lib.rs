//! Core library of `svault`: crypto, vault envelope, session, store and CLI.
//!
//! Behavior contracts live in `docs/` (protocol, architecture, threat model).

pub mod audit;
pub mod broker;
pub mod broker_identity;
pub mod cli;
pub mod client;
pub mod crypto;
pub mod dotenv;
pub mod envelope;
pub mod error;
pub mod fdpass;
pub mod fsops;
pub mod ipc;
pub mod mcp;
pub mod model;
pub mod run;
pub mod session;
pub mod store;
pub mod wire;

pub use error::VaultError;

/// Test-only helpers shared by unit tests across modules.
#[cfg(test)]
pub(crate) mod testutil {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Unique temporary directory, removed on drop (including panics).
    pub struct TestDir(PathBuf);

    impl TestDir {
        pub fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("svault-test-{}-{}", std::process::id(), n));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
