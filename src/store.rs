//! Vault file storage: XDG paths and atomic persistence
//! (temp file + fsync + rename), mode 0600.
//!
//! The rename is the commit point: a failed write never damages the
//! previously stored file. The parent-directory fsync afterwards is
//! best-effort durability and never changes the success/failure of the
//! visible file state.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::VaultError;

/// `$XDG_DATA_HOME/svault/vault.enc` (fallback `$HOME/.local/share/...`).
pub fn default_vault_path() -> Result<PathBuf, VaultError> {
    let base = match std::env::var("XDG_DATA_HOME") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => {
            let home = std::env::var("HOME")
                .map_err(|_| VaultError::Io(std::io::Error::other("HOME not set")))?;
            PathBuf::from(home).join(".local/share")
        }
    };
    Ok(base.join("svault").join("vault.enc"))
}

/// `$XDG_DATA_HOME/svault/audit.jsonl` — next to the vault file.
pub fn audit_path(vault_path: &Path) -> PathBuf {
    vault_path.with_file_name("audit.jsonl")
}

/// Atomically write `bytes` to `path`: temp file in the same directory
/// (mode 0600), fsync, rename over the target.
///
/// The temp name carries 16 bytes of CSPRNG entropy and is created `O_EXCL`.
/// A predictable name (`.<name>.tmp.<pid>`) let a same-UID attacker pre-create
/// the path — or a symlink at it — either winning the race or making every
/// save fail; `create_new` refuses to follow or reuse whatever is there, and
/// the random name simply retries elsewhere.
pub fn save_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let dir = path
        .parent()
        .ok_or_else(|| VaultError::Io(std::io::Error::other("vault path has no parent")))?;
    let name = path
        .file_name()
        .ok_or_else(|| VaultError::Io(std::io::Error::other("vault path has no file name")))?;

    // Bounded attempts: a collision is already vanishingly unlikely, and an
    // attacker who can fill the directory can deny the save regardless.
    let mut last: Option<std::io::Error> = None;
    for _ in 0..8 {
        let tag = crate::crypto::hex(&crate::crypto::random_bytes::<16>()?);
        let tmp = dir.join(format!(".{}.tmp.{tag}", name.to_string_lossy()));
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp);
        let file = match opened {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last = Some(e);
                continue;
            }
            Err(e) => return Err(VaultError::Io(e)),
        };
        // From here the temp file exists and is ours: any failure removes it.
        let result = (|| -> std::io::Result<()> {
            let mut f = file;
            f.write_all(bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)?;
            // Best-effort directory fsync for durability; the rename has
            // already committed the new content, so its failure is not
            // reported as a failed save.
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
            Ok(())
        })();
        return match result {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(VaultError::Io(e))
            }
        };
    }
    Err(VaultError::Io(last.unwrap_or_else(|| {
        std::io::Error::other("could not create a temporary file")
    })))
}

pub fn load(path: &Path) -> Result<Vec<u8>, VaultError> {
    Ok(std::fs::read(path)?)
}

/// Create `path` (all missing components) with mode 0700 on the final dir.
pub fn ensure_private_dir(path: &Path) -> Result<(), VaultError> {
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestDir;

    #[test]
    fn save_sets_mode_0600_and_roundtrips() {
        let dir = TestDir::new();
        let path = dir.path().join("vault.enc");
        save_atomic(&path, b"one").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(load(&path).unwrap(), b"one");
        save_atomic(&path, b"two").unwrap();
        assert_eq!(load(&path).unwrap(), b"two");
    }

    #[test]
    fn failed_save_preserves_previous_file() {
        let dir = TestDir::new();
        let path = dir.path().join("vault.enc");
        save_atomic(&path, b"precious").unwrap();

        // Make the directory read-only so creating the temp file fails.
        let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(dir.path(), perms).unwrap();

        let result = save_atomic(&path, b"doomed");
        assert!(result.is_err());

        let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(dir.path(), perms).unwrap();

        assert_eq!(load(&path).unwrap(), b"precious");
    }

    /// L2: the temp name must carry CSPRNG entropy, so it cannot be derived
    /// from the vault path — an attacker who can guess it can pre-create the
    /// path (or plant a symlink there) and either win the race or wedge saves.
    #[test]
    fn temp_name_is_unpredictable_and_never_left_behind() {
        let dir = TestDir::new();
        let path = dir.path().join("vault.enc");
        save_atomic(&path, b"one").unwrap();

        // A pre-created file at the OLD predictable name must not block or
        // corrupt the save.
        let squat = dir
            .path()
            .join(format!(".vault.enc.tmp.{}", std::process::id()));
        std::fs::write(&squat, b"squatter").unwrap();
        save_atomic(&path, b"two").unwrap();
        assert_eq!(load(&path).unwrap(), b"two", "the save must still land");
        assert_eq!(
            std::fs::read(&squat).unwrap(),
            b"squatter",
            "the squatted path must be untouched"
        );

        // No temp file survives a successful save.
        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .filter(|n| n != &format!(".vault.enc.tmp.{}", std::process::id()))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp file may survive a successful save: {leftovers:?}"
        );
    }

    #[test]
    fn ensure_private_dir_creates_0700() {
        let dir = TestDir::new();
        let nested = dir.path().join("a/b/c");
        ensure_private_dir(&nested).unwrap();
        let meta = std::fs::metadata(&nested).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }
}
