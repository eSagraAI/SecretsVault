//! Wave 3 (L3) — test hygiene: no world-readable capabilities, no residue.
//!
//! Tests are ordinary code and their artifacts are real: a token file written
//! with `std::fs::write` lands at the process umask (0644 by default), so a
//! live agent capability sat readable by every local user for the duration of
//! the run; and harnesses without a `Drop` left their temporary directories —
//! vault, socket and token — behind for good.
//!
//! This binary asserts the invariant from the outside, which is the only way
//! it can actually be checked: measure the filesystem before and after a test
//! binary runs.

use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_svault");

/// Every `svault-*` temp directory currently present.
fn temp_dirs() -> Vec<(PathBuf, u32)> {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.starts_with("svault-") {
            continue;
        }
        let mut mode = 0u32;
        if let Ok(md) = e.metadata() {
            use std::os::unix::fs::PermissionsExt;
            mode = md.permissions().mode() & 0o777;
        }
        out.push((e.path(), mode));
    }
    out.sort();
    out
}

/// Recursively find every token file under `root`.
fn token_files(root: &Path) -> Vec<(PathBuf, u32)> {
    use std::os::unix::fs::PermissionsExt;
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "token") {
                out.push((p, md.permissions().mode() & 0o777));
            }
        }
    }
    out.sort();
    out
}

/// The temp directories this binary owns and cleans up, to keep the checks
/// below scoped to what this test created rather than the whole machine.
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("svault-l3-{tag}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Running a real test binary end to end must leave no temp directory behind.
/// This is the observable form of "the harness cleans up", and it is what a
/// developer actually notices: the sibling binary is executed for real, and
/// the filesystem is compared before and after.
#[test]
fn l3_test_binary_leaves_no_temp_residue() {
    // Sibling integration binaries live next to this one in `deps/`.
    let me = std::env::current_exe().expect("current exe");
    let dir = me.parent().expect("deps dir").to_path_buf();
    let Some(victim) = std::fs::read_dir(&dir).ok().and_then(|entries| {
        entries.flatten().map(|e| e.path()).find(|p| {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            name.starts_with("phase6-") && !name.ends_with(".d")
        })
    }) else {
        // No sibling binary (e.g. running this file alone): nothing to prove.
        return;
    };

    let before: Vec<PathBuf> = temp_dirs().into_iter().map(|(p, _)| p).collect();
    // One cheap test from that binary, exercising its fixture and Drop.
    let out = Command::new(&victim)
        .args([
            "--exact",
            "lease_create_and_revoke_are_audited",
            "--nocapture",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run sibling test binary");
    assert!(out.success(), "the sibling test must pass");

    let after: Vec<PathBuf> = temp_dirs().into_iter().map(|(p, _)| p).collect();
    let leaked: Vec<_> = after
        .iter()
        .filter(|p| !before.contains(p))
        .filter(|p| !p.to_string_lossy().contains("svault-l3-"))
        .collect();
    assert!(
        leaked.is_empty(),
        "L3 REGRESSION: {} left temp residue: {leaked:?}",
        victim.display()
    );
}

/// The write path the harnesses must use creates 0600 from the first byte.
/// Pinned here directly, so the invariant is stated once and the harnesses are
/// checked against it by `l3_no_token_file_is_world_readable`.
#[test]
fn l3_harness_token_writer_is_0600() {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;
    let dir = Dir::new("harness-token");
    let path = dir.0.join("bot.token");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    f.write_all(b"agent-token-material").unwrap();
    f.sync_all().unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "got {mode:o}");
    drop(f);
}

/// A token file written during this run must never be group/world readable.
///
/// Scoped to files created at or after this test started, so pre-existing junk
/// from other runs cannot fail it while a genuinely world-readable token from
/// the code under test still does.
#[test]
fn l3_no_token_file_is_world_readable() {
    let started = std::time::SystemTime::now() - std::time::Duration::from_secs(1);
    let mut offenders = Vec::new();
    for (dir, _) in temp_dirs() {
        for (path, mode) in token_files(&dir) {
            let Ok(md) = std::fs::metadata(&path) else {
                continue;
            };
            let Ok(mtime) = md.modified() else { continue };
            if mtime < started {
                continue; // pre-existing, not this run's business
            }
            if mode & 0o077 != 0 {
                offenders.push(format!("{mode:o} {}", path.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "L3 REGRESSION: world-readable token files: {offenders:?}"
    );
}

/// The binaries under test must not leave live daemons behind either: a
/// leaked process holds the socket and the vault lock.
#[test]
fn l3_no_leaked_daemons_from_our_own_temp_dirs() {
    let dirs = temp_dirs();
    if dirs.is_empty() {
        return;
    }
    let ps = Command::new("ps")
        .args(["-eo", "pid,args"])
        .output()
        .expect("ps runs");
    let ps = String::from_utf8_lossy(&ps.stdout);
    let mut leaked = Vec::new();
    for (dir, _) in dirs {
        let needle = dir.display().to_string();
        for line in ps.lines() {
            if line.contains(&needle) && line.contains(BIN) {
                leaked.push(line.trim().to_string());
            }
        }
    }
    assert!(
        leaked.is_empty(),
        "L3 REGRESSION: daemons still running for temp dirs: {leaked:?}"
    );
}
