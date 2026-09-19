//! Local-IPC trust anchors: single-instance locking and positive server
//! identification for the broker socket, plus process hardening.
//!
//! Why this exists: on a Unix socket, filesystem permissions prove nothing
//! about **who answers**. A same-UID process can `unlink` a live broker's
//! socket and bind its own listener at the same path (or bind it while no
//! broker runs), which made the human proof (the vault passphrase) reachable
//! by an impostor.
//!
//! Two kernel-attested facts close that gap:
//!
//! 1. **Single instance.** The broker takes an exclusive `flock(2)` on
//!    `<socket>.lock` for its whole lifetime. A second broker fails
//!    (`E_BUSY`) instead of silently replacing the first, and the lock is
//!    released by the kernel if the broker dies, so a stale socket can never
//!    be mistaken for a live one.
//! 2. **Positive server identification.** Before a client sends any request,
//!    it checks that the process the kernel says is on the other end
//!    (`SO_PEERCRED`) is the process holding that lock. A rogue listener that
//!    hijacked the path is not the lock holder, so the client refuses to send
//!    credentials.
//!
//! These two checks authenticate *lock ownership*, never *what the peer is*:
//! while the legitimate daemon is down any same-UID process can take the free
//! lock and bind the socket path (N1). They stay as cheap defense in depth;
//! the Ed25519 broker-identity handshake ([`crate::broker_identity`]) is the
//! authority the client trusts before writing credentials.
//!
//! Residual (documented in `docs/threat-model.md`): a same-UID attacker who
//! can read the broker identity private key (`<vault>.broker-id`, mode 0600
//! but owned by the same UID) can forge handshake proofs and is NOT stopped.
//! The guarantee is bounded by filesystem permissions the adversary shares
//! with the owner.

use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use crate::error::VaultError;

/// `<socket>.lock`, next to the socket (same 0700 directory, mode 0600).
pub fn instance_lock_path(socket: &Path) -> PathBuf {
    let name = socket
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "svault.sock".to_string());
    socket.with_file_name(format!("{name}.lock"))
}

/// `<vault>.lock`, next to the vault file (H2).
///
/// Two *mutable owners* of one vault silently lose writes: each holds its own
/// in-memory document, so whichever saves second overwrites the other's
/// committed change. The lock is per-vault, not per-socket, because the
/// danger is the file, not the transport — a second daemon on a different
/// socket races just as hard as a second in-process session.
pub fn vault_lock_path(vault: &Path) -> PathBuf {
    let name = vault
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault.enc".to_string());
    vault.with_file_name(format!("{name}.lock"))
}

/// Exclusive broker instance lock, held for the daemon's lifetime.
///
/// The file itself carries no data: the lock is the state. Closing (or
/// process death) releases it, so recovery after a crash needs no cleanup and
/// a stale socket file can be told apart from a live listener.
pub struct InstanceLock {
    file: std::fs::File,
    path: PathBuf,
}

impl InstanceLock {
    /// Take the instance lock for `socket`, or fail closed.
    ///
    /// `EWOULDBLOCK` means another process already serves this socket: the
    /// caller must refuse to start rather than unlink and replace it.
    pub fn acquire(socket: &Path) -> Result<Self, VaultError> {
        Self::acquire_file(&instance_lock_path(socket))
    }

    /// Take the exclusive lock on `vault` (H2): only one mutable owner at a
    /// time. Same fail-closed contract as the socket lock, and the same
    /// recovery property — the kernel releases it when the owner dies, so a
    /// crash never leaves the vault permanently unopenable.
    pub fn acquire_vault(vault: &Path) -> Result<Self, VaultError> {
        Self::acquire_file(&vault_lock_path(vault))
    }

    fn acquire_file(path: &Path) -> Result<Self, VaultError> {
        if let Some(parent) = path.parent()
            && parent != Path::new("")
        {
            crate::store::ensure_private_dir(parent)?;
        }
        // `truncate(false)`: the lock file holds no data, and truncating a
        // file another instance may be reading is pointless churn.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if r != 0 {
            let e = std::io::Error::last_os_error();
            return if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                Err(VaultError::Busy)
            } else {
                Err(VaultError::Io(e))
            };
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The lock file's (device, inode), for peer verification.
    pub fn identity(&self) -> Result<(u64, u64), VaultError> {
        let md = self.file.metadata()?;
        Ok((md.dev(), md.ino()))
    }
}

impl std::fmt::Debug for InstanceLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceLock")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Kernel-reported peer credentials of a connected socket: `(pid, uid)`.
pub fn peer_credentials(stream: &UnixStream) -> Result<(i32, u32), VaultError> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if r != 0 {
        return Err(VaultError::Io(std::io::Error::last_os_error()));
    }
    Ok((cred.pid, cred.uid))
}

/// PID currently holding an exclusive `flock` on `lock`, per `/proc/locks`.
///
/// `/proc/locks` prints `maj:min:ino` with major/minor in hex and the inode
/// in decimal. Returns `None` when the lock is free, unreadable, or held by
/// another user (kernel hides those).
pub fn lock_holder_pid(lock: &Path) -> Option<i32> {
    let md = std::fs::metadata(lock).ok()?;
    let maj = libc::major(md.dev()) as u32;
    let min = libc::minor(md.dev()) as u32;
    let ino = md.ino();
    let text = std::fs::read_to_string("/proc/locks").ok()?;
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // "<n>: FLOCK ADVISORY WRITE <pid> <maj>:<min>:<ino> <start> <end>"
        if f.len() < 8 || !f[0].ends_with(':') || f[1] != "FLOCK" || f[3] != "WRITE" {
            continue;
        }
        let p: Vec<&str> = f[5].split(':').collect();
        if p.len() != 3 {
            continue;
        }
        let (Ok(dmaj), Ok(dmin), Ok(dino)) = (
            u32::from_str_radix(p[0], 16),
            u32::from_str_radix(p[1], 16),
            p[2].parse::<u64>(),
        ) else {
            continue;
        };
        if dmaj == maj && dmin == min && dino == ino {
            return f[4].parse().ok();
        }
    }
    None
}

/// Verify, before sending anything, that the peer really is the broker that
/// owns `socket`.
///
/// Two kernel-attested checks, both fail-closed:
/// 1. the peer's UID is ours;
/// 2. the peer process is the one holding the instance lock for this socket
///    (`/proc/locks`), so a listener that hijacked the path — or a foreign
///    process bound to it — is rejected. No lock held at all also fails.
///
/// Deliberately **not** used: `/proc/<pid>/exe` or `/proc/<pid>/fd`. The
/// daemon sets `PR_SET_DUMPABLE = 0` (see [`harden_process`]), which makes
/// both unreadable to same-UID observers, while `/proc/locks` stays visible.
///
/// This check alone authenticates *lock ownership*, never *what the peer
/// is*: while the legitimate daemon is down any same-UID process can take
/// the free lock and bind the socket path (N1). It stays as cheap defense
/// in depth; the cryptographic broker-identity handshake in
/// [`crate::broker_identity`] is the authority. Its failures surface as
/// `E_BROKER_UNTRUSTED` (see [`verify_server_with_policy`]).
pub fn verify_server(stream: &UnixStream, socket: &Path) -> Result<(), VaultError> {
    verify_server_with_policy(stream, socket, true)
}

/// Same gate as [`verify_server`] with an explicit strictness flag, for
/// callers that need richer policy later. `strict = true` is byte-identical
/// to [`verify_server`]; `strict = false` is currently identical too (the
/// relaxed policy, if any is ever defined, belongs here — not in
/// `verify_server`, whose strict default `mcp.rs` relies on).
pub fn verify_server_with_policy(
    stream: &UnixStream,
    socket: &Path,
    _strict: bool,
) -> Result<(), VaultError> {
    verify_server_inner(stream, socket)
}

fn verify_server_inner(stream: &UnixStream, socket: &Path) -> Result<(), VaultError> {
    let (pid, uid) = peer_credentials(stream)?;
    if pid <= 0 || uid != unsafe { libc::geteuid() } {
        return Err(server_unverified());
    }
    let lock = instance_lock_path(socket);
    if lock_holder_pid(&lock) != Some(pid) {
        return Err(server_unverified());
    }
    Ok(())
}

fn server_unverified() -> VaultError {
    VaultError::Protocol(
        "server identity could not be verified; refusing to send credentials \
         (no svault daemon holds the instance lock for this socket)"
            .into(),
    )
}

/// Harden the broker process against core dumps that would expose MEK/DEK/
/// `K_audit` from RAM.
///
/// Both mechanisms are applied: `PR_SET_DUMPABLE = 0` stops the core-pipe
/// helper from being invoked at all, and `RLIMIT_CORE = 0` keeps the kernel
/// from producing a dump even if dumpability is re-enabled later in the
/// process.
pub fn harden_process() {
    unsafe {
        // Best-effort: a failure here must not stop the daemon from serving,
        // but it is reported so operators can see it in the log.
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            eprintln!(
                "svault: warning: could not disable core dumps (prctl): {}",
                std::io::Error::last_os_error()
            );
        }
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &lim) != 0 {
            eprintln!(
                "svault: warning: could not disable core dumps (setrlimit): {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestDir;

    #[test]
    fn lock_path_is_next_to_the_socket() {
        let p = instance_lock_path(Path::new("/run/user/1000/svault/svault.sock"));
        assert_eq!(p, Path::new("/run/user/1000/svault/svault.sock.lock"));
    }

    #[test]
    fn second_acquire_is_refused_and_released_on_drop() {
        let dir = TestDir::new();
        let socket = dir.path().join("svault.sock");
        let first = InstanceLock::acquire(&socket).unwrap();
        assert!(
            matches!(InstanceLock::acquire(&socket), Err(VaultError::Busy)),
            "a second instance must be refused"
        );
        drop(first);
        assert!(
            InstanceLock::acquire(&socket).is_ok(),
            "the lock must be released when the holder goes away"
        );
    }

    #[test]
    fn holder_pid_is_the_acquiring_process() {
        let dir = TestDir::new();
        let socket = dir.path().join("svault.sock");
        let lock = InstanceLock::acquire(&socket).unwrap();
        assert_eq!(
            lock_holder_pid(lock.path()),
            Some(std::process::id() as i32)
        );
    }

    #[test]
    fn free_lock_reports_no_holder() {
        let dir = TestDir::new();
        let socket = dir.path().join("svault.sock");
        drop(InstanceLock::acquire(&socket).unwrap());
        assert_eq!(lock_holder_pid(&instance_lock_path(&socket)), None);
    }

    #[test]
    fn verify_accepts_the_lock_holder_and_rejects_a_path_without_one() {
        // Two listeners, same process: only the one whose path has an
        // instance lock verifies. A listener that bound a path where the
        // client expects the broker (exactly the C1 hijack shape) is refused.
        let dir = TestDir::new();
        let sock = dir.path().join("svault.sock");
        let usurper = dir.path().join("other.sock");
        let _lock = InstanceLock::acquire(&sock).unwrap();
        let l1 = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let l2 = std::os::unix::net::UnixListener::bind(&usurper).unwrap();
        let c1 = UnixStream::connect(&sock).unwrap();
        let _a1 = l1.accept().unwrap();
        assert!(verify_server(&c1, &sock).is_ok());
        let c2 = UnixStream::connect(&usurper).unwrap();
        let _a2 = l2.accept().unwrap();
        assert!(verify_server(&c2, &usurper).is_err());
        // And with the lock released, even the right path stops verifying.
        drop(_lock);
        assert!(verify_server(&c1, &sock).is_err());
    }

    #[test]
    fn harden_process_is_callable_without_panicking() {
        // Applies PR_SET_DUMPABLE=0 and RLIMIT_CORE=0 to this test process;
        // asserted observable in the integration suite against a real daemon.
        harden_process();
    }
}
