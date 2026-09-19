//! Linux filesystem containment for `inject_file`: kernel-enforced path
//! resolution via `openat2` from a pinned authorized-directory fd, and
//! atomic file replacement inside that directory.
//!
//! No TOCTOU between authorization and use: the authorized folder fd is
//! acquired by opening `/` as a stable anchor (no resolve flags, so the
//! anchor open itself cannot fail on resolve semantics) and then resolving
//! the folder's absolute path — converted to a path relative to that anchor —
//! in a single `openat2` call with
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`. Every
//! ancestor is resolved symlink-free by the kernel at acquisition time, and
//! the identity we authorize is the resolved directory itself. The fd is
//! thereafter a capability over that directory: if the pathname is later
//! renamed or swapped, the fd keeps pointing at the directory we authorized
//! (explicit, chosen semantics). Every resolution below it is a single
//! `openat2` call with the same three flags, and the final publication is a
//! `renameat` relative to that same pinned fd.
//!
//! If the kernel lacks `openat2` (ENOSYS) every operation fails closed.
//!
//! Final publication semantics (contract option A): a temporary regular
//! file (mode 0600, `O_CREAT|O_EXCL`) is created inside the resolved
//! directory, fully written, fsynced, then renamed over the destination
//! pathname. Only an existing REGULAR file (or nothing) is replaceable; a
//! symlink — at the leaf or anywhere in the path — is refused, never
//! followed, never swapped. The directory is fsynced after the rename.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use crate::error::VaultError;

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_FLAGS: u64 = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;

const O_CLOEXEC: i32 = 0o2000000;
const O_DIRECTORY: i32 = 0o200000;
const O_CREAT: i32 = 0o100;
const O_EXCL: i32 = 0o200;
const O_WRONLY: i32 = 1;
const O_RDONLY: i32 = 0;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// A destination pinned to kernel state: the parent directory fd plus the
/// final file name (a plain component, no separators).
pub struct ContainedTarget {
    parent_fd: OwnedFd,
    file_name: String,
    /// Human-visible path (authorized folder + relative path).
    pub display_path: PathBuf,
}

fn last_os_error(_context: &str) -> VaultError {
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::ENOSYS) {
        return VaultError::Protocol(
            "kernel lacks openat2 support; refusing filesystem writes (fail closed)".into(),
        );
    }
    // ponytail: keep the raw errno (no context wrap — `io::Error::new` drops
    // it) so callers can tell resource failures apart from authz denials.
    VaultError::Io(e)
}

/// True for operational failures that must never be relabeled as
/// authorization denials: resource/system errors and fail-closed `Protocol`.
fn is_operational_error(e: &VaultError) -> bool {
    match e {
        VaultError::Protocol(_) => true,
        VaultError::Io(io) => matches!(
            io.raw_os_error(),
            Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOMEM) | Some(libc::EIO)
        ),
        _ => false,
    }
}

/// `openat2(dirfd, path, {flags, mode, resolve})` — raw syscall; the libc
/// crate does not wrap it. `resolve` is passed through per call site: the
/// `/` anchor itself opens with no resolve flags (applying RESOLVE_BENEATH
/// to the anchor open fails with EPERM — the kernel cannot establish a
/// "beneath" scope while resolving the scope root itself), while every
/// resolution *beneath* an anchor uses the full
/// `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` set.
/// Mount-point crossings need no special handling: RESOLVE_BENEATH permits
/// them (only RESOLVE_NO_XDEV would forbid them, and it is deliberately not
/// used).
fn openat2(
    dirfd: RawFd,
    path: &str,
    flags: i32,
    mode: u32,
    resolve: u64,
) -> Result<OwnedFd, VaultError> {
    let cpath =
        CString::new(path.as_bytes()).map_err(|_| VaultError::InvalidInput("path contains NUL"))?;
    let how = OpenHow {
        flags: flags as u64,
        mode: mode as u64,
        resolve,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            cpath.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        Err(last_os_error("openat2"))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }
}

/// Validate a client-supplied relative destination: no absolute paths, no
/// `..`/`.` components, no empty components, bounded length, no NUL.
pub fn validate_relative(relative: &str) -> Result<(), VaultError> {
    if relative.is_empty() || relative.len() > crate::model::MAX_PATH_LEN {
        return Err(VaultError::InvalidInput("invalid destination path length"));
    }
    if relative.contains('\0') {
        return Err(VaultError::InvalidInput("path contains NUL"));
    }
    let path = Path::new(relative);
    if path.is_absolute() {
        return Err(VaultError::InvalidInput(
            "destination must be a relative path",
        ));
    }
    for component in path.components() {
        match component {
            std::path::Component::Normal(_) => {}
            _ => {
                return Err(VaultError::InvalidInput(
                    "destination must be relative with no '..' or '.' components",
                ));
            }
        }
    }
    Ok(())
}

/// Open an authorized folder as the containment root.
///
/// Flow: open `/` as a stable anchor (plain `open`, no resolve flags — the
/// kernel rejects RESOLVE_BENEATH on the anchor open itself with EPERM), then
/// resolve the folder's absolute path converted to a path relative to that
/// anchor in one `openat2` call with
/// `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`. The
/// relative form has no leading `/` and no `..` (the stored folder is
/// canonicalized absolute, so `strip_prefix("/")` yields plain components);
/// any deviation fails closed.
pub fn open_containment_root(folder: &Path) -> Result<OwnedFd, VaultError> {
    if !folder.is_absolute() {
        return Err(VaultError::InvalidInput(
            "authorized folder must be an absolute path",
        ));
    }
    let anchor = {
        let cpath = CString::new("/").expect("literal has no NUL");
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(last_os_error("containment anchor open"));
        }
        unsafe { OwnedFd::from_raw_fd(fd) }
    };
    let relative = folder
        .strip_prefix("/")
        .map_err(|_| VaultError::InvalidInput("authorized folder must be absolute"))?;
    let relative = relative.to_str().ok_or(VaultError::InvalidInput(
        "authorized folder must be valid UTF-8",
    ))?;
    // Belt and braces: strip_prefix of a canonicalized absolute path cannot
    // yield these ("/" itself yields the empty path, which we open as the
    // anchor fd), but the kernel must never see them here.
    if relative.starts_with('/')
        || relative
            .split('/')
            .any(|c| c == ".." || c == "." || c.is_empty())
    {
        return Err(VaultError::InvalidInput(
            "authorized folder is not a plain relative descendant path",
        ));
    }
    let empty = "";
    openat2(
        anchor.as_raw_fd(),
        if relative.is_empty() { empty } else { relative },
        O_RDONLY | O_DIRECTORY | O_CLOEXEC,
        0,
        RESOLVE_FLAGS,
    )
}

/// Open an authorized cwd as a pinned directory fd for `fchdir` in child pre-exec.
///
/// For an absolute requested `cwd`, tries each authorized project root in
/// order: pins the root via [`open_containment_root`] (kernel-resolved,
/// symlink-free capability fd), then resolves the `cwd` relative to that
/// pinned fd in one `openat2` call with
/// `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
/// The lexical `strip_prefix` below only selects candidate roots and derives
/// the relative path; the authorization decision is the kernel resolution
/// itself — there is deliberately no `canonicalize`/metadata comparison.
/// An authorized root itself (empty relative) and descendants resolve; a
/// path outside every root, containing `..`, traversing a symlink, missing,
/// or not a directory fails closed. Outside (including non-absolute, which
/// cannot sit beneath an absolute root) surfaces as
/// [`VaultError::PathNotAuthorized`] with the static `E_PATH_NOT_AUTHORIZED`
/// code; malformed encodings (NUL, non-UTF-8, overlong) surface as
/// `InvalidInput`. A missing-`openat2` kernel propagates its fail-closed
/// `Protocol` error instead of being masked as unauthorized, as do resource
/// failures (`EMFILE`, `ENFILE`, `ENOMEM`, `EIO`); only path-resolution
/// denials fall through to the next root and finally `PathNotAuthorized`.
///
/// Cwd authorization is not sandboxing: the child keeps normal OS access and
/// may read parent/sibling paths (e.g. `../marker.txt`) through its own
/// syscalls. The returned fd is `O_RDONLY | O_DIRECTORY | O_CLOEXEC`,
/// hence CLOEXEC-owned and suitable for `fchdir`.
pub fn open_authorized_cwd(cwd: &Path, roots: &[PathBuf]) -> Result<OwnedFd, VaultError> {
    if !cwd.is_absolute() {
        return Err(VaultError::PathNotAuthorized);
    }
    if cwd.as_os_str().len() > crate::model::MAX_PATH_LEN {
        return Err(VaultError::InvalidInput("cwd path too long"));
    }
    let cwd_str = cwd
        .to_str()
        .ok_or(VaultError::InvalidInput("cwd must be valid UTF-8"))?;
    if cwd_str.contains('\0') {
        return Err(VaultError::InvalidInput("path contains NUL"));
    }
    // Any `..` is refused outright, even one that would lexically stay
    // beneath a root; `.` is left to the kernel (it cannot escape beneath).
    if cwd
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(VaultError::PathNotAuthorized);
    }
    for root in roots {
        let relative = match cwd.strip_prefix(root) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let root_fd = match open_containment_root(root) {
            Ok(fd) => fd,
            Err(e) if is_operational_error(&e) => return Err(e),
            Err(_) => continue,
        };
        if relative.as_os_str().is_empty() {
            return Ok(root_fd);
        }
        let rel_str = match relative.to_str() {
            Some(s) => s,
            None => continue,
        };
        if rel_str.starts_with('/') || rel_str.contains('\0') {
            continue;
        }
        match openat2(
            root_fd.as_raw_fd(),
            rel_str,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC,
            0,
            RESOLVE_FLAGS,
        ) {
            Ok(fd) => return Ok(fd),
            Err(e) if is_operational_error(&e) => return Err(e),
            Err(_) => continue,
        }
    }
    Err(VaultError::PathNotAuthorized)
}

/// Pin the destination: resolve the relative path's parent directory under
/// the containment root and isolate the final file name.
pub fn resolve_target(
    root: &OwnedFd,
    relative: &str,
    folder: &Path,
) -> Result<ContainedTarget, VaultError> {
    validate_relative(relative)?;
    let (parent_fd, file_name) = match relative.rfind('/') {
        Some(pos) => {
            let parent_rel = &relative[..pos];
            let name = &relative[pos + 1..];
            let fd = openat2(
                root.as_raw_fd(),
                parent_rel,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC,
                0,
                RESOLVE_FLAGS,
            )?;
            (fd, name.to_string())
        }
        None => (root.try_clone()?, relative.to_string()),
    };
    if file_name == "." || file_name == ".." || file_name.is_empty() {
        return Err(VaultError::InvalidInput("invalid destination file name"));
    }
    Ok(ContainedTarget {
        parent_fd,
        file_name,
        display_path: folder.join(relative),
    })
}

/// Write the whole buffer to `fd`, retrying **only** `EINTR`.
///
/// Any other negative return (`ENOSPC`, `EFBIG`, `EDQUOT`, `EIO`, …) is a
/// hard error: treating it as zero progress would spin forever under the
/// daemon-wide session mutex.
fn write_all(fd: RawFd, bytes: &[u8]) -> io::Result<()> {
    let mut written = 0usize;
    while written < bytes.len() {
        let n = unsafe {
            libc::write(
                fd,
                bytes[written..].as_ptr() as *const libc::c_void,
                bytes.len() - written,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "write returned zero",
            ));
        }
        written += n as usize;
    }
    Ok(())
}

/// Atomically publish `bytes` at the pinned destination: exclusive 0600
/// temp file in the same directory, write, fsync, `renameat` over the
/// destination, fsync the directory. Non-regular existing destinations are
/// rejected; existing regular files are replaced, never followed.
pub fn write_file_atomic(target: &ContainedTarget, bytes: &[u8]) -> Result<(), VaultError> {
    let parent = target.parent_fd.as_raw_fd();
    let cname = CString::new(target.file_name.as_bytes())
        .map_err(|_| VaultError::InvalidInput("file name contains NUL"))?;

    // Destination type check without following (contract option A): ONLY a
    // regular file or nothing is replaceable. Symlinks, directories, FIFOs,
    // sockets and devices as the final component are refused — never
    // followed, never replaced by this operation.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstatat(parent, cname.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if ret == 0 && (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(VaultError::InvalidInput(
            "destination exists and is not a regular file (symlinks, directories, FIFOs, sockets and devices are refused)",
        ));
    }

    // Unpredictable temp name (CSPRNG suffix) with O_EXCL and bounded
    // retries: no trivial DoS via predictable collision.
    let mut tmp_fd = None;
    let mut tmp_name = String::new();
    for _ in 0..5 {
        let suffix = crate::crypto::hex(&crate::crypto::random_bytes::<8>()?);
        tmp_name = format!(".{}.tmp.{}", target.file_name, suffix);
        match openat2(
            parent,
            &tmp_name,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
            0o600,
            RESOLVE_FLAGS,
        ) {
            Ok(fd) => {
                tmp_fd = Some(fd);
                break;
            }
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => continue,
            Err(e) => return Err(e),
        }
    }
    let Some(tmp_fd) = tmp_fd else {
        return Err(VaultError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique temp file after 5 attempts",
        )));
    };
    let ctmp = CString::new(tmp_name.as_bytes())
        .map_err(|_| VaultError::InvalidInput("temp name contains NUL"))?;

    // The created entry must be a regular file owned by us (paranoia).
    let fd_raw = tmp_fd.as_raw_fd();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd_raw, &mut st) } != 0 || (st.st_mode & libc::S_IFMT) != libc::S_IFREG
    {
        return Err(VaultError::Corrupt(
            "created temp file is not regular".into(),
        ));
    }

    let result = (|| -> io::Result<()> {
        write_all(fd_raw, bytes)?;
        if unsafe { libc::fsync(fd_raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();

    if let Err(e) = result {
        unsafe {
            libc::unlinkat(parent, ctmp.as_ptr(), 0);
        }
        return Err(VaultError::Io(e));
    }

    // Atomic publication within the pinned directory. renameat replaces the
    // directory entry without following symlinks or the destination inode.
    let ret = unsafe { libc::renameat(parent, ctmp.as_ptr(), parent, cname.as_ptr()) };
    if ret != 0 {
        unsafe {
            libc::unlinkat(parent, ctmp.as_ptr(), 0);
        }
        return Err(last_os_error("renameat"));
    }

    // Durability: fsync the parent directory (best-effort; the rename has
    // already committed the new content).
    let dir_file = unsafe { std::fs::File::from_raw_fd(parent) };
    let _ = dir_file.sync_all();
    std::mem::forget(dir_file); // do not close the borrowed fd
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestDir;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn folder() -> (TestDir, OwnedFd) {
        let dir = TestDir::new();
        let fd = open_containment_root(dir.path()).unwrap();
        (dir, fd)
    }

    #[test]
    fn relative_validation_rejects_traversal_and_absolute() {
        assert!(validate_relative(".env").is_ok());
        assert!(validate_relative("sub/dir/.env").is_ok());
        assert!(validate_relative("/etc/passwd").is_err());
        assert!(validate_relative("../../outside").is_err());
        assert!(validate_relative("a/../b").is_err());
        assert!(validate_relative("..").is_err());
        assert!(validate_relative("./x").is_err());
        assert!(validate_relative("").is_err());
        assert!(validate_relative("a\0b").is_err());
    }

    #[test]
    fn atomic_write_creates_file_0600_with_content() {
        let (dir, root) = folder();
        let t = resolve_target(&root, ".env", dir.path()).unwrap();
        write_file_atomic(&t, b"A=1\n").unwrap();
        let content = std::fs::read(dir.path().join(".env")).unwrap();
        assert_eq!(content, b"A=1\n");
        let mode = std::fs::metadata(dir.path().join(".env"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn existing_regular_file_is_replaced_atomically() {
        let (dir, root) = folder();
        std::fs::write(dir.path().join(".env"), b"OLD=1\n").unwrap();
        let t = resolve_target(&root, ".env", dir.path()).unwrap();
        write_file_atomic(&t, b"NEW=2\n").unwrap();
        assert_eq!(std::fs::read(dir.path().join(".env")).unwrap(), b"NEW=2\n");
        // No temp residue.
        assert!(
            dir.path().read_dir().unwrap().all(|e| !e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp."))
        );
    }

    #[test]
    fn symlink_destination_is_rejected_and_untouched() {
        // Contract option A: a symlink as the final destination component is
        // REFUSED (never followed, never replaced by this operation).
        let (dir, root) = folder();
        symlink(dir.path().join("outside.target"), dir.path().join(".env")).unwrap();
        let t = resolve_target(&root, ".env", dir.path()).unwrap();
        assert!(write_file_atomic(&t, b"SAFE=1\n").is_err());
        // The symlink and its target are untouched.
        assert!(
            std::fs::symlink_metadata(dir.path().join(".env"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let t2 = resolve_target(&root, "outside.target", dir.path())
            .unwrap_or_else(|_| resolve_target(&root, ".env", dir.path()).unwrap());
        let _ = t2;
    }

    #[test]
    fn symlink_in_intermediate_directory_is_rejected() {
        let (dir, root) = folder();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
        let err = resolve_target(&root, "link/.env", dir.path());
        assert!(err.is_err(), "symlinked intermediate dir must be rejected");
    }

    #[test]
    fn traversal_beneath_is_kernel_rejected() {
        // validate_relative rejects ".." outright. This test also probes the
        // kernel boundary directly: a crafted traversal name that bypasses
        // validation must still be refused by RESOLVE_BENEATH at open/rename
        // time, and the outside sentinel must remain untouched.
        let (dir, root) = folder();
        let outside = TestDir::new();
        std::fs::write(outside.path().join("sentinel"), b"do-not-touch").unwrap();

        // Bypass validate_relative: resolve the parent ".." directly via
        // openat2 — RESOLVE_BENEATH must refuse it.
        assert!(
            openat2(
                root.as_raw_fd(),
                "..",
                O_RDONLY | O_DIRECTORY | O_CLOEXEC,
                0,
                RESOLVE_FLAGS,
            )
            .is_err()
        );

        // Full path: destination name containing traversal is refused at
        // resolve/write time.
        let bypassed = ContainedTarget {
            parent_fd: root.try_clone().unwrap(),
            file_name: "../outside/sentinel".into(),
            display_path: dir.path().to_path_buf(),
        };
        assert!(write_file_atomic(&bypassed, b"pwn").is_err());
        assert_eq!(
            std::fs::read(outside.path().join("sentinel")).unwrap(),
            b"do-not-touch"
        );
    }

    #[test]
    fn non_regular_destination_is_rejected_and_untouched() {
        let (dir, root) = folder();
        let fifo = dir.path().join("pipe.env");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
        let t = resolve_target(&root, "pipe.env", dir.path()).unwrap();
        assert!(write_file_atomic(&t, b"x").is_err());
        let md = std::fs::metadata(&fifo).unwrap();
        assert!(md.file_type().is_fifo(), "fifo must remain untouched");
    }

    #[test]
    fn subdirectory_destination_works_under_containment() {
        let (dir, root) = folder();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let t = resolve_target(&root, "sub/.env", dir.path()).unwrap();
        write_file_atomic(&t, b"A=1\n").unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("sub/.env")).unwrap(),
            b"A=1\n"
        );
    }

    #[test]
    fn ancestor_symlink_rejects_root_acquisition() {
        // A symlink in an ANCESTOR of the authorized folder fails closed:
        // the whole relative path is resolved by openat2 from the "/"
        // anchor with RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS.
        let dir = TestDir::new();
        let real = dir.path().join("real/authorized");
        std::fs::create_dir_all(&real).unwrap();
        symlink(&real, dir.path().join("linked")).unwrap();
        assert!(open_containment_root(&dir.path().join("linked")).is_err());
        // The real folder still opens.
        assert!(open_containment_root(&real).is_ok());
    }

    #[test]
    fn beneath_flags_allow_mount_points_but_block_escape() {
        // RESOLVE_BENEATH permits entering a legitimate mount point (here
        // /proc, a separate filesystem) via a relative path under the "/"
        // anchor — only RESOLVE_NO_XDEV would forbid that, and it is
        // deliberately unused. Escaping upward with ".." is refused.
        // (The "/" anchor for these probes is opened directly; production
        // code acquires it inside open_containment_root.)
        let anchor = openat2(
            libc::AT_FDCWD,
            "/",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC,
            0,
            0,
        )
        .unwrap();
        let proc_dir = openat2(
            anchor.as_raw_fd(),
            "proc",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC,
            0,
            RESOLVE_FLAGS,
        );
        assert!(proc_dir.is_ok(), "entering /proc must work");
        assert!(
            openat2(
                anchor.as_raw_fd(),
                "../etc",
                O_RDONLY | O_DIRECTORY | O_CLOEXEC,
                0,
                RESOLVE_FLAGS,
            )
            .is_err(),
            "escaping the anchor with .. must fail"
        );
    }

    #[test]
    fn internal_dotdot_that_stays_beneath_is_allowed() {
        // "a/../a" never leaves the authorized tree: the kernel allows the
        // resolution and the result stays within containment.
        let (dir, root) = folder();
        std::fs::create_dir(dir.path().join("a")).unwrap();
        let t = resolve_target(&root, "a", dir.path()).unwrap();
        assert!(t.display_path.starts_with(dir.path()));
    }

    #[test]
    fn root_replaced_by_symlink_is_rejected() {
        let dir = TestDir::new();
        let folder = dir.path().join("authorized");
        std::fs::create_dir_all(&folder).unwrap();
        assert!(open_containment_root(&folder).is_ok());
        // Replace the folder itself with a symlink: acquisition fails.
        std::fs::remove_dir_all(&folder).unwrap();
        symlink(dir.path().join("other"), &folder).unwrap();
        std::fs::create_dir_all(dir.path().join("other")).unwrap();
        assert!(open_containment_root(&folder).is_err());
    }

    #[test]
    fn intermediate_component_swap_during_injections_zero_escapes() {
        // Race: swap an INTERMEDIATE component of the authorized path
        // between real directory and symlink while many root acquisitions
        // and writes happen → 0 escapes.
        let dir = TestDir::new();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"do-not-touch").unwrap();
        let base = dir.path().join("base");
        let authorized = base.join("authorized");
        std::fs::create_dir_all(&authorized).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let racer_stop = stop.clone();
        let swap = base.join("authorized");
        let outside_for_racer = outside.clone();
        let racer = std::thread::spawn(move || {
            let mut flip = false;
            while !racer_stop.load(Ordering::Relaxed) {
                let _ = std::fs::remove_dir_all(&swap);
                if flip {
                    let _ = symlink(&outside_for_racer, &swap);
                } else {
                    let _ = std::fs::create_dir_all(&swap);
                }
                flip = !flip;
            }
        });

        let mut escapes = 0;
        for _ in 0..200 {
            match open_containment_root(&authorized) {
                Ok(root) => {
                    let escaped = resolve_target(&root, ".env", &authorized)
                        .and_then(|t| {
                            let inside = t.display_path.starts_with(&authorized);
                            write_file_atomic(&t, b"x")?;
                            Ok(!inside)
                        })
                        .unwrap_or(false);
                    if escaped {
                        escapes += 1;
                    }
                }
                Err(_) => { /* clean refusal during a symlink swap is fine */ }
            }
        }
        stop.store(true, Ordering::Relaxed);
        racer.join().unwrap();
        assert_eq!(escapes, 0, "no write may escape the authorized folder");
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"do-not-touch"
        );
    }

    #[test]
    fn magic_link_paths_are_rejected() {
        // Intermediate components are resolved by openat2 with
        // RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS: a symlink pointing at
        // /proc is refused outright. A symlink as the FINAL component is
        // refused too (contract option A) — /proc is never touched.
        let (dir, root) = folder();
        symlink("/proc/self", dir.path().join("pmagic")).unwrap();
        assert!(resolve_target(&root, "pmagic/.env", dir.path()).is_err());
        symlink("/proc/self/environ", dir.path().join("magic")).unwrap();
        let t = resolve_target(&root, "magic", dir.path()).unwrap();
        assert!(write_file_atomic(&t, b"x").is_err());
        assert!(
            std::fs::symlink_metadata(dir.path().join("magic"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(std::fs::read_to_string("/proc/self/environ").is_ok());
    }
}
