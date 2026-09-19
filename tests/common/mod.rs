#![allow(dead_code)]
//! Shared integration helpers for FD-passing `run_with_secrets` tests.
//! Compact RAII setup + real UDS daemon + SCM_RIGHTS send + bounded reads.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

use svault::broker::{Daemon, DaemonConfig};
use svault::model::Op;
use svault::session::{Session, SystemClock};
use svault::wire::{AuthField, Request, Response, VERSION};

const PASS: &[u8] = b"correct horse battery";
const IDLE: Duration = Duration::from_secs(60);

/// Trap secret value; tests assert it reaches the child but never the broker.
pub const TRAP: &str = "sk-trap-0xf00dVALUE";

/// Write a token file the way a real enrollment does (L3): mode 0600 from the
/// moment it exists, never world-readable. `std::fs::write` would apply the
/// process umask (0644 under a default 022), leaving a live capability
/// readable by every local user for the duration of the test.
pub fn write_token_file(path: &Path, token: &str) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create token file");
    f.write_all(token.as_bytes()).expect("write token");
    f.sync_all().expect("sync token");
}

pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("svault-runfd-{}-{n}", std::process::id()));
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

pub struct Fixture {
    pub dir: TestDir,
    pub token: String,
    pub socket: PathBuf,
}

/// Create vault + project + secret + agent with `run` grant, spawn the real
/// daemon on UDS, wait for it, unlock via dispatch, return fixture.
pub fn setup() -> Fixture {
    let dir = TestDir::new();
    let vault_path = dir.path().join("vault.enc");
    let socket_path = dir.path().join("svault.sock");
    let authorized = dir.path().join("authorized");
    std::fs::create_dir_all(&authorized).unwrap();

    let mut s = Session::create(&vault_path, PASS, IDLE, Box::new(SystemClock)).unwrap();
    s.project_add("human", "acme", &[authorized]).unwrap();
    s.secret_set("human", "acme", "STRIPE_KEY", TRAP.as_bytes())
        .unwrap();
    let (_id, token) = s.agent_add("human", "harness").unwrap();
    s.grant_add("human", "harness", "acme", &[Op::Run]).unwrap();
    drop(s);

    let daemon = Daemon::new(DaemonConfig {
        socket_path: socket_path.clone(),
        vault_path: vault_path.clone(),
        idle_lock: IDLE,
    })
    .unwrap();
    let daemon = Arc::new(daemon);
    let srv = Arc::clone(&daemon);
    std::thread::spawn(move || {
        let _ = srv.serve();
    });
    for _ in 0..200 {
        if UnixStream::connect(&socket_path).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let unlock = daemon.handle_request(Request {
        v: VERSION,
        id: "unlock".to_string(),
        op: "vault.unlock".to_string(),
        auth: Some(AuthField {
            token: None,
            passphrase: Some("correct horse battery".to_string()),
            session: None,
        }),
        params: serde_json::json!({}),
    });
    assert!(unlock.ok, "setup unlock failed: {:?}", unlock.error);
    Fixture {
        dir,
        token,
        socket: socket_path,
    }
}

/// Authenticated agent request.
pub fn authed_request(id: &str, op: &str, token: &str, params: serde_json::Value) -> Request {
    Request {
        v: VERSION,
        id: id.to_string(),
        op: op.to_string(),
        auth: Some(AuthField {
            token: Some(token.to_string()),
            passphrase: None,
            session: None,
        }),
        params,
    }
}

/// Send one NDJSON request; when `fds` is non-empty the bytes carry exactly
/// those FDs via `SCM_RIGHTS` in the same `sendmsg`.
pub fn send_with_fds(stream: &mut UnixStream, req: &Request, fds: &[RawFd]) -> std::io::Result<()> {
    let mut line = serde_json::to_string(req).expect("request serializes");
    line.push('\n');
    let bytes = line.as_bytes();
    if fds.is_empty() {
        use std::io::Write;
        stream.write_all(bytes)?;
        stream.flush()?;
        return Ok(());
    }
    unsafe {
        let mut iov = libc::iovec {
            iov_base: bytes.as_ptr() as *mut libc::c_void,
            iov_len: bytes.len(),
        };
        let space = libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) as usize;
        let mut ctrl = vec![0u8; space];
        let mut hdr: libc::msghdr = std::mem::zeroed();
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = ctrl.as_mut_ptr() as *mut libc::c_void;
        hdr.msg_controllen = ctrl.len() as _;
        let cmsg = libc::CMSG_FIRSTHDR(&hdr);
        if cmsg.is_null() {
            return Err(std::io::Error::other("CMSG_FIRSTHDR null"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as _;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr() as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of_val(fds),
        );
        let n = libc::sendmsg(stream.as_raw_fd(), &hdr, libc::MSG_NOSIGNAL);
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if (n as usize) != bytes.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short sendmsg",
            ));
        }
        Ok(())
    }
}

/// Read one bounded NDJSON response line.
pub fn read_response<R: std::io::BufRead>(reader: &mut R) -> Result<Response, svault::VaultError> {
    svault::wire::read_response(reader)
}

/// Pipe pair with ownership-safe cleanup (close-on-drop).
pub fn make_pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0 as libc::c_int; 2];
    let r = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(r, 0, "pipe failed: {}", std::io::Error::last_os_error());
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

/// File-backed FD (`/dev/null`) with ownership-safe cleanup.
pub fn open_devnull() -> OwnedFd {
    std::fs::File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map(OwnedFd::from)
        .expect("/dev/null opens")
}

/// Connect to the daemon socket with bounded timeouts.
pub fn connect(socket: &Path) -> UnixStream {
    let s = UnixStream::connect(socket).expect("daemon socket connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}
