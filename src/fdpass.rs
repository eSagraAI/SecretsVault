//! SCM_RIGHTS transport for the first NDJSON request on a UDS connection.
//!
//! Server: [`recv_request_with_fds`] loops `recvmsg` until the first `\n`,
//! collecting data bytes (bounded by `MAX_MESSAGE_LEN`) and any `SCM_RIGHTS`
//! FDs in one logical operation. Client: [`send_request_with_fds`]
//! serializes one [`Request`] and carries the caller's raw FDs in the first
//! `sendmsg`.
//!
//! Safety / ownership:
//! - Receive uses `MSG_CMSG_CLOEXEC` so every delivered FD is CLOEXEC-owned.
//! - Received FDs are wrapped in `OwnedFd` immediately; any `Err` drops the
//!   `Vec<OwnedFd>`, closing them — no leak on truncation, malformed
//!   ancillary, oversize, or bad JSON.
//! - `MSG_TRUNC` / `MSG_CTRUNC` are hard errors (truncation detected).
//! - Bytes after the first `\n` already in the buffer are rejected instead of
//!   silently accepting a pipelined second request.

use crate::error::VaultError;
use crate::wire::{MAX_MESSAGE_LEN, Request, VERSION};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

/// Stream read chunk; the full line still caps at `MAX_MESSAGE_LEN`.
const DATA_CHUNK: usize = 8192;
/// Total received-FD cap per request: stdio needs 3, slack for validation to
/// report counts (tests use up to 4); excess fails closed instead of
/// exhausting the process table.
const MAX_RECV_FDS: usize = 32;

/// Receive the first NDJSON request plus its `SCM_RIGHTS` FDs.
///
/// Returns the parsed [`Request`] and owned CLOEXEC FDs (empty for ordinary
/// zero-FD requests). One logical request only: trailing bytes after the
/// first newline are a protocol error.
pub fn recv_request_with_fds(stream: &UnixStream) -> Result<(Request, Vec<OwnedFd>), VaultError> {
    let mut acc: Vec<u8> = Vec::new();
    // Owned from the moment each FD is extracted; drop closes all on error.
    let mut fds: Vec<OwnedFd> = Vec::new();
    loop {
        let mut data = [0u8; DATA_CHUNK];
        let ctrl_space =
            unsafe { libc::CMSG_SPACE((MAX_RECV_FDS * size_of::<RawFd>()) as u32) as usize };
        let mut ctrl = vec![0u8; ctrl_space];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };
        let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = ctrl.as_mut_ptr() as *mut libc::c_void;
        hdr.msg_controllen = ctrl.len();

        // MSG_CMSG_CLOEXEC: received FDs arrive CLOEXEC-owned.
        let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut hdr, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(VaultError::from(e));
        }
        if n == 0 {
            if acc.is_empty() {
                return Err(VaultError::Protocol("connection closed".into()));
            }
            return Err(VaultError::Protocol("unterminated message".into()));
        }
        let msg_trunc = (hdr.msg_flags & libc::MSG_TRUNC) != 0;
        let cmsg_trunc = (hdr.msg_flags & libc::MSG_CTRUNC) != 0;
        // Reclaim every safely addressable delivered SCM_RIGHTS FD into
        // `fds` before reporting any protocol error, so the owned vec's
        // drop closes the received prefix (no leak on truncation or
        // malformed ancillary). Payload reads are clamped to the delivered
        // control bytes; never trust `cmsg_len` past `msg_controllen`.
        let delivered = (hdr.msg_controllen as usize).min(ctrl.len());
        let ctrl_base = ctrl.as_ptr() as usize;
        let mut anc_err: Option<VaultError> = None;
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&hdr) };
        while !cmsg.is_null() {
            // Never trust `cmsg_len` before proving the header itself was
            // delivered: a truncated tail may leave a partial `cmsghdr`.
            let cmsg_off = (cmsg as usize).wrapping_sub(ctrl_base);
            if cmsg_off.saturating_add(size_of::<libc::cmsghdr>()) > delivered {
                if anc_err.is_none() {
                    anc_err = Some(VaultError::Protocol("malformed ancillary".into()));
                }
                break;
            }
            let (level, typ, cmsg_len) = unsafe {
                (
                    (*cmsg).cmsg_level,
                    (*cmsg).cmsg_type,
                    (*cmsg).cmsg_len as usize,
                )
            };
            let hdr_len = unsafe { libc::CMSG_LEN(0) as usize };
            if cmsg_len < hdr_len {
                if anc_err.is_none() {
                    anc_err = Some(VaultError::Protocol("malformed ancillary".into()));
                }
                break;
            }
            if level != libc::SOL_SOCKET || typ != libc::SCM_RIGHTS {
                if anc_err.is_none() {
                    anc_err = Some(VaultError::Protocol("unexpected ancillary".into()));
                }
                cmsg = unsafe { libc::CMSG_NXTHDR(&hdr, cmsg) };
                continue;
            }
            let avail = delivered.saturating_sub(cmsg_off);
            let safe_len = cmsg_len.min(avail);
            if safe_len < hdr_len {
                if anc_err.is_none() {
                    anc_err = Some(VaultError::Protocol("malformed ancillary".into()));
                }
                break;
            }
            let safe_payload = safe_len - hdr_len;
            let full_payload = cmsg_len - hdr_len;
            // Own the safely addressable prefix first, then reject the
            // malformed tail / overflow via the owned vec's drop: no leak.
            let count = safe_payload / size_of::<RawFd>();
            let ptr = unsafe { libc::CMSG_DATA(cmsg) } as *const RawFd;
            let mut bad = full_payload % size_of::<RawFd>() != 0;
            if cmsg_len > avail && !cmsg_trunc {
                bad = true;
            }
            for i in 0..count {
                let raw = unsafe { *ptr.add(i) };
                if raw < 0 {
                    bad = true; // invalid slot holds no FD; keep owning rest
                    continue;
                }
                // Safety: kernel transferred ownership of this FD to us.
                fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
            if bad && anc_err.is_none() {
                anc_err = Some(VaultError::Protocol("malformed ancillary".into()));
            }
            if fds.len() > MAX_RECV_FDS && anc_err.is_none() {
                anc_err = Some(VaultError::Protocol("too many file descriptors".into()));
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&hdr, cmsg) };
        }
        if msg_trunc {
            return Err(VaultError::Protocol("message truncated".into()));
        }
        if cmsg_trunc {
            return Err(VaultError::Protocol("ancillary truncated".into()));
        }
        if let Some(e) = anc_err {
            return Err(e);
        }

        acc.extend_from_slice(&data[..n as usize]);
        if let Some(pos) = acc.iter().position(|&b| b == b'\n') {
            if pos > MAX_MESSAGE_LEN {
                return Err(VaultError::TooLarge);
            }
            if acc.len() != pos + 1 {
                return Err(VaultError::Protocol("trailing bytes after request".into()));
            }
            let req: Request = serde_json::from_slice(&acc[..pos])
                .map_err(|_| VaultError::Protocol("invalid request".into()))?;
            if req.v != VERSION {
                return Err(VaultError::Protocol("unsupported protocol version".into()));
            }
            return Ok((req, fds));
        }
        if acc.len() > MAX_MESSAGE_LEN {
            return Err(VaultError::TooLarge);
        }
    }
}

/// Send one NDJSON [`Request`], carrying `fds` via `SCM_RIGHTS`.
///
/// `fds` are borrowed: the kernel duplicates them, the caller keeps
/// ownership. Empty `fds` is a plain stream write. Short writes loop; only
/// the first `sendmsg` carries ancillary, the remainder goes plain.
pub fn send_request_with_fds(
    stream: &UnixStream,
    req: &Request,
    fds: &[RawFd],
) -> Result<(), VaultError> {
    let mut line =
        serde_json::to_string(req).map_err(|_| VaultError::Protocol("invalid request".into()))?;
    line.push('\n');
    let bytes = line.as_bytes();
    if bytes.len() - 1 > MAX_MESSAGE_LEN {
        return Err(VaultError::TooLarge);
    }
    if fds.is_empty() {
        let mut off = 0;
        while off < bytes.len() {
            let n = unsafe {
                libc::send(
                    stream.as_raw_fd(),
                    bytes[off..].as_ptr() as *const libc::c_void,
                    bytes.len() - off,
                    libc::MSG_NOSIGNAL,
                )
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(VaultError::from(e));
            }
            if n == 0 {
                return Err(VaultError::from(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "short send",
                )));
            }
            off += n as usize;
        }
        return Ok(());
    }

    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) as usize };
    let mut ctrl = vec![0u8; space];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = ctrl.as_mut_ptr() as *mut libc::c_void;
    hdr.msg_controllen = ctrl.len();
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&hdr);
        if cmsg.is_null() {
            return Err(VaultError::Protocol("control setup failed".into()));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as _;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr() as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of_val(fds),
        );
    }
    // First sendmsg carries FDs; any short remainder goes plain (FDs already
    // transferred). EINTR before any byte retries with FDs intact.
    let mut sent = 0usize;
    loop {
        let n = unsafe {
            if sent == 0 {
                libc::sendmsg(stream.as_raw_fd(), &hdr, libc::MSG_NOSIGNAL)
            } else {
                libc::send(
                    stream.as_raw_fd(),
                    bytes[sent..].as_ptr() as *const libc::c_void,
                    bytes.len() - sent,
                    libc::MSG_NOSIGNAL,
                )
            }
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(VaultError::from(e));
        }
        if n == 0 {
            return Err(VaultError::from(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short sendmsg",
            )));
        }
        sent += n as usize;
        if sent >= bytes.len() {
            return Ok(());
        }
    }
}
