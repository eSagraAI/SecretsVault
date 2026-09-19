//! Error taxonomy. Messages never embed secret values or key material (I1).

use std::fmt;

#[derive(Debug)]
pub enum VaultError {
    /// Wrong passphrase or unusable passphrase slot. Deliberately generic:
    /// a tampered slot is cryptographically indistinguishable from a wrong
    /// passphrase, so both must surface as the same error (no oracle).
    Auth,
    /// Operation requires an unlocked vault.
    Locked,
    /// Too many concurrent operations (run/connection caps).
    Busy,
    /// Vault envelope failed integrity or format validation.
    Corrupt(String),
    /// KDF parameters are below the accepted security minimums.
    InsecureParams,
    /// Passphrase shorter than the minimum length.
    WeakPassphrase,
    /// An interactive terminal is required but unavailable.
    HumanRequired,
    /// The vault file already exists (refused by `init`).
    Exists,
    /// The requested project or secret does not exist.
    NotFound,
    /// The authenticated identity lacks the required grant.
    Permission,
    /// A filesystem path is outside every authorized folder for the project.
    /// Static message only — never embeds the requested path.
    PathNotAuthorized,
    /// Presented lease is unknown, revoked, expired, or no longer covered
    /// by the current grant (no escalation, no oracle beyond the code).
    LeaseExpired,
    /// Presented human session is unknown, closed, idle-lapsed,
    /// absolute-lapsed, or purged by a vault lock (no oracle beyond the code).
    /// Never carries credential material.
    SessionExpired,
    /// Agent reveal without an approval: carries the pending approval id
    /// and seconds until expiry (surfaced as wire error `data`, never as
    /// part of the display message).
    ApprovalPending {
        approval_id: String,
        expires_in: u64,
    },
    /// Approval was denied by the human owner.
    ApprovalDenied,
    /// Approval was already claimed (single-use).
    ApprovalConsumed,
    /// Approval left pending past its window or claimed past its claim
    /// window.
    ApprovalExpired,
    /// A wire message exceeded the size cap.
    TooLarge,
    /// A vault mutation would produce a file the loader itself rejects
    /// (over `MAX_FILE_LEN` / `MAX_HEADER_LEN`). Refused before any write, so
    /// the previously stored vault is never replaced by an unopenable one.
    VaultTooLarge,
    /// User-controlled input failed validation (charset, length, caps).
    InvalidInput(&'static str),
    /// The vault change committed but the audit event could not be written.
    AuditWrite(String),
    /// The audit log has no room left for this event, so the operation was
    /// refused *before* changing anything. Distinct from [`Self::AuditWrite`],
    /// which means the change happened and only its record failed.
    AuditFull(&'static str),
    /// The two passphrase prompts did not match.
    Mismatch,
    /// The broker's identity could not be established: pin mismatch, failed
    /// handshake, or no pin on a non-interactive first contact. The client
    /// wrote zero credential bytes before failing.
    BrokerUntrusted(String),
    /// Filesystem error.
    Io(std::io::Error),
    /// Internal protocol/serialization misuse (never file-format parsing,
    /// which maps to `Corrupt`).
    Protocol(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth => f.write_str("authentication failed"),
            Self::Locked => f.write_str("vault is locked"),
            Self::Busy => f.write_str("too many concurrent operations"),
            Self::Corrupt(why) => write!(f, "vault file corrupted: {why}"),
            Self::InsecureParams => f.write_str("kdf parameters outside accepted bounds"),
            Self::WeakPassphrase => f.write_str("passphrase must be at least 12 characters"),
            Self::HumanRequired => {
                f.write_str("interactive passphrase required and no terminal is available; use --passphrase-file for non-interactive use")
            }
            Self::Exists => f.write_str("vault already exists"),
            Self::Mismatch => f.write_str("passphrases do not match"),
            Self::NotFound => f.write_str("not found"),
            Self::Permission => f.write_str("permission denied"),
            Self::PathNotAuthorized => f.write_str("path outside authorized folders"),
            Self::LeaseExpired => f.write_str("lease expired or revoked"),
            Self::SessionExpired => f.write_str("session expired or revoked"),
            Self::ApprovalPending { .. } => f.write_str("approval pending"),
            Self::ApprovalDenied => f.write_str("approval denied"),
            Self::ApprovalConsumed => f.write_str("approval already claimed"),
            Self::ApprovalExpired => f.write_str("approval expired"),
            Self::TooLarge => f.write_str("message too large"),
            Self::VaultTooLarge => f.write_str(
                "vault would exceed the maximum vault size; refusing to store a vault that could not be reopened",
            ),
            Self::InvalidInput(why) => write!(f, "invalid input: {why}"),
            Self::AuditWrite(e) => {
                write!(f, "vault change committed but the audit event failed to write: {e}")
            }
            Self::AuditFull(why) => write!(f, "audit log is full: {why}"),
            Self::BrokerUntrusted(why) => write!(
                f,
                "broker identity could not be verified; refusing to send credentials: {why}"
            ),
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Protocol(s) => write!(f, "protocol error: {s}"),
        }
    }
}

impl std::error::Error for VaultError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(e: serde_json::Error) -> Self {
        Self::Protocol(e.to_string())
    }
}

impl VaultError {
    /// Underlying OS error code, when the error wraps one.
    pub fn raw_os_error(&self) -> Option<i32> {
        match self {
            Self::Io(e) => e.raw_os_error(),
            _ => None,
        }
    }

    /// Stable error code for audit `reason` fields. Codes only — never
    /// dynamic messages, so no secret/path data can leak into the audit.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Auth => "E_AUTH",
            Self::Locked => "E_LOCKED",
            Self::Busy => "E_BUSY",
            Self::Corrupt(_) => "E_VAULT_CORRUPT",
            Self::InsecureParams => "E_INSECURE_PARAMS",
            Self::WeakPassphrase => "E_WEAK_PASSPHRASE",
            Self::HumanRequired => "E_HUMAN_REQUIRED",
            Self::Exists => "E_EXISTS",
            Self::NotFound => "E_NOT_FOUND",
            Self::Permission => "E_PERMISSION",
            Self::PathNotAuthorized => "E_PATH_NOT_AUTHORIZED",
            Self::LeaseExpired => "E_LEASE_EXPIRED",
            Self::SessionExpired => "E_SESSION_EXPIRED",
            Self::ApprovalPending { .. } => "E_APPROVAL_PENDING",
            Self::ApprovalDenied => "E_APPROVAL_DENIED",
            Self::ApprovalConsumed => "E_APPROVAL_CONSUMED",
            Self::ApprovalExpired => "E_APPROVAL_EXPIRED",
            Self::TooLarge => "E_TOO_LARGE",
            Self::VaultTooLarge => "E_VAULT_TOO_LARGE",
            Self::InvalidInput(_) => "E_INVALID_INPUT",
            Self::AuditWrite(_) => "E_AUDIT_WRITE",
            Self::AuditFull(_) => "E_AUDIT_FULL",
            Self::Mismatch => "E_MISMATCH",
            Self::BrokerUntrusted(_) => "E_BROKER_UNTRUSTED",
            Self::Io(_) => "E_IO",
            Self::Protocol(_) => "E_PROTOCOL",
        }
    }
}
