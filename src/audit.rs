//! Authenticated audit log: append-only JSONL with a hash chain, MACed with
//! a key derived independently from the MEK.
//!
//! Format (one JSON object per line):
//! `{ts, seq, prev_hash, hash, mac, actor, op, project, keys, target,
//!   decision, reason}` plus optional `run_with_secrets` metadata
//! (`run_id, executable, arg_count, cwd, result, exit_code, signal`),
//! skipped when absent so old canonical events verify unchanged.
//!
//! - `hash_i   = SHA-256(prev_hash_i || canonical(event_i))` where
//!   `canonical(event)` is the JSON of the entry without `hash`/`mac`
//!   (fixed field order → deterministic).
//! - `mac_i    = HMAC-SHA256(K_audit, prev_hash_i || canonical(event_i))`,
//!   present only while the vault is unlocked. Semantics: valid MAC =
//!   authenticated; `mac: null` (entries written while locked, or forged at
//!   the tail) = unauthenticated — a later MAC anchors the entry's position
//!   and bytes but never its provenance.
//! - genesis `prev_hash` is 32 zero bytes.
//!
//! Redaction is structural: the append API accepts only key *names*, the
//! project name and a target path — there is no parameter a secret value,
//! passphrase or token could travel through.
//!
//! Documented v1 limits (accepted): tail truncation after the last MACed
//! entry is undetectable (no external anchor); a writer holding `K_audit`
//! (root or the unlocked daemon's memory) can recompute MACs.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::crypto::{KEY_LEN, SecretKey};
use crate::error::VaultError;

/// HKDF info label binding `K_audit` to its purpose (spec-frozen).
pub const AUDIT_INFO: &[u8] = b"svault/audit-mac/v1";

/// Hard ceiling on the audit log file (L2).
///
/// The log previously grew without bound, and every append (`stage`) re-reads
/// and re-parses the whole file to recover the chain head — so both disk use
/// and per-operation cost grew linearly with history. This caps the disk and
/// the per-append work by refusing further appends once the file reaches the
/// limit.
///
/// The refusal is **fail closed and loud**: the op that needed the entry fails
/// with `E_AUDIT_WRITE` rather than proceeding unaudited, and nothing is
/// truncated or rewritten — history that is there stays byte-identical and
/// keeps verifying. Rotation/archival is the designed replacement and is
/// post-MVP; until then a vault that reaches this ceiling needs an operator,
/// which is the honest failure mode for an append-only audit trail.
///
/// Sized to match the vault's own `MAX_FILE_LEN`, which is the defensible
/// anchor: a typical entry is ~400 bytes, so this is roughly 40k events —
/// years of a single-operator vault.
///
/// The ceiling also bounds the per-append cost, which is what makes the cap
/// load-bearing rather than cosmetic: `resync` re-parses the log on every
/// append, measured at 0.055 ms for a 320-byte log, 0.13 ms at 16 KiB and
/// 0.52 ms at 100 KiB — linear in file size. At this ceiling that is tens of
/// milliseconds per operation, not seconds, and it cannot grow beyond it.
/// Making appends O(1) means recovering the chain head from the file tail
/// instead of a full parse; that is a change to a security-relevant routine
/// and belongs with rotation, post-MVP.
pub const MAX_AUDIT_LEN: u64 = crate::envelope::MAX_FILE_LEN as u64;

/// Operational ceiling for **ordinary** operations: they are refused once the
/// log would pass it, leaving [`AUDIT_HEADROOM`] bytes that only lifecycle
/// events may spend.
///
/// The reserve exists because the two kinds of append are not equivalent.
/// An ordinary mutation that cannot be recorded must not happen at all, so it
/// is refused *before* touching the vault. A lifecycle event — `vault.lock`,
/// the idle auto-lock, a capability revocation, a drained run — is the
/// opposite: refusing to record it must never prevent the security action it
/// describes, and losing the ability to lock the vault because the audit is
/// full would invert the point of locking.
pub const AUDIT_SOFT_LIMIT: u64 = MAX_AUDIT_LEN - AUDIT_HEADROOM;

/// Bytes reserved below [`MAX_AUDIT_LEN`] for lifecycle events. Sized for a
/// few thousand events at ~400 bytes each, far more than any shutdown path
/// needs; the hard cap still bounds total growth.
pub const AUDIT_HEADROOM: u64 = 2 * 1024 * 1024;

/// Whether an event may spend the reserved headroom *and* may proceed
/// unrecorded. Everything else pays the ordinary soft limit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Priority {
    /// An ordinary operation. It may not proceed unaudited: if its entry cannot
    /// be written it is refused and changes nothing.
    Ordinary,
    /// An authority-reducing or authority-holding security action (revocation,
    /// lock, auto-lock, run drain). Spending the reserve is a *preference*, not
    /// the point: if even the reserve is gone the action still happens. A
    /// revocation that cannot be recorded would otherwise leave the capability
    /// alive. The checkpoint is then left on the last entry that really exists,
    /// so the vault stays coherent and loadable.
    Lifecycle,
}

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allowed,
    Denied,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
        })
    }
}

/// The authenticated content of one audit entry (everything but `hash`/`mac`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditEvent {
    /// RFC3339 timestamp.
    pub ts: String,
    pub seq: u64,
    pub prev_hash: String,
    /// `human` in Phase 2; `agent:<id>` / `lease:<id>` arrive with the broker.
    pub actor: String,
    pub op: String,
    pub project: Option<String>,
    /// Key *names* only — the API cannot carry values.
    pub keys: Vec<String>,
    pub target: Option<String>,
    pub decision: Decision,
    /// Stable error code (`E_*`), never a dynamic message.
    pub reason: Option<String>,
    /// Optional `run_with_secrets` metadata. `None` fields are skipped in
    /// serialization, so events written before Phase 5 keep byte-identical
    /// canonical form (old logs keep verifying).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Executable path only — never argv.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    /// Number of argv elements — never the argv itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Stable outcome token (e.g. `"exited"`), never dynamic output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Final signal string as safe status metadata (e.g. `"TERM (15)"`).
    /// `None` skipped so old canonical log bytes remain unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

/// One stored line: event plus integrity fields.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditLine {
    #[serde(flatten)]
    pub event: AuditEvent,
    pub hash: String,
    pub mac: Option<String>,
}

impl std::fmt::Display for AuditLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "#{} {} {} {} {}",
            self.event.seq, self.event.ts, self.event.actor, self.event.op, self.event.decision
        )?;
        if let Some(r) = &self.event.reason {
            write!(f, " reason={r}")?;
        }
        if let Some(p) = &self.event.project {
            write!(f, " project={p}")?;
        }
        if !self.event.keys.is_empty() {
            write!(f, " keys={:?}", self.event.keys)?;
        }
        if let Some(t) = &self.event.target {
            write!(f, " target={t}")?;
        }
        if let Some(run_id) = &self.event.run_id {
            write!(f, " run_id={run_id}")?;
        }
        if let Some(exe) = &self.event.executable {
            write!(f, " executable={exe}")?;
        }
        if let Some(n) = self.event.arg_count {
            write!(f, " arg_count={n}")?;
        }
        if let Some(cwd) = &self.event.cwd {
            write!(f, " cwd={cwd}")?;
        }
        if let Some(r) = &self.event.result {
            write!(f, " result={r}")?;
        }
        if let Some(code) = self.event.exit_code {
            write!(f, " exit_code={code}")?;
        }
        if let Some(sig) = &self.event.signal {
            write!(f, " signal={sig}")?;
        }
        // proof of authorship/integrity — a later MAC anchors its bytes but
        // does not authenticate its provenance.
        if self.mac.is_none() {
            f.write_str(" [unauthenticated]")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VerifyReport {
    pub entries: usize,
    pub macs_verified: usize,
    pub macs_null: usize,
}

/// One log entry to record. Only metadata travels here; there is no field a
/// secret value could occupy.
pub struct Record<'a> {
    /// `"human"` or `"agent:<id>"` — who the log attributes the entry to.
    pub actor: &'a str,
    pub op: &'a str,
    pub project: Option<&'a str>,
    pub keys: &'a [String],
    pub target: Option<&'a Path>,
    pub decision: Decision,
    pub reason: Option<&'a str>,
}
/// One `run_with_secrets` entry to record. Structurally safe by
/// construction: there is no field that could carry argv, environment
/// values, or secret bytes — only the executable path, the argv *count*,
/// cwd, key *names*, stable outcome tokens and numeric exit status.
pub struct RunRecord<'a> {
    /// `"agent:<id>"` — who the log attributes the entry to.
    pub actor: &'a str,
    pub project: Option<&'a str>,
    /// Key *names* only — the API cannot carry values.
    pub keys: &'a [String],
    /// Correlating run id (allocated before spawn; present on a denial
    /// only when one was allocated before rejection).
    pub run_id: Option<&'a str>,
    /// Executable path as invoked (allowed/start/exit only; denials scrub it).
    pub executable: Option<&'a str>,
    /// Number of argv elements (never the argv itself).
    pub arg_count: Option<u64>,
    pub cwd: Option<&'a Path>,
    pub decision: Decision,
    /// Stable error code (`E_*`), never a dynamic message.
    pub reason: Option<&'a str>,
    /// Stable outcome token (e.g. `"exited"`), never dynamic output.
    pub result: Option<&'a str>,
    pub exit_code: Option<i32>,
    /// Final signal string as safe status metadata (e.g. `"TERM (15)"`).
    /// Caller-provided display string only — never argv/env/values.
    pub signal: Option<&'a str>,
}

/// Derive the audit MAC key from the MEK via HKDF-SHA256 with the frozen info
/// label: an independent subkey, never the MEK or DEK itself.
pub fn derive_audit_key(mek: &SecretKey) -> SecretKey {
    let hk = Hkdf::<Sha256>::new(None, mek.as_bytes());
    let mut out = [0u8; KEY_LEN];
    hk.expand(AUDIT_INFO, &mut out)
        .expect("hkdf expand with valid output length cannot fail");
    SecretKey::from_bytes(out)
}

fn entry_hash(prev_hash: &[u8; 32], event: &AuditEvent) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(canonical(event));
    hasher.finalize().into()
}

fn entry_mac(mac_key: &SecretKey, prev_hash: &[u8; 32], event: &AuditEvent) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(mac_key.as_bytes()).expect("hmac accepts any key length");
    mac.update(prev_hash);
    mac.update(&canonical(event));
    mac.finalize().into_bytes().into()
}

fn canonical(event: &AuditEvent) -> Vec<u8> {
    serde_json::to_vec(event).expect("audit event serialization cannot fail")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<[u8; 32], VaultError> {
    let mut out = [0u8; 32];
    if s.len() != out.len() * 2 {
        return Err(VaultError::Corrupt("audit hex field length".into()));
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| VaultError::Corrupt("audit hex field".into()))?;
    }
    Ok(out)
}

/// A staged entry: built against a log head but not yet written. The vault
/// embeds `seq`/`hash_hex` as its audit checkpoint before committing, then
/// the entry is appended; any gap between the two is detectable forever.
pub struct StagedEntry {
    pub event: AuditEvent,
    pub hash_hex: String,
    pub mac_hex: Option<String>,
}

impl StagedEntry {
    /// Compute and attach the MAC after staging (same event bytes, same
    /// hash) — used when the key becomes available between staging and
    /// appending, e.g. at vault creation.
    pub fn mac_with(&mut self, key: &SecretKey) {
        let prev = unhex(&self.event.prev_hash).expect("staged prev_hash is internal hex");
        self.mac_hex = Some(hex(&entry_mac(key, &prev, &self.event)));
    }
}

/// Verify that the audit log has advanced at least to `head_seq` and that
/// the entry at `head_seq` is exactly `head_hash` — i.e. the log is not
/// behind the vault's checkpoint. Entries beyond the checkpoint (later
/// reads/denials) are legitimate and unchecked here; chain/MAC verification
/// is `verify`'s job.
pub fn check_checkpoint(path: &Path, head_seq: u64, head_hash: &str) -> Result<(), VaultError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| VaultError::Corrupt(format!("audit unreadable: {e}")))?;
    let mut prev = [0u8; 32];
    let mut seq: u64 = 0;
    for line in content.lines().filter(|l| !l.is_empty()) {
        let parsed: AuditLine = serde_json::from_str(line)
            .map_err(|_| VaultError::Corrupt("audit line invalid".into()))?;
        seq += 1;
        if parsed.event.seq != seq {
            return Err(VaultError::Corrupt("audit seq out of order".into()));
        }
        let computed = entry_hash(&prev, &parsed.event);
        if seq == head_seq {
            if unhex(&parsed.hash)? != computed || parsed.hash != head_hash {
                return Err(VaultError::Corrupt(
                    "audit log diverges from the vault checkpoint".into(),
                ));
            }
            return Ok(());
        }
        prev = computed;
    }
    Err(VaultError::Corrupt(
        "audit log is behind the vault checkpoint: the event for the last vault change is missing"
            .into(),
    ))
}

/// Append-only audit log bound to a file, tracking the chain head.
pub struct AuditLog {
    path: PathBuf,
    seq: u64,
    last_hash: [u8; 32],
    /// Ceilings in force for this log. Defaults to the constants; tests inject
    /// small values so the ceiling can be reached without writing megabytes.
    limits: Limits,
}

/// The ceilings a log enforces. See [`AUDIT_SOFT_LIMIT`] / [`MAX_AUDIT_LEN`].
#[derive(Clone, Copy, Debug)]
struct Limits {
    soft: u64,
    hard: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            soft: AUDIT_SOFT_LIMIT,
            hard: MAX_AUDIT_LEN,
        }
    }
}

impl AuditLog {
    /// Open the log, creating an empty file (mode 0600) when missing, and
    /// validate structural integrity (seq continuity, hash linkage and
    /// correctness — public checks, no key needed).
    pub fn load_or_init(path: &Path) -> Result<Self, VaultError> {
        if !path.exists() {
            let f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            f.sync_all()?;
            return Ok(Self {
                path: path.to_path_buf(),
                seq: 0,
                last_hash: [0u8; 32],
                limits: Limits::default(),
            });
        }
        let (report, last_hash) = Self::walk(path, None)?;
        Ok(Self {
            path: path.to_path_buf(),
            seq: report.entries as u64,
            last_hash,
            limits: Limits::default(),
        })
    }

    /// Build the next entry for this log without touching it. Returns the
    /// event, its chain hash (hex) and the MAC (hex) when a key is provided.
    /// Used to embed an audit checkpoint inside a vault before the vault is
    /// committed, so vault and audit can be checked for coherence later.
    pub fn stage(
        &self,
        record: Record,
        mac_key: Option<&SecretKey>,
        priority: Priority,
    ) -> Result<StagedEntry, VaultError> {
        // Multi-writer coherence: re-read the file tail before computing the
        // next seq/hash.
        let mut synced = Self {
            path: self.path.clone(),
            seq: self.seq,
            last_hash: self.last_hash,
            limits: self.limits,
        };
        synced.resync();
        let event = AuditEvent {
            ts: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map_err(|e| VaultError::Protocol(format!("audit timestamp: {e}")))?,
            seq: synced.seq + 1,
            prev_hash: hex(&synced.last_hash),
            actor: record.actor.to_string(),
            op: record.op.to_string(),
            project: record.project.map(str::to_string),
            keys: record.keys.to_vec(),
            target: record.target.map(|p| p.to_string_lossy().into_owned()),
            decision: record.decision,
            reason: record.reason.map(str::to_string),
            run_id: None,
            executable: None,
            arg_count: None,
            cwd: None,
            result: None,
            exit_code: None,
            signal: None,
        };
        // L2 + lifecycle: refuse *before* anything is written when this exact
        // entry would not fit. Measuring the serialized line (rather than just
        // the current file length) is what makes the ceiling a real bound —
        // comparing file length alone lets an entry overshoot it.
        synced.preflight(&event, priority)?;
        let hash = entry_hash(&synced.last_hash, &event);
        let mac = mac_key.map(|k| hex(&entry_mac(k, &synced.last_hash, &event)));
        Ok(StagedEntry {
            event,
            hash_hex: hex(&hash),
            mac_hex: mac,
        })
    }

    /// Refuse an append that would not fit, before it is written.
    ///
    /// `Priority` chooses the ceiling: ordinary operations stop at the soft
    /// limit (leaving the reserve intact), lifecycle events may use the whole
    /// hard cap. Both compare the *resulting* file size, so neither can
    /// overshoot its ceiling by one entry.
    fn preflight(&self, event: &AuditEvent, priority: Priority) -> Result<(), VaultError> {
        let path = &self.path;
        let probe = serde_json::to_string(&AuditLine {
            event: event.clone(),
            hash: "0".repeat(64),
            mac: Some("0".repeat(64)),
        })
        .map_err(|_| VaultError::Protocol("audit line serialization failed".into()))?;
        let projected =
            std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) + probe.len() as u64 + 1;
        let ceiling = match priority {
            Priority::Ordinary => self.limits.soft,
            Priority::Lifecycle => self.limits.hard,
        };
        if projected > ceiling {
            return match priority {
                // Ordinary: refuse before the vault is touched. The caller has
                // not written anything yet, so nothing needs undoing.
                Priority::Ordinary => Err(VaultError::AuditFull(
                    "refused before any change; rotation is post-MVP",
                )),
                // Lifecycle: the security action must still happen. Past the
                // hard cap the entry cannot be written at all; the caller
                // treats a lifecycle audit failure as non-fatal so the lock,
                // revocation and zeroization still complete.
                Priority::Lifecycle => Err(VaultError::AuditWrite(
                    "audit log reached its hard ceiling".into(),
                )),
            };
        }
        Ok(())
    }

    /// Write a previously staged entry. Verifies it chains from the current
    /// head, fsyncs, then advances the head. The MAC travels inside the
    /// staged entry (computed at stage time or via `mac_with`).
    pub fn append_staged(&mut self, staged: &StagedEntry) -> Result<(), VaultError> {
        self.resync();
        if staged.event.seq != self.seq + 1 || unhex(&staged.event.prev_hash)? != self.last_hash {
            return Err(VaultError::Protocol(
                "staged audit entry does not chain from the log head".into(),
            ));
        }
        let recomputed = entry_hash(&self.last_hash, &staged.event);
        if hex(&recomputed) != staged.hash_hex {
            return Err(VaultError::Protocol("staged audit hash mismatch".into()));
        }
        let line = AuditLine {
            event: staged.event.clone(),
            hash: staged.hash_hex.clone(),
            mac: staged.mac_hex.clone(),
        };
        let mut f = OpenOptions::new().append(true).open(&self.path)?;
        writeln!(
            f,
            "{}",
            serde_json::to_string(&line).expect("audit line serialization cannot fail")
        )?;
        f.sync_all()?;
        self.seq += 1;
        self.last_hash = recomputed;
        Ok(())
    }

    /// Append one record built now; MACed when `mac_key` is present (vault
    /// unlocked), `mac: null` otherwise. Convenience for events that do not
    /// need a vault-side checkpoint.
    pub fn append(
        &mut self,
        record: Record,
        mac_key: Option<&SecretKey>,
        priority: Priority,
    ) -> Result<(), VaultError> {
        let staged = self.stage(record, mac_key, priority)?;
        self.append_staged(&staged)
    }
    /// Build the next `run_with_secrets` entry without touching the log.
    /// The op is fixed (callers cannot relabel it) and `target` stays empty:
    /// run identity travels in the dedicated `run_*` fields, never in argv.
    pub fn stage_run(
        &self,
        record: RunRecord,
        mac_key: Option<&SecretKey>,
        priority: Priority,
    ) -> Result<StagedEntry, VaultError> {
        let mut synced = Self {
            path: self.path.clone(),
            seq: self.seq,
            last_hash: self.last_hash,
            limits: self.limits,
        };
        synced.resync();
        let event = AuditEvent {
            ts: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map_err(|e| VaultError::Protocol(format!("audit timestamp: {e}")))?,
            seq: synced.seq + 1,
            prev_hash: hex(&synced.last_hash),
            actor: record.actor.to_string(),
            op: "run_with_secrets".to_string(),
            project: record.project.map(str::to_string),
            keys: record.keys.to_vec(),
            target: None,
            decision: record.decision,
            reason: record.reason.map(str::to_string),
            run_id: record.run_id.map(str::to_string),
            executable: record.executable.map(str::to_string),
            arg_count: record.arg_count,
            cwd: record.cwd.map(|p| p.to_string_lossy().into_owned()),
            result: record.result.map(str::to_string),
            exit_code: record.exit_code,
            signal: record.signal.map(str::to_string),
        };
        synced.preflight(&event, priority)?;
        let hash = entry_hash(&synced.last_hash, &event);
        let mac = mac_key.map(|k| hex(&entry_mac(k, &synced.last_hash, &event)));
        Ok(StagedEntry {
            event,
            hash_hex: hex(&hash),
            mac_hex: mac,
        })
    }

    /// Append one run record built now; MACed when `mac_key` is present
    /// (vault unlocked), `mac: null` otherwise. Run events never checkpoint
    /// into the vault, so there is no staged/commit variant.
    pub fn append_run(
        &mut self,
        record: RunRecord,
        mac_key: Option<&SecretKey>,
        priority: Priority,
    ) -> Result<(), VaultError> {
        let staged = self.stage_run(record, mac_key, priority)?;
        self.append_staged(&staged)
    }

    /// Re-read the file tail and advance the cached head if the file has
    /// grown. Detects duplicate-seq conflicts by refusing to append when the
    /// file's last entry does not match our cached head (a divergent writer).
    fn resync(&mut self) {
        let Ok(content) = std::fs::read_to_string(&self.path) else {
            return;
        };
        let mut prev = [0u8; 32];
        let mut seq: u64 = 0;
        for line in content.lines().filter(|l| !l.is_empty()) {
            let Ok(parsed) = serde_json::from_str::<AuditLine>(line) else {
                return;
            };
            seq += 1;
            if parsed.event.seq != seq {
                return; // divergent file; leave our state as-is (verify will fail closed)
            }
            prev = match unhex(&parsed.hash) {
                Ok(h) => h,
                Err(_) => return,
            };
        }
        if seq > self.seq {
            self.seq = seq;
            self.last_hash = prev;
        } else if seq < self.seq {
            // The file was truncated relative to our view: a subsequent
            // verify will fail closed. Do not rewind our head (would
            // duplicate seqs); leave as-is and let verify catch it.
        }
    }

    /// Full verification walk: structural chain for every entry plus HMAC
    /// verification for every MACed entry when `mac_key` is provided.
    /// Fails closed on modification, reordering or deletion of any entry
    /// covered by a later MAC.
    pub fn verify(path: &Path, mac_key: Option<&SecretKey>) -> Result<VerifyReport, VaultError> {
        Ok(Self::walk(path, mac_key)?.0)
    }

    /// Single structural walk: seq continuity, hash linkage/correctness and,
    /// when a key is provided, HMAC verification of every present MAC.
    fn walk(
        path: &Path,
        mac_key: Option<&SecretKey>,
    ) -> Result<(VerifyReport, [u8; 32]), VaultError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| VaultError::Corrupt(format!("audit unreadable: {e}")))?;
        let mut prev = [0u8; 32];
        let mut seq: u64 = 0;
        let mut report = VerifyReport {
            entries: 0,
            macs_verified: 0,
            macs_null: 0,
        };
        for line in content.lines().filter(|l| !l.is_empty()) {
            let parsed: AuditLine = serde_json::from_str(line)
                .map_err(|_| VaultError::Corrupt("audit line invalid".into()))?;
            seq += 1;
            if parsed.event.seq != seq {
                return Err(VaultError::Corrupt("audit seq out of order".into()));
            }
            if unhex(&parsed.event.prev_hash)? != prev {
                return Err(VaultError::Corrupt("audit chain linkage broken".into()));
            }
            let computed = entry_hash(&prev, &parsed.event);
            if unhex(&parsed.hash)? != computed {
                return Err(VaultError::Corrupt("audit hash mismatch".into()));
            }
            match (&parsed.mac, mac_key) {
                (Some(mac_hex), Some(key)) => {
                    let mut mac =
                        HmacSha256::new_from_slice(key.as_bytes()).expect("hmac key length");
                    mac.update(&unhex(&parsed.event.prev_hash)?);
                    mac.update(&canonical(&parsed.event));
                    if mac.verify_slice(&unhex(mac_hex)?).is_err() {
                        return Err(VaultError::Corrupt("audit mac mismatch".into()));
                    }
                    report.macs_verified += 1;
                }
                _ => report.macs_null += 1,
            }
            prev = computed;
            report.entries += 1;
        }
        Ok((report, prev))
    }

    /// All stored lines in file order (ascending `seq`).
    pub fn read_all(path: &Path) -> Result<Vec<AuditLine>, VaultError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| VaultError::Corrupt(format!("audit unreadable: {e}")))?;
        content
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                serde_json::from_str(l)
                    .map_err(|_| VaultError::Corrupt("audit line invalid".into()))
            })
            .collect::<Result<_, _>>()
    }

    /// Last `n` stored lines (rendering is the caller's concern).
    pub fn tail(path: &Path, n: usize) -> Result<Vec<AuditLine>, VaultError> {
        let mut lines = Self::read_all(path)?;
        let start = lines.len().saturating_sub(n);
        lines.drain(..start);
        Ok(lines)
    }

    /// Replace both ceilings. Test-only seam: it exists so the ceiling can be
    /// reached deterministically without writing megabytes of history, which
    /// would also make the test quadratically slow (`resync` re-parses the
    /// whole log on every append).
    #[doc(hidden)]
    pub fn set_limits_for_test(&mut self, soft: u64, hard: u64) {
        self.limits = Limits { soft, hard };
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// L2: the ceiling is enforced fail-closed — the append is refused, and
    /// nothing already in the log is truncated or rewritten.
    #[test]
    fn audit_growth_ceiling_is_fail_closed() {
        let dir = crate::testutil::TestDir::new();
        let path = dir.path().join("audit.jsonl");
        let mut log = AuditLog::load_or_init(&path).unwrap();
        // Small ceilings: the boundary is reached in a few real entries rather
        // than by writing megabytes.
        log.set_limits_for_test(8 * 1024, 16 * 1024);
        fn rec<'a>(keys: &'a [String]) -> Record<'a> {
            Record {
                actor: "human",
                op: "secret.set",
                project: Some("acme"),
                keys,
                target: None,
                decision: Decision::Allowed,
                reason: None,
            }
        }

        // Ordinary appends succeed until the soft limit.
        let mut refused = None;
        for i in 0..500 {
            let keys = vec![format!("K{i}")];
            match log.append(rec(&keys), None, Priority::Ordinary) {
                Ok(()) => {}
                Err(e) => {
                    refused = Some(e);
                    break;
                }
            }
        }
        let err = refused.expect("the soft limit must eventually refuse");
        assert_eq!(err.code(), "E_AUDIT_FULL", "got {err}");

        let after_refusal = std::fs::read_to_string(&path).unwrap();
        let len = std::fs::metadata(&path).unwrap().len();
        assert!(
            len <= 8 * 1024 + 1024,
            "an ordinary append must not overshoot the soft limit: {len}"
        );

        // The refused entry was not written, and nothing was truncated.
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            len,
            "a refused append writes nothing"
        );

        // Lifecycle may still spend the reserve, but never past the hard cap.
        let mut life = 0;
        let live = vec!["L".to_string()];
        while log.append(rec(&live), None, Priority::Lifecycle).is_ok() {
            life += 1;
            assert!(life < 1000, "lifecycle must also hit the hard cap");
        }
        let len = std::fs::metadata(&path).unwrap().len();
        assert!(
            len <= 16 * 1024,
            "the hard cap must bound lifecycle events too: {len}"
        );
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .starts_with(&after_refusal),
            "existing history must stay byte-identical"
        );
    }
    use crate::testutil::TestDir;

    fn key() -> SecretKey {
        SecretKey::generate()
    }

    fn rec(op: &str) -> Record<'_> {
        Record {
            actor: "human",
            op,
            project: Some("acme"),
            keys: &[],
            target: None,
            decision: Decision::Allowed,
            reason: None,
        }
    }

    fn read_lines(path: &Path) -> Vec<AuditLine> {
        let content = std::fs::read_to_string(path).unwrap();
        content
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn write_lines(path: &Path, lines: &[AuditLine]) {
        let mut out = String::new();
        for l in lines {
            out.push_str(&serde_json::to_string(l).unwrap());
            out.push('\n');
        }
        std::fs::write(path, out).unwrap();
    }

    /// A keyless attacker rewrites content and recomputes the public hash
    /// chain, but cannot forge the HMACs of untouched later entries.
    fn attacker_recompute(lines: &mut [AuditLine]) {
        let mut prev = [0u8; 32];
        for l in lines.iter_mut() {
            l.event.prev_hash = hex(&prev);
            l.hash = hex(&entry_hash(&prev, &l.event));
            prev = entry_hash(&prev, &l.event);
        }
    }

    #[test]
    fn audit_key_is_a_deterministic_independent_subkey() {
        let mek = key();
        let a = derive_audit_key(&mek);
        let b = derive_audit_key(&mek);
        assert_eq!(a.as_bytes(), b.as_bytes());
        let other = derive_audit_key(&key());
        assert_ne!(a.as_bytes(), other.as_bytes());
    }

    #[test]
    fn append_and_verify_roundtrip_with_and_without_key() {
        let dir = TestDir::new();
        let path = dir.path().join("audit.jsonl");
        let k = key();
        let mut log = AuditLog::load_or_init(&path).unwrap();

        log.append(rec("vault.created"), Some(&k), Priority::Ordinary)
            .unwrap();
        log.append(rec("vault.locked"), None, Priority::Lifecycle)
            .unwrap(); // locked period: mac null
        log.append(rec("vault.unlocked"), Some(&k), Priority::Lifecycle)
            .unwrap();

        let report = AuditLog::verify(&path, Some(&k)).unwrap();
        assert_eq!(report.entries, 3);
        assert_eq!(report.macs_verified, 2);
        assert_eq!(report.macs_null, 1);

        // Without the key only the chain is checked; tampered content with
        // recomputed hashes is NOT detectable (documented limit).
        let report = AuditLog::verify(&path, None).unwrap();
        assert_eq!(report.entries, 3);
    }

    #[test]
    fn tampering_a_maced_entry_fails_verification() {
        let dir = TestDir::new();
        let path = dir.path().join("audit.jsonl");
        let k = key();
        let mut log = AuditLog::load_or_init(&path).unwrap();
        log.append(rec("project.add"), Some(&k), Priority::Ordinary)
            .unwrap();
        log.append(rec("secret.set"), Some(&k), Priority::Ordinary)
            .unwrap();

        let mut lines = read_lines(&path);
        lines[0].event.op = "secret.delete".into(); // rewrite history
        write_lines(&path, &lines);
        assert!(AuditLog::verify(&path, Some(&k)).is_err());
    }

    #[test]
    fn reordering_entries_fails_verification() {
        let dir = TestDir::new();
        let path = dir.path().join("audit.jsonl");
        let k = key();
        let mut log = AuditLog::load_or_init(&path).unwrap();
        log.append(rec("project.add"), Some(&k), Priority::Ordinary)
            .unwrap();
        log.append(rec("secret.set"), Some(&k), Priority::Ordinary)
            .unwrap();
        log.append(rec("secret.delete"), Some(&k), Priority::Ordinary)
            .unwrap();

        let mut lines = read_lines(&path);
        lines.swap(0, 1);
        write_lines(&path, &lines);
        assert!(AuditLog::verify(&path, Some(&k)).is_err());
    }

    #[test]
    fn deleting_a_maced_entry_fails_verification() {
        let dir = TestDir::new();
        let path = dir.path().join("audit.jsonl");
        let k = key();
        let mut log = AuditLog::load_or_init(&path).unwrap();
        log.append(rec("project.add"), Some(&k), Priority::Ordinary)
            .unwrap();
        log.append(rec("secret.set"), Some(&k), Priority::Ordinary)
            .unwrap();
        log.append(rec("secret.delete"), Some(&k), Priority::Ordinary)
            .unwrap();

        let lines = read_lines(&path);
        let mut kept = lines.clone();
        kept.remove(1); // remove a middle authenticated entry
        write_lines(&path, &kept);
        assert!(AuditLog::verify(&path, Some(&k)).is_err());
    }

    #[test]
    fn keyless_forge_with_recomputed_hashes_is_detected_by_macs() {
        let dir = TestDir::new();
        let path = dir.path().join("audit.jsonl");
        let k = key();
        let mut log = AuditLog::load_or_init(&path).unwrap();
        log.append(rec("project.add"), Some(&k), Priority::Ordinary)
            .unwrap();
        log.append(rec("secret.set"), Some(&k), Priority::Ordinary)
            .unwrap();

        let mut lines = read_lines(&path);
        lines[0].event.op = "forged.op".into();
        attacker_recompute(&mut lines);
        write_lines(&path, &lines);
        assert!(AuditLog::verify(&path, Some(&k)).is_err());
    }

    #[test]
    fn tail_truncation_after_last_maced_entry_is_undetectable() {
        // Documented v1 limit (spec'd behavior): truncating the tail after
        // the last MACed entry is not detectable without an external anchor.
        let dir = TestDir::new();
        let path = dir.path().join("audit.jsonl");
        let k = key();
        let mut log = AuditLog::load_or_init(&path).unwrap();
        log.append(rec("project.add"), Some(&k), Priority::Ordinary)
            .unwrap();
        log.append(rec("vault.locked"), None, Priority::Lifecycle)
            .unwrap(); // unauthenticated tail

        let mut lines = read_lines(&path);
        lines.truncate(1);
        write_lines(&path, &lines);
        assert!(AuditLog::verify(&path, Some(&k)).is_ok());
    }

    #[test]
    fn file_mode_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new();
        let path = dir.path().join("audit.jsonl");
        AuditLog::load_or_init(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn offline_null_insertion_before_a_maced_entry_is_detected() {
        // A keyless attacker forging a well-formed mac:null entry BEFORE a
        // later MACed entry shifts the chain: the untouched entry's MAC no
        // longer matches → detected at verification.
        let dir = TestDir::new();
        let path = dir.path().join("audit.jsonl");
        let k = key();
        let mut log = AuditLog::load_or_init(&path).unwrap();
        log.append(rec("project.add"), Some(&k), Priority::Ordinary)
            .unwrap();
        log.append(rec("secret.set"), Some(&k), Priority::Ordinary)
            .unwrap();

        let mut lines = read_lines(&path);
        let prev = unhex(&lines[0].hash).unwrap();
        let mut forged = AuditLine {
            event: AuditEvent {
                ts: lines[0].event.ts.clone(),
                seq: 2,
                prev_hash: hex(&prev),
                actor: "human".into(),
                op: "forged.secret.set".into(),
                project: Some("ghost".into()),
                keys: vec!["KEY".into()],
                target: None,
                decision: Decision::Allowed,
                reason: None,
                run_id: None,
                executable: None,
                arg_count: None,
                cwd: None,
                result: None,
                exit_code: None,
                signal: None,
            },
            hash: String::new(),
            mac: None,
        };
        forged.hash = hex(&entry_hash(&prev, &forged.event));
        lines.insert(1, forged);
        attacker_recompute(&mut lines);
        write_lines(&path, &lines);
        assert!(AuditLog::verify(&path, Some(&k)).is_err());
    }

    #[test]
    fn offline_null_insertion_at_tail_is_chained_but_unauthenticated() {
        // Documented semantics: a well-formed mac:null entry forged at the
        // tail (after the last MACed entry) chains correctly and the log is
        // structurally valid — but the entry is NOT authenticated (mac stays
        // null); a later MAC can anchor its bytes, never its provenance.
        let dir = TestDir::new();
        let path = dir.path().join("audit.jsonl");
        let k = key();
        let mut log = AuditLog::load_or_init(&path).unwrap();
        log.append(rec("project.add"), Some(&k), Priority::Ordinary)
            .unwrap();

        let mut lines = read_lines(&path);
        let prev = unhex(&lines[0].hash).unwrap();
        let mut forged = AuditLine {
            event: AuditEvent {
                ts: lines[0].event.ts.clone(),
                seq: 2,
                prev_hash: hex(&prev),
                actor: "human".into(),
                op: "forged.secret.set".into(),
                project: Some("ghost".into()),
                keys: vec!["KEY".into()],
                target: None,
                decision: Decision::Allowed,
                reason: None,
                run_id: None,
                executable: None,
                arg_count: None,
                cwd: None,
                result: None,
                exit_code: None,
                signal: None,
            },
            hash: String::new(),
            mac: None,
        };
        forged.hash = hex(&entry_hash(&prev, &forged.event));
        lines.push(forged.clone());
        write_lines(&path, &lines);

        let report = AuditLog::verify(&path, Some(&k)).unwrap();
        assert_eq!(report.macs_verified, 1);
        assert_eq!(report.macs_null, 1);
        assert!(lines[1].mac.is_none());
    }

    #[test]
    fn display_marks_unauthenticated_entries() {
        let dir = TestDir::new();
        let path = dir.path().join("audit.jsonl");
        let k = key();
        let mut log = AuditLog::load_or_init(&path).unwrap();
        log.append(rec("project.add"), Some(&k), Priority::Ordinary)
            .unwrap();
        log.append(rec("vault.locked"), None, Priority::Lifecycle)
            .unwrap();
        let lines = AuditLog::tail(&path, 10).unwrap();
        assert!(!format!("{}", lines[0]).contains("unauthenticated"));
        assert!(format!("{}", lines[1]).contains("[unauthenticated]"));
    }

    #[test]
    fn checkpoint_coherence_is_checkable() {
        let dir = TestDir::new();
        let path = dir.path().join("audit.jsonl");
        let k = key();
        let mut log = AuditLog::load_or_init(&path).unwrap();
        let staged = log
            .stage(rec("vault.created"), Some(&k), Priority::Ordinary)
            .unwrap();
        log.append_staged(&staged).unwrap();

        // Checkpoint present and matching → coherent.
        assert!(check_checkpoint(&path, staged.event.seq, &staged.hash_hex).is_ok());
        // Wrong hash at the checkpoint seq → divergence.
        assert!(check_checkpoint(&path, staged.event.seq, &"f".repeat(64)).is_err());
        // Checkpoint beyond the file → the log is behind the vault.
        assert!(check_checkpoint(&path, staged.event.seq + 1, &staged.hash_hex).is_err());
    }
}
