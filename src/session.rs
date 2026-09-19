//! Vault session: in-memory unlocked state with idle auto-lock, human
//! operations on projects/secrets, and authenticated audit logging.
//!
//! Mutation semantics (documented contract):
//! 1. mutations apply to a clone; the session adopts them only after the
//!    atomic vault save succeeds (all-or-nothing for the vault);
//! 2. the audit entry is staged first and appended (fsync) **before** the
//!    vault is replaced, and its `{seq, hash}` checkpoint is embedded in the
//!    sealed document. An entry is only ever written ahead of the vault that
//!    names it, because a vault naming a missing entry can never be unlocked
//!    again; the reverse (an entry no vault names) is harmless;
//! 3. an ordinary mutation whose entry cannot be written fails closed and
//!    changes nothing (`E_AUDIT_FULL` / `E_AUDIT_WRITE`). An authority-reducing
//!    lifecycle operation (revocation) is applied anyway and leaves the
//!    checkpoint on the last entry that exists, so coherence holds;
//! 4. `unlock` verifies the full audit chain (and MACs with `K_audit`) plus
//!    the checkpoint, and fails closed on any tampering.
//!
//! Entries beyond the checkpoint are unconfirmed: they may be reads, denials,
//! a crash between append and save, or an unrecorded revocation. The log
//! records what was *written*; the vault document is the authority on what is
//! *authorized*.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use zeroize::{Zeroize, Zeroizing};

use crate::audit::{
    self, AuditLine, AuditLog, Decision, Priority, Record, RunRecord, VerifyReport,
};
use crate::crypto::SecretKey;
use crate::dotenv;
use crate::envelope::{B64, DerivedKeks, Envelope, KdfParams, KekRecipe, Keys, SlotType};
use crate::error::VaultError;
use crate::fsops;
use crate::model::{
    APPROVAL_CLAIM_SECS, APPROVAL_PENDING_SECS, AgentRecord, AgentStatus, Approval, ApprovalStatus,
    AuditHead, Grant, GrantSummary, Lease, MAX_APPROVALS, MAX_LEASE_TTL_SECS, MAX_LEASES,
    MIN_LEASE_TTL_SECS, Op, Project, Secret,
};
use crate::store;

pub use crate::model::{Meta, VaultDocument};

/// Safe metadata returned by `inject_file` — never values.
pub struct InjectReport {
    pub path: PathBuf,
    pub keys: Vec<String>,
}

/// Drop every lease/approval that can no longer authorize anything.
///
/// Shared by the explicit [`Session::gc_terminal_credentials`] and the sweep
/// the cap checks run before refusing a new entry — one implementation, so the
/// two can never disagree about what "terminal" means.
fn purge_terminal(doc: &mut VaultDocument, now: OffsetDateTime) -> GcReport {
    let leases_before = doc.leases.len();
    let approvals_before = doc.approvals.len();
    doc.leases
        .retain(|l| !(now >= l.expires_at || l.revoked_at.is_some()));
    doc.approvals.retain(|a| {
        let terminal = matches!(a.status, ApprovalStatus::Consumed | ApprovalStatus::Denied);
        let past_pending = a.status == ApprovalStatus::Pending && now >= a.pending_expires_at;
        // An approved-but-unclaimed approval is live only inside its claim
        // window; past it the claim fails closed and the row is inert.
        let past_claim =
            a.status == ApprovalStatus::Approved && a.claim_expires_at.is_some_and(|d| now >= d);
        !(terminal || past_pending || past_claim)
    });
    GcReport {
        leases: leases_before - doc.leases.len(),
        approvals: approvals_before - doc.approvals.len(),
    }
}

/// What [`Session::gc_terminal_credentials`] dropped.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GcReport {
    pub leases: usize,
    pub approvals: usize,
}

impl GcReport {
    pub fn is_empty(&self) -> bool {
        self.leases == 0 && self.approvals == 0
    }
}

pub const DEFAULT_IDLE_LOCK: Duration = Duration::from_secs(900);
pub const MIN_PASSPHRASE_LEN: usize = 12;

/// Injectable monotonic clock.
pub trait Clock: Send {
    fn now(&self) -> Instant;
    /// Wall-clock time for lease/approval windows. Defaults to real time so
    /// existing clocks (including test fakes) keep compiling.
    fn wall_now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

pub struct Status {
    pub version: u32,
    pub created_at: OffsetDateTime,
    pub slots: Vec<(SlotType, KdfParams)>,
    pub locked: bool,
}

pub struct Session {
    path: PathBuf,
    audit_path: PathBuf,
    envelope: Envelope,
    doc: Option<VaultDocument>,
    keys: Option<Keys>,
    audit_key: Option<SecretKey>,
    audit: AuditLog,
    /// H2: exclusive ownership of the vault file. Held for as long as this
    /// session may mutate the vault, and released when it drops (or when the
    /// process dies, since the kernel owns the flock). Never read: the lock
    /// *is* the field's existence.
    _vault_lock: crate::ipc::InstanceLock,
    /// Digest → agent_id of ACTIVE agents, rebuilt at unlock and after
    /// every agents.* commit. Retained while locked so agents can still
    /// authenticate (digests carry no secret material) and get E_LOCKED
    /// rather than E_AUTH.
    agent_digests: std::collections::HashMap<[u8; 32], String>,
    /// Memory-only human-session registry: digest → live session entry.
    /// Never part of `VaultDocument`, never serialized, never written to
    /// `vault.enc` — a daemon restart wipes it. Only the SHA-256 digest and
    /// the 8-hex display prefix are stored; the credential itself is returned
    /// once at mint and is never recoverable afterwards. `Debug` redacts it
    /// (see the manual impl below).
    sessions: std::collections::HashMap<[u8; 32], HumanSession>,
    last_activity: Instant,
    idle_timeout: Duration,
    /// Whether an expired idle window may lock this session from inside an
    /// operation ([`Self::check_idle`]).
    ///
    /// The daemon sets this to `false` when it takes ownership: there the
    /// watchdog timer is the single lifecycle owner, and an in-op lock would
    /// drop key material **without** draining managed runs (the daemon, not
    /// the session, holds the run registry). Standalone callers (tests,
    /// in-process use) keep the convenience self-lock.
    idle_self_lock: bool,
    clock: Box<dyn Clock>,
}

/// One live human session: monotonic-clock windows only. Wall-clock
/// `expires_at` strings are derived at the edge for display.
#[derive(Clone)]
struct HumanSession {
    /// 8-hex display prefix (audit actor `human(session:<prefix>)`).
    prefix: String,
    /// Monotonic instant of minting (absolute ceiling anchor).
    minted_at: Instant,
    /// Monotonic instant of last authenticated use (sliding window anchor).
    last_used: Instant,
    /// Sliding TTL in seconds (1..=1800, chosen at mint).
    ttl_secs: u64,
}

/// Sliding default (s) and absolute ceiling (s) for human sessions.
pub const SESSION_DEFAULT_TTL_SECS: u64 = 300;
pub const SESSION_MAX_TTL_SECS: u64 = 1800;
/// Memory-only cap on live human sessions. Sweep-then-evict (never refuse):
/// `vault.unlock` must always return a usable credential.
pub const MAX_SESSIONS: usize = 256;

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("path", &self.path)
            .field("locked", &self.keys.is_none())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Create and persist a new vault (refuses to overwrite), then open a
    /// live unlocked session — the human just authenticated by creating it.
    pub fn create(
        path: &Path,
        passphrase: &[u8],
        idle_timeout: Duration,
        clock: Box<dyn Clock>,
    ) -> Result<Self, VaultError> {
        if passphrase.len() < MIN_PASSPHRASE_LEN {
            return Err(VaultError::WeakPassphrase);
        }
        if path.exists() {
            return Err(VaultError::Exists);
        }
        if let Some(parent) = path.parent()
            && parent != Path::new("")
        {
            store::ensure_private_dir(parent)?;
        }
        // H2: claim the vault before writing anything. Taken before the
        // existence check so two concurrent creates cannot both win.
        let vault_lock = crate::ipc::InstanceLock::acquire_vault(path)?;
        let created_at = OffsetDateTime::now_utc();
        let audit_path = store::audit_path(path);
        let mut audit = AuditLog::load_or_init(&audit_path)?;
        // Stage the creation event first: the vault embeds its checkpoint
        // before being sealed. No MEK exists yet, so the entry is MACed as
        // soon as the key is derived (same process, same event bytes).
        let mut staged = audit.stage(
            Record {
                actor: "human",
                op: "vault.created",
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
            None,
            Priority::Ordinary,
        )?;
        let mut doc = VaultDocument::new(created_at);
        doc.audit_head = AuditHead {
            seq: staged.event.seq,
            hash: staged.hash_hex.clone(),
        };
        let doc_bytes = serde_json::to_vec(&doc)?;
        let envelope = Envelope::create(passphrase, &doc_bytes, created_at)?;
        let keys = envelope.unlock(passphrase)?;
        let audit_key = audit::derive_audit_key(&keys.mek);
        staged.mac_with(&audit_key);
        // Same ordering rule as `commit_with`: record the event before the
        // vault that checkpoints it, so a failure here leaves no vault on disk
        // claiming an audit entry that was never written.
        audit.append_staged(&staged)?;
        store::save_atomic(path, &envelope.to_bytes())?;
        let last_activity = clock.now();
        let mut session = Self {
            path: path.to_path_buf(),
            audit_path,
            envelope,
            doc: Some(doc),
            keys: Some(keys),
            audit_key: Some(audit_key),
            audit,
            _vault_lock: vault_lock,
            agent_digests: std::collections::HashMap::new(),
            sessions: std::collections::HashMap::new(),
            last_activity,
            idle_timeout,
            idle_self_lock: true,
            clock,
        };
        session.rebuild_agent_digests();
        Ok(session)
    }

    /// Load a vault from disk (locked). The audit log's structural integrity
    /// is validated here; full MAC verification happens at unlock.
    pub fn load(
        path: &Path,
        idle_timeout: Duration,
        clock: Box<dyn Clock>,
    ) -> Result<Self, VaultError> {
        // H2: one mutable owner. Refused before reading, so a second opener
        // cannot even build an in-memory copy that would later clobber the
        // owner's writes.
        let vault_lock = crate::ipc::InstanceLock::acquire_vault(path)?;
        // Reject oversized vaults without reading them into memory.
        let meta = std::fs::metadata(path)?;
        if meta.len() as usize > crate::envelope::MAX_FILE_LEN {
            return Err(VaultError::Corrupt(
                "vault file exceeds maximum size".into(),
            ));
        }
        let bytes = store::load(path)?;
        let envelope = Envelope::parse(&bytes)?;
        let audit_path = store::audit_path(path);
        let audit = AuditLog::load_or_init(&audit_path)?;
        let last_activity = clock.now();
        Ok(Self {
            path: path.to_path_buf(),
            audit_path,
            envelope,
            doc: None,
            keys: None,
            audit_key: None,
            audit,
            _vault_lock: vault_lock,
            agent_digests: std::collections::HashMap::new(),
            sessions: std::collections::HashMap::new(),
            last_activity,
            idle_timeout,
            idle_self_lock: true,
            clock,
        })
    }

    /// Verify the passphrase, verify the audit log, and hold key material in
    /// memory until lock or idle exit.
    ///
    /// Convenience wrapper that derives inline. Callers that must not run
    /// Argon2 under their own lock (the broker) use
    /// [`Self::kek_recipe`] + `KekRecipe::derive` + [`Self::unlock_with_proof`].
    pub fn unlock(&mut self, passphrase: &[u8]) -> Result<(), VaultError> {
        let unlocked = match self.envelope.kek_recipe() {
            Ok(recipe) => recipe.derive(passphrase),
            Err(e) => Err(e),
        };
        match unlocked {
            Ok(derived) => self.unlock_with_proof(&derived),
            Err(e) => Err(e),
        }
    }

    /// The public, secretless KDF inputs of this vault's key slots. Reading it
    /// needs no passphrase and no lock held across the derivation.
    pub fn kek_recipe(&self) -> Result<KekRecipe, VaultError> {
        self.envelope.kek_recipe()
    }

    /// Unlock using KEKs derived elsewhere. Only the AEAD unwraps run here, so
    /// this is cheap enough to hold a lock across.
    pub fn unlock_with_proof(&mut self, derived: &DerivedKeks) -> Result<(), VaultError> {
        match self.do_unlock(derived) {
            Ok(()) => {
                // A full audit log must not turn a successful unlock into a
                // reported failure (the vault is already open in memory by
                // now), so this record is best-effort and uses the reserved
                // headroom.
                let _ = self.audit_record_lifecycle(
                    "human",
                    Record {
                        actor: "human",
                        op: "vault.unlocked",
                        project: None,
                        keys: &[],
                        target: None,
                        decision: Decision::Allowed,
                        reason: None,
                    },
                );
                self.last_activity = self.clock.now();
                Ok(())
            }
            // Auth failures are the security-relevant denials: audit them
            // (mac: null — no key material exists yet). Best-effort too: an
            // unwritable log must not replace `E_AUTH` with an audit error,
            // which would both mask the real result and become an oracle.
            Err(e @ VaultError::Auth) => {
                let _ = self.audit.append(
                    Record {
                        actor: "human",
                        op: "vault.unlock",
                        project: None,
                        keys: &[],
                        target: None,
                        decision: Decision::Denied,
                        reason: Some(e.code()),
                    },
                    None,
                    Priority::Lifecycle,
                );
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    fn do_unlock(&mut self, derived: &DerivedKeks) -> Result<(), VaultError> {
        let keys = self.envelope.unlock_with(derived)?;
        let audit_key = audit::derive_audit_key(&keys.mek);
        // Fail closed on any tampering of authenticated audit history.
        AuditLog::verify(&self.audit_path, Some(&audit_key))
            .map_err(|_| VaultError::Corrupt("audit log verification failed".into()))?;
        let mut doc_bytes = self.envelope.open_document(&keys)?;
        let doc: VaultDocument = serde_json::from_slice(&doc_bytes)?;
        doc_bytes.zeroize();
        // Vault↔audit coherence: the log must contain the entry the last
        // committed mutation checkpointed. Entries beyond the checkpoint
        // (later reads/denials) are legitimate; a missing checkpoint entry
        // means a vault change was committed without its audit event.
        audit::check_checkpoint(&self.audit_path, doc.audit_head.seq, &doc.audit_head.hash)?;
        self.keys = Some(keys);
        self.audit_key = Some(audit_key);
        self.doc = Some(doc);
        self.rebuild_agent_digests();
        Ok(())
    }

    /// Drop key material, the audit MAC key, and the decrypted document.
    /// The agent digest map is retained (no secrets) so agents still
    /// authenticate and receive `E_LOCKED` instead of `E_AUTH`.
    /// The human-session registry is purged here — every path that drops key
    /// material funnels through `lock()` (`lock_persist` ends here, and the
    /// idle fallback calls `lock_persist` then `lock`), so no lock path can
    /// miss it. Daemon restart invalidates everything because the table is
    /// memory-only and never part of `VaultDocument`.
    pub fn lock(&mut self) {
        self.keys = None;
        self.audit_key = None;
        self.doc = None;
        self.sessions.clear();
    }

    /// Auto-lock if idle past the timeout; then refresh the activity
    /// timestamp and return the keys. `idle_timeout == 0` disables auto-lock.
    pub fn require_keys(&mut self) -> Result<&Keys, VaultError> {
        self.check_idle();
        if self.keys.is_none() {
            return Err(VaultError::Locked);
        }
        self.last_activity = self.clock.now();
        Ok(self.keys.as_ref().expect("keys checked present above"))
    }

    /// Re-seal and atomically persist the vault. Requires unlocked state.
    pub fn save(&mut self) -> Result<(), VaultError> {
        self.check_idle();
        let doc = match &self.doc {
            Some(d) => d.clone(),
            None => return Err(VaultError::Locked),
        };
        let keys = match &self.keys {
            Some(k) => k.clone(),
            None => return Err(VaultError::Locked),
        };
        self.last_activity = self.clock.now();
        let mut doc_bytes = serde_json::to_vec(&doc)?;
        self.envelope.reseal_document(&doc_bytes, &keys)?;
        doc_bytes.zeroize();
        // C4: never persist a vault the loader would reject. Refused here, so
        // the previously stored file stays valid and openable.
        self.envelope.validate_persistable()?;
        store::save_atomic(&self.path, &self.envelope.to_bytes())
    }

    pub fn status(&self) -> Status {
        Status {
            version: crate::envelope::VERSION,
            created_at: self.envelope.header.created_at,
            slots: self
                .envelope
                .header
                .slots
                .iter()
                .map(|s| (s.kind.clone(), s.kdf.clone()))
                .collect(),
            locked: self.keys.is_none(),
        }
    }

    /// Dashboard health read: locked flag, idle window, file bytes + ceilings,
    /// live-run count, and lease/approval counts (null while locked — the
    /// decrypted document is unavailable). No secrets, no user-controlled
    /// strings, no paths. Works while locked; never calls `require_keys()`.
    pub fn vault_health(&self, idle_lock_secs: u64, runs_active: u64) -> serde_json::Value {
        let locked = self.is_locked();
        let idle_in = if locked || idle_lock_secs == 0 {
            serde_json::Value::Null
        } else {
            let now = self.clock.now();
            let elapsed = now.duration_since(self.last_activity).as_secs();
            serde_json::json!(idle_lock_secs.saturating_sub(elapsed))
        };
        let audit_bytes = std::fs::metadata(&self.audit_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let vault_bytes = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let (leases_active, approvals_pending) = match self.doc.as_ref() {
            None => (serde_json::Value::Null, serde_json::Value::Null),
            Some(doc) => {
                let now = self.clock.wall_now();
                let leases = doc
                    .leases
                    .iter()
                    .filter(|l| l.revoked_at.is_none() && now < l.expires_at)
                    .count() as u64;
                let pending = doc
                    .approvals
                    .iter()
                    .filter(|a| {
                        a.status == crate::model::ApprovalStatus::Pending
                            && now < a.pending_expires_at
                    })
                    .count() as u64;
                (serde_json::json!(leases), serde_json::json!(pending))
            }
        };
        serde_json::json!({
            "locked": locked,
            "idle_lock_secs": idle_lock_secs,
            "idle_in": idle_in,
            "audit_bytes": audit_bytes,
            "audit_soft_limit": crate::audit::AUDIT_SOFT_LIMIT,
            "audit_hard_limit": crate::audit::MAX_AUDIT_LEN,
            "vault_bytes": vault_bytes,
            "vault_max_bytes": crate::envelope::MAX_FILE_LEN,
            "runs_active": runs_active,
            "leases_active": leases_active,
            "approvals_pending": approvals_pending,
        })
    }

    /// Decrypted document, present only while unlocked.
    pub fn document(&self) -> Option<&VaultDocument> {
        self.doc.as_ref()
    }

    /// Lock state (part of the per-request capability evaluation).
    pub fn is_locked(&self) -> bool {
        self.keys.is_none()
    }

    /// Collect leases and approvals that can no longer authorize anything, so
    /// terminal entries cannot occupy `MAX_LEASES` / `MAX_APPROVALS` forever
    /// (L1: without this, a long-lived vault fills with dead entries and then
    /// refuses new ones — a self-inflicted DoS an agent can trigger by
    /// repeatedly minting short-lived leases).
    ///
    /// What is removed, and why it is safe:
    ///
    /// * **leases** — expired (`now >= expires_at`) or revoked (`revoked_at`).
    ///   Both already fail authorization, so removal cannot resurrect a
    ///   capability. Only the credential's *digest* is stored, and the digest
    ///   dies with the entry; the audit log keeps the history.
    /// * **approvals** — consumed/denied, or past their pending window. The
    ///   single-use guarantee is the status transition plus the audit trail,
    ///   not the presence of the row.
    ///
    /// Consequence, stated plainly: a claim of an approval whose row has been
    /// collected answers `E_NOT_FOUND` instead of `E_APPROVAL_CONSUMED`, since
    /// the terminal row is gone. The access decision is identical (both deny,
    /// neither reveals a value); only the code for that late re-claim changes.
    ///
    /// Live entries (pending/approved-in-window approvals, unexpired unrevoked
    /// leases) are never touched. Returns how many of each were dropped.
    pub fn gc_terminal_credentials(&mut self) -> GcReport {
        let Some(doc) = self.doc.clone() else {
            return GcReport::default();
        };
        let now = self.clock.wall_now();
        let mut swept = doc;
        let report = purge_terminal(&mut swept, now);
        self.doc = Some(swept);
        report
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    // ----- Phase 2: human project operations -------------------------------

    /// Create a project with its initial authorized folders (canonicalized).
    pub fn project_add(
        &mut self,
        actor: &str,
        name: &str,
        paths: &[PathBuf],
    ) -> Result<String, VaultError> {
        self.gate(actor, "project.add", Some(name), &[])?;
        let mut doc = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        match Self::do_project_add(&mut doc, name, paths) {
            Ok(id) => {
                self.commit(
                    doc,
                    Record {
                        actor,
                        op: "project.add",
                        project: Some(name),
                        keys: &[],
                        target: None,
                        decision: Decision::Allowed,
                        reason: None,
                    },
                )?;
                Ok(id)
            }
            Err(e) => {
                self.audit_denied(actor, "project.add", Some(name), &[], None, &e);
                Err(e)
            }
        }
    }

    fn do_project_add(
        doc: &mut VaultDocument,
        name: &str,
        paths: &[PathBuf],
    ) -> Result<String, VaultError> {
        doc.check_new_project_name(name)?;
        let mut id = crate::envelope::hex_id()?;
        while doc.project_by_id(&id).is_some() {
            id = crate::envelope::hex_id()?;
        }
        let mut project = Project {
            id: id.clone(),
            name: name.to_string(),
            paths: Vec::new(),
            created_at: OffsetDateTime::now_utc(),
        };
        for p in paths {
            let canonical = VaultDocument::check_new_path(&project, p)?;
            project.paths.push(canonical);
        }
        doc.projects.push(project);
        Ok(id)
    }

    /// List projects (names, paths, creation time). Never secret values.
    pub fn project_list(&mut self, actor: &str) -> Result<Vec<Project>, VaultError> {
        self.gate(actor, "project.list", None, &[])?;
        match self.do_project_list() {
            Ok(list) => {
                self.audit_record(
                    actor,
                    Record {
                        actor,
                        op: "project.list",
                        project: None,
                        keys: &[],
                        target: None,
                        decision: Decision::Allowed,
                        reason: None,
                    },
                )?;
                Ok(list)
            }
            Err(e) => {
                self.audit_denied(actor, "project.list", None, &[], None, &e);
                Err(e)
            }
        }
    }

    fn do_project_list(&self) -> Result<Vec<Project>, VaultError> {
        Ok(self
            .doc
            .as_ref()
            .ok_or(VaultError::Locked)?
            .projects
            .clone())
    }

    /// Add an authorized folder to a project (canonicalized, deduplicated).
    pub fn project_path_add(
        &mut self,
        actor: &str,
        name: &str,
        path: &Path,
    ) -> Result<(), VaultError> {
        self.gate(actor, "project.path.add", Some(name), &[])?;
        let mut doc = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        match Self::do_project_path_add(&mut doc, name, path) {
            Ok(()) => {
                self.commit(
                    doc,
                    Record {
                        actor,
                        op: "project.path.add",
                        project: Some(name),
                        keys: &[],
                        target: Some(path),
                        decision: Decision::Allowed,
                        reason: None,
                    },
                )?;
                Ok(())
            }
            Err(e) => {
                self.audit_denied(actor, "project.path.add", Some(name), &[], Some(path), &e);
                Err(e)
            }
        }
    }

    fn do_project_path_add(
        doc: &mut VaultDocument,
        name: &str,
        path: &Path,
    ) -> Result<(), VaultError> {
        let idx = doc
            .projects
            .iter()
            .position(|p| p.name == name)
            .ok_or(VaultError::NotFound)?;
        let canonical = VaultDocument::check_new_path(&doc.projects[idx], path)?;
        doc.projects[idx].paths.push(canonical);
        Ok(())
    }

    /// Remove an authorized folder from a project.
    pub fn project_path_remove(
        &mut self,
        actor: &str,
        name: &str,
        path: &Path,
    ) -> Result<(), VaultError> {
        self.gate(actor, "project.path.remove", Some(name), &[])?;
        let mut doc = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        match Self::do_project_path_remove(&mut doc, name, path) {
            Ok(()) => {
                self.commit(
                    doc,
                    Record {
                        actor,
                        op: "project.path.remove",
                        project: Some(name),
                        keys: &[],
                        target: Some(path),
                        decision: Decision::Allowed,
                        reason: None,
                    },
                )?;
                Ok(())
            }
            Err(e) => {
                self.audit_denied(
                    actor,
                    "project.path.remove",
                    Some(name),
                    &[],
                    Some(path),
                    &e,
                );
                Err(e)
            }
        }
    }

    fn do_project_path_remove(
        doc: &mut VaultDocument,
        name: &str,
        path: &Path,
    ) -> Result<(), VaultError> {
        let idx = doc
            .projects
            .iter()
            .position(|p| p.name == name)
            .ok_or(VaultError::NotFound)?;
        // Prefer the canonical form; fall back to the raw path so a deleted
        // directory can still be removed from the list.
        let candidate = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let pos = doc.projects[idx]
            .paths
            .iter()
            .position(|p| p == &candidate)
            .or_else(|| doc.projects[idx].paths.iter().position(|p| p == path))
            .ok_or(VaultError::NotFound)?;
        doc.projects[idx].paths.remove(pos);
        Ok(())
    }

    /// Remove a project; refused while it still has secrets.
    pub fn project_remove(&mut self, actor: &str, name: &str) -> Result<(), VaultError> {
        self.gate(actor, "project.remove", Some(name), &[])?;
        let mut doc = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        match Self::do_project_remove(&mut doc, name) {
            Ok(()) => {
                self.commit(
                    doc,
                    Record {
                        actor,
                        op: "project.remove",
                        project: Some(name),
                        keys: &[],
                        target: None,
                        decision: Decision::Allowed,
                        reason: None,
                    },
                )?;
                Ok(())
            }
            Err(e) => {
                self.audit_denied(actor, "project.remove", Some(name), &[], None, &e);
                Err(e)
            }
        }
    }

    fn do_project_remove(doc: &mut VaultDocument, name: &str) -> Result<(), VaultError> {
        let idx = doc
            .projects
            .iter()
            .position(|p| p.name == name)
            .ok_or(VaultError::NotFound)?;
        doc.check_project_removable(&doc.projects[idx].id)?;
        doc.projects.remove(idx);
        Ok(())
    }

    // ----- Phase 2: human secret operations --------------------------------

    /// Create or update a secret. The value never leaves this call except
    /// into the encrypted document; the audit records only the key name.
    pub fn secret_set(
        &mut self,
        actor: &str,
        project: &str,
        key: &str,
        value: &[u8],
    ) -> Result<(), VaultError> {
        let keys_arg = [key.to_string()];
        self.gate(actor, "secret.set", Some(project), &keys_arg)?;
        let mut doc = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        match Self::do_secret_set(&mut doc, project, key, value) {
            Ok(()) => {
                self.commit(
                    doc,
                    Record {
                        actor,
                        op: "secret.set",
                        project: Some(project),
                        keys: &keys_arg,
                        target: None,
                        decision: Decision::Allowed,
                        reason: None,
                    },
                )?;
                Ok(())
            }
            Err(e) => {
                self.audit_denied(actor, "secret.set", Some(project), &keys_arg, None, &e);
                Err(e)
            }
        }
    }

    fn do_secret_set(
        doc: &mut VaultDocument,
        project: &str,
        key: &str,
        value: &[u8],
    ) -> Result<(), VaultError> {
        VaultDocument::check_secret_value(value)?;
        let pid = doc
            .project_by_name(project)
            .ok_or(VaultError::NotFound)?
            .id
            .clone();
        let now = OffsetDateTime::now_utc();
        if let Some(existing) = doc
            .secrets
            .iter_mut()
            .find(|s| s.project_id == pid && s.key == key)
        {
            existing.value = B64(Zeroizing::new(value.to_vec()));
            existing.updated_at = now;
        } else {
            doc.check_new_secret_key(&pid, key)?;
            doc.secrets.push(Secret {
                project_id: pid,
                key: key.to_string(),
                value: B64(Zeroizing::new(value.to_vec())),
                created_at: now,
                updated_at: now,
            });
        }
        Ok(())
    }

    /// List a project's secret key names and timestamps — never values.
    pub fn secret_list(
        &mut self,
        project: &str,
        actor: &str,
    ) -> Result<Vec<(String, OffsetDateTime)>, VaultError> {
        let keys_arg: Vec<String> = Vec::new();
        self.gate(actor, "secret.list", Some(project), &keys_arg)?;
        match self.do_secret_list(project) {
            Ok(list) => {
                self.audit_record(
                    actor,
                    Record {
                        actor,
                        op: "secret.list",
                        project: Some(project),
                        keys: &keys_arg,
                        target: None,
                        decision: Decision::Allowed,
                        reason: None,
                    },
                )?;
                Ok(list)
            }
            Err(e) => {
                self.audit_denied(actor, "secret.list", Some(project), &keys_arg, None, &e);
                Err(e)
            }
        }
    }

    fn do_secret_list(&self, project: &str) -> Result<Vec<(String, OffsetDateTime)>, VaultError> {
        let doc = self.doc.as_ref().ok_or(VaultError::Locked)?;
        let pid = doc
            .project_by_name(project)
            .ok_or(VaultError::NotFound)?
            .id
            .clone();
        Ok(doc
            .secrets
            .iter()
            .filter(|s| s.project_id == pid)
            .map(|s| (s.key.clone(), s.updated_at))
            .collect())
    }

    /// Delete a secret.
    pub fn secret_delete(
        &mut self,
        actor: &str,
        project: &str,
        key: &str,
    ) -> Result<(), VaultError> {
        let keys_arg = [key.to_string()];
        self.gate(actor, "secret.delete", Some(project), &keys_arg)?;
        let mut doc = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        match Self::do_secret_delete(&mut doc, project, key) {
            Ok(()) => {
                self.commit(
                    doc,
                    Record {
                        actor,
                        op: "secret.delete",
                        project: Some(project),
                        keys: &keys_arg,
                        target: None,
                        decision: Decision::Allowed,
                        reason: None,
                    },
                )?;
                Ok(())
            }
            Err(e) => {
                self.audit_denied(actor, "secret.delete", Some(project), &keys_arg, None, &e);
                Err(e)
            }
        }
    }

    fn do_secret_delete(
        doc: &mut VaultDocument,
        project: &str,
        key: &str,
    ) -> Result<(), VaultError> {
        let pid = doc
            .project_by_name(project)
            .ok_or(VaultError::NotFound)?
            .id
            .clone();
        let pos = doc
            .secrets
            .iter()
            .position(|s| s.project_id == pid && s.key == key)
            .ok_or(VaultError::NotFound)?;
        doc.secrets.remove(pos);
        Ok(())
    }

    // ----- Phase 2: audit inspection ---------------------------------------

    /// Last `n` audit entries. Works while locked (the log is plaintext and
    /// never contains secret values); the read itself is audited.
    pub fn audit_tail(&mut self, actor: &str, n: usize) -> Result<Vec<AuditLine>, VaultError> {
        let (lines, _) = self.audit_show_page(actor, n, None)?;
        Ok(lines)
    }

    /// Paged audit read: at most `tail` entries, ascending by `seq`, from
    /// entries with `seq <= before_seq` when present, else the newest entries
    /// backwards. Returns the page plus the cursor for the previous (older)
    /// page, or null when exhausted / the page is empty. The read itself is
    /// audited with the caller's actor (human reads only; the broker enforces
    /// human-only). Entry shape, HMAC chain, and checkpoint semantics are
    /// untouched; the log is never rewritten or truncated.
    /// H-10: the head seq is snapshotted BEFORE appending the read's own
    /// entry, and the page is computed from that snapshot — the self-append
    /// never shifts the window. `before_seq` beyond the head clamps to the
    /// head; `before_seq: 0` yields an empty page + null cursor.
    pub fn audit_show_page(
        &mut self,
        actor: &str,
        tail: usize,
        before_seq: Option<u64>,
    ) -> Result<(Vec<AuditLine>, Option<u64>), VaultError> {
        let lines = AuditLog::read_all(&self.audit_path)?;
        let head: u64 = lines.last().map(|l| l.event.seq).unwrap_or(0);
        let upper = match before_seq {
            Some(b) => b.min(head),
            None => head,
        };
        let eligible: Vec<&AuditLine> = lines.iter().filter(|l| l.event.seq <= upper).collect();
        let start = eligible.len().saturating_sub(tail);
        let page: Vec<AuditLine> = eligible[start..].iter().map(|l| (*l).clone()).collect();
        // Cursor from the PRE-append snapshot: first_returned - 1 when older
        // entries remain in the snapshot, else null. Empty page => null.
        let next_before_seq = match page.first() {
            None => None,
            Some(first) => {
                if first.event.seq > 1 && lines.iter().any(|l| l.event.seq < first.event.seq) {
                    Some(first.event.seq - 1)
                } else {
                    None
                }
            }
        };
        self.audit_record(
            actor,
            Record {
                actor,
                op: "audit.show",
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        )?;
        Ok((page, next_before_seq))
    }

    /// Verify the audit log. With `K_audit` in memory (unlocked) MACs are
    /// verified; while locked only the structural chain is checked.
    pub fn audit_verify(&self) -> Result<VerifyReport, VaultError> {
        AuditLog::verify(&self.audit_path, self.audit_key.as_ref())
    }

    // ----- Phase 4: agent-driven file injection ----------------------------

    /// Inject project secrets into a dotenv file under one of the project's
    /// authorized folders. Kernel containment (openat2) applies; values never
    /// leave this call except into the encrypted file. The audit records key
    /// names and the destination — never values.
    pub fn inject_file(
        &mut self,
        actor: &str,
        project: &str,
        relative: &str,
        keys: Option<&[String]>,
    ) -> Result<InjectReport, VaultError> {
        self.gate(actor, "inject_file", Some(project), &[])?;
        let doc = match self.doc.as_ref() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        match Self::do_inject_file(doc, project, relative, keys) {
            Ok(report) => {
                let key_names = report.keys.clone();
                self.audit_record(
                    actor,
                    Record {
                        actor,
                        op: "inject_file",
                        project: Some(project),
                        keys: &key_names,
                        target: Some(report.path.as_path()),
                        decision: Decision::Allowed,
                        reason: None,
                    },
                )?;
                Ok(report)
            }
            Err(e) => {
                self.audit_denied(actor, "inject_file", Some(project), &[], None, &e);
                Err(e)
            }
        }
    }

    fn do_inject_file(
        doc: &VaultDocument,
        project: &str,
        relative: &str,
        keys: Option<&[String]>,
    ) -> Result<InjectReport, VaultError> {
        let project_rec = doc.project_by_name(project).ok_or(VaultError::NotFound)?;
        let pid = project_rec.id.clone();
        let folders = project_rec.paths.clone();
        if folders.is_empty() {
            return Err(VaultError::InvalidInput(
                "project has no authorized folders",
            ));
        }

        // Key selection: explicit list (must all exist) or all project keys.
        let mut entries: Vec<dotenv::Entry> = Vec::new();
        let selected: Vec<String> = match keys {
            Some(list) => {
                for k in list {
                    let secret = doc.secret(&pid, k).ok_or(VaultError::NotFound)?;
                    let value = String::from_utf8(secret.value.0.to_vec()).map_err(|_| {
                        VaultError::InvalidInput(
                            "secret value is not valid UTF-8 for dotenv injection",
                        )
                    })?;
                    entries.push(dotenv::Entry {
                        key: k.clone(),
                        value,
                    });
                }
                list.to_vec()
            }
            None => {
                let mut secrets: Vec<&Secret> =
                    doc.secrets.iter().filter(|s| s.project_id == pid).collect();
                secrets.sort_by(|a, b| a.key.cmp(&b.key));
                for s in secrets {
                    let value = String::from_utf8(s.value.0.to_vec()).map_err(|_| {
                        VaultError::InvalidInput(
                            "secret value is not valid UTF-8 for dotenv injection",
                        )
                    })?;
                    entries.push(dotenv::Entry {
                        key: s.key.clone(),
                        value,
                    });
                }
                entries.iter().map(|e| e.key.clone()).collect()
            }
        };
        if selected.is_empty() {
            return Err(VaultError::InvalidInput("no secrets to inject"));
        }
        let bytes = dotenv::serialize(&entries)?;

        // Contained write: try each authorized folder in order; the first
        // folder where the kernel allows a contained publication wins.
        let mut last_err: Option<VaultError> = None;
        for folder in &folders {
            match fsops::open_containment_root(folder)
                .and_then(|root| fsops::resolve_target(&root, relative, folder))
                .and_then(|t| {
                    let path = t.display_path.clone();
                    fsops::write_file_atomic(&t, &bytes)?;
                    Ok(InjectReport {
                        path,
                        keys: selected.clone(),
                    })
                }) {
                Ok(report) => return Ok(report),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or(VaultError::InvalidInput("no authorized folders")))
    }

    // ----- Phase 3: agent enrollment and grants (human-only) ---------------

    /// Enroll an agent. Returns the one-time token (shown once / written to a
    /// 0600 file by the CLI); only its digest is persisted.
    pub fn agent_add(&mut self, actor: &str, name: &str) -> Result<(String, String), VaultError> {
        self.gate(actor, "agents.add", Some(name), &[])?;
        let mut doc = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        match Self::do_agent_add(&mut doc, name) {
            Ok(pair) => {
                self.commit(
                    doc,
                    Record {
                        actor,
                        op: "agents.add",
                        project: None,
                        keys: &[],
                        target: None,
                        decision: Decision::Allowed,
                        reason: None,
                    },
                )?;
                Ok(pair)
            }
            Err(e) => {
                self.audit_denied(actor, "agents.add", Some(name), &[], None, &e);
                Err(e)
            }
        }
    }

    fn do_agent_add(doc: &mut VaultDocument, name: &str) -> Result<(String, String), VaultError> {
        doc.check_new_agent_name(name)?;
        let (token, digest, prefix) = crate::crypto::generate_agent_token()?;
        let mut id = crate::envelope::hex_id()?;
        while doc.agent_by_id(&id).is_some() {
            id = crate::envelope::hex_id()?;
        }
        doc.agents.push(AgentRecord {
            id: id.clone(),
            name: name.to_string(),
            status: AgentStatus::Active,
            token_hash: B64(Zeroizing::new(digest.to_vec())),
            token_prefix: prefix,
            created_at: OffsetDateTime::now_utc(),
            last_seen: None,
        });
        Ok((id, token))
    }

    /// Revoke an agent by name: its token stops resolving immediately.
    /// Also revokes its leases and denies its active approvals (single commit).
    pub fn agent_revoke(&mut self, actor: &str, name: &str) -> Result<(), VaultError> {
        self.gate(actor, "agents.revoke", Some(name), &[])?;
        let now = self.clock.wall_now();
        let mut doc = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        match Self::do_agent_revoke(&mut doc, name) {
            Ok(agent_id) => {
                Self::revoke_agent_leases(&mut doc, &agent_id, now);
                Self::deny_agent_approvals(&mut doc, &agent_id);
                self.commit_lifecycle(
                    doc,
                    Record {
                        actor,
                        op: "agents.revoke",
                        project: None,
                        keys: &[],
                        target: None,
                        decision: Decision::Allowed,
                        reason: None,
                    },
                )?;
                Ok(())
            }
            Err(e) => {
                self.audit_denied(actor, "agents.revoke", Some(name), &[], None, &e);
                Err(e)
            }
        }
    }

    fn do_agent_revoke(doc: &mut VaultDocument, name: &str) -> Result<String, VaultError> {
        let idx = doc
            .agents
            .iter()
            .position(|a| a.name == name)
            .ok_or(VaultError::NotFound)?;
        doc.agents[idx].status = AgentStatus::Revoked;
        Ok(doc.agents[idx].id.clone())
    }

    // ----- Phase 6: leases ----------------------------------------------------
    /// Create a TTL-bound lease: a revocable subset of the caller's own grant.
    /// Clone+commit; audits allowed/denied; never carries secret material.
    ///
    /// Returns the lease (public handle, digest, prefix) plus the one-time
    /// credential. Only the credential's SHA-256 digest and display prefix are
    /// persisted: the credential is returned to the caller exactly once and
    /// can never be recovered from the vault, the audit log, or a listing.
    pub fn lease_create(
        &mut self,
        actor: &str,
        agent_id: &str,
        project: &str,
        ops: &[Op],
        ttl_secs: u64,
    ) -> Result<(Lease, String), VaultError> {
        self.check_idle();
        if self.keys.is_none() {
            self.audit_denied(
                actor,
                "lease.create",
                Some(project),
                &[],
                None,
                &VaultError::Locked,
            );
            return Err(VaultError::Locked);
        }
        if !(MIN_LEASE_TTL_SECS..=MAX_LEASE_TTL_SECS).contains(&ttl_secs) {
            let e = VaultError::InvalidInput("ttl_secs must be 1..86400");
            self.audit_denied(actor, "lease.create", Some(project), &[], None, &e);
            return Err(e);
        }
        if ops.is_empty() {
            let e = VaultError::InvalidInput("lease must include at least one op");
            self.audit_denied(actor, "lease.create", Some(project), &[], None, &e);
            return Err(e);
        }
        let now = self.clock.wall_now();
        let doc0 = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        let project_id = match doc0.project_by_name(project) {
            Some(p) => p.id.clone(),
            None => {
                let e = VaultError::NotFound;
                self.audit_denied(actor, "lease.create", Some(project), &[], None, &e);
                return Err(e);
            }
        };
        match doc0.agents.iter().find(|a| a.id == agent_id) {
            Some(a) if a.status == AgentStatus::Active => {}
            _ => {
                let e = VaultError::NotFound;
                self.audit_denied(actor, "lease.create", Some(project), &[], None, &e);
                return Err(e);
            }
        }
        let grant_ops = match doc0.active_grant(agent_id, &project_id) {
            Some(g) => g.ops.clone(),
            None => {
                let e = VaultError::Permission;
                self.audit_denied(actor, "lease.create", Some(project), &[], None, &e);
                return Err(e);
            }
        };
        if !ops.iter().all(|o| grant_ops.contains(o)) {
            let e = VaultError::Permission;
            self.audit_denied(actor, "lease.create", Some(project), &[], None, &e);
            return Err(e);
        }
        // L1: terminal leases are inert, so reclaim them before refusing. The
        // cap must bound *live* credentials, not an ever-growing junk pile.
        let mut doc = doc0;
        if doc.leases.len() >= MAX_LEASES {
            purge_terminal(&mut doc, now);
        }
        if doc.leases.len() >= MAX_LEASES {
            let e = VaultError::InvalidInput("too many leases");
            self.audit_denied(actor, "lease.create", Some(project), &[], None, &e);
            return Err(e);
        }
        let mut id = crate::envelope::hex_id()?;
        while doc.leases.iter().any(|l| l.id == id) {
            id = crate::envelope::hex_id()?;
        }
        let (credential, digest, prefix) = crate::crypto::generate_capability()?;
        let lease = Lease {
            id: id.clone(),
            agent_id: agent_id.to_string(),
            project_id,
            ops: ops.to_vec(),
            credential_hash: B64(Zeroizing::new(digest.to_vec())),
            credential_prefix: prefix,
            created_at: now,
            expires_at: now + time::Duration::seconds(ttl_secs as i64),
            revoked_at: None,
        };
        doc.leases.push(lease.clone());
        match self.commit(
            doc,
            Record {
                actor,
                op: "lease.create",
                project: Some(project),
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        ) {
            Ok(()) => Ok((lease, credential)),
            Err(e) => Err(e),
        }
    }
    /// List leases: agent (`Some(id)`) sees own only; human (`None`) sees all.
    pub fn lease_list(
        &mut self,
        actor: &str,
        agent_id: Option<&str>,
    ) -> Result<Vec<Lease>, VaultError> {
        self.check_idle();
        if self.keys.is_none() {
            self.audit_denied(actor, "lease.list", None, &[], None, &VaultError::Locked);
            return Err(VaultError::Locked);
        }
        let doc = match self.doc.as_ref() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        let list = match agent_id {
            Some(id) => doc
                .leases
                .iter()
                .filter(|l| l.agent_id == id)
                .cloned()
                .collect(),
            None => doc.leases.clone(),
        };
        let _ = self.audit_record(
            actor,
            Record {
                actor,
                op: "lease.list",
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        );
        Ok(list)
    }
    /// Revoke a lease immediately. Agents (`Some(id)`) may only revoke their
    /// own; human (`None`) may revoke any. Idempotent.
    pub fn lease_revoke(
        &mut self,
        actor: &str,
        agent_id: Option<&str>,
        lease_id: &str,
    ) -> Result<(), VaultError> {
        self.check_idle();
        if self.keys.is_none() {
            self.audit_denied(actor, "lease.revoke", None, &[], None, &VaultError::Locked);
            return Err(VaultError::Locked);
        }
        let now = self.clock.wall_now();
        let mut doc = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        let pos = match doc.leases.iter().position(|l| l.id == lease_id) {
            Some(p) => p,
            None => {
                let e = VaultError::NotFound;
                self.audit_denied(actor, "lease.revoke", None, &[], None, &e);
                return Err(e);
            }
        };
        if let Some(id) = agent_id
            && doc.leases[pos].agent_id != id
        {
            let e = VaultError::Permission;
            self.audit_denied(actor, "lease.revoke", None, &[], None, &e);
            return Err(e);
        }
        if doc.leases[pos].revoked_at.is_none() {
            doc.leases[pos].revoked_at = Some(now);
        }
        match self.commit_lifecycle(
            doc,
            Record {
                actor,
                op: "lease.revoke",
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        ) {
            Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
    }
    /// Per-request capability evaluation: grant ∩ lease ∩ TTL ∩ unlocked.
    /// Takes the presented lease *credential* (never the public handle) and
    /// resolves it by SHA-256 digest: an unknown credential is
    /// indistinguishable from a revoked/expired one (`E_LEASE_EXPIRED`, no
    /// oracle). Returns the audit actor (`lease:<handle>` or `agent:<id>`).
    ///
    /// Unknown/other-agent/wrong-project/revoked/expired/grant-uncovered
    /// lease → `E_LEASE_EXPIRED`; active lease used for an op outside its
    /// subset, or no-lease without grant → `E_PERMISSION`.
    pub fn authorize_lease(
        &mut self,
        agent_id: &str,
        project: &str,
        op: Op,
        lease_credential: Option<&str>,
    ) -> Result<String, VaultError> {
        self.check_idle();
        let actor = format!("agent:{agent_id}");
        if self.keys.is_none() {
            self.audit_denied(
                &actor,
                "authorize",
                Some(project),
                &[],
                None,
                &VaultError::Locked,
            );
            return Err(VaultError::Locked);
        }
        let now = self.clock.wall_now();
        let doc = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        let project_id = match doc.project_by_name(project) {
            Some(p) => p.id.clone(),
            None => {
                let e = VaultError::NotFound;
                self.audit_denied(&actor, "authorize", Some(project), &[], None, &e);
                return Err(e);
            }
        };
        let active = doc
            .agents
            .iter()
            .any(|a| a.id == agent_id && a.status == AgentStatus::Active);
        if !active {
            let e = VaultError::Permission;
            self.audit_denied(&actor, "authorize", Some(project), &[], None, &e);
            return Err(e);
        }
        let Some(presented) = lease_credential else {
            if doc.authorize(agent_id, &project_id, op) {
                let _ = self.audit_record(
                    &actor,
                    Record {
                        actor: &actor,
                        op: "authorize",
                        project: Some(project),
                        keys: &[],
                        target: None,
                        decision: Decision::Allowed,
                        reason: None,
                    },
                );
                return Ok(actor);
            }
            let e = VaultError::Permission;
            self.audit_denied(&actor, "authorize", Some(project), &[], None, &e);
            return Err(e);
        };
        // Resolve by digest only; the handle is what the caller learns, the
        // credential is what authorizes.
        let digest = crate::crypto::token_digest(presented);
        let lease = match doc
            .leases
            .iter()
            .find(|l| l.credential_hash.0.as_slice() == digest)
        {
            Some(l) => l.clone(),
            None => {
                let e = VaultError::LeaseExpired;
                self.audit_denied(&actor, "authorize", Some(project), &[], None, &e);
                return Err(e);
            }
        };
        let lid = lease.id.clone();
        // Ownership + binding: never reveal other-agent leases (no oracle
        // beyond the code).
        if lease.agent_id != agent_id || lease.project_id != project_id {
            let e = VaultError::LeaseExpired;
            self.audit_denied(&actor, "authorize", Some(project), &[], None, &e);
            return Err(e);
        }
        if lease.revoked_at.is_some() || now >= lease.expires_at {
            let e = VaultError::LeaseExpired;
            self.audit_denied(&actor, "authorize", Some(project), &[], None, &e);
            return Err(e);
        }
        // Current-grant revalidation: a narrowed/removed grant invalidates
        // the lease even before any eager sweep persists it.
        match doc.active_grant(agent_id, &project_id) {
            Some(g) => {
                if !lease.ops.iter().all(|o| g.ops.contains(o)) {
                    // Persist the invalidation best-effort, then deny.
                    let mut swept = doc.clone();
                    if let Some(slot) = swept.leases.iter_mut().find(|l| l.id == lid) {
                        slot.revoked_at = Some(now);
                    }
                    let _ = self.commit(
                        swept,
                        Record {
                            actor: &actor,
                            op: "lease.invalidate",
                            project: Some(project),
                            keys: &[],
                            target: None,
                            decision: Decision::Allowed,
                            reason: None,
                        },
                    );
                    let e = VaultError::LeaseExpired;
                    self.audit_denied(&actor, "authorize", Some(project), &[], None, &e);
                    return Err(e);
                }
            }
            None => {
                let e = VaultError::LeaseExpired;
                self.audit_denied(&actor, "authorize", Some(project), &[], None, &e);
                return Err(e);
            }
        }
        if !lease.ops.contains(&op) {
            let e = VaultError::Permission;
            self.audit_denied(&actor, "authorize", Some(project), &[], None, &e);
            return Err(e);
        }
        let leased_actor = format!("lease:{lid}");
        let _ = self.audit_record(
            &leased_actor,
            Record {
                actor: &leased_actor,
                op: "authorize",
                project: Some(project),
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        );
        Ok(leased_actor)
    }
    // ----- Phase 6: approvals -------------------------------------------------
    /// Agent reveal without `approval_id`: creates a pending approval bound
    /// to (agent, project, key). Requires a live `reveal` grant.
    pub fn approval_request(
        &mut self,
        actor: &str,
        agent_id: &str,
        project: &str,
        key: &str,
    ) -> Result<Approval, VaultError> {
        self.check_idle();
        let keys_arg = [key.to_string()];
        if self.keys.is_none() {
            self.audit_denied(
                actor,
                "approval.request",
                Some(project),
                &keys_arg,
                None,
                &VaultError::Locked,
            );
            return Err(VaultError::Locked);
        }
        let now = self.clock.wall_now();
        let doc0 = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        let project_id = match doc0.project_by_name(project) {
            Some(p) => p.id.clone(),
            None => {
                let e = VaultError::NotFound;
                self.audit_denied(
                    actor,
                    "approval.request",
                    Some(project),
                    &keys_arg,
                    None,
                    &e,
                );
                return Err(e);
            }
        };
        if !doc0
            .agents
            .iter()
            .any(|a| a.id == agent_id && a.status == AgentStatus::Active)
        {
            let e = VaultError::Permission;
            self.audit_denied(
                actor,
                "approval.request",
                Some(project),
                &keys_arg,
                None,
                &e,
            );
            return Err(e);
        }
        if !doc0.authorize(agent_id, &project_id, Op::Reveal) {
            let e = VaultError::Permission;
            self.audit_denied(
                actor,
                "approval.request",
                Some(project),
                &keys_arg,
                None,
                &e,
            );
            return Err(e);
        }
        if doc0.secret(&project_id, key).is_none() {
            let e = VaultError::NotFound;
            self.audit_denied(
                actor,
                "approval.request",
                Some(project),
                &keys_arg,
                None,
                &e,
            );
            return Err(e);
        }
        // L1: same reasoning as leases — reclaim terminal rows first.
        let mut doc = doc0;
        if doc.approvals.len() >= MAX_APPROVALS {
            purge_terminal(&mut doc, now);
        }
        if doc.approvals.len() >= MAX_APPROVALS {
            let e = VaultError::InvalidInput("too many approvals");
            self.audit_denied(
                actor,
                "approval.request",
                Some(project),
                &keys_arg,
                None,
                &e,
            );
            return Err(e);
        }
        let mut id = crate::envelope::hex_id()?;
        while doc.approvals.iter().any(|a| a.id == id) {
            id = crate::envelope::hex_id()?;
        }
        let approval = Approval {
            id: id.clone(),
            agent_id: agent_id.to_string(),
            project_id,
            key: key.to_string(),
            status: ApprovalStatus::Pending,
            created_at: now,
            pending_expires_at: now + time::Duration::seconds(APPROVAL_PENDING_SECS as i64),
            approved_at: None,
            claim_expires_at: None,
        };
        doc.approvals.push(approval.clone());
        match self.commit(
            doc,
            Record {
                actor,
                op: "approval.request",
                project: Some(project),
                keys: &keys_arg,
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        ) {
            Ok(()) => Ok(approval),
            Err(e) => Err(e),
        }
    }
    /// Poll an own approval's state. Returns
    /// `pending|approved|denied|expired|consumed`.
    pub fn approval_status(
        &mut self,
        agent_id: &str,
        approval_id: &str,
    ) -> Result<String, VaultError> {
        self.check_idle();
        let actor = format!("agent:{agent_id}");
        if self.keys.is_none() {
            self.audit_denied(
                &actor,
                "approval.status",
                None,
                &[],
                None,
                &VaultError::Locked,
            );
            return Err(VaultError::Locked);
        }
        let now = self.clock.wall_now();
        let doc = match self.doc.as_ref() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        let approval = match doc.approvals.iter().find(|a| a.id == approval_id) {
            Some(a) => a,
            None => {
                let e = VaultError::NotFound;
                self.audit_denied(&actor, "approval.status", None, &[], None, &e);
                return Err(e);
            }
        };
        if approval.agent_id != agent_id {
            let e = VaultError::Permission;
            self.audit_denied(&actor, "approval.status", None, &[], None, &e);
            return Err(e);
        }
        let status = Self::approval_view(approval, now);
        let _ = self.audit_record(
            &actor,
            Record {
                actor: &actor,
                op: "approval.status",
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        );
        Ok(status.to_string())
    }
    /// Human-only: list active (non-expired) pending approvals.
    pub fn approval_pending(&mut self, actor: &str) -> Result<Vec<Approval>, VaultError> {
        self.check_idle();
        if !Self::is_human_identity(actor) {
            let e = VaultError::HumanRequired;
            self.audit_denied(actor, "approval.pending", None, &[], None, &e);
            return Err(e);
        }
        if self.keys.is_none() {
            self.audit_denied(
                actor,
                "approval.pending",
                None,
                &[],
                None,
                &VaultError::Locked,
            );
            return Err(VaultError::Locked);
        }
        let now = self.clock.wall_now();
        let doc = match self.doc.as_ref() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        let list = doc
            .approvals
            .iter()
            .filter(|a| a.status == ApprovalStatus::Pending && now < a.pending_expires_at)
            .cloned()
            .collect();
        let _ = self.audit_record(
            actor,
            Record {
                actor,
                op: "approval.pending",
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        );
        Ok(list)
    }
    /// Human-only: approve (`true`) or deny (`false`) a pending approval.
    pub fn approval_decide(
        &mut self,
        actor: &str,
        approval_id: &str,
        approve: bool,
    ) -> Result<(), VaultError> {
        self.check_idle();
        if !Self::is_human_identity(actor) {
            let e = VaultError::HumanRequired;
            self.audit_denied(actor, "approval.decide", None, &[], None, &e);
            return Err(e);
        }
        if self.keys.is_none() {
            self.audit_denied(
                actor,
                "approval.decide",
                None,
                &[],
                None,
                &VaultError::Locked,
            );
            return Err(VaultError::Locked);
        }
        let now = self.clock.wall_now();
        let mut doc = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        let pos = match doc.approvals.iter().position(|a| a.id == approval_id) {
            Some(p) => p,
            None => {
                let e = VaultError::NotFound;
                self.audit_denied(actor, "approval.decide", None, &[], None, &e);
                return Err(e);
            }
        };
        let status = doc.approvals[pos].status;
        if status != ApprovalStatus::Pending {
            let e = match status {
                ApprovalStatus::Denied => VaultError::ApprovalDenied,
                ApprovalStatus::Consumed => VaultError::ApprovalConsumed,
                ApprovalStatus::Approved => VaultError::InvalidInput("approval already decided"),
                ApprovalStatus::Pending => unreachable!(),
            };
            self.audit_denied(actor, "approval.decide", None, &[], None, &e);
            return Err(e);
        }
        if now >= doc.approvals[pos].pending_expires_at {
            let e = VaultError::ApprovalExpired;
            self.audit_denied(actor, "approval.decide", None, &[], None, &e);
            return Err(e);
        }
        if approve {
            doc.approvals[pos].status = ApprovalStatus::Approved;
            doc.approvals[pos].approved_at = Some(now);
            doc.approvals[pos].claim_expires_at =
                Some(now + time::Duration::seconds(APPROVAL_CLAIM_SECS as i64));
        } else {
            doc.approvals[pos].status = ApprovalStatus::Denied;
        }
        let op = if approve {
            "approval.approve"
        } else {
            "approval.deny"
        };
        match self.commit(
            doc,
            Record {
                actor,
                op,
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        ) {
            Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
    }
    /// Single-use bound claim. Rechecks the live `reveal` grant first
    /// (`E_PERMISSION` when gone), then ownership/binding/expiry/state.
    /// Returns the secret bytes (zeroized on drop); audit/errors never
    /// carry the value.
    pub fn reveal_claim(
        &mut self,
        actor: &str,
        agent_id: &str,
        project: &str,
        key: &str,
        approval_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.check_idle();
        let keys_arg = [key.to_string()];
        if self.keys.is_none() {
            self.audit_denied(
                actor,
                "reveal",
                Some(project),
                &keys_arg,
                None,
                &VaultError::Locked,
            );
            return Err(VaultError::Locked);
        }
        let now = self.clock.wall_now();
        let mut doc = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        let project_id = match doc.project_by_name(project) {
            Some(p) => p.id.clone(),
            None => {
                let e = VaultError::NotFound;
                self.audit_denied(actor, "reveal", Some(project), &keys_arg, None, &e);
                return Err(e);
            }
        };
        let pos = match doc.approvals.iter().position(|a| a.id == approval_id) {
            Some(p) => p,
            None => {
                let e = VaultError::NotFound;
                self.audit_denied(actor, "reveal", Some(project), &keys_arg, None, &e);
                return Err(e);
            }
        };
        // Ownership + binding (no oracle beyond the code).
        if doc.approvals[pos].agent_id != agent_id
            || doc.approvals[pos].project_id != project_id
            || doc.approvals[pos].key != key
        {
            let e = VaultError::Permission;
            self.audit_denied(actor, "reveal", Some(project), &keys_arg, None, &e);
            return Err(e);
        }
        // Current-grant revalidation takes precedence: a withdrawn grant
        // fails `E_PERMISSION` even for an otherwise-claimable approval.
        if !doc.authorize(agent_id, &project_id, Op::Reveal) {
            let e = VaultError::Permission;
            self.audit_denied(actor, "reveal", Some(project), &keys_arg, None, &e);
            return Err(e);
        }
        match doc.approvals[pos].status {
            ApprovalStatus::Denied => {
                let e = VaultError::ApprovalDenied;
                self.audit_denied(actor, "reveal", Some(project), &keys_arg, None, &e);
                return Err(e);
            }
            ApprovalStatus::Consumed => {
                let e = VaultError::ApprovalConsumed;
                self.audit_denied(actor, "reveal", Some(project), &keys_arg, None, &e);
                return Err(e);
            }
            ApprovalStatus::Pending => {
                if now >= doc.approvals[pos].pending_expires_at {
                    let e = VaultError::ApprovalExpired;
                    self.audit_denied(actor, "reveal", Some(project), &keys_arg, None, &e);
                    return Err(e);
                }
                let pending = &doc.approvals[pos];
                let expires_in = (pending.pending_expires_at - now).whole_seconds().max(0) as u64;
                let e = VaultError::ApprovalPending {
                    approval_id: approval_id.to_string(),
                    expires_in,
                };
                self.audit_denied(actor, "reveal", Some(project), &keys_arg, None, &e);
                return Err(e);
            }
            ApprovalStatus::Approved => {
                if let Some(exp) = doc.approvals[pos].claim_expires_at
                    && now >= exp
                {
                    let e = VaultError::ApprovalExpired;
                    self.audit_denied(actor, "reveal", Some(project), &keys_arg, None, &e);
                    return Err(e);
                }
            }
        }
        let secret = match doc.secret(&project_id, key) {
            Some(s) => Zeroizing::new(s.value.0.to_vec()),
            None => {
                let e = VaultError::NotFound;
                self.audit_denied(actor, "reveal", Some(project), &keys_arg, None, &e);
                return Err(e);
            }
        };
        doc.approvals[pos].status = ApprovalStatus::Consumed;
        match self.commit(
            doc,
            Record {
                actor,
                op: "reveal",
                project: Some(project),
                keys: &keys_arg,
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        ) {
            Ok(()) => Ok(secret),
            Err(e) => Err(e),
        }
    }
    /// Direct human reveal: unlocked project/key to value bytes (zeroized
    /// on drop). Audit/errors carry actor/project/key name only, never value.
    pub fn reveal_human(
        &mut self,
        actor: &str,
        project: &str,
        key: &str,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.check_idle();
        let keys_arg = [key.to_string()];
        if self.keys.is_none() {
            self.audit_denied(
                actor,
                "reveal",
                Some(project),
                &keys_arg,
                None,
                &VaultError::Locked,
            );
            return Err(VaultError::Locked);
        }
        let value = match self.doc.as_ref() {
            Some(doc) => {
                let pid = match doc.project_by_name(project) {
                    Some(p) => p.id.clone(),
                    None => {
                        let e = VaultError::NotFound;
                        self.audit_denied(actor, "reveal", Some(project), &keys_arg, None, &e);
                        return Err(e);
                    }
                };
                match doc.secret(&pid, key) {
                    Some(s) => s.value.0.to_vec(),
                    None => {
                        let e = VaultError::NotFound;
                        self.audit_denied(actor, "reveal", Some(project), &keys_arg, None, &e);
                        return Err(e);
                    }
                }
            }
            None => return Err(VaultError::Locked),
        };
        let secret = Zeroizing::new(value);
        self.audit_record(
            actor,
            Record {
                actor,
                op: "reveal",
                project: Some(project),
                keys: &keys_arg,
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        )?;
        Ok(secret)
    }
    /// Lock: revoke every active lease and deny every active
    /// (pending/approved) approval, persist via commit/audit, then drop
    /// key material. Used by both explicit and idle locking.
    pub fn lock_persist(&mut self) -> Result<(), VaultError> {
        if self.keys.is_none() || self.doc.is_none() {
            self.lock();
            return Ok(());
        }
        let now = self.clock.wall_now();
        let mut doc = match self.doc.clone() {
            Some(d) => d,
            None => {
                self.lock();
                return Ok(());
            }
        };
        for lease in doc.leases.iter_mut() {
            if lease.revoked_at.is_none() {
                lease.revoked_at = Some(now);
            }
        }
        for approval in doc.approvals.iter_mut() {
            if matches!(
                approval.status,
                ApprovalStatus::Pending | ApprovalStatus::Approved
            ) {
                approval.status = ApprovalStatus::Denied;
            }
        }
        // The lock is the security action: recording it must never be the
        // reason it fails. Lifecycle priority lets it spend the reserved
        // headroom, and if even that is exhausted the commit error is not
        // propagated — the stored document keeps the previous checkpoint
        // (valid and loadable) and the in-memory key material is dropped
        // regardless.
        let _ = self.commit_with(
            doc,
            Record {
                actor: "human",
                op: "vault.lock",
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
            Priority::Lifecycle,
        );
        self.lock();
        Ok(())
    }
    fn approval_view(approval: &Approval, now: OffsetDateTime) -> &'static str {
        match approval.status {
            ApprovalStatus::Denied => "denied",
            ApprovalStatus::Consumed => "consumed",
            ApprovalStatus::Pending => {
                if now >= approval.pending_expires_at {
                    "expired"
                } else {
                    "pending"
                }
            }
            ApprovalStatus::Approved => match approval.claim_expires_at {
                Some(exp) if now >= exp => "expired",
                _ => "approved",
            },
        }
    }
    fn revoke_agent_leases(doc: &mut VaultDocument, agent_id: &str, now: OffsetDateTime) {
        for lease in doc.leases.iter_mut() {
            if lease.agent_id == agent_id && lease.revoked_at.is_none() {
                lease.revoked_at = Some(now);
            }
        }
    }
    fn deny_agent_approvals(doc: &mut VaultDocument, agent_id: &str) {
        for approval in doc.approvals.iter_mut() {
            if approval.agent_id == agent_id
                && matches!(
                    approval.status,
                    ApprovalStatus::Pending | ApprovalStatus::Approved
                )
            {
                approval.status = ApprovalStatus::Denied;
            }
        }
    }
    fn revoke_uncovered_leases(
        doc: &mut VaultDocument,
        agent_id: &str,
        project_id: &str,
        now: OffsetDateTime,
    ) {
        let grant_ops = doc
            .active_grant(agent_id, project_id)
            .map(|g| g.ops.clone())
            .unwrap_or_default();
        for lease in doc.leases.iter_mut() {
            if lease.agent_id == agent_id
                && lease.project_id == project_id
                && lease.revoked_at.is_none()
                && !lease.ops.iter().all(|o| grant_ops.contains(o))
            {
                lease.revoked_at = Some(now);
            }
        }
    }
    fn deny_pair_approvals_if_reveal_lost(
        doc: &mut VaultDocument,
        agent_id: &str,
        project_id: &str,
    ) {
        if doc.authorize(agent_id, project_id, Op::Reveal) {
            return;
        }
        for approval in doc.approvals.iter_mut() {
            if approval.agent_id == agent_id
                && approval.project_id == project_id
                && matches!(
                    approval.status,
                    ApprovalStatus::Pending | ApprovalStatus::Approved
                )
            {
                approval.status = ApprovalStatus::Denied;
            }
        }
    }

    /// List agents (name, status, token prefix). Never tokens or digests.
    pub fn agent_list(
        &mut self,
        actor: &str,
    ) -> Result<Vec<(String, AgentStatus, String)>, VaultError> {
        self.gate(actor, "agents.list", None, &[])?;
        let doc = self.doc.as_ref().ok_or(VaultError::Locked)?;
        let list = doc
            .agents
            .iter()
            .map(|a| (a.name.clone(), a.status, a.token_prefix.clone()))
            .collect();
        self.audit_record(
            actor,
            Record {
                actor,
                op: "agents.list",
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        )?;
        Ok(list)
    }

    /// Grant `ops` to an agent on a project (upserts the active grant).
    pub fn grant_add(
        &mut self,
        actor: &str,
        agent_name: &str,
        project_name: &str,
        ops: &[Op],
    ) -> Result<(), VaultError> {
        self.gate(actor, "grants.grant", Some(project_name), &[])?;
        let now = self.clock.wall_now();
        let mut doc = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        // A narrowing grant removes authority, so a full log must not block it
        // (same rule as the revocations). A widening one fails closed: the
        // agent simply does not gain. Captured before the mutation below.
        let previously_granted = match (
            doc.agent_by_name(agent_name).map(|a| a.id.clone()),
            doc.project_by_name(project_name).map(|p| p.id.clone()),
        ) {
            (Some(agent_id), Some(project_id)) => doc
                .active_grant(&agent_id, &project_id)
                .map(|g| g.ops.clone()),
            _ => None,
        };
        match Self::do_grant_add(&mut doc, agent_name, project_name, ops, now) {
            Ok(()) => {
                let record = Record {
                    actor,
                    op: "grants.grant",
                    project: Some(project_name),
                    keys: &[],
                    target: None,
                    decision: Decision::Allowed,
                    reason: None,
                };
                let is_reduction = previously_granted
                    .as_ref()
                    .is_some_and(|before| ops.iter().all(|o| before.contains(o)));
                if is_reduction {
                    self.commit_lifecycle(doc, record)
                } else {
                    self.commit(doc, record)
                }?;
                Ok(())
            }
            Err(e) => {
                self.audit_denied(actor, "grants.grant", Some(project_name), &[], None, &e);
                Err(e)
            }
        }
    }

    fn do_grant_add(
        doc: &mut VaultDocument,
        agent_name: &str,
        project_name: &str,
        ops: &[Op],
        now: OffsetDateTime,
    ) -> Result<(), VaultError> {
        if ops.is_empty() {
            return Err(VaultError::InvalidInput(
                "grant must include at least one op",
            ));
        }
        let agent_id = doc
            .agent_by_name(agent_name)
            .ok_or(VaultError::NotFound)?
            .id
            .clone();
        let project_id = doc
            .project_by_name(project_name)
            .ok_or(VaultError::NotFound)?
            .id
            .clone();
        if let Some(existing) = doc.grants.iter_mut().find(|g| {
            g.agent_id == agent_id && g.project_id == project_id && g.revoked_at.is_none()
        }) {
            existing.ops = ops.to_vec();
        } else {
            doc.grants.push(Grant {
                agent_id: agent_id.clone(),
                project_id: project_id.clone(),
                ops: ops.to_vec(),
                created_at: now,
                revoked_at: None,
            });
        }
        Self::revoke_uncovered_leases(doc, &agent_id, &project_id, now);
        Self::deny_pair_approvals_if_reveal_lost(doc, &agent_id, &project_id);
        Ok(())
    }

    /// Revoke the active grant of an agent on a project. Also revokes
    /// affected leases and denies affected reveal approvals (single commit).
    pub fn grant_revoke(
        &mut self,
        actor: &str,
        agent_name: &str,
        project_name: &str,
    ) -> Result<(), VaultError> {
        self.gate(actor, "grants.revoke", Some(project_name), &[])?;
        let now = self.clock.wall_now();
        let mut doc = match self.doc.clone() {
            Some(d) => d,
            None => return Err(VaultError::Locked),
        };
        match Self::do_grant_revoke(&mut doc, agent_name, project_name, now) {
            Ok(()) => {
                self.commit_lifecycle(
                    doc,
                    Record {
                        actor,
                        op: "grants.revoke",
                        project: Some(project_name),
                        keys: &[],
                        target: None,
                        decision: Decision::Allowed,
                        reason: None,
                    },
                )?;
                Ok(())
            }
            Err(e) => {
                self.audit_denied(actor, "grants.revoke", Some(project_name), &[], None, &e);
                Err(e)
            }
        }
    }

    fn do_grant_revoke(
        doc: &mut VaultDocument,
        agent_name: &str,
        project_name: &str,
        now: OffsetDateTime,
    ) -> Result<(), VaultError> {
        let agent_id = doc
            .agent_by_name(agent_name)
            .ok_or(VaultError::NotFound)?
            .id
            .clone();
        let project_id = doc
            .project_by_name(project_name)
            .ok_or(VaultError::NotFound)?
            .id
            .clone();
        let grant = doc
            .grants
            .iter_mut()
            .find(|g| {
                g.agent_id == agent_id && g.project_id == project_id && g.revoked_at.is_none()
            })
            .ok_or(VaultError::NotFound)?;
        grant.revoked_at = Some(now);
        let (agent_id, project_id) = (grant.agent_id.clone(), grant.project_id.clone());
        Self::revoke_uncovered_leases(doc, &agent_id, &project_id, now);
        Self::deny_pair_approvals_if_reveal_lost(doc, &agent_id, &project_id);
        Ok(())
    }

    /// List grants (agent name, project name, ops, revoked?).
    pub fn grant_list(
        &mut self,
        actor: &str,
    ) -> Result<Vec<crate::model::GrantSummary>, VaultError> {
        self.gate(actor, "grants.list", None, &[])?;
        let doc = self.doc.as_ref().ok_or(VaultError::Locked)?;
        let list = doc
            .grants
            .iter()
            .map(|g| {
                let agent = doc
                    .agents
                    .iter()
                    .find(|a| a.id == g.agent_id)
                    .map(|a| a.name.clone())
                    .unwrap_or_else(|| g.agent_id.clone());
                let project = doc
                    .projects
                    .iter()
                    .find(|p| p.id == g.project_id)
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| g.project_id.clone());
                GrantSummary {
                    agent,
                    project,
                    ops: g.ops.clone(),
                    revoked: g.revoked_at.is_some(),
                }
            })
            .collect();
        self.audit_record(
            actor,
            Record {
                actor,
                op: "grants.list",
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        )?;
        Ok(list)
    }

    /// Resolve an agent token to its id (active agents only, digest lookup).
    /// Works while locked: only digests are consulted.
    pub fn resolve_agent(&self, token: &str) -> Option<String> {
        let digest = crate::crypto::token_digest(token);
        self.agent_digests.get(&digest).cloned()
    }

    // ----- Dashboard D0: human sessions (memory-only capability) ------------

    /// Mint a human session: caller must already hold positive human proof
    /// (the broker verified the passphrase). Requires unlocked vault.
    /// Returns the one-time credential plus display prefix and windows.
    /// Audit `Priority::Ordinary` (B-2): at the soft ceiling this refuses
    /// with `E_AUDIT_FULL` and stores NOTHING. B-1 bound: sweep lapsed
    /// entries, then evict oldest-`last_used` at the cap — mint never fails
    /// for capacity, so `vault.unlock` always returns a usable credential.
    pub fn session_open(
        &mut self,
        actor: &str,
        ttl_secs: u64,
    ) -> Result<(String, String, u64, u64), VaultError> {
        if self.keys.is_none() || self.doc.is_none() {
            self.audit_denied(actor, "session.open", None, &[], None, &VaultError::Locked);
            return Err(VaultError::Locked);
        }
        if !(1..=SESSION_MAX_TTL_SECS).contains(&ttl_secs) {
            let e = VaultError::InvalidInput("ttl_secs must be 1..=1800");
            self.audit_denied(actor, "session.open", None, &[], None, &e);
            return Err(e);
        }
        // B-1: sweep terminal entries first, evict oldest-live at the cap.
        self.sweep_lapsed_sessions();
        if self.sessions.len() >= MAX_SESSIONS
            && let Some(oldest) = self
                .sessions
                .iter()
                .min_by_key(|(_, e)| (e.last_used, e.minted_at))
                .map(|(k, _)| *k)
        {
            self.sessions.remove(&oldest);
        }
        let staged = self.audit.stage(
            Record {
                actor,
                op: "session.open",
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
            self.audit_key.as_ref(),
            Priority::Ordinary,
        );
        let staged = match staged {
            Ok(s) => s,
            Err(e @ VaultError::AuditFull(_)) => {
                return Err(e);
            }
            Err(e @ VaultError::AuditWrite(_)) => {
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        // Capacity already made: mint only after the audit preflight passed,
        // so a refused mint stores nothing.
        let (credential, digest, prefix) = crate::crypto::generate_capability()?;
        let now = self.clock.now();
        self.sessions.insert(
            digest,
            HumanSession {
                prefix: prefix.clone(),
                minted_at: now,
                last_used: now,
                ttl_secs,
            },
        );
        if self.audit.append_staged(&staged).is_err() {
            // Lost a benign race (another writer advanced the head between
            // stage and append): roll back the mint so a refused mint stores
            // nothing, and report the write failure.
            self.sessions.remove(&digest);
            return Err(VaultError::AuditWrite("audit write failed".into()));
        }
        Ok((credential, prefix, ttl_secs, SESSION_MAX_TTL_SECS))
    }

    /// Validate a session credential WITHOUT sliding: returns the entry's
    /// prefix when live, enforcing sliding + absolute TTL on the monotonic
    /// clock. Unknown, closed, idle-lapsed, or absolute-lapsed credentials are
    /// one indistinguishable `E_SESSION_EXPIRED` (no oracle); lapsed entries
    /// are removed. Never touches `last_activity`: a session NEVER extends
    /// the vault idle window — the daemon's idle auto-lock remains the outer
    /// bound and it kills sessions. C-03: the caller slides explicitly only
    /// on `session.touch` or an ALLOWED human op — never on a denial, never
    /// on expiry — so failing calls cannot keep a stolen credential alive.
    fn validate_session(&mut self, credential: &str) -> Result<String, VaultError> {
        let digest = crate::crypto::token_digest(credential);
        let now = self.clock.now();
        let live = match self.sessions.get(&digest) {
            Some(e) => e.clone(),
            None => {
                return Err(VaultError::SessionExpired);
            }
        };
        let idle_lapsed = now.duration_since(live.last_used).as_secs() >= live.ttl_secs;
        let absolute_lapsed = now.duration_since(live.minted_at).as_secs() >= SESSION_MAX_TTL_SECS;
        if self.keys.is_none() || idle_lapsed || absolute_lapsed {
            self.sessions.remove(&digest);
            return Err(VaultError::SessionExpired);
        }
        Ok(live.prefix)
    }

    /// Resolve a session credential to its audit actor
    /// (`human(session:<prefix>)`) WITHOUT sliding. The broker slides
    /// explicitly after the op is known-allowed (C-03).
    pub fn authorize_session(&mut self, credential: &str) -> Result<String, VaultError> {
        let prefix = self.validate_session(credential).inspect_err(|e| {
            self.audit_denied("unauthenticated", "session.use", None, &[], None, e);
        })?;
        Ok(format!("human(session:{prefix})"))
    }

    /// Slide `last_used` to now for a known-live digest. Call only after the
    /// op is known-allowed (C-03).
    pub fn slide_session(&mut self, credential: &str) {
        let digest = crate::crypto::token_digest(credential);
        let now = self.clock.now();
        if let Some(slot) = self.sessions.get_mut(&digest) {
            slot.last_used = now;
        }
    }

    /// B-1 sweep: drop closed/sliding-lapsed/absolute-lapsed entries.
    fn sweep_lapsed_sessions(&mut self) {
        let now = self.clock.now();
        let locked = self.keys.is_none();
        self.sessions.retain(|_, e| {
            if locked {
                return false;
            }
            let idle = now.duration_since(e.last_used).as_secs() >= e.ttl_secs;
            let abs = now.duration_since(e.minted_at).as_secs() >= SESSION_MAX_TTL_SECS;
            !(idle || abs)
        });
    }

    /// True for the passphrase actor and the session actor form
    /// `human(session:<prefix>)` (C-05): the single human-identity notion used
    /// by both the audit string and the human gate, instead of
    /// string-comparing `"human"` in two places.
    pub fn is_human_identity(actor: &str) -> bool {
        actor == "human" || actor.starts_with("human(session:") && actor.ends_with(')')
    }

    /// Remaining windows for a live session entry (sliding, absolute) in
    /// seconds. Caller must have resolved the entry first.
    fn session_windows(&self, entry: &HumanSession, now: Instant) -> (u64, u64) {
        let idle_used = now.duration_since(entry.last_used).as_secs();
        let abs_used = now.duration_since(entry.minted_at).as_secs();
        (
            entry.ttl_secs.saturating_sub(idle_used),
            SESSION_MAX_TTL_SECS.saturating_sub(abs_used),
        )
    }

    /// `session.touch`: re-validate and slide, reporting windows without
    /// performing a real operation. Does not extend the vault idle window.
    /// Audit `Priority::Ordinary` (B-2): at the soft ceiling this refuses
    /// with `E_AUDIT_FULL` and slides NOTHING (C-03).
    pub fn session_touch(&mut self, credential: &str) -> Result<(String, u64, u64), VaultError> {
        let prefix = self.validate_session(credential).inspect_err(|e| {
            self.audit_denied("unauthenticated", "session.touch", None, &[], None, e);
        })?;
        let actor = format!("human(session:{prefix})");
        // Ordinary preflight BEFORE sliding: a refused touch renews nothing.
        if let Err(e) = self.audit.stage(
            Record {
                actor: actor.as_str(),
                op: "session.touch",
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
            self.audit_key.as_ref(),
            Priority::Ordinary,
        ) {
            self.audit_denied(&actor, "session.touch", None, &[], None, &e);
            return Err(e);
        }
        self.slide_session(credential);
        let digest = crate::crypto::token_digest(credential);
        let now = self.clock.now();
        let entry = self.sessions.get(&digest).cloned().expect("just slid");
        let (expires_in, max_expires_in) = self.session_windows(&entry, now);
        let _ = self.audit_record(
            &actor.clone(),
            Record {
                actor: &actor,
                op: "session.touch",
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
        );
        Ok((actor, expires_in, max_expires_in))
    }

    /// `session.close`: revoke immediately. B-4: the FIRST close returns
    /// success; ANY later presentation of that credential — including a close
    /// replay — answers `E_SESSION_EXPIRED` like any unknown credential (a
    /// replay returning success would oracle-ize closed-valid vs unknown).
    /// Audit `Priority::Lifecycle` (B-2, authority-reducing like
    /// `lease.revoke`): applied even when the entry cannot be written, and
    pub fn session_close(&mut self, credential: &str) -> Result<String, VaultError> {
        let prefix = self.validate_session(credential).inspect_err(|e| {
            self.audit_denied("unauthenticated", "session.close", None, &[], None, e);
        })?;
        let actor = format!("human(session:{prefix})");
        let digest = crate::crypto::token_digest(credential);
        self.sessions.remove(&digest);
        let _ = self.audit.append(
            Record {
                actor: actor.as_str(),
                op: "session.close",
                project: None,
                keys: &[],
                target: None,
                decision: Decision::Allowed,
                reason: None,
            },
            self.audit_key.as_ref(),
            Priority::Lifecycle,
        );
        Ok(actor)
    }

    /// Wall-clock display timestamps for session windows: `wall_now +
    /// remaining`. Display only — enforcement is monotonic.
    pub fn session_display_times(&self, expires_in: u64, max_expires_in: u64) -> (String, String) {
        let wall = self.clock.wall_now();
        let exp = wall + time::Duration::seconds(expires_in as i64);
        let max = wall + time::Duration::seconds(max_expires_in as i64);
        (exp.to_string(), max.to_string())
    }

    /// Positive human proof: check pre-derived KEKs against the vault's key
    /// slots (AEAD unwrap only). Works locked or unlocked; the keys produced
    /// by the check are discarded. No oracle: every failure is the same
    /// generic `Auth` (callers map it to one message).
    pub fn proof_is_valid(&self, derived: &DerivedKeks) -> bool {
        self.envelope.unlock_with(derived).is_ok()
    }

    // ----- internals --------------------------------------------------------

    pub(crate) fn audit_record<'a>(
        &mut self,
        actor: &'a str,
        mut record: Record<'a>,
    ) -> Result<(), VaultError> {
        record.actor = actor;
        self.audit
            .append(record, self.audit_key.as_ref(), Priority::Ordinary)
    }

    /// Like [`Self::audit_record`], but for lifecycle events (lock, unlock,
    /// revocation): these may spend the reserved headroom and must never be
    /// the reason a security action fails.
    pub(crate) fn audit_record_lifecycle<'a>(
        &mut self,
        actor: &'a str,
        mut record: Record<'a>,
    ) -> Result<(), VaultError> {
        record.actor = actor;
        self.audit
            .append(record, self.audit_key.as_ref(), Priority::Lifecycle)
    }

    pub(crate) fn audit_denied<'a>(
        &mut self,
        actor: &'a str,
        op: &'a str,
        project: Option<&str>,
        keys: &[String],
        target: Option<&Path>,
        err: &VaultError,
    ) {
        let _ = self.audit.append(
            Record {
                actor,
                op,
                project,
                keys,
                target,
                decision: Decision::Denied,
                reason: Some(err.code()),
            },
            self.audit_key.as_ref(),
            Priority::Ordinary,
        );
    }

    /// Current audit sequence number. The dispatch boundary uses it as a
    /// marker: if a rejected request left it unchanged, nothing recorded that
    /// decision and the boundary records it itself (M4).
    /// Test-only: shrink the audit ceilings so a test can reach them without
    /// writing megabytes. Returns the previous (soft, hard).
    #[doc(hidden)]
    pub fn set_audit_limits_for_test(&mut self, soft: u64, hard: u64) {
        self.audit.set_limits_for_test(soft, hard);
    }

    pub(crate) fn audit_seq(&self) -> u64 {
        self.audit.seq()
    }

    /// Record a denial whose reason is a wire code rather than a `VaultError`.
    /// Used by the dispatch boundary, which only sees the response it is about
    /// to return (M4: an op the broker understood well enough to reject must
    /// not vanish from the log).
    pub(crate) fn audit_denied_code<'a>(
        &mut self,
        actor: &'a str,
        op: &'a str,
        project: Option<&str>,
        reason_code: &str,
    ) {
        let _ = self.audit.append(
            Record {
                actor,
                op,
                project,
                keys: &[],
                target: None,
                decision: Decision::Denied,
                reason: Some(reason_code),
            },
            self.audit_key.as_ref(),
            Priority::Ordinary,
        );
    }
    // ----- Phase 5: run_with_secrets audit ----------------------------------
    // Structural run audit: metadata only (run_id, executable path, argv
    // *count*, cwd, key names, stable outcome tokens, numeric exit status).
    // No parameter can carry argv, environment, or secret values, and nothing
    // secret-bearing is returned. No gate: recording never refuses.
    /// Allowed run gate event: validation passed, before spawn (no run_id yet).
    pub(crate) fn audit_run_allowed(
        &mut self,
        actor: &str,
        project: &str,
        keys: &[String],
        arg_count: u64,
    ) -> Result<(), VaultError> {
        self.audit.append_run(
            RunRecord {
                actor,
                project: Some(project),
                keys,
                run_id: None,
                executable: None,
                arg_count: Some(arg_count),
                cwd: None,
                decision: Decision::Allowed,
                reason: None,
                result: None,
                exit_code: None,
                signal: None,
            },
            self.audit_key.as_ref(),
            Priority::Ordinary,
        )
    }

    /// Run gate for broker `handle_run`/`run_signal`: run the idle-lock
    /// check, then report locked/unlocked. No audit here; callers audit
    /// denials with the run paths below.
    pub(crate) fn ensure_run_unlocked(&mut self) -> Result<(), VaultError> {
        self.check_idle();
        if self.keys.is_none() {
            return Err(VaultError::Locked);
        }
        Ok(())
    }

    /// Signal event: who signaled which run and whether it was allowed.
    /// Structurally safe: no signal name/argv/env/value travels here —
    /// only identity, correlation, decision and a stable `E_*` reason.
    pub(crate) fn audit_run_signal(
        &mut self,
        actor: &str,
        project: &str,
        run_id: &str,
        decision: Decision,
        reason: Option<&str>,
    ) -> Result<(), VaultError> {
        self.audit.append_run(
            RunRecord {
                actor,
                project: Some(project),
                keys: &[],
                run_id: Some(run_id),
                executable: None,
                arg_count: None,
                cwd: None,
                decision,
                reason,
                result: Some("signaled"),
                exit_code: None,
                signal: None,
            },
            self.audit_key.as_ref(),
            Priority::Ordinary,
        )
    }

    /// Capability-withdrawal cleanup for one live run. Only safe correlation
    /// metadata is accepted; argv, environment, output, and secret values
    /// cannot enter this record.
    pub(crate) fn audit_run_revoked(
        &mut self,
        actor: &str,
        project: &str,
        run_id: &str,
    ) -> Result<(), VaultError> {
        // Revocation runs during lock/drain: it may spend the reserved
        // headroom, and the caller treats a failure as non-fatal (see
        // `Daemon::terminate_matching_runs`) — the process groups are already
        // terminated by the time this is recorded.
        self.audit.append_run(
            RunRecord {
                actor,
                project: Some(project),
                keys: &[],
                run_id: Some(run_id),
                executable: None,
                arg_count: None,
                cwd: None,
                decision: Decision::Allowed,
                reason: None,
                result: Some("revoked"),
                exit_code: None,
                signal: None,
            },
            self.audit_key.as_ref(),
            Priority::Lifecycle,
        )
    }

    /// Denied run (best-effort, like `audit_denied`). Stable code only;
    /// executable/cwd are scrubbed — a rejected value may itself carry
    /// secret material.
    pub(crate) fn audit_run_denied(
        &mut self,
        actor: &str,
        project: Option<&str>,
        keys: &[String],
        run_id: Option<&str>,
        err: &VaultError,
    ) {
        let _ = self.audit.append_run(
            RunRecord {
                actor,
                project,
                keys,
                run_id,
                executable: None,
                arg_count: None,
                cwd: None,
                decision: Decision::Denied,
                reason: Some(err.code()),
                result: Some("denied"),
                exit_code: None,
                signal: None,
            },
            self.audit_key.as_ref(),
            Priority::Ordinary,
        );
    }

    /// Start event: child spawned. The stable `"started"` token keeps the
    /// entry self-describing before the exit entry lands.
    // Flat structurally safe audit API: scalar fields only, deliberately no
    // argv/env/value-bearing aggregate objects.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn audit_run_started(
        &mut self,
        actor: &str,
        project: &str,
        keys: &[String],
        run_id: &str,
        executable: &str,
        arg_count: u64,
        cwd: Option<&Path>,
    ) -> Result<(), VaultError> {
        self.audit.append_run(
            RunRecord {
                actor,
                project: Some(project),
                keys,
                run_id: Some(run_id),
                executable: Some(executable),
                arg_count: Some(arg_count),
                cwd,
                decision: Decision::Allowed,
                reason: None,
                result: Some("started"),
                exit_code: None,
                signal: None,
            },
            self.audit_key.as_ref(),
            Priority::Ordinary,
        )
    }

    /// Exit event: stable outcome token plus numeric status and final signal
    /// string only — never output, argv, environment, or values.
    // Flat structurally safe audit API: scalar fields only, deliberately no
    // argv/env/value-bearing aggregate objects.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn audit_run_exited(
        &mut self,
        actor: &str,
        project: &str,
        keys: &[String],
        run_id: &str,
        executable: &str,
        arg_count: u64,
        cwd: Option<&Path>,
        exit_code: Option<i32>,
        signal: Option<&str>,
    ) -> Result<(), VaultError> {
        self.audit.append_run(
            RunRecord {
                actor,
                project: Some(project),
                keys,
                run_id: Some(run_id),
                executable: Some(executable),
                arg_count: Some(arg_count),
                cwd,
                decision: Decision::Allowed,
                reason: None,
                result: Some("exited"),
                exit_code,
                signal,
            },
            self.audit_key.as_ref(),
            Priority::Ordinary,
        )
    }

    /// Refuse locked-state operations, auditing the denial.
    fn gate<'a>(
        &mut self,
        actor: &'a str,
        op: &'a str,
        project: Option<&str>,
        keys: &[String],
    ) -> Result<(), VaultError> {
        self.check_idle();
        if self.keys.is_none() {
            self.audit.append(
                Record {
                    actor,
                    op,
                    project,
                    keys,
                    target: None,
                    decision: Decision::Denied,
                    reason: Some("E_LOCKED"),
                },
                None,
                Priority::Ordinary,
            )?;
            return Err(VaultError::Locked);
        }
        Ok(())
    }

    /// Apply a mutated document: enforce the audit ceiling, append the entry,
    /// then embed its checkpoint and save. On any failure the session keeps the
    /// previous document.
    ///
    /// Ordering is the safety property. The audit entry is appended **before**
    /// `vault.enc` is replaced, because the checkpoint embedded in the vault
    /// names that entry: committing first and appending after would let a
    /// predictable condition (a full audit log) leave the vault on disk
    /// referencing an event that was never written, and `check_checkpoint`
    /// would then refuse every future unlock — a permanently unopenable vault.
    /// Appending first removes that window entirely: an entry with no vault is
    /// harmless (it is just a record beyond the checkpoint), while a vault with
    /// no entry is fatal.
    ///
    /// The ceiling is enforced by [`AuditLog::stage`] before anything is
    /// written, as [`Priority::Ordinary`]: an ordinary mutation that cannot be
    /// recorded is refused with `E_AUDIT_FULL` and the vault is untouched.
    fn commit(&mut self, doc: VaultDocument, record: Record) -> Result<(), VaultError> {
        self.commit_with(doc, record, Priority::Ordinary)
    }

    /// [`Self::commit`] for authority-reducing operations (revocations). These
    /// MUST be applied even when their audit entry cannot be written: refusing
    /// them would leave the capability alive, which is worse than an
    /// unrecorded revocation. The checkpoint then keeps naming the last entry
    /// that really exists, so the vault stays coherent and loadable.
    fn commit_lifecycle(&mut self, doc: VaultDocument, record: Record) -> Result<(), VaultError> {
        self.commit_with(doc, record, Priority::Lifecycle)
    }

    /// [`Self::commit`] with an explicit audit priority. Lifecycle callers
    /// (`vault.lock`, auto-lock, revocation, run drain) pass
    /// [`Priority::Lifecycle`] so a full log can never block a security action.
    fn commit_with(
        &mut self,
        mut doc: VaultDocument,
        record: Record,
        priority: Priority,
    ) -> Result<(), VaultError> {
        let keys = self.keys.clone().ok_or(VaultError::Locked)?;
        // The entry is written before the vault that checkpoints it: the vault
        // must never name an entry that is missing, because `check_checkpoint`
        // would then refuse every future unlock. An entry with no vault is
        // harmless; a vault without its entry is fatal.
        //
        // Ordinary operations fail closed (E_AUDIT_FULL / E_AUDIT_WRITE) and
        // change nothing. A lifecycle operation removes authority
        // (revocation) or holds it (lock): refusing it would leave a
        // capability alive, so it is applied anyway and the checkpoint is left
        // *unmoved*, still naming the last entry that really was written.
        // Coherence holds — the checkpoint always names an existing entry —
        // at the cost of one unrecorded change, which is reported on stderr
        // rather than passed off as success. See `Priority`.
        let op = record.op;
        let mut dropped: Option<VaultError> = None;
        match self.audit.stage(record, self.audit_key.as_ref(), priority) {
            Ok(staged) => match self.audit.append_staged(&staged) {
                Ok(()) => {
                    doc.audit_head = AuditHead {
                        seq: staged.event.seq,
                        hash: staged.hash_hex.clone(),
                    };
                }
                Err(e) if priority == Priority::Ordinary => {
                    return Err(VaultError::AuditWrite(e.to_string()));
                }
                Err(e) => dropped = Some(e),
            },
            Err(e) if priority == Priority::Ordinary => return Err(e),
            Err(e) => dropped = Some(e),
        }
        if let Some(e) = dropped {
            eprintln!(
                "svault: audit entry for lifecycle op `{op}` was NOT written ({e}); \
                 the change is applied and the checkpoint stays on the last recorded entry"
            );
        }
        let mut doc_bytes = serde_json::to_vec(&doc)?;
        self.envelope.reseal_document(&doc_bytes, &keys)?;
        doc_bytes.zeroize();
        // C4: fail BEFORE the commit point when the result would exceed the
        // loader's caps. The appended entry above is now a harmless orphan
        // beyond the checkpoint, so the stored vault stays valid and loadable.
        self.envelope.validate_persistable()?;
        store::save_atomic(&self.path, &self.envelope.to_bytes())?;
        self.doc = Some(doc);
        self.rebuild_agent_digests();
        Ok(())
    }

    /// Rebuild the active-agent digest map from the decrypted document.
    fn rebuild_agent_digests(&mut self) {
        self.agent_digests = self
            .doc
            .as_ref()
            .map(|d| {
                d.agents
                    .iter()
                    .filter(|a| a.status == AgentStatus::Active)
                    .filter_map(|a| {
                        let arr: [u8; 32] = a.token_hash.0.as_slice().try_into().ok()?;
                        Some((arr, a.id.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default();
    }

    fn check_idle(&mut self) {
        if self.idle_self_lock
            && self.idle_timeout != Duration::ZERO
            && self.clock.now().duration_since(self.last_activity) >= self.idle_timeout
            && self.lock_persist().is_err()
        {
            self.lock();
        }
    }

    /// True when the idle window has elapsed. The caller owns the reaction:
    /// the broker runs the full lock lifecycle (terminating runs), while
    /// in-process callers use [`Self::check_idle`].
    pub fn idle_expired(&self) -> bool {
        self.idle_timeout != Duration::ZERO
            && self.clock.now().duration_since(self.last_activity) >= self.idle_timeout
    }

    /// Hand ownership of the idle lock to a caller that can run the full
    /// lifecycle (the daemon's watchdog). After this an expired window never
    /// locks from inside an operation — that path could only drop key material
    /// without draining managed runs, and it would disarm the watchdog. An
    /// operation already authorized when the window passed counts as activity,
    /// which is the documented "the countdown resets on any operation that
    /// requires unlocked state". One lifecycle, one owner.
    pub fn defer_idle_lock(&mut self) {
        self.idle_self_lock = false;
    }

    /// Wall-clock instant at which this session must lock itself, or `None`
    /// when auto-lock is disabled or the vault is already locked. The broker's
    /// watchdog timer arms itself on this value (H1: the lock must happen
    /// without a request to trigger it).
    pub fn idle_deadline(&self) -> Option<Instant> {
        if self.idle_timeout == Duration::ZERO || self.is_locked() {
            return None;
        }
        Some(self.last_activity + self.idle_timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestDir;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    };

    fn pass() -> &'static [u8] {
        b"correct horse battery"
    }

    #[derive(Clone)]
    struct FakeClock(Arc<Mutex<Instant>>);

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }
    }

    fn fake_clock() -> (FakeClock, Arc<Mutex<Instant>>) {
        let t = Arc::new(Mutex::new(Instant::now()));
        (FakeClock(t.clone()), t)
    }

    #[derive(Clone)]
    struct AdjustableClock {
        monotonic_start: Instant,
        wall_start: OffsetDateTime,
        monotonic_secs: Arc<AtomicU64>,
        wall_secs: Arc<AtomicU64>,
    }

    impl Clock for AdjustableClock {
        fn now(&self) -> Instant {
            self.monotonic_start + Duration::from_secs(self.monotonic_secs.load(Ordering::Relaxed))
        }

        fn wall_now(&self) -> OffsetDateTime {
            self.wall_start + time::Duration::seconds(self.wall_secs.load(Ordering::Relaxed) as i64)
        }
    }

    fn reveal_ready(
        dir: &TestDir,
        idle: Duration,
    ) -> (Session, String, Arc<AtomicU64>, Arc<AtomicU64>) {
        let monotonic_secs = Arc::new(AtomicU64::new(0));
        let wall_secs = Arc::new(AtomicU64::new(0));
        let clock = AdjustableClock {
            monotonic_start: Instant::now(),
            wall_start: OffsetDateTime::now_utc(),
            monotonic_secs: monotonic_secs.clone(),
            wall_secs: wall_secs.clone(),
        };
        let (path, _) = fresh(dir);
        let mut session = Session::create(&path, pass(), idle, Box::new(clock)).unwrap();
        session.project_add("human", "acme", &[]).unwrap();
        session
            .secret_set("human", "acme", "API_KEY", b"trap")
            .unwrap();
        let (agent_id, _) = session.agent_add("human", "bot").unwrap();
        session
            .grant_add("human", "bot", "acme", &[Op::Reveal])
            .unwrap();
        (session, agent_id, monotonic_secs, wall_secs)
    }

    fn min_idle() -> Duration {
        Duration::from_secs(60)
    }

    fn fresh(dir: &TestDir) -> (PathBuf, PathBuf) {
        let path = dir.path().join("vault.enc");
        let audit = store::audit_path(&path);
        (path, audit)
    }

    fn unlocked(dir: &TestDir) -> Session {
        let (path, _) = fresh(dir);
        let (clock, _) = fake_clock();
        Session::create(&path, pass(), min_idle(), Box::new(clock)).unwrap()
    }

    fn reload_locked(dir: &TestDir) -> Session {
        let (path, _) = fresh(dir);
        let (clock, _) = fake_clock();
        Session::load(&path, min_idle(), Box::new(clock)).unwrap()
    }

    fn reopen_and_unlock(dir: &TestDir) -> Session {
        let mut s = reload_locked(dir);
        s.unlock(pass()).unwrap();
        s
    }

    #[test]
    fn create_then_fresh_load_reports_locked() {
        let dir = TestDir::new();
        let (path, audit) = fresh(&dir);
        let (clock, _) = fake_clock();
        Session::create(&path, pass(), min_idle(), Box::new(clock)).unwrap();

        let (clock, _) = fake_clock();
        let s = Session::load(&path, min_idle(), Box::new(clock)).unwrap();
        let st = s.status();
        assert!(st.locked);
        assert_eq!(st.version, 1);
        assert_eq!(st.slots.len(), 1);
        assert!(matches!(st.slots[0].0, SlotType::Passphrase));
        // Audit file exists next to the vault with the creation event.
        let content = std::fs::read_to_string(&audit).unwrap();
        assert!(content.contains("vault.created"));
    }

    #[test]
    fn unlock_decrypts_and_wrong_passphrase_is_auth() {
        let dir = TestDir::new();
        let mut s = unlocked(&dir);
        assert!(matches!(
            s.unlock(b"not the passphrase"),
            Err(VaultError::Auth)
        ));
        s.unlock(pass()).unwrap();
        assert!(!s.status().locked);
    }

    #[test]
    fn failed_unlock_is_audited_as_denied() {
        let dir = TestDir::new();
        let (_, audit) = fresh(&dir);
        {
            let mut s = unlocked(&dir);
            assert!(matches!(
                s.unlock(b"not the passphrase"),
                Err(VaultError::Auth)
            ));
        }
        let content = std::fs::read_to_string(&audit).unwrap();
        assert!(content.contains("vault.unlock"));
        assert!(content.contains("denied"));
        assert!(content.contains("E_AUTH"));
    }

    #[test]
    fn tampered_audit_fails_closed_at_load_or_unlock() {
        let dir = TestDir::new();
        {
            unlocked(&dir);
        }
        let (path, audit) = fresh(&dir);
        // Rewrite a MACed entry's operation (history tampering): caught by
        // the structural walk already at load time — the vault is unusable.
        let content = std::fs::read_to_string(&audit)
            .unwrap()
            .replace("vault.created", "vault.hacked");
        std::fs::write(&audit, content).unwrap();

        let (clock, _) = fake_clock();
        assert!(matches!(
            Session::load(&path, min_idle(), Box::new(clock)),
            Err(VaultError::Corrupt(_))
        ));
    }

    #[test]
    fn lock_drops_access() {
        let dir = TestDir::new();
        let mut s = unlocked(&dir);
        s.unlock(pass()).unwrap();
        s.lock();
        assert!(s.status().locked);
        assert!(matches!(s.require_keys(), Err(VaultError::Locked)));
    }

    /// The daemon owns the idle lifecycle (its watchdog runs `lock_and_drain`),
    /// so a daemon-owned session must NOT lock itself from inside an operation:
    /// that path drops key material without draining managed runs and would
    /// also disarm the watchdog. The window still fails closed there; it just
    /// does not perform the lock.
    #[test]
    fn deferred_idle_lock_leaves_the_lock_to_the_owner() {
        // Daemon-owned session: the self-lock is deferred.
        let dir = TestDir::new();
        let (path, _) = fresh(&dir);
        let (clock, _) = fake_clock();
        Session::create(&path, pass(), min_idle(), Box::new(clock)).unwrap();

        let (clock, shared) = fake_clock();
        let mut owned = Session::load(&path, min_idle(), Box::new(clock)).unwrap();
        owned.unlock(pass()).unwrap();
        owned.defer_idle_lock();

        // Cross the timeout with no owner having run yet: the vault must still
        // be unlocked, because an in-op lock here is exactly the bug.
        *shared.lock().unwrap() += min_idle() + Duration::from_secs(1);
        owned.check_idle();
        assert!(
            !owned.status().locked,
            "a daemon-owned session must not lock itself from inside an operation"
        );
        // The owner still sees the expired window, so it knows to act.
        assert!(
            owned.idle_deadline().is_some(),
            "the owner must still see the expired window to act on it"
        );
        drop(owned);

        // Standalone session: the self-lock convenience is retained.
        let dir2 = TestDir::new();
        let (path2, _) = fresh(&dir2);
        let (clock, _) = fake_clock();
        Session::create(&path2, pass(), min_idle(), Box::new(clock)).unwrap();
        let (clock2, shared2) = fake_clock();
        let mut own = Session::load(&path2, min_idle(), Box::new(clock2)).unwrap();
        own.unlock(pass()).unwrap();
        *shared2.lock().unwrap() += min_idle() + Duration::from_secs(1);
        own.check_idle();
        assert!(own.status().locked, "a standalone session locks itself");
    }

    #[test]
    fn auto_lock_after_idle_and_activity_reset() {
        let dir = TestDir::new();
        let (path, _) = fresh(&dir);
        let (clock, _) = fake_clock();
        Session::create(&path, pass(), min_idle(), Box::new(clock)).unwrap();

        let (clock, shared) = fake_clock();
        let mut s = Session::load(&path, min_idle(), Box::new(clock)).unwrap();
        s.unlock(pass()).unwrap();

        // Advance just below the timeout: still unlocked.
        *shared.lock().unwrap() += min_idle() - Duration::from_secs(1);
        s.require_keys().unwrap();

        // Activity reset keeps it unlocked for another window.
        *shared.lock().unwrap() += min_idle() - Duration::from_secs(1);
        s.require_keys().unwrap();

        // Cross the timeout since the last activity refresh: locks itself.
        *shared.lock().unwrap() += min_idle();
        assert!(matches!(s.require_keys(), Err(VaultError::Locked)));
        assert!(s.status().locked);
    }

    #[test]
    fn idle_timeout_zero_disables_auto_lock() {
        let dir = TestDir::new();
        let (path, _) = fresh(&dir);
        let (clock, _) = fake_clock();
        Session::create(&path, pass(), Duration::ZERO, Box::new(clock)).unwrap();

        let (clock, shared) = fake_clock();
        let mut s = Session::load(&path, Duration::ZERO, Box::new(clock)).unwrap();
        s.unlock(pass()).unwrap();
        *shared.lock().unwrap() += Duration::from_secs(3600);
        s.require_keys().unwrap();
        assert!(!s.status().locked);
    }

    #[test]
    fn weak_passphrase_rejected_and_no_file_written() {
        let dir = TestDir::new();
        let (path, _) = fresh(&dir);
        let (clock, _) = fake_clock();
        let err = Session::create(&path, b"short", min_idle(), Box::new(clock)).unwrap_err();
        assert!(matches!(err, VaultError::WeakPassphrase));
        assert!(!path.exists());
    }

    #[test]
    fn create_refuses_existing_vault() {
        let dir = TestDir::new();
        let (path, _) = fresh(&dir);
        let (clock, _) = fake_clock();
        Session::create(&path, pass(), min_idle(), Box::new(clock)).unwrap();
        let (clock, _) = fake_clock();
        assert!(matches!(
            Session::create(&path, pass(), min_idle(), Box::new(clock)),
            Err(VaultError::Exists)
        ));
    }

    #[test]
    fn save_roundtrips_document_through_disk() {
        let dir = TestDir::new();
        let created = unlocked(&dir);
        let expected = created.document().cloned();
        drop(created);

        // H2: one mutable owner at a time, so release before reopening.
        let mut s = reopen_and_unlock(&dir);
        s.save().unwrap();
        drop(s);

        let s2 = reopen_and_unlock(&dir);
        assert_eq!(s2.document().cloned(), expected);
    }

    // ----- Phase 2 ----------------------------------------------------------

    #[test]
    fn project_add_list_and_persistence() {
        let dir = TestDir::new();
        {
            let mut s = unlocked(&dir);
            s.project_add("human", "acme", &[dir.path().to_path_buf()])
                .unwrap();
            s.project_add("human", "beta", &[]).unwrap();
        }
        let mut s = reopen_and_unlock(&dir);
        let projects = s.project_list("human").unwrap();
        assert_eq!(projects.len(), 2);
        let acme = projects.iter().find(|p| p.name == "acme").unwrap();
        assert_eq!(acme.paths, vec![dir.path().to_path_buf()]);
    }

    #[test]
    fn duplicate_project_denied_and_audited_without_state_change() {
        let dir = TestDir::new();
        let mut s = unlocked(&dir);
        s.project_add("human", "acme", &[]).unwrap();
        assert!(matches!(
            s.project_add("human", "acme", &[]),
            Err(VaultError::Exists)
        ));
        assert_eq!(s.project_list("human").unwrap().len(), 1);
        // The denial is in the audit log with a stable reason code.
        let lines = s.audit_tail("human", 50).unwrap();
        assert!(lines.iter().any(|l| l.event.op == "project.add"
            && l.event.decision == Decision::Denied
            && l.event.reason.as_deref() == Some("E_EXISTS")));
    }

    #[test]
    fn secret_set_list_update_delete_roundtrip_and_persistence() {
        let dir = TestDir::new();
        {
            let mut s = unlocked(&dir);
            s.project_add("human", "acme", &[]).unwrap();
            s.secret_set("human", "acme", "STRIPE_KEY", b"sk-live-old")
                .unwrap();
            let listed = s.secret_list("acme", "human").unwrap();
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].0, "STRIPE_KEY");
        }
        {
            let mut s = reopen_and_unlock(&dir);
            s.secret_set("human", "acme", "STRIPE_KEY", b"sk-live-new")
                .unwrap(); // update
            s.secret_delete("human", "acme", "STRIPE_KEY").unwrap();
            assert_eq!(s.secret_list("acme", "human").unwrap().len(), 0);
        }
        let mut s = reopen_and_unlock(&dir);
        assert_eq!(s.secret_list("acme", "human").unwrap().len(), 0);
    }

    #[test]
    fn secret_requires_existing_project_and_is_audited() {
        let dir = TestDir::new();
        let mut s = unlocked(&dir);
        assert!(matches!(
            s.secret_set("human", "ghost", "KEY", b"v"),
            Err(VaultError::NotFound)
        ));
        let lines = s.audit_tail("human", 10).unwrap();
        assert!(lines.iter().any(
            |l| l.event.op == "secret.set" && l.event.reason.as_deref() == Some("E_NOT_FOUND")
        ));
    }

    #[test]
    fn project_remove_refused_while_secrets_exist() {
        let dir = TestDir::new();
        let mut s = unlocked(&dir);
        s.project_add("human", "acme", &[]).unwrap();
        s.secret_set("human", "acme", "K", b"v").unwrap();
        assert!(matches!(
            s.project_remove("human", "acme"),
            Err(VaultError::InvalidInput(_))
        ));
        s.secret_delete("human", "acme", "K").unwrap();
        s.project_remove("human", "acme").unwrap();
        assert!(s.project_list("human").unwrap().is_empty());
    }

    #[test]
    fn path_add_remove_roundtrip() {
        let dir = TestDir::new();
        let mut s = unlocked(&dir);
        s.project_add("human", "acme", &[]).unwrap();
        s.project_path_add("human", "acme", dir.path()).unwrap();
        s.project_path_add("human", "acme", dir.path()).unwrap_err(); // duplicate
        let projects = s.project_list("human").unwrap();
        assert_eq!(projects[0].paths.len(), 1);
        s.project_path_remove("human", "acme", dir.path()).unwrap();
        assert_eq!(s.project_list("human").unwrap()[0].paths.len(), 0);
        s.project_path_remove("human", "acme", dir.path())
            .unwrap_err(); // not found
    }

    #[test]
    fn audit_never_contains_secret_values() {
        let dir = TestDir::new();
        let (_, audit) = fresh(&dir);
        let mut s = unlocked(&dir);
        s.project_add("human", "acme", &[]).unwrap();
        s.secret_set("human", "acme", "STRIPE_KEY", b"sk-trap-0xf00dVALUE")
            .unwrap();
        let content = std::fs::read_to_string(&audit).unwrap();
        assert!(content.contains("STRIPE_KEY"));
        assert!(!content.contains("sk-trap-0xf00dVALUE"));
    }

    #[test]
    fn audit_show_works_while_locked() {
        let dir = TestDir::new();
        {
            unlocked(&dir);
        }
        let mut s = reload_locked(&dir);
        let first = s.audit_tail("human", 10).unwrap();
        assert!(!first.is_empty());
        // The previous read is itself in the log as a mac:null entry (the
        // read happened while locked); the second read surfaces it as the
        // last returned line (its own event is appended afterwards).
        let second = s.audit_tail("human", 10).unwrap();
        let last = second.last().unwrap();
        assert_eq!(last.event.op, "audit.show");
        assert!(last.mac.is_none());
    }

    #[test]
    fn audit_verify_reports_macs_when_unlocked() {
        let dir = TestDir::new();
        let mut s = unlocked(&dir);
        s.project_add("human", "acme", &[]).unwrap();
        let report = s.audit_verify().unwrap();
        assert!(report.entries >= 2);
        assert!(report.macs_verified >= 2);
        assert_eq!(report.macs_null, 0);
    }

    #[test]
    fn locked_ops_are_denied_and_audited() {
        let dir = TestDir::new();
        {
            unlocked(&dir);
        }
        let mut s = reload_locked(&dir);
        assert!(matches!(
            s.project_add("human", "acme", &[]),
            Err(VaultError::Locked)
        ));
        let lines = s.audit_tail("human", 5).unwrap();
        assert!(
            lines
                .iter()
                .any(|l| l.event.op == "project.add"
                    && l.event.reason.as_deref() == Some("E_LOCKED"))
        );
    }

    #[test]
    fn oversized_vault_file_is_rejected_without_reading() {
        let dir = TestDir::new();
        let path = dir.path().join("vault.enc");
        // Sparse file beyond the size cap: rejected by metadata, never read.
        let f = std::fs::File::create(&path).unwrap();
        f.set_len((crate::envelope::MAX_FILE_LEN + 1) as u64)
            .unwrap();
        drop(f);
        let (clock, _) = fake_clock();
        assert!(matches!(
            Session::load(&path, min_idle(), Box::new(clock)),
            Err(VaultError::Corrupt(_))
        ));
    }

    #[test]
    fn missing_audit_event_after_vault_commit_is_detected_forever() {
        // The crash/failure window: the vault committed (embedding a
        // checkpoint) but the audit append was lost. Every subsequent unlock
        // must fail closed until the audit file is repaired.
        let dir = TestDir::new();
        {
            let mut s = unlocked(&dir);
            s.project_add("human", "acme", &[]).unwrap();
        }
        let (_, audit) = fresh(&dir);
        // Drop the last audit line, simulating the append never happening.
        let content = std::fs::read_to_string(&audit).unwrap();
        let trimmed = content.trim_end();
        let without_last = match trimmed.rfind('\n') {
            Some(p) => &trimmed[..=p],
            None => "",
        };
        std::fs::write(&audit, without_last).unwrap();

        let mut s = reload_locked(&dir);
        assert!(matches!(s.unlock(pass()), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn audit_reads_beyond_the_checkpoint_are_allowed() {
        // Reads and denials append entries beyond the vault checkpoint; the
        // audit being AHEAD of the checkpoint is legitimate and must not
        // block unlock.
        let dir = TestDir::new();
        {
            let mut s = unlocked(&dir);
            s.project_add("human", "acme", &[]).unwrap();
            s.audit_tail("human", 5).unwrap();
            s.audit_tail("human", 5).unwrap();
        }
        reopen_and_unlock(&dir);
    }
    #[test]
    fn approval_pending_and_claim_windows_expire() {
        let dir = TestDir::new();
        let (mut session, agent_id, _, wall) = reveal_ready(&dir, min_idle());

        let pending = session
            .approval_request("agent:bot", &agent_id, "acme", "API_KEY")
            .unwrap();
        wall.fetch_add(crate::model::APPROVAL_PENDING_SECS, Ordering::Relaxed);
        assert!(matches!(
            session.approval_decide("human", &pending.id, true),
            Err(VaultError::ApprovalExpired)
        ));

        let approved = session
            .approval_request("agent:bot", &agent_id, "acme", "API_KEY")
            .unwrap();
        session
            .approval_decide("human", &approved.id, true)
            .unwrap();
        wall.fetch_add(crate::model::APPROVAL_CLAIM_SECS, Ordering::Relaxed);
        assert!(matches!(
            session.reveal_claim("agent:bot", &agent_id, "acme", "API_KEY", &approved.id),
            Err(VaultError::ApprovalExpired)
        ));
    }

    #[test]
    fn idle_lock_invalidates_approved_claim_after_unlock() {
        let dir = TestDir::new();
        let idle = min_idle();
        let (mut session, agent_id, monotonic, _) = reveal_ready(&dir, idle);
        let approval = session
            .approval_request("agent:bot", &agent_id, "acme", "API_KEY")
            .unwrap();
        session
            .approval_decide("human", &approval.id, true)
            .unwrap();

        monotonic.store(idle.as_secs(), Ordering::Relaxed);
        assert!(matches!(session.require_keys(), Err(VaultError::Locked)));
        session.unlock(pass()).unwrap();
        assert!(matches!(
            session.reveal_claim("agent:bot", &agent_id, "acme", "API_KEY", &approval.id),
            Err(VaultError::ApprovalDenied)
        ));
    }
}
