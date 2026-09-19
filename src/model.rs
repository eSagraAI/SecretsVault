//! Vault document model: projects with authorized folders, secrets, and the
//! size limits that bound user-controlled metadata (no unbounded growth).
//!
//! Invariants:
//! - a secret always references an existing project (`project_id`);
//! - project names are unique; secret keys are unique per project;
//! - a project with secrets cannot be removed (no partial states);
//! - all user-controlled names/metadata are length-capped.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::envelope::B64;
use crate::error::VaultError;

pub const MAX_PROJECTS: usize = 256;
pub const MAX_SECRETS: usize = 10_000;
pub const MAX_PATHS_PER_PROJECT: usize = 32;
pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_PROJECT_NAME: usize = 64;
pub const MAX_KEY_LEN: usize = 128;
/// Secret values are environment-style strings; 64 KiB is far beyond any
/// legitimate use and caps document growth.
pub const MAX_VALUE_LEN: usize = 64 * 1024;
pub const MAX_AGENTS: usize = 64;
pub const MAX_LEASES: usize = 1024;
pub const MAX_APPROVALS: usize = 1024;
pub const MIN_LEASE_TTL_SECS: u64 = 1;
pub const MAX_LEASE_TTL_SECS: u64 = 86_400;
pub const APPROVAL_PENDING_SECS: u64 = 600;
pub const APPROVAL_CLAIM_SECS: u64 = 300;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub paths: Vec<PathBuf>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Secret {
    pub project_id: String,
    pub key: String,
    pub value: B64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Meta {
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Operations a grant can authorize. `Manage` exists in the model but no
/// agent-callable management op exists in the MVP (management is human-only).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    Read,
    Inject,
    Run,
    Reveal,
    Manage,
}

impl Op {
    pub fn parse_list(spec: &str) -> Result<Vec<Op>, VaultError> {
        spec.split(',')
            .filter(|s| !s.is_empty())
            .map(|s| match s.trim() {
                "read" => Ok(Op::Read),
                "inject" => Ok(Op::Inject),
                "run" => Ok(Op::Run),
                "reveal" => Ok(Op::Reveal),
                "manage" => Ok(Op::Manage),
                _ => Err(VaultError::InvalidInput(
                    "ops must be a comma-separated list of read/inject/run/reveal/manage",
                )),
            })
            .collect()
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Active,
    Revoked,
}

/// An enrolled agent identity. Only the token digest is stored — the one-time
/// token is shown at enrollment and cannot be recovered.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AgentRecord {
    pub id: String,
    pub name: String,
    pub status: AgentStatus,
    pub token_hash: B64,
    pub token_prefix: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_seen: Option<OffsetDateTime>,
}

/// Flattened grant view for listing.
#[derive(Clone, Debug)]
pub struct GrantSummary {
    pub agent: String,
    pub project: String,
    pub ops: Vec<Op>,
    pub revoked: bool,
}

/// agent × project × operations. Evaluated per request; `revoked_at` ends it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Grant {
    pub agent_id: String,
    pub project_id: String,
    pub ops: Vec<Op>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}

/// TTL-bound subset of an agent's grant on one project. Evaluated per
/// request as grant ∩ lease ops ∩ TTL ∩ unlocked; `revoked_at` ends it.
///
/// `id` is a public handle (listing, revocation, audit actors). Presenting a
/// lease requires the *credential*, of which only a SHA-256 digest is stored:
/// a leaked vault document, audit log, or LLM transcript yields no usable
/// capability. A handle alone authorizes nothing.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Lease {
    pub id: String,
    pub agent_id: String,
    pub project_id: String,
    pub ops: Vec<Op>,
    /// SHA-256 digest of the lease credential (high-entropy random secret —
    /// no slow KDF needed). Never the credential itself.
    pub credential_hash: B64,
    /// Display prefix of the credential (first 4 digest bytes). Safe for
    /// audit entries, listings and logs; cannot be presented as a credential.
    pub credential_prefix: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}

/// Stored approval state. Expiry is computed from the windows, so there is
/// no stored `Expired` variant — the wire `expired` string is derived.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Consumed,
}

/// Human-in-the-loop reveal approval bound to (agent, project, key).
/// Single-use: the claim returns the value exactly once.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Approval {
    pub id: String,
    pub agent_id: String,
    pub project_id: String,
    pub key: String,
    pub status: ApprovalStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub pending_expires_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub approved_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub claim_expires_at: Option<OffsetDateTime>,
}

/// Checkpoint binding the encrypted vault to the expected audit state: the
/// `{seq, hash}` of the audit entry the last committed vault mutation
/// produced. If the audit log does not contain this entry, a vault change
/// was committed without its audit event — detected at every unlock.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuditHead {
    pub seq: u64,
    pub hash: String,
}

impl AuditHead {
    /// Genesis checkpoint of an empty log.
    pub fn genesis() -> Self {
        Self {
            seq: 0,
            hash: "00".repeat(32),
        }
    }
}

/// The DEK-encrypted document. Later phases extend it with serde-default
/// collections without a version bump.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct VaultDocument {
    pub v: u32,
    pub meta: Meta,
    pub projects: Vec<Project>,
    pub secrets: Vec<Secret>,
    #[serde(default)]
    pub agents: Vec<AgentRecord>,
    #[serde(default)]
    pub grants: Vec<Grant>,
    #[serde(default)]
    pub leases: Vec<Lease>,
    #[serde(default)]
    pub approvals: Vec<Approval>,
    #[serde(default = "AuditHead::genesis")]
    pub audit_head: AuditHead,
}

impl VaultDocument {
    pub fn new(created_at: OffsetDateTime) -> Self {
        Self {
            v: 1,
            meta: Meta { created_at },
            projects: Vec::new(),
            secrets: Vec::new(),
            agents: Vec::new(),
            grants: Vec::new(),
            leases: Vec::new(),
            approvals: Vec::new(),
            audit_head: AuditHead::genesis(),
        }
    }

    pub fn project_by_name(&self, name: &str) -> Option<&Project> {
        self.projects.iter().find(|p| p.name == name)
    }

    pub fn project_by_id(&self, id: &str) -> Option<&Project> {
        self.projects.iter().find(|p| p.id == id)
    }

    pub fn secret(&self, project_id: &str, key: &str) -> Option<&Secret> {
        self.secrets
            .iter()
            .find(|s| s.project_id == project_id && s.key == key)
    }

    /// Resolve an agent by token digest. Only active agents resolve.
    pub fn agent_by_token_hash(&self, digest: &[u8; 32]) -> Option<&AgentRecord> {
        self.agents
            .iter()
            .find(|a| a.status == AgentStatus::Active && a.token_hash.0.as_slice() == digest)
    }

    pub fn agent_by_name(&self, name: &str) -> Option<&AgentRecord> {
        self.agents.iter().find(|a| a.name == name)
    }

    pub fn agent_by_id(&self, id: &str) -> Option<&AgentRecord> {
        self.agents.iter().find(|a| a.id == id)
    }

    /// Validate an agent name and its uniqueness (names are unique across
    /// active and revoked agents).
    pub fn check_new_agent_name(&self, name: &str) -> Result<(), VaultError> {
        if !valid_project_name(name) {
            return Err(VaultError::InvalidInput(
                "agent name must be 1-64 chars of [a-zA-Z0-9._-] and not '.' or '..'",
            ));
        }
        if self.agent_by_name(name).is_some() {
            return Err(VaultError::Exists);
        }
        if self.agents.len() >= MAX_AGENTS {
            return Err(VaultError::InvalidInput("too many agents"));
        }
        Ok(())
    }

    /// The active grant for (agent, project), if any.
    pub fn active_grant(&self, agent_id: &str, project_id: &str) -> Option<&Grant> {
        self.grants.iter().find(|g| {
            g.agent_id == agent_id && g.project_id == project_id && g.revoked_at.is_none()
        })
    }

    /// Authorize `op` for the agent on the project: an active, non-revoked
    /// grant whose operation set contains `op`.
    pub fn authorize(&self, agent_id: &str, project_id: &str, op: Op) -> bool {
        self.active_grant(agent_id, project_id)
            .is_some_and(|g| g.ops.contains(&op))
    }

    /// Validate a project name and its uniqueness. `Ok(new_id)` semantics are
    /// handled by the caller; this checks charset, length and duplicates.
    pub fn check_new_project_name(&self, name: &str) -> Result<(), VaultError> {
        if !valid_project_name(name) {
            return Err(VaultError::InvalidInput(
                "project name must be 1-64 chars of [a-zA-Z0-9._-] and not '.' or '..'",
            ));
        }
        if self.project_by_name(name).is_some() {
            return Err(VaultError::Exists);
        }
        if self.projects.len() >= MAX_PROJECTS {
            return Err(VaultError::InvalidInput("too many projects"));
        }
        Ok(())
    }

    /// Validate a secret key (env-style name) and its uniqueness within a
    /// project, plus the global secret cap.
    pub fn check_new_secret_key(&self, project_id: &str, key: &str) -> Result<(), VaultError> {
        if !valid_key(key) {
            return Err(VaultError::InvalidInput(
                "secret key must match [A-Za-z_][A-Za-z0-9_]* (max 128 chars)",
            ));
        }
        if self.secrets.len() >= MAX_SECRETS {
            return Err(VaultError::InvalidInput("too many secrets"));
        }
        if self.secret(project_id, key).is_some() {
            return Err(VaultError::Exists);
        }
        Ok(())
    }

    /// Validate a value length (charset-free: values are arbitrary bytes).
    pub fn check_secret_value(value: &[u8]) -> Result<(), VaultError> {
        if value.is_empty() || value.len() > MAX_VALUE_LEN {
            return Err(VaultError::InvalidInput(
                "secret value must be 1-65536 bytes",
            ));
        }
        Ok(())
    }

    /// Validate and canonicalize an authorized folder: must exist, be a
    /// directory, be absolute after canonicalization, and not duplicate an
    /// existing path of the project.
    pub fn check_new_path(project: &Project, path: &Path) -> Result<PathBuf, VaultError> {
        let canonical = std::fs::canonicalize(path)
            .map_err(|_| VaultError::InvalidInput("path not usable (missing or inaccessible)"))?;
        if !canonical.is_dir() {
            return Err(VaultError::InvalidInput(
                "authorized path must be a directory",
            ));
        }
        if !canonical.is_absolute() {
            return Err(VaultError::InvalidInput("authorized path must be absolute"));
        }
        if canonical.as_os_str().len() > MAX_PATH_LEN {
            return Err(VaultError::InvalidInput("path too long"));
        }
        if project.paths.len() >= MAX_PATHS_PER_PROJECT {
            return Err(VaultError::InvalidInput("too many paths for project"));
        }
        if project.paths.iter().any(|p| p == &canonical) {
            return Err(VaultError::Exists);
        }
        Ok(canonical)
    }

    /// A project can only be removed when no secret references it.
    pub fn check_project_removable(&self, project_id: &str) -> Result<(), VaultError> {
        if self.secrets.iter().any(|s| s.project_id == project_id) {
            return Err(VaultError::InvalidInput(
                "project still has secrets; delete them first",
            ));
        }
        Ok(())
    }
}

/// Project names: 1-64 chars of `[a-zA-Z0-9._-]`, not `.` or `..`.
pub fn valid_project_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_PROJECT_NAME || name == "." || name == ".." {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Secret keys are environment-variable names: `[A-Za-z_][A-Za-z0-9_]*`.
pub fn valid_key(key: &str) -> bool {
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        return false;
    }
    let mut chars = key.chars();
    let first = chars.next().unwrap();
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn doc() -> VaultDocument {
        VaultDocument::new(time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap())
    }

    fn add_project(d: &mut VaultDocument, name: &str) -> String {
        d.check_new_project_name(name).unwrap();
        let id = format!("p{:015x}", d.projects.len());
        d.projects.push(Project {
            id: id.clone(),
            name: name.into(),
            paths: vec![],
            created_at: d.meta.created_at,
        });
        id
    }

    #[test]
    fn project_name_validation() {
        let d = doc();
        assert!(d.check_new_project_name("acme").is_ok());
        assert!(d.check_new_project_name("acme-app.v2_beta").is_ok());
        assert!(d.check_new_project_name("").is_err());
        assert!(d.check_new_project_name("..").is_err());
        assert!(d.check_new_project_name("has space").is_err());
        assert!(
            d.check_new_project_name(&"x".repeat(MAX_PROJECT_NAME + 1))
                .is_err()
        );
    }

    #[test]
    fn duplicate_project_name_rejected() {
        let mut d = doc();
        add_project(&mut d, "acme");
        assert!(matches!(
            d.check_new_project_name("acme"),
            Err(VaultError::Exists)
        ));
    }

    #[test]
    fn key_validation_is_env_style() {
        let mut d = doc();
        let pid = add_project(&mut d, "acme");
        assert!(d.check_new_secret_key(&pid, "STRIPE_KEY").is_ok());
        assert!(d.check_new_secret_key(&pid, "_private").is_ok());
        assert!(d.check_new_secret_key(&pid, "9START").is_err());
        assert!(d.check_new_secret_key(&pid, "HAS-DASH").is_err());
        assert!(d.check_new_secret_key(&pid, "").is_err());
        assert!(
            d.check_new_secret_key(&pid, &"K".repeat(MAX_KEY_LEN + 1))
                .is_err()
        );
        // Same key under a different project is a different namespace.
        let pid2 = add_project(&mut d, "other");
        assert!(d.check_new_secret_key(&pid2, "STRIPE_KEY").is_ok());
    }

    #[test]
    fn duplicate_secret_key_within_project_rejected() {
        let mut d = doc();
        let pid = add_project(&mut d, "acme");
        assert!(d.check_new_secret_key(&pid, "STRIPE_KEY").is_ok());
        d.secrets.push(Secret {
            project_id: pid.clone(),
            key: "STRIPE_KEY".into(),
            value: B64(Zeroizing::new(b"v".to_vec())),
            created_at: d.meta.created_at,
            updated_at: d.meta.created_at,
        });
        assert!(matches!(
            d.check_new_secret_key(&pid, "STRIPE_KEY"),
            Err(VaultError::Exists)
        ));
    }

    #[test]
    fn value_length_is_capped() {
        assert!(VaultDocument::check_secret_value(b"v").is_ok());
        assert!(VaultDocument::check_secret_value(b"").is_err());
        assert!(VaultDocument::check_secret_value(&vec![b'x'; MAX_VALUE_LEN + 1]).is_err());
    }

    #[test]
    fn project_with_secrets_is_not_removable() {
        let mut d = doc();
        let pid = add_project(&mut d, "acme");
        assert!(d.check_project_removable(&pid).is_ok());
        d.secrets.push(Secret {
            project_id: pid.clone(),
            key: "K".into(),
            value: B64(Zeroizing::new(b"v".to_vec())),
            created_at: d.meta.created_at,
            updated_at: d.meta.created_at,
        });
        assert!(d.check_project_removable(&pid).is_err());
    }

    #[test]
    fn path_checks_canonicalize_and_dedupe() {
        let mut d = doc();
        let pid = add_project(&mut d, "acme");
        let dir = crate::testutil::TestDir::new();
        // Callers validate then push (the model never mutates on check).
        let mut project = d.project_by_id(&pid).unwrap().clone();
        let canonical = VaultDocument::check_new_path(&project, dir.path()).unwrap();
        assert!(canonical.is_absolute());
        project.paths.push(canonical);
        // Duplicate (already canonicalized) rejected.
        assert!(matches!(
            VaultDocument::check_new_path(&project, dir.path()),
            Err(VaultError::Exists)
        ));
        // Nonexistent path rejected.
        assert!(VaultDocument::check_new_path(&project, &dir.path().join("missing")).is_err());
    }
}
