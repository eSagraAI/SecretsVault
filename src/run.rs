//! Phase 5 run foundations: structural params, child environment, spawn,
//! registry, and signal helpers.
//!
//! Broker integration owns auth/policy/audit/wiring; this module only builds
//! what the child observes and tracks live runs. Security boundary (I1/I9):
//! broker values never enter wire/argv/audit/errors/logs/tempfiles — child
//! output travels only through the passed stdio FDs. The spawned child is
//! agent-controlled and may exfiltrate its own environment; granting `run`
//! implies accepting that channel. Cwd authorization (caller-provided) selects
//! the directory only; it is not sandboxing. No shell use or interpolation:
//! `executable` is spawned directly with an explicit argv.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use crate::error::VaultError;

/// Max `executable` length in bytes.
pub const MAX_EXECUTABLE_BYTES: usize = 4096;
/// Max argv element count.
pub const MAX_ARGV_ENTRIES: usize = 256;
/// Max aggregate argv bytes.
pub const MAX_ARGV_BYTES: usize = 128 * 1024;
/// Max selected secret keys per run.
pub const MAX_KEYS: usize = 256;
/// Max caller-supplied env entry count.
pub const MAX_ENV_ENTRIES: usize = 256;
/// Max aggregate caller-supplied env bytes (`key.len() + value.len()` summed).
pub const MAX_ENV_BYTES: usize = 128 * 1024;
/// Max resultant child environment bytes (allowlisted + secrets).
pub const MAX_CHILD_ENV_BYTES: usize = 1024 * 1024;
/// Max active runs per agent.
pub const MAX_RUNS_PER_AGENT: usize = 4;
/// Max active runs daemon-wide.
pub const MAX_RUNS_TOTAL: usize = 16;
/// Max run duration in seconds (24h).
pub const MAX_DURATION_SECS: u64 = 24 * 3600;
/// Grace between SIGTERM and SIGKILL in [`terminate_group`].
pub const TERMINATE_GRACE: Duration = Duration::from_millis(250);

/// Deny-by-default passthrough allowlist for caller-supplied env.
pub const ALLOWED_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "SHELL",
    "USER",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
];

/// Structural run params. No `Debug`: `argv`/`env` may carry secret material.
/// `keys: None` (omitted) is distinct from `Some(vec![])` (explicit empty).
pub struct RunParams {
    pub project: String,
    pub executable: String,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub keys: Option<Vec<String>>,
    pub env: Vec<(String, String)>,
    pub timeout_secs: Option<u64>,
}

/// True for names that must never pass through from caller env, even if
/// allowlisted in the future. Secrets bypass this filter (explicit selection
/// wins); only caller passthrough is filtered.
pub fn is_forbidden_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    name == "SVAULT_TOKEN"
        || upper.starts_with("SVAULT_")
        || upper.contains("TOKEN")
        || upper.contains("PASSPHRASE")
        || upper.contains("INTERNAL")
        || upper.starts_with("LD_")
        || upper.starts_with("DYLD_")
}

fn has_nul(s: &str) -> bool {
    s.as_bytes().contains(&0)
}

/// Parse and validate structural run params from a wire `params` value.
/// Distinguishes missing `keys` (`None`) from explicit `[]` (`Some(vec![])`).
/// Byte-aggregate overflows report `TooLarge`; shape/count/name violations
/// report `InvalidInput`. Never echoes values.
pub fn parse_run_params(params: &serde_json::Value) -> Result<RunParams, VaultError> {
    let obj = params
        .as_object()
        .ok_or(VaultError::InvalidInput("params must be an object"))?;
    let get_str = |key: &str| -> Option<&str> { obj.get(key).and_then(|v| v.as_str()) };

    let project = get_str("project").ok_or(VaultError::InvalidInput("missing project"))?;
    if !crate::model::valid_project_name(project) {
        return Err(VaultError::InvalidInput("invalid project"));
    }
    let executable = get_str("executable").ok_or(VaultError::InvalidInput("missing executable"))?;
    if executable.is_empty() || executable.len() > MAX_EXECUTABLE_BYTES || has_nul(executable) {
        return Err(VaultError::InvalidInput("invalid executable"));
    }
    let argv_val = obj
        .get("argv")
        .ok_or(VaultError::InvalidInput("missing argv"))?;
    let argv_arr = argv_val
        .as_array()
        .ok_or(VaultError::InvalidInput("argv must be an array"))?;
    if argv_arr.is_empty() || argv_arr.len() > MAX_ARGV_ENTRIES {
        return Err(VaultError::InvalidInput("invalid argv count"));
    }
    let mut argv = Vec::with_capacity(argv_arr.len());
    let mut argv_bytes = 0usize;
    for item in argv_arr {
        let s = item
            .as_str()
            .ok_or(VaultError::InvalidInput("argv must be strings"))?;
        if has_nul(s) {
            return Err(VaultError::InvalidInput("invalid argv value"));
        }
        argv_bytes = argv_bytes.saturating_add(s.len());
        if argv_bytes > MAX_ARGV_BYTES {
            return Err(VaultError::TooLarge);
        }
        argv.push(s.to_string());
    }

    let cwd = match obj.get("cwd") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => {
            let s = v
                .as_str()
                .ok_or(VaultError::InvalidInput("cwd must be a string"))?;
            if s.is_empty() || has_nul(s) {
                return Err(VaultError::InvalidInput("invalid cwd"));
            }
            Some(s.to_string())
        }
    };

    let keys = match obj.get("keys") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => {
            let arr = v
                .as_array()
                .ok_or(VaultError::InvalidInput("keys must be an array"))?;
            if arr.len() > MAX_KEYS {
                return Err(VaultError::InvalidInput("too many keys"));
            }
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item
                    .as_str()
                    .ok_or(VaultError::InvalidInput("keys must be strings"))?;
                if !crate::model::valid_key(s) {
                    return Err(VaultError::InvalidInput("invalid key"));
                }
                out.push(s.to_string());
            }
            Some(out)
        }
    };

    let mut env = Vec::new();
    if let Some(ev) = obj.get("env")
        && !ev.is_null()
    {
        let map = ev
            .as_object()
            .ok_or(VaultError::InvalidInput("env must be an object"))?;
        if map.len() > MAX_ENV_ENTRIES {
            return Err(VaultError::InvalidInput("too many env entries"));
        }
        let mut env_bytes = 0usize;
        for (k, v) in map {
            let vs = v
                .as_str()
                .ok_or(VaultError::InvalidInput("env values must be strings"))?;
            if k.is_empty() || has_nul(k) || has_nul(vs) {
                return Err(VaultError::InvalidInput("invalid env entry"));
            }
            env_bytes = env_bytes.saturating_add(k.len() + vs.len());
            if env_bytes > MAX_ENV_BYTES {
                return Err(VaultError::TooLarge);
            }
            env.push((k.clone(), vs.to_string()));
        }
    }

    let timeout_secs = match obj.get("timeout_secs") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => {
            let t = v
                .as_u64()
                .ok_or(VaultError::InvalidInput("invalid timeout_secs"))?;
            if t == 0 || t > MAX_DURATION_SECS {
                return Err(VaultError::InvalidInput("invalid timeout_secs"));
            }
            Some(t)
        }
    };

    Ok(RunParams {
        project: project.to_string(),
        executable: executable.to_string(),
        argv,
        cwd,
        keys,
        env,
        timeout_secs,
    })
}

/// Build the child environment: allowlisted caller passthrough plus selected
/// secrets. Caller entries colliding with a selected secret are rejected;
/// forbidden/non-allowlisted caller entries are silently dropped. Any NUL in
/// a surviving value is rejected (execve cannot carry NUL); non-UTF8 secret
/// bytes ride as Unix `OsString`. Resultant size over 1MiB is rejected.
pub fn build_child_env(
    request_env: &[(String, String)],
    secrets: &[(String, Vec<u8>)],
) -> Result<Vec<(OsString, OsString)>, VaultError> {
    let selected: HashSet<&str> = secrets.iter().map(|(k, _)| k.as_str()).collect();
    let allowed: HashSet<&str> = ALLOWED_ENV.iter().copied().collect();
    let mut out: Vec<(OsString, OsString)> = Vec::with_capacity(request_env.len() + secrets.len());
    let mut total = 0usize;
    let push = |k: &[u8],
                v: &[u8],
                out: &mut Vec<(OsString, OsString)>,
                total: &mut usize|
     -> Result<(), VaultError> {
        if k.contains(&0) || v.contains(&0) {
            return Err(VaultError::InvalidInput("env value cannot carry NUL"));
        }
        *total = total.saturating_add(k.len() + v.len());
        if *total > MAX_CHILD_ENV_BYTES {
            return Err(VaultError::TooLarge);
        }
        out.push((
            OsString::from_vec(k.to_vec()),
            OsString::from_vec(v.to_vec()),
        ));
        Ok(())
    };
    for (k, v) in request_env {
        if selected.contains(k.as_str()) {
            return Err(VaultError::InvalidInput(
                "env collides with a selected secret",
            ));
        }
        if is_forbidden_env_name(k) || !allowed.contains(k.as_str()) {
            continue;
        }
        push(k.as_bytes(), v.as_bytes(), &mut out, &mut total)?;
    }
    for (k, v) in secrets {
        push(k.as_bytes(), v, &mut out, &mut total)?;
    }
    Ok(out)
}

/// Spawn `executable` with explicit `argv`/`env` and exactly the three passed
/// stdio FDs (stdin, stdout, stderr). `env_clear` + caller env; dedicated
/// process group (`pgid = pid`); optional `cwd_fd` is an authorized directory
/// capability applied via `fchdir` in `pre_exec` (no pathname, no TOCTOU).
/// Cwd authorization is the caller's job; this is not containment. No shell.
pub fn spawn_from_fds(
    executable: &str,
    argv: &[String],
    env: &[(OsString, OsString)],
    fds: [OwnedFd; 3],
    cwd_fd: Option<OwnedFd>,
) -> std::io::Result<Child> {
    let [stdin_fd, stdout_fd, stderr_fd] = fds;
    let mut cmd = Command::new(executable);
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    if let Some(arg0) = argv.first() {
        cmd.arg0(arg0);
    }
    cmd.env_clear();
    cmd.envs(env.iter().map(|(k, v)| (k, v)));
    cmd.stdin(Stdio::from(stdin_fd));
    cmd.stdout(Stdio::from(stdout_fd));
    cmd.stderr(Stdio::from(stderr_fd));
    // Owned capability: keep open across fork, only the raw number enters the
    // child. `fchdir` + `setpgid` are async-signal-safe; no pathname use.
    let cwd_raw: Option<RawFd> = cwd_fd.as_ref().map(AsRawFd::as_raw_fd);
    unsafe {
        cmd.pre_exec(move || {
            if let Some(fd) = cwd_raw
                && libc::fchdir(fd) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// Unpredictable random run ID (128-bit CSPRNG, hex).
pub fn new_run_id() -> Result<String, VaultError> {
    let b = crate::crypto::random_bytes::<16>()?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn signal_name(sig: i32) -> String {
    match sig {
        1 => "HUP (1)".to_string(),
        2 => "INT (2)".to_string(),
        9 => "KILL (9)".to_string(),
        15 => "TERM (15)".to_string(),
        n => format!("SIG{n} ({n})"),
    }
}

/// Structured exit summary: `{"exit_code": n}` or `{"signal": name}`.
pub fn exit_result(status: &ExitStatus) -> serde_json::Value {
    if let Some(code) = status.code() {
        serde_json::json!({"exit_code": code})
    } else if let Some(sig) = status.signal() {
        serde_json::json!({"signal": signal_name(sig)})
    } else {
        serde_json::json!({"signal": "unknown"})
    }
}

/// Safe signal status for audit: `Some("TERM (15)")`-style string when the
/// child died by signal, else `None`. Never output, argv, env, or values.
pub fn exit_signal(status: &ExitStatus) -> Option<String> {
    status.signal().map(signal_name)
}

/// Parse a `run_signal` name to a libc signal number.
pub fn parse_signal(name: &str) -> Result<i32, VaultError> {
    match name.to_ascii_uppercase().as_str() {
        "TERM" | "SIGTERM" | "15" => Ok(libc::SIGTERM),
        "KILL" | "SIGKILL" | "9" => Ok(libc::SIGKILL),
        "HUP" | "SIGHUP" | "1" => Ok(libc::SIGHUP),
        "INT" | "SIGINT" | "2" => Ok(libc::SIGINT),
        "QUIT" | "SIGQUIT" | "3" => Ok(libc::SIGQUIT),
        _ => Err(VaultError::InvalidInput("unknown signal")),
    }
}

/// Quota failure for registry reservation; carries a stable wire code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReserveError {
    pub code: &'static str,
    pub msg: &'static str,
}

impl ReserveError {
    pub fn code(&self) -> &'static str {
        self.code
    }
}

impl std::fmt::Display for ReserveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.msg)
    }
}

impl std::error::Error for ReserveError {}

/// Safe run metadata only: owner, project, pid, pgid. Never secrets/argv/env/cwd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunMeta {
    pub agent: String,
    pub project: String,
    pub pid: i32,
    pub pgid: i32,
    pub started_at: time::OffsetDateTime,
}

/// Mutex-protected live-run registry enforcing 4/agent and 16/daemon caps.
/// Check-and-insert is atomic under one lock, so concurrent launches cannot
/// overshoot; [`Reservation`] frees uncommitted slots on drop (no leaks).
pub struct RunRegistry {
    inner: Mutex<HashMap<String, RunMeta>>,
}

impl RunRegistry {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Reserve a slot for (`agent`, `run_id`). Returns an RAII guard: call
    /// [`Reservation::activate`] after spawn, then [`Reservation::commit`]
    /// to keep the entry; dropping without commit removes it.
    pub fn try_reserve<'a>(
        &'a self,
        agent: &str,
        project: &str,
        run_id: &str,
    ) -> Result<Reservation<'a>, ReserveError> {
        let mut inner = self.inner.lock().expect("run registry mutex poisoned");
        if inner.contains_key(run_id) {
            return Err(ReserveError {
                code: "E_PROTOCOL",
                msg: "duplicate run_id",
            });
        }
        if inner.len() >= MAX_RUNS_TOTAL {
            return Err(ReserveError {
                code: "E_BUSY",
                msg: "too many concurrent runs",
            });
        }
        let owned = inner.values().filter(|m| m.agent == agent).count();
        if owned >= MAX_RUNS_PER_AGENT {
            return Err(ReserveError {
                code: "E_BUSY",
                msg: "too many concurrent runs for agent",
            });
        }
        inner.insert(
            run_id.to_string(),
            RunMeta {
                agent: agent.to_string(),
                project: project.to_string(),
                pid: 0,
                pgid: 0,
                started_at: time::OffsetDateTime::now_utc(),
            },
        );
        Ok(Reservation {
            registry: self,
            run_id: run_id.to_string(),
            committed: false,
        })
    }
    /// `(agent, project, pid, pgid)` for a run, if live.
    pub fn lookup(&self, run_id: &str) -> Option<(String, String, i32, i32)> {
        self.inner
            .lock()
            .expect("run registry mutex poisoned")
            .get(run_id)
            .map(|m| (m.agent.clone(), m.project.clone(), m.pid, m.pgid))
    }

    /// `(project, pid, pgid)` only when `agent` owns the run.
    pub fn lookup_owned(&self, agent: &str, run_id: &str) -> Option<(String, i32, i32)> {
        self.inner
            .lock()
            .expect("run registry mutex poisoned")
            .get(run_id)
            .filter(|m| m.agent == agent)
            .map(|m| (m.project.clone(), m.pid, m.pgid))
    }

    pub fn remove(&self, run_id: &str) -> Option<RunMeta> {
        self.inner
            .lock()
            .expect("run registry mutex poisoned")
            .remove(run_id)
    }

    pub fn remove_owned(&self, agent: &str, run_id: &str) -> Option<RunMeta> {
        let mut inner = self.inner.lock().expect("run registry mutex poisoned");
        match inner.get(run_id) {
            Some(m) if m.agent == agent => inner.remove(run_id),
            _ => None,
        }
    }

    /// Atomically remove matching runs. The caller that receives an entry owns
    /// process-group termination; concurrent natural-exit cleanup becomes a
    /// no-op for that entry.
    pub(crate) fn take_matching(
        &self,
        agent: Option<&str>,
        project: Option<&str>,
    ) -> Vec<(String, RunMeta)> {
        self.inner
            .lock()
            .expect("run registry mutex poisoned")
            .extract_if(|_, meta| {
                agent.is_none_or(|expected| meta.agent == expected)
                    && project.is_none_or(|expected| meta.project == expected)
            })
            .collect()
    }

    pub fn count_for(&self, agent: &str) -> usize {
        self.inner
            .lock()
            .expect("run registry mutex poisoned")
            .values()
            .filter(|m| m.agent == agent)
            .count()
    }

    /// Live-run count (daemon-wide).
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("run registry mutex poisoned")
            .len()
    }

    /// No live runs.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Safe snapshot of live runs: `(run_id, meta)` pairs. Metadata only —
    /// never argv, environment, secrets, stdio, cwd, or executable.
    pub fn snapshot(&self) -> Vec<(String, RunMeta)> {
        self.inner
            .lock()
            .expect("run registry mutex poisoned")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl Default for RunRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII reservation from [`RunRegistry::try_reserve`]. Drop without commit
/// removes the slot, so failed spawns never leak quota.
pub struct Reservation<'a> {
    registry: &'a RunRegistry,
    run_id: String,
    committed: bool,
}

impl<'a> Reservation<'a> {
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Record the spawned child's pid/pgid on the reserved entry.
    pub fn activate(&self, pid: i32, pgid: i32) -> bool {
        let Ok(mut inner) = self.registry.inner.lock() else {
            return false;
        };
        let Some(meta) = inner.get_mut(&self.run_id) else {
            return false;
        };
        meta.pid = pid;
        meta.pgid = pgid;
        true
    }

    /// Keep the entry beyond this guard (normal post-spawn path).
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl<'a> Drop for Reservation<'a> {
    fn drop(&mut self) {
        if !self.committed
            && let Ok(mut inner) = self.registry.inner.lock()
        {
            inner.remove(&self.run_id);
        }
    }
}

/// Signal a whole dedicated process group.
pub fn signal_group(pgid: i32, sig: i32) -> std::io::Result<()> {
    if pgid <= 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid pgid",
        ));
    }
    // SAFETY: killpg with a validated positive pgid only signals that group.
    let r = unsafe { libc::killpg(pgid, sig) };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Disconnect cleanup: SIGTERM the group, then bounded SIGKILL. Reaping the
/// direct child stays with the owner's `Child::wait`.
pub fn terminate_group(pgid: i32) {
    if pgid <= 0 {
        return;
    }
    // SAFETY: killpg on the run's own dedicated group only.
    unsafe {
        libc::killpg(pgid, libc::SIGTERM);
    }
    std::thread::sleep(TERMINATE_GRACE);
    // SAFETY: existence probe (sig 0) followed by SIGKILL of the same group.
    let alive = unsafe { libc::killpg(pgid, 0) } == 0;
    if alive {
        unsafe {
            libc::killpg(pgid, libc::SIGKILL);
        }
    }
}
