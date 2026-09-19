//! CLI: human management commands and agent operations, all as thin clients
//! of the broker daemon over the Unix domain socket. The daemon owns the
//! vault; the CLI never touches vault files.
//!
//! Passphrases and secret values are only ever read from an interactive TTY
//! or (explicitly, with a warning) from files/stdin — never argv. Agent
//! tokens travel via token-fd / token-file / env, never argv (I9).

use std::io::{IsTerminal, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::broker;
use crate::client::{Auth, Client};
use crate::error::VaultError;
use crate::session::DEFAULT_IDLE_LOCK;
use crate::store;

#[derive(Parser)]
#[command(
    name = "svault",
    version,
    about = "Local secrets and permissions broker for AI agents"
)]
struct Cli {
    /// Vault file path (daemon side; defaults to $XDG_DATA_HOME/svault/vault.enc).
    #[arg(long, global = true, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Daemon socket (defaults to $XDG_RUNTIME_DIR/svault/svault.sock).
    #[arg(long, global = true, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Skip the human passphrase prompt by reading it from a file ('-' for
    /// stdin). Warns: test convenience only.
    #[arg(long, global = true, value_name = "PATH")]
    passphrase_file: Option<PathBuf>,

    /// Read the agent token from a file ('-' for stdin). Preferred over
    /// SVAULT_TOKEN (I9: never argv).
    #[arg(long, global = true, value_name = "PATH")]
    token_file: Option<PathBuf>,

    /// Read the agent token from a file descriptor.
    #[arg(long, global = true, value_name = "FD")]
    token_fd: Option<i32>,

    /// Read the lease credential from a file ('-' for stdin). Like the agent
    /// token, a capability never travels in argv (I9).
    #[arg(long, global = true, value_name = "PATH")]
    lease_file: Option<PathBuf>,

    /// Seconds of inactivity after which the daemon locks itself (0 disables).
    /// Defaults to 900.
    #[arg(long, global = true, value_name = "SECS")]
    idle_lock_secs: Option<u64>,

    /// Compare-assist for the interactive first-contact ceremony (64 hex
    /// chars): when pinning at a TTY, a mismatch aborts before prompting.
    /// NEVER a standalone trust root — non-interactive + no pin fails closed
    /// with or without this flag (argv is agent-controlled).
    #[arg(long, global = true, value_name = "HEX")]
    trust_fingerprint: Option<String>,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the broker daemon (owns the vault; blocks).
    Daemon,
    /// Create a new vault (the daemon persists it).
    Init,
    /// Show vault metadata and lock state.
    Status,
    /// Verify the passphrase and unlock the daemon's session.
    Unlock,
    /// Lock the daemon's session (drops key material).
    Lock,
    /// Manage projects and their authorized folders.
    Project {
        #[command(subcommand)]
        command: ProjectCmd,
    },
    /// Manage secrets of a project.
    Secret {
        #[command(subcommand)]
        command: SecretCmd,
    },
    /// Enroll and revoke agents (human-only).
    Agent {
        #[command(subcommand)]
        command: AgentCmd,
    },
    /// Manage agent grants (human-only).
    Grant {
        #[command(subcommand)]
        command: GrantCmd,
    },
    /// Inspect the audit log.
    Audit {
        #[command(subcommand)]
        command: AuditCmd,
    },
    /// Run a child with the project's secrets in its environment (agent only).
    /// Child stdio is inherited; only run metadata prints (to stderr).
    Run {
        /// Project whose secrets enter the child environment.
        project: String,
        /// Secret key names to select (repeatable; omitted = all keys).
        #[arg(long = "key", value_name = "NAME")]
        keys: Vec<String>,
        /// Child working directory (must sit inside an authorized folder).
        #[arg(long, value_name = "PATH")]
        cwd: Option<PathBuf>,
        /// Extra passthrough env as KEY=VALUE (repeatable; allowlisted names only).
        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Kill the run after N seconds (1..86400).
        #[arg(long = "timeout-secs", value_name = "N")]
        timeout_secs: Option<u64>,
        /// Executable plus arguments; the executable is also argv[0].
        #[arg(
            value_name = "COMMAND",
            required = true,
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        command: Vec<String>,
    },
    /// Signal an owned live run.
    RunSignal {
        /// Run ID from the `run` started line.
        run_id: String,
        /// TERM, KILL, HUP, INT, QUIT (SIG prefix and numbers accepted).
        signal: String,
    },
    /// Manage TTL-bound leases: a revocable subset of the caller's own grant.
    Lease {
        #[command(subcommand)]
        command: LeaseCmd,
    },
    /// Reveal one secret value. Agents: without --approval-id this requests
    /// approval (prints the approval id, exit 1); with an approved
    /// --approval-id it prints the value exactly once. Humans print the
    /// value directly.
    Reveal {
        /// Project holding the secret.
        project: String,
        /// Secret key name.
        key: String,
        /// Approval from a prior pending reveal (agent claim).
        #[arg(long = "approval-id", value_name = "ID")]
        approval_id: Option<String>,
    },
    /// Write project secrets to a dotenv file under an authorized folder (agent only).
    Inject {
        /// Project holding the secrets.
        project: String,
        /// Destination path relative to an authorized folder.
        path: String,
        /// Secret key names to select (repeatable; omitted = all keys).
        #[arg(long = "key", value_name = "NAME")]
        keys: Vec<String>,
    },
    /// Inspect and decide reveal approvals.
    Approval {
        #[command(subcommand)]
        command: ApprovalCmd,
    },
    /// Serve the six agent MCP tools over stdio (thin UDS translator).
    McpServe,
    /// Inspect or rotate the broker identity (fingerprints, pins).
    Trust {
        #[command(subcommand)]
        command: TrustCmd,
    },
}
#[derive(Subcommand)]
enum ProjectCmd {
    /// Create a project with optional authorized folders.
    Add {
        name: String,
        #[arg(long = "path")]
        paths: Vec<PathBuf>,
    },
    /// List projects and their authorized folders.
    List,
    /// Add an authorized folder to a project.
    PathAdd { name: String, path: PathBuf },
    /// Remove an authorized folder from a project.
    PathRemove { name: String, path: PathBuf },
    /// Remove a project (refused while it still has secrets).
    Remove { name: String },
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Create or update a secret (value via hidden prompt or stdin).
    Set { project: String, key: String },
    /// List a project's secret key names — never values.
    List { project: String },
    /// Delete a secret.
    Delete { project: String, key: String },
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Enroll an agent; the token is shown once.
    Add {
        name: String,
        /// Also write the token to this file (mode 0600).
        #[arg(long, value_name = "PATH")]
        write_token_file: Option<PathBuf>,
    },
    /// Revoke an agent: its token stops resolving immediately.
    Revoke { name: String },
    /// List agents (name, status, token prefix).
    List,
}

#[derive(Subcommand)]
enum GrantCmd {
    /// Grant ops to an agent on a project (upsert).
    Add {
        agent: String,
        project: String,
        /// Comma-separated: read,inject,run,reveal,manage.
        #[arg(long = "ops")]
        ops: String,
    },
    /// Revoke the grant of an agent on a project.
    Revoke { agent: String, project: String },
    /// List grants.
    List,
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Show the last audit entries (works while locked).
    Show {
        #[arg(long, default_value_t = 20)]
        tail: usize,
    },
    /// Verify the audit chain (MACs are verified on every unlock).
    Verify,
}
#[derive(Subcommand)]
enum LeaseCmd {
    /// Create a TTL-bound subset of your own grant on a project (agent only).
    Create {
        /// Project the lease binds to.
        project: String,
        /// Comma-separated op subset: read,inject,run,reveal,manage.
        #[arg(long = "ops")]
        ops: String,
        /// Time to live in seconds.
        #[arg(long = "ttl-secs", value_name = "N")]
        ttl_secs: u64,
    },
    /// List your leases (agents) or all leases (human).
    List,
    /// Revoke a lease immediately (owner or human).
    Revoke {
        /// Lease id to revoke.
        lease_id: String,
    },
}

#[derive(Subcommand)]
enum ApprovalCmd {
    /// Poll an own approval's state (agent only).
    Status {
        /// Approval id from a pending reveal.
        approval_id: String,
    },
    /// List pending approvals (human only).
    Pending,
    /// Approve a pending reveal (human only).
    Approve {
        /// Approval id to approve.
        approval_id: String,
    },
    /// Deny a pending reveal (human only).
    Deny {
        /// Approval id to deny.
        approval_id: String,
    },
}

#[derive(Subcommand)]
enum TrustCmd {
    /// Show the broker identity fingerprint (live daemon, or `--file` vault's
    /// identity file). Compare out-of-band before first contact.
    Show,
    /// Generate a FRESH broker identity, replacing the current one. LOUD:
    /// every existing client pin fails closed until the human re-pins.
    Reset,
}

/// Entry point; returns the process exit code. `args` is the full argv
/// including the binary name at index 0 (clap convention).
pub fn run(args: &[String], stdin: &mut dyn Read, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return e.exit_code();
        }
    };
    // `run` owns stdio via fd passing, so it reports metadata on stderr and
    // propagates the child exit code instead of 0/1.
    if matches!(cli.command, Cmd::Run { .. }) {
        return match execute_run(&cli, err) {
            Ok(code) => code,
            Err(e) => {
                let _ = writeln!(err, "{e}");
                1
            }
        };
    }
    match execute(&cli, stdin, out, err) {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            1
        }
    }
}

fn execute(
    cli: &Cli,
    stdin: &mut dyn Read,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), VaultError> {
    if let Cmd::Daemon = cli.command {
        // C2: this is the only place a real broker process starts, and it is
        // the only process that ever holds MEK/DEK/K_audit in RAM. Disable
        // core dumps before any key material exists.
        crate::ipc::harden_process();
        let config = broker::DaemonConfig {
            socket_path: socket_path(cli.socket.clone())?,
            vault_path: vault_path(cli.file.clone())?,
            idle_lock: idle_lock(cli.idle_lock_secs),
        };
        let daemon = std::sync::Arc::new(broker::Daemon::new(config)?);
        return daemon.serve();
    }
    if let Cmd::McpServe = cli.command {
        // Thin stdio adapter: token via the existing --token-file/--token-fd/
        // SVAULT_TOKEN priority, never argv. The handshake answers without a
        // broker; each tool call opens one UDS request.
        let token = agent_token(cli)?;
        let socket = socket_path(cli.socket.clone())?;
        return crate::mcp::serve(&socket, token, stdin, out);
    }
    // `trust show|reset` never send credentials: they use a credential-free
    // handshake (show) or touch only the identity file (reset), so they
    // bypass the pin gate by construction.
    if let Cmd::Trust { command } = &cli.command {
        return execute_trust(cli, command, out, err);
    }
    // N1: broker trust is established HERE, before the passphrase is even
    // read (connect happens first by construction) and before any credential
    // byte is written. `--trust-fingerprint` is the explicit out-of-band
    // first-contact path; a TTY human gets an SSH-style confirmation;
    // everyone else fails closed with E_BROKER_UNTRUSTED when no pin exists.
    let mut client = connect_client(cli, err)?;
    // When a token source is configured, EVERY request carries it: the
    // broker then enforces I3 (human-only ops reject agent tokens). An agent
    // omitting its token to masquerade as the human is a documented
    // same-uid residual (threat model).
    let token = agent_token(cli)?;
    let token = token.as_deref();
    match &cli.command {
        Cmd::Init => {
            // Bootstrap: no vault exists yet, so there is nothing to prove.
            let pass = read_passphrase(cli.passphrase_file.as_ref(), true, err)?;
            client.call(
                "vault.create",
                &Auth::None,
                serde_json::json!({"passphrase": pass.as_str()}),
            )?;
            writeln!(out, "vault created")?;
        }
        Cmd::Status => {
            // Public: metadata only, no credentials required.
            let result = client.call("vault.status", &Auth::None, serde_json::json!({}))?;
            writeln!(out, "version: {}", result["version"])?;
            writeln!(out, "created: {}", result["created"].as_str().unwrap_or(""))?;
            writeln!(
                out,
                "state: {}",
                if result["locked"].as_bool().unwrap_or(true) {
                    "locked"
                } else {
                    "unlocked"
                }
            )?;
        }
        Cmd::Unlock => {
            // The passphrase itself is the human proof (cryptographically
            // verified against the key slots by the unlock).
            let pass = read_passphrase(cli.passphrase_file.as_ref(), false, err)?;
            client.call(
                "vault.unlock",
                &Auth::Passphrase(pass.to_string()),
                serde_json::json!({}),
            )?;
            writeln!(out, "unlocked (the daemon session holds the key material)")?;
        }
        Cmd::Lock => {
            // Dual: agents lock with their token, humans with their proof.
            let auth = match &token {
                Some(t) => Auth::AgentToken(t.to_string()),
                None => human_auth(cli, err)?,
            };
            client.call("vault.lock", &auth, serde_json::json!({}))?;
            writeln!(out, "locked")?;
        }
        Cmd::Project { command } => match command {
            ProjectCmd::Add { name, paths } => {
                let paths: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
                client.call(
                    "project.add",
                    &human_auth(cli, err)?,
                    serde_json::json!({"name": name, "paths": paths}),
                )?;
                writeln!(out, "project added: {name}")?;
            }
            ProjectCmd::List => {
                let result = client.call(
                    "project.list",
                    &human_auth(cli, err)?,
                    serde_json::json!({}),
                )?;
                for p in result["projects"].as_array().unwrap_or(&Vec::new()) {
                    writeln!(
                        out,
                        "{} ({} authorized folders)",
                        p["name"].as_str().unwrap_or(""),
                        p["paths"].as_array().map(|a| a.len()).unwrap_or(0)
                    )?;
                    for path in p["paths"].as_array().unwrap_or(&Vec::new()) {
                        writeln!(out, "  {}", path.as_str().unwrap_or(""))?;
                    }
                }
            }
            ProjectCmd::PathAdd { name, path } => {
                client.call(
                    "project.path.add",
                    &human_auth(cli, err)?,
                    serde_json::json!({"name": name, "path": path.display().to_string()}),
                )?;
                writeln!(out, "authorized folder added to {name}")?;
            }
            ProjectCmd::PathRemove { name, path } => {
                client.call(
                    "project.path.remove",
                    &human_auth(cli, err)?,
                    serde_json::json!({"name": name, "path": path.display().to_string()}),
                )?;
                writeln!(out, "authorized folder removed from {name}")?;
            }
            ProjectCmd::Remove { name } => {
                client.call(
                    "project.remove",
                    &human_auth(cli, err)?,
                    serde_json::json!({"name": name}),
                )?;
                writeln!(out, "project removed: {name}")?;
            }
        },
        Cmd::Secret { command } => match command {
            SecretCmd::Set { project, key } => {
                let value = read_value(stdin, err)?;
                client.call(
                    "secret.set",
                    &human_auth(cli, err)?,
                    serde_json::json!({"project": project, "key": key, "value": value.as_str()}),
                )?;
                writeln!(out, "secret set: {project}/{key}")?;
            }
            SecretCmd::List { project } => {
                // Dual: agents use their token, the human uses proof.
                let auth = match &token {
                    Some(t) => Auth::AgentToken(t.to_string()),
                    None => human_auth(cli, err)?,
                };
                let params = lease_scoped(cli, serde_json::json!({"project": project}))?;
                let result = client.call("secrets.list", &auth, params)?;
                for s in result["secrets"].as_array().unwrap_or(&Vec::new()) {
                    writeln!(
                        out,
                        "{} (updated {})",
                        s["key"].as_str().unwrap_or(""),
                        s["updated"].as_str().unwrap_or("")
                    )?;
                }
            }
            SecretCmd::Delete { project, key } => {
                client.call(
                    "secret.delete",
                    &human_auth(cli, err)?,
                    serde_json::json!({"project": project, "key": key}),
                )?;
                writeln!(out, "secret deleted: {project}/{key}")?;
            }
        },
        Cmd::Agent { command } => match command {
            AgentCmd::Add {
                name,
                write_token_file: token_path,
            } => {
                let result = client.call(
                    "agents.add",
                    &human_auth(cli, err)?,
                    serde_json::json!({"name": name}),
                )?;
                let token = result["token"].as_str().unwrap_or_default();
                writeln!(
                    out,
                    "agent enrolled: {name} ({})",
                    result["agent_id"].as_str().unwrap_or("")
                )?;
                writeln!(out, "token (shown once, store it now): {token}")?;
                if let Some(p) = token_path {
                    write_token_file(p, token)?;
                    writeln!(out, "token written to {} (0600)", p.display())?;
                }
            }
            AgentCmd::Revoke { name } => {
                client.call(
                    "agents.revoke",
                    &human_auth(cli, err)?,
                    serde_json::json!({"name": name}),
                )?;
                writeln!(out, "agent revoked: {name}")?;
            }
            AgentCmd::List => {
                let result =
                    client.call("agents.list", &human_auth(cli, err)?, serde_json::json!({}))?;
                for a in result["agents"].as_array().unwrap_or(&Vec::new()) {
                    writeln!(
                        out,
                        "{} ({}, token prefix {})",
                        a["name"].as_str().unwrap_or(""),
                        a["status"].as_str().unwrap_or(""),
                        a["token_prefix"].as_str().unwrap_or("")
                    )?;
                }
            }
        },
        Cmd::Grant { command } => match command {
            GrantCmd::Add {
                agent,
                project,
                ops,
            } => {
                client.call(
                    "grants.grant",
                    &human_auth(cli, err)?,
                    serde_json::json!({"agent": agent, "project": project, "ops": ops}),
                )?;
                writeln!(out, "grant added: {agent} on {project} ({ops})")?;
            }
            GrantCmd::Revoke { agent, project } => {
                client.call(
                    "grants.revoke",
                    &human_auth(cli, err)?,
                    serde_json::json!({"agent": agent, "project": project}),
                )?;
                writeln!(out, "grant revoked: {agent} on {project}")?;
            }
            GrantCmd::List => {
                let result =
                    client.call("grants.list", &human_auth(cli, err)?, serde_json::json!({}))?;
                for g in result["grants"].as_array().unwrap_or(&Vec::new()) {
                    writeln!(
                        out,
                        "{} on {} ops={} revoked={}",
                        g["agent"].as_str().unwrap_or(""),
                        g["project"].as_str().unwrap_or(""),
                        g["ops"],
                        g["revoked"]
                    )?;
                }
            }
        },
        Cmd::Audit { command } => match command {
            AuditCmd::Show { tail } => {
                let result = client.call(
                    "audit.show",
                    &human_auth(cli, err)?,
                    serde_json::json!({"tail": tail}),
                )?;
                for e in result["entries"].as_array().unwrap_or(&Vec::new()) {
                    writeln!(out, "{}", render_audit_line(e))?;
                }
            }
            AuditCmd::Verify => {
                let result = client.call(
                    "audit.verify",
                    &human_auth(cli, err)?,
                    serde_json::json!({}),
                )?;
                writeln!(
                    out,
                    "entries: {} · macs verified: {} · macs null: {}",
                    result["entries"], result["macs_verified"], result["macs_null"]
                )?;
            }
        },
        Cmd::RunSignal { run_id, signal } => {
            let auth = agent_auth(token)?;
            let ack = client.run_signal(&auth, run_id, signal)?;
            writeln!(out, "run {} signaled", ack.run_id)?;
        }
        Cmd::Lease { command } => match command {
            LeaseCmd::Create {
                project,
                ops,
                ttl_secs,
            } => {
                // Agent-only: a lease is a TTL-bound subset of the caller's own grant.
                let auth = agent_auth(token)?;
                let socket = socket_path(cli.socket.clone())?;
                let result = crate::mcp::broker_call(
                    &socket,
                    "lease.create",
                    &auth,
                    serde_json::json!({"project": project, "ops": ops, "ttl_secs": ttl_secs}),
                )
                .map_err(|e| e.into_protocol())?;
                // The credential prints once, here, like an enrollment token:
                // it is never persisted in the vault and never in argv.
                writeln!(
                    out,
                    "lease created: {} (expires in {}s)",
                    result["lease_id"].as_str().unwrap_or(""),
                    result["expires_in"]
                )?;
                if let Some(credential) = result["lease_credential"].as_str() {
                    writeln!(
                        out,
                        "lease credential (shown once, store it now): {credential}"
                    )?;
                }
            }
            LeaseCmd::List => {
                // Dual: agents see their own leases, the human sees all.
                let auth = match &token {
                    Some(t) => Auth::AgentToken(t.to_string()),
                    None => human_auth(cli, err)?,
                };
                let socket = socket_path(cli.socket.clone())?;
                let result =
                    crate::mcp::broker_call(&socket, "lease.list", &auth, serde_json::json!({}))
                        .map_err(|e| e.into_protocol())?;
                for l in result["leases"].as_array().unwrap_or(&Vec::new()) {
                    let ops = l
                        .get("ops")
                        .map(|v| {
                            v.as_str()
                                .map(str::to_string)
                                .unwrap_or_else(|| v.to_string())
                        })
                        .unwrap_or_default();
                    writeln!(
                        out,
                        "{} [{}] {} {} (expires in {}s)",
                        l["lease_id"].as_str().unwrap_or(""),
                        l["lease_prefix"].as_str().unwrap_or(""),
                        l["project"].as_str().unwrap_or(""),
                        ops,
                        l["expires_in"]
                    )?;
                }
            }
            LeaseCmd::Revoke { lease_id } => {
                // Dual: the owner revokes with its token, the human with proof.
                let auth = match &token {
                    Some(t) => Auth::AgentToken(t.to_string()),
                    None => human_auth(cli, err)?,
                };
                let socket = socket_path(cli.socket.clone())?;
                crate::mcp::broker_call(
                    &socket,
                    "lease.revoke",
                    &auth,
                    serde_json::json!({"lease_id": lease_id}),
                )
                .map_err(|e| e.into_protocol())?;
                writeln!(out, "lease revoked: {lease_id}")?;
            }
        },
        Cmd::Reveal {
            project,
            key,
            approval_id,
        } => {
            // Dual: agents request/claim with their token, the human reads
            // directly. The only path that ever prints a secret value is an
            // intentionally successful claim.
            let auth = match &token {
                Some(t) => Auth::AgentToken(t.to_string()),
                None => human_auth(cli, err)?,
            };
            let mut params =
                lease_scoped(cli, serde_json::json!({"project": project, "key": key}))?;
            if let Some(a) = approval_id {
                params["approval_id"] = serde_json::json!(a);
            }
            let socket = socket_path(cli.socket.clone())?;
            match crate::mcp::broker_call(&socket, "reveal", &auth, params) {
                Ok(result) => {
                    let Some(v) = result.get("value").and_then(|v| v.as_str()) else {
                        return Err(VaultError::Protocol("reveal response missing value".into()));
                    };
                    writeln!(out, "{v}")?;
                }
                Err(e) if e.code == "E_APPROVAL_PENDING" => {
                    let id = e
                        .data
                        .as_ref()
                        .and_then(|d| d.get("approval_id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let exp = e
                        .data
                        .as_ref()
                        .and_then(|d| d.get("expires_in"))
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    writeln!(out, "approval pending: {id} (expires in {exp}s)")?;
                    return Err(e.into_protocol());
                }
                Err(e) => return Err(e.into_protocol()),
            }
        }
        Cmd::Inject {
            project,
            path,
            keys,
        } => {
            let auth = agent_auth(token)?;
            let mut params = serde_json::json!({"project": project, "path": path});
            if !keys.is_empty() {
                params["keys"] = serde_json::json!(keys);
            }
            let params = lease_scoped(cli, params)?;
            let result = client.call("inject_file", &auth, params)?;
            let dest = result["path"].as_str().unwrap_or(path.as_str());
            let count = result["count"].clone();
            writeln!(out, "injected {count} keys to {dest}")?;
            for k in result["keys"].as_array().unwrap_or(&Vec::new()) {
                writeln!(out, "{}", k.as_str().unwrap_or(""))?;
            }
        }
        Cmd::Approval { command } => match command {
            ApprovalCmd::Status { approval_id } => {
                // Agent-only: agents poll their own approvals.
                let auth = agent_auth(token)?;
                let socket = socket_path(cli.socket.clone())?;
                let result = crate::mcp::broker_call(
                    &socket,
                    "approvals.status",
                    &auth,
                    serde_json::json!({"approval_id": approval_id}),
                )
                .map_err(|e| e.into_protocol())?;
                writeln!(
                    out,
                    "{} {} (expires in {}s)",
                    result["status"].as_str().unwrap_or(""),
                    approval_id,
                    result["expires_in"]
                )?;
            }
            ApprovalCmd::Pending => {
                let socket = socket_path(cli.socket.clone())?;
                let result = crate::mcp::broker_call(
                    &socket,
                    "approvals.pending",
                    &human_auth(cli, err)?,
                    serde_json::json!({}),
                )
                .map_err(|e| e.into_protocol())?;
                for a in result["approvals"].as_array().unwrap_or(&Vec::new()) {
                    writeln!(
                        out,
                        "{} {} {}/{} {}",
                        a["approval_id"].as_str().unwrap_or(""),
                        a["agent"].as_str().unwrap_or(""),
                        a["project"].as_str().unwrap_or(""),
                        a["key"].as_str().unwrap_or(""),
                        a["status"].as_str().unwrap_or("")
                    )?;
                }
            }
            ApprovalCmd::Approve { approval_id } => {
                let socket = socket_path(cli.socket.clone())?;
                crate::mcp::broker_call(
                    &socket,
                    "approvals.approve",
                    &human_auth(cli, err)?,
                    serde_json::json!({"approval_id": approval_id}),
                )
                .map_err(|e| e.into_protocol())?;
                writeln!(out, "approved: {approval_id}")?;
            }
            ApprovalCmd::Deny { approval_id } => {
                let socket = socket_path(cli.socket.clone())?;
                crate::mcp::broker_call(
                    &socket,
                    "approvals.deny",
                    &human_auth(cli, err)?,
                    serde_json::json!({"approval_id": approval_id}),
                )
                .map_err(|e| e.into_protocol())?;
                writeln!(out, "denied: {approval_id}")?;
            }
        },
        Cmd::Trust { .. } => unreachable!("handled above"),
        Cmd::McpServe => unreachable!("handled above"),
        Cmd::Daemon | Cmd::Run { .. } => unreachable!("handled above"),
    }
    Ok(())
}

/// `trust show|reset`: credential-free by construction (a bare handshake for
/// show, identity-file only for reset), so no pin gate applies.
fn execute_trust(
    cli: &Cli,
    command: &TrustCmd,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), VaultError> {
    match command {
        TrustCmd::Show => {
            // Prefer the live daemon (credential-free handshake, no pin);
            // compare with the identity file next to `--file` and WARN on
            // disagreement (F8): after `trust reset` the file holds the new
            // key while a still-running daemon proves with the old one, so a
            // silent single line would strand the operator.
            let live = trust_show_live(&socket_path(cli.socket.clone())?).ok();
            let file_fp = crate::broker_identity::BrokerIdentity::load_or_generate(&vault_path(
                cli.file.clone(),
            )?)
            .map(|id| crate::broker_identity::fingerprint(&id.public_key()))
            .ok();
            match (live, file_fp) {
                (Some(l), Some(f)) if l == f => writeln!(out, "broker fingerprint: {l}")?,
                (Some(l), Some(f)) => {
                    writeln!(out, "broker fingerprint (live daemon): {l}")?;
                    writeln!(out, "broker fingerprint (identity file): {f}")?;
                    writeln!(
                        err,
                        "svault: WARNING: live daemon and identity file disagree — \
                         restart the daemon after `trust reset` before re-pinning"
                    )?;
                }
                (Some(l), None) => writeln!(out, "broker fingerprint: {l}")?,
                (None, Some(f)) => writeln!(
                    out,
                    "broker fingerprint (identity file, daemon not reachable): {f}"
                )?,
                (None, None) => {
                    return Err(VaultError::BrokerUntrusted(
                        "no live daemon and no identity file; nothing to show".into(),
                    ));
                }
            }
        }
        TrustCmd::Reset => {
            // Human-gated: TTY confirmation, no silent rotation. Resetting
            // while a daemon serves the same vault strands it (it keeps
            // proving with the OLD key): require the daemon to be stopped
            // first — refuse when the socket still answers — and say so.
            if !std::io::stdin().is_terminal() && cli.passphrase_file.is_none() {
                return Err(VaultError::HumanRequired);
            }
            let socket = socket_path(cli.socket.clone())?;
            if trust_show_live(&socket).is_ok() {
                return Err(VaultError::InvalidInput(
                    "a daemon is still serving this socket: stop it before `trust reset`, \
                     then start it again afterwards so it loads the new identity",
                ));
            }
            confirm_reset_tty(err)?;
            let vault = vault_path(cli.file.clone())?;
            let fp = crate::broker_identity::BrokerIdentity::regenerate(&vault)?;
            writeln!(
                err,
                "svault: broker identity ROTATED — restart the daemon, then re-pin every client \
                 at a TTY (all existing pins now fail closed by design)"
            )?;
            writeln!(
                out,
                "new broker fingerprint: {}",
                crate::broker_identity::fingerprint(&fp)
            )?;
        }
    }
    Ok(())
}

/// Run a child with secrets: build structural params, pass OS FDs 0/1/2 via
/// `SCM_RIGHTS`, report safe metadata on stderr, map the child's exit.
/// `executable` doubles as argv[0]; no shell, no interpolation. Never prints
/// secret values, tokens, or child output — child stdio is inherited, and
/// nothing from the `out`/`stdin` handles touches the wire.
fn execute_run(cli: &Cli, err: &mut dyn Write) -> Result<i32, VaultError> {
    let Cmd::Run {
        project,
        keys,
        cwd,
        env,
        timeout_secs,
        command,
    } = &cli.command
    else {
        unreachable!("run dispatch");
    };
    let (executable, argv) = build_argv(command)?;
    let params = build_run_params(project, keys, cwd, env, *timeout_secs, &executable, argv)?;
    validate_run_token_source(cli)?;
    let auth = agent_auth(agent_token(cli)?.as_deref())?;
    // Agents never TOFU: `run` fails closed without a pin. The human pins
    // once via any interactive command at a TTY first (the flag alone never
    // pins); afterwards non-interactive contexts reuse the pin.
    let mut client = Client::connect(&socket_path(cli.socket.clone())?)?;
    use std::os::fd::AsRawFd;
    let fds = [
        std::io::stdin().as_raw_fd(),
        std::io::stdout().as_raw_fd(),
        std::io::stderr().as_raw_fd(),
    ];
    let (_, exited) = client.run_with_secrets_notify(&auth, params, &fds, |started| {
        let _ = writeln!(err, "run {} pid {}", started.run_id, started.pid);
    })?;
    match (exited.exit_code, exited.signal.as_deref()) {
        (Some(code), _) => {
            let _ = writeln!(err, "run {} exited {code}", exited.run_id);
            Ok(code)
        }
        (None, Some(signal)) => {
            let _ = writeln!(err, "run {} signaled {signal}", exited.run_id);
            Ok(1)
        }
        (None, None) => Err(VaultError::Protocol(
            "run: exited response lacks status".into(),
        )),
    }
}

fn validate_run_token_source(cli: &Cli) -> Result<(), VaultError> {
    if cli.token_fd.is_some_and(|fd| fd <= 2) || cli.token_file.as_deref() == Some(Path::new("-")) {
        return Err(VaultError::InvalidInput(
            "run token source cannot alias child stdio",
        ));
    }
    Ok(())
}

/// Require an agent token (never argv/passphrase) for run operations.
fn agent_auth(token: Option<&str>) -> Result<Auth, VaultError> {
    match token {
        Some(t) => Ok(Auth::AgentToken(t.to_string())),
        // Same message as the broker's missing-grant denial: no oracle,
        // no hint about token plumbing.
        None => Err(VaultError::Permission),
    }
}

/// The full command vector is the child argv verbatim, with the executable
/// also at argv[0]. Empty elements or NUL bytes are rejected before sending.
fn build_argv(command: &[String]) -> Result<(String, Vec<String>), VaultError> {
    let Some(executable) = command.first().cloned() else {
        return Err(VaultError::InvalidInput("missing command"));
    };
    if executable.is_empty() || executable.as_bytes().contains(&0) {
        return Err(VaultError::InvalidInput("invalid executable"));
    }
    for arg in command {
        if arg.as_bytes().contains(&0) {
            return Err(VaultError::InvalidInput("invalid argv value"));
        }
    }
    Ok((executable, command.to_vec()))
}

/// Assemble the structural `run_with_secrets` params. `env` overrides are
/// `KEY=VALUE` pairs for allowlisted names only; the collected process
/// environment covers exactly `crate::run::ALLOWED_ENV` minus forbidden
/// names (never `SVAULT_*` or credential material). `keys: []` means
/// omitted (all keys), matching the broker's `None` semantics.
fn build_run_params(
    project: &str,
    keys: &[String],
    cwd: &Option<PathBuf>,
    env_overrides: &[String],
    timeout_secs: Option<u64>,
    executable: &str,
    argv: Vec<String>,
) -> Result<serde_json::Value, VaultError> {
    let mut overrides = std::collections::HashMap::new();
    for item in env_overrides {
        let (name, value) = item
            .split_once('=')
            .ok_or(VaultError::InvalidInput("invalid env entry"))?;
        if name.is_empty()
            || name.as_bytes().contains(&0)
            || value.as_bytes().contains(&0)
            || crate::run::is_forbidden_env_name(name)
            || !crate::run::ALLOWED_ENV.contains(&name)
        {
            return Err(VaultError::InvalidInput("invalid env entry"));
        }
        overrides.insert(name.to_string(), value.to_string());
    }
    let mut env = serde_json::Map::new();
    for name in crate::run::ALLOWED_ENV {
        if let Some(value) = overrides.get(*name) {
            env.insert(
                (*name).to_string(),
                serde_json::Value::String(value.clone()),
            );
        } else if !crate::run::is_forbidden_env_name(name)
            && let Ok(value) = std::env::var(*name)
        {
            env.insert((*name).to_string(), serde_json::Value::String(value));
        }
    }
    let mut params = serde_json::Map::new();
    params.insert(
        "project".to_string(),
        serde_json::Value::String(project.to_string()),
    );
    params.insert(
        "executable".to_string(),
        serde_json::Value::String(executable.to_string()),
    );
    params.insert(
        "argv".to_string(),
        serde_json::Value::Array(argv.into_iter().map(serde_json::Value::String).collect()),
    );
    if let Some(dir) = cwd {
        params.insert(
            "cwd".to_string(),
            serde_json::Value::String(dir.display().to_string()),
        );
    }
    if !keys.is_empty() {
        params.insert(
            "keys".to_string(),
            serde_json::Value::Array(
                keys.iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !env.is_empty() {
        params.insert("env".to_string(), serde_json::Value::Object(env));
    }
    if let Some(t) = timeout_secs {
        params.insert(
            "timeout_secs".to_string(),
            serde_json::Value::Number(t.into()),
        );
    }
    Ok(serde_json::Value::Object(params))
}

fn render_audit_line(entry: &serde_json::Value) -> String {
    let mut s = format!(
        "#{} {} {} {} {}",
        entry["seq"], entry["ts"], entry["actor"], entry["op"], entry["decision"]
    );
    if let Some(r) = entry["reason"].as_str() {
        s.push_str(&format!(" reason={r}"));
    }
    if let Some(p) = entry["project"].as_str() {
        s.push_str(&format!(" project={p}"));
    }
    if let Some(keys) = entry["keys"].as_array() {
        let names: Vec<&str> = keys.iter().filter_map(|k| k.as_str()).collect();
        if !names.is_empty() {
            s.push_str(&format!(" keys={names:?}"));
        }
    }
    if let Some(t) = entry["target"].as_str() {
        s.push_str(&format!(" target={t}"));
    }
    if entry["mac"].is_null() {
        s.push_str(" [unauthenticated]");
    }
    s
}

/// Positive human proof for a privileged command: the vault passphrase,
/// entered interactively (or from the test convenience file). Sent as auth
/// and verified against the key slots by the broker on every request.
fn human_auth(cli: &Cli, err: &mut dyn Write) -> Result<Auth, VaultError> {
    let pass = read_passphrase(cli.passphrase_file.as_ref(), false, err)?;
    Ok(Auth::Passphrase(pass.to_string()))
}

/// N1: establish broker trust with zero credential bytes written before it.
/// Only a TTY stdin is an interactive human (the confirmation is read from
/// /dev/tty). `--trust-fingerprint` only pre-compares inside that ceremony;
/// `--passphrase-file` does NOT authorize pinning. Everyone else (agents,
/// MCP, CI, pipes — flag or not) fails closed when no pin exists.
fn connect_client(cli: &Cli, err: &mut dyn Write) -> Result<Client, VaultError> {
    use crate::client::{ConnectOptions, TrustMode};
    let socket = socket_path(cli.socket.clone())?;
    let trust_fingerprint = match &cli.trust_fingerprint {
        Some(s) => Some(crate::broker_identity::parse_fingerprint(s)?),
        None => None,
    };
    let interactive = std::io::stdin().is_terminal();
    let opts = ConnectOptions {
        trust: if interactive {
            TrustMode::Interactive
        } else {
            TrustMode::NonInteractive
        },
        trust_fingerprint,
    };
    // No TTY + no fingerprint + no pin: fail BEFORE reading the passphrase,
    // so tests/scripted use get E_BROKER_UNTRUSTED without ever prompting.
    // With a TTY, `Client` calls back into `confirm_broker_pin` below.
    let _ = err;
    Client::connect_with(&socket, &opts)
}

/// SSH-style first-contact ceremony, called by the client handshake when no
/// pin exists and the caller is interactive. `expected` is the optional
/// `--trust-fingerprint` compare-assist: when present and different from the
/// presented key, abort BEFORE prompting (the human mis-copied, or the peer
/// is not the broker they meant). Otherwise prints the fingerprint and only
/// an explicit `yes` pins. Anything else fails closed. `pub(crate)` so
/// `client.rs` can call it without a Cli handle.
pub(crate) fn confirm_broker_pin(
    fingerprint_bytes: &[u8; 32],
    expected: Option<&[u8; 32]>,
) -> Result<(), VaultError> {
    use std::io::BufRead as _;
    if let Some(exp) = expected
        && *exp != *fingerprint_bytes
    {
        return Err(VaultError::BrokerUntrusted(
            "broker fingerprint does not match --trust-fingerprint; refusing to send credentials"
                .into(),
        ));
    }
    let fp = crate::broker_identity::fingerprint(fingerprint_bytes);
    eprintln!(
        "svault: unknown broker identity for this socket (first contact).\n\
         svault: broker fingerprint: {fp}\n\
         svault: verify this out-of-band (compare with `svault trust show` on the broker host).\n\
         svault: type `yes` to pin this identity, anything else aborts."
    );
    // Read the confirmation from the controlling TTY, not stdin: stdin may
    // be a pipe carrying key material (`--passphrase-file -`) or test data.
    // No TTY (piped/closed stdin in tests, CI, agents) fails closed here.
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| {
            VaultError::BrokerUntrusted(
                "no pinned broker identity for this socket; refusing to send credentials \
                 (a human must pin once at a TTY: run any svault command interactively, \
                 verify the fingerprint out-of-band, answer `yes`)"
                    .into(),
            )
        })?;
    let mut line = String::new();
    std::io::BufReader::new(&tty).read_line(&mut line)?;
    if line.trim() != "yes" {
        return Err(VaultError::BrokerUntrusted(
            "broker identity not confirmed; refusing to send credentials".into(),
        ));
    }
    Ok(())
}

/// Confirm a destructive identity rotation at a TTY.
fn confirm_reset_tty(err: &mut dyn Write) -> Result<(), VaultError> {
    use std::io::BufRead as _;
    writeln!(
        err,
        "svault: ROTATING the broker identity will break every existing client pin until re-pinned."
    )?;
    writeln!(
        err,
        "svault: type `ROTATE` to proceed, anything else aborts."
    )?;
    let stdin = std::io::stdin();
    let mut line = String::new();
    std::io::BufReader::new(stdin.lock()).read_line(&mut line)?;
    if line.trim() != "ROTATE" {
        return Err(VaultError::BrokerUntrusted("rotation aborted".into()));
    }
    Ok(())
}

/// Fetch the live daemon's fingerprint with a credential-free handshake and
/// NO pin requirement (used by `trust show`). Writes zero credential bytes.
/// Delegates to [`crate::broker_identity::broker_fingerprint_live`] — one
/// implementation, no duplication.
fn trust_show_live(socket: &Path) -> Result<String, VaultError> {
    crate::broker_identity::broker_fingerprint_live(socket)
}

/// Daemon socket: explicit `--socket` or the shared default.
fn socket_path(socket: Option<PathBuf>) -> Result<PathBuf, VaultError> {
    match socket {
        Some(p) => Ok(p),
        None => crate::broker_identity::default_socket_path(),
    }
}

fn vault_path(file: Option<PathBuf>) -> Result<PathBuf, VaultError> {
    match file {
        Some(p) => Ok(p),
        None => store::default_vault_path(),
    }
}

/// Idle auto-lock window. `--idle-lock-secs 0` disables it; the flag exists so
/// an operator (and the smoke test) can prove the wall-clock lock without
/// waiting the 15-minute default.
fn idle_lock(secs: Option<u64>) -> Duration {
    match secs {
        Some(s) => Duration::from_secs(s),
        None => DEFAULT_IDLE_LOCK,
    }
}

/// Agent token delivery (I9): token-fd > token-file > SVAULT_TOKEN env.
/// There is no flag carrying a token in argv.
fn agent_token(cli: &Cli) -> Result<Option<String>, VaultError> {
    if let Some(fd) = cli.token_fd {
        use std::os::fd::FromRawFd;
        // The fd belongs to the caller; we must not close it.
        let file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
        return Ok(Some(read_trimmed(&mut &*file)?));
    }
    if let Some(p) = &cli.token_file {
        if p.as_os_str() == "-" {
            return Ok(Some(read_trimmed(&mut std::io::stdin())?));
        }
        return Ok(Some(read_trimmed(&mut std::fs::File::open(p)?)?));
    }
    match std::env::var("SVAULT_TOKEN") {
        Ok(t) => Ok(Some(t)),
        Err(_) => Ok(None),
    }
}

/// Attach the presented lease capability to broker params. The credential is
/// read from `--lease-file` (or stdin) — never argv — mirroring agent-token
/// delivery (I9); the wire field is `lease`.
fn lease_scoped(cli: &Cli, mut params: serde_json::Value) -> Result<serde_json::Value, VaultError> {
    if let Some(path) = &cli.lease_file {
        // Zeroizing: the credential is wiped from memory when this drops.
        let credential = Zeroizing::new(read_lease_credential(path)?);
        if !credential.is_empty() {
            params["lease"] = serde_json::json!(credential.as_str());
        }
    }
    Ok(params)
}

/// Read a capability credential from `-` (stdin) or a regular file. A
/// non-regular file (symlink, fifo, device) is refused: a swapped target
/// would silently redirect or stall a capability read.
fn read_lease_credential(path: &Path) -> Result<String, VaultError> {
    if path.as_os_str() == "-" {
        return read_trimmed(&mut std::io::stdin());
    }
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(VaultError::Io(std::io::Error::other(
            "lease credential source must be a regular file",
        )));
    }
    read_trimmed(&mut std::fs::File::open(path)?)
}

fn read_trimmed(reader: &mut dyn Read) -> Result<String, VaultError> {
    let mut s = String::new();
    reader.read_to_string(&mut s)?;
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    Ok(s)
}

/// Test hook: the CLI-internal safe token file writer.
#[cfg(test)]
pub fn write_token_file_for_test(path: &Path, token: &str) -> Result<(), VaultError> {
    write_token_file(path, token)
}

/// Write an enrollment token to `path` with the CLI's safe semantics:
/// `O_CREAT|O_EXCL` (refuses overwrite, never follows a symlink), mode `0600`
/// from the first byte, parent directory made private first, and the bytes
/// `fsync`ed before return.
///
/// Public so a human-facing consumer (the dashboard) reuses this one
/// implementation instead of re-deriving the security-critical flags. The
/// token is still shown once at enrollment; this only persists it when the
/// human explicitly asks for a file.
pub fn write_token_file(path: &Path, token: &str) -> Result<(), VaultError> {
    if let Some(parent) = path.parent()
        && parent != Path::new("")
    {
        store::ensure_private_dir(parent)?;
    }
    use std::fs::OpenOptions;
    // O_CREAT|O_EXCL: refuses overwrites and never follows a symlink —
    // a second enrollment to the same path must fail, not clobber it.
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                VaultError::Exists
            } else {
                VaultError::Io(e)
            }
        })?;
    writeln!(f, "{token}")?;
    f.sync_all()?;
    Ok(())
}

fn read_passphrase(
    passphrase_file: Option<&PathBuf>,
    confirm: bool,
    err: &mut dyn Write,
) -> Result<Zeroizing<String>, VaultError> {
    if let Some(pf) = passphrase_file {
        writeln!(
            err,
            "warning: reading the passphrase from a file — test convenience only; prefer the interactive prompt"
        )?;
        read_passphrase_file(pf)
    } else if std::io::stdin().is_terminal() {
        let first = prompt_tty("Passphrase: ")?;
        if confirm {
            let second = prompt_tty("Confirm passphrase: ")?;
            if first.as_str() != second.as_str() {
                return Err(VaultError::Mismatch);
            }
        }
        Ok(first)
    } else {
        Err(VaultError::HumanRequired)
    }
}

fn read_passphrase_file(path: &PathBuf) -> Result<Zeroizing<String>, VaultError> {
    let mut s = String::new();
    if path.as_os_str() == "-" {
        std::io::stdin().read_to_string(&mut s)?;
    } else {
        std::fs::File::open(path)?.read_to_string(&mut s)?;
    }
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    Ok(Zeroizing::new(s))
}

/// Secret values: hidden TTY prompt when interactive, otherwise one line
/// from the provided reader (piped stdin). Never argv, never echoed.
fn read_value(stdin: &mut dyn Read, err: &mut dyn Write) -> Result<Zeroizing<String>, VaultError> {
    if std::io::stdin().is_terminal() {
        let v = Zeroizing::new(rpassword::prompt_password("Value: ")?);
        let _ = writeln!(err, "value read from terminal");
        Ok(v)
    } else {
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(stdin), &mut line)?;
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        Ok(Zeroizing::new(line))
    }
}

fn prompt_tty(prompt: &str) -> Result<Zeroizing<String>, VaultError> {
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker;
    use crate::testutil::TestDir;
    use clap::CommandFactory;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::time::Duration;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn pass_file(dir: &TestDir, name: &str, pass: &str) -> PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, format!("{pass}\n")).unwrap();
        p
    }

    fn run_ok(args_v: &[&str]) -> (i32, String, String) {
        run_ok_stdin(args(args_v), b"")
    }

    fn run_ok_stdin(args_v: Vec<String>, stdin: &[u8]) -> (i32, String, String) {
        let mut o = Vec::new();
        let mut e = Vec::new();
        let mut inbuf = Cursor::new(stdin.to_vec());
        let code = run(&args_v, &mut inbuf, &mut o, &mut e);
        (
            code,
            String::from_utf8(o).unwrap(),
            String::from_utf8(e).unwrap(),
        )
    }

    #[test]
    fn inject_command_accepts_keys_and_lease_file() {
        let cli = Cli::try_parse_from([
            "svault",
            "inject",
            "acme",
            ".env",
            "--key",
            "API_KEY",
            "--lease-file",
            "/tmp/lease",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Cmd::Inject {
                project,
                path,
                keys,
            } if project == "acme" && path == ".env" && keys == ["API_KEY"]
        ));
        assert_eq!(cli.lease_file.as_deref(), Some(Path::new("/tmp/lease")));
    }

    #[test]
    fn no_argv_flag_carries_a_lease_credential() {
        // I9 applies to lease capabilities too: the only lease input is a
        // file/fd source, never an inline argument value.
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("--lease-file"));
        for banned in ["--lease ", "--lease-id ", "--lease-credential "] {
            assert!(!help.contains(banned), "argv lease flag present: {banned}");
        }
        // An inline credential value is rejected by the parser outright.
        assert!(
            Cli::try_parse_from(["svault", "inject", "acme", ".env", "--lease", "cap"]).is_err()
        );
    }

    #[test]
    fn lease_credential_travels_by_file_and_never_by_argv() {
        let dir = TestDir::new();
        let socket = spawn_daemon(&dir);
        let pf = pass_file(&dir, "pass", "correct horse battery");
        let s = socket.to_str().unwrap().to_string();
        let human = |extra: &[&str], stdin: &[u8]| {
            let mut v = args(&[
                "svault",
                "--socket",
                &s,
                "--passphrase-file",
                pf.to_str().unwrap(),
            ]);
            v.extend(extra.iter().map(|x| x.to_string()));
            run_ok_stdin(v, stdin)
        };
        assert_eq!(human(&["init"], b"").0, 0);
        assert_eq!(human(&["unlock"], b"").0, 0);
        assert_eq!(human(&["project", "add", "acme"], b"").0, 0);
        assert_eq!(
            human(
                &["secret", "set", "acme", "STRIPE_KEY"],
                b"sk-trap-0xf00dVALUE\n"
            )
            .0,
            0
        );
        let token_file = dir.path().join("bot.token");
        assert_eq!(
            human(
                &[
                    "agent",
                    "add",
                    "bot",
                    "--write-token-file",
                    token_file.to_str().unwrap(),
                ],
                b"",
            )
            .0,
            0
        );
        assert_eq!(
            human(&["grant", "add", "bot", "acme", "--ops", "read"], b"").0,
            0
        );

        // Create a lease; the credential prints once on stdout.
        let (code, out, _e) = run_ok(&[
            "svault",
            "--socket",
            &s,
            "--token-file",
            token_file.to_str().unwrap(),
            "lease",
            "create",
            "acme",
            "--ops",
            "read",
            "--ttl-secs",
            "60",
        ]);
        assert_eq!(code, 0, "{out}");
        let credential = out
            .lines()
            .find_map(|l| l.strip_prefix("lease credential (shown once, store it now): "))
            .expect("credential line")
            .to_owned();
        let handle = out
            .lines()
            .find_map(|l| l.strip_prefix("lease created: "))
            .and_then(|rest| rest.split(' ').next())
            .expect("handle")
            .to_owned();
        assert_ne!(credential, handle);

        // The credential file is the only lease input; the invocation below
        // contains the file path, never the credential itself.
        let lease_file = dir.path().join("lease.cred");
        std::fs::write(&lease_file, format!("{credential}\n")).unwrap();
        let lease_args = args(&[
            "svault",
            "--socket",
            &s,
            "--token-file",
            token_file.to_str().unwrap(),
            "--lease-file",
            lease_file.to_str().unwrap(),
            "secret",
            "list",
            "acme",
        ]);
        assert!(
            !lease_args.iter().any(|a| a.contains(&credential)),
            "credential present in argv"
        );
        let (code, o, e) = run_ok_stdin(lease_args, b"");
        assert_eq!(code, 0, "{o}{e}");
        assert!(o.contains("STRIPE_KEY"));
        assert!(!o.contains(&credential));
        assert!(!e.contains(&credential));

        // The public handle is not a credential: presenting it as one fails.
        let handle_file = dir.path().join("handle.cred");
        std::fs::write(&handle_file, format!("{handle}\n")).unwrap();
        let (code, _o, _e) = run_ok(&[
            "svault",
            "--socket",
            &s,
            "--token-file",
            token_file.to_str().unwrap(),
            "--lease-file",
            handle_file.to_str().unwrap(),
            "secret",
            "list",
            "acme",
        ]);
        assert_eq!(code, 1);

        // Nothing on disk carries the credential beyond the file we wrote.
        let audit = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap_or_default();
        assert!(!audit.contains(&credential), "credential in audit");
    }

    #[test]
    fn lease_credential_source_must_be_a_regular_file() {
        let dir = TestDir::new();
        let target = dir.path().join("real.cred");
        std::fs::write(&target, "cap\n").unwrap();
        let link = dir.path().join("link.cred");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // A symlinked capability source is refused outright.
        assert!(read_lease_credential(&link).is_err());
        assert_eq!(read_lease_credential(&target).unwrap(), "cap");
    }

    #[test]
    fn run_rejects_token_sources_that_alias_child_stdio() {
        for source in [["--token-fd", "0"], ["--token-file", "-"]] {
            let (code, _out, err) = run_ok(&[
                "svault",
                source[0],
                source[1],
                "run",
                "acme",
                "--",
                "/bin/true",
            ]);
            assert_eq!(code, 1);
            assert!(
                err.contains("run token source cannot alias child stdio"),
                "unexpected error for {source:?}: {err}"
            );
        }
    }

    /// Spawn an in-process broker daemon on a private socket; the thread is
    /// detached and dies with the test process.
    fn spawn_daemon(dir: &TestDir) -> PathBuf {
        spawn_daemon_with_pin(dir, true)
    }

    /// Spawn an in-process daemon; when `pin` is true, write the pin DIRECTLY
    /// (test stand-in for the human TTY ceremony — never via argv; a flag
    /// alone can never pin, see F1).
    fn spawn_daemon_with_pin(dir: &TestDir, pin: bool) -> PathBuf {
        let socket = dir.path().join("svault.sock");
        let vault = dir.path().join("vault.enc");
        let config = broker::DaemonConfig {
            socket_path: socket.clone(),
            vault_path: vault.clone(),
            idle_lock: Duration::from_secs(60),
        };
        let daemon = Arc::new(broker::Daemon::new(config).unwrap());
        if pin {
            crate::broker_identity::store_pin(&socket, &daemon.broker_public_key()).unwrap();
        }
        std::thread::spawn(move || {
            let _ = daemon.serve();
        });
        // Wait for the socket to accept connections.
        for _ in 0..100 {
            if Client::connect(&socket).is_ok() {
                return socket;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("daemon socket never became ready");
    }

    #[test]
    fn full_human_flow_through_daemon() {
        let dir = TestDir::new();
        let socket = spawn_daemon(&dir);
        let pf = pass_file(&dir, "pass", "correct horse battery");
        let s = socket.to_str().unwrap().to_string();
        let base = args(&[
            "svault",
            "--socket",
            &s,
            "--passphrase-file",
            pf.to_str().unwrap(),
        ]);

        let (code, _o, e) = {
            let mut inbuf = Cursor::new(Vec::new());
            let mut o = Vec::new();
            let mut e = Vec::new();
            let mut v = base.clone();
            v.push("init".into());
            let code = run(&v, &mut inbuf, &mut o, &mut e);
            (
                code,
                String::from_utf8(o).unwrap(),
                String::from_utf8(e).unwrap(),
            )
        };
        assert_eq!(code, 0, "init failed: {e}");
        assert!(e.contains("warning:"));

        let mut status = base.clone();
        status.push("status".into());
        let (code, o, _e) = run_ok_stdin(status, b"");
        assert_eq!(code, 0);
        // The human just authenticated by creating the vault: unlocked.
        assert!(o.contains("state: unlocked"));

        let mut add = base.clone();
        add.extend(["project", "add", "acme"].iter().map(|s| s.to_string()));
        let (code, _o, _e) = run_ok_stdin(add, b"");
        assert_eq!(code, 0);

        let mut set = base.clone();
        set.extend(
            ["secret", "set", "acme", "STRIPE_KEY"]
                .iter()
                .map(|s| s.to_string()),
        );
        let (code, _o, _e) = run_ok_stdin(set, b"sk-trap-0xf00dVALUE\n");
        assert_eq!(code, 0);

        // Locked via CLI; status confirms; unlock restores.
        let mut lock = base.clone();
        lock.push("lock".into());
        let (code, _o, _e) = run_ok_stdin(lock, b"");
        assert_eq!(code, 0);
        let mut status = base.clone();
        status.push("status".into());
        let (code, o, _e) = run_ok_stdin(status, b"");
        assert_eq!(code, 0);
        assert!(o.contains("state: locked"));
        let mut unlock = base.clone();
        unlock.push("unlock".into());
        let (code, o, _e) = run_ok_stdin(unlock, b"");
        assert_eq!(code, 0);
        assert!(o.contains("unlocked"));
    }

    #[test]
    fn agent_lifecycle_and_authorization_matrix() {
        let dir = TestDir::new();
        let socket = spawn_daemon(&dir);
        let pf = pass_file(&dir, "pass", "correct horse battery");
        let s = socket.to_str().unwrap().to_string();

        let human = |extra: &[&str], stdin: &[u8]| {
            let mut v = args(&[
                "svault",
                "--socket",
                &s,
                "--passphrase-file",
                pf.to_str().unwrap(),
            ]);
            v.extend(extra.iter().map(|x| x.to_string()));
            run_ok_stdin(v, stdin)
        };

        assert_eq!(human(&["init"], b"").0, 0);
        assert_eq!(human(&["unlock"], b"").0, 0);
        assert_eq!(human(&["project", "add", "acme"], b"").0, 0);
        assert_eq!(
            human(
                &["secret", "set", "acme", "STRIPE_KEY"],
                b"sk-trap-0xf00dVALUE\n"
            )
            .0,
            0
        );

        // Enroll: token printed once and written to a 0600 file.
        let (code, o, _e) = human(
            &[
                "agent",
                "add",
                "harness",
                "--write-token-file",
                dir.path().join("harness.token").to_str().unwrap(),
            ],
            b"",
        );
        assert_eq!(code, 0);
        assert!(o.contains("token (shown once"));
        let token_file = dir.path().join("harness.token");
        let token = std::fs::read_to_string(&token_file).unwrap();
        let mode = std::fs::metadata(&token_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // Without a grant the agent is denied.
        let (code, _o, _e) = run_ok(&[
            "svault",
            "--socket",
            &s,
            "--token-file",
            token_file.to_str().unwrap(),
            "secret",
            "list",
            "acme",
        ]);
        assert_eq!(code, 1);

        // Grant read: the agent sees names, never values.
        let (code, _o, _e) = human(&["grant", "add", "harness", "acme", "--ops", "read"], b"");
        assert_eq!(code, 0);
        let (code, o, _e) = run_ok(&[
            "svault",
            "--socket",
            &s,
            "--token-file",
            token_file.to_str().unwrap(),
            "secret",
            "list",
            "acme",
        ]);
        assert_eq!(code, 0);
        assert!(o.contains("STRIPE_KEY"));
        assert!(!o.contains("sk-trap-0xf00dVALUE"));

        // Revoke: the token stops resolving immediately.
        let (code, _o, _e) = human(&["agent", "revoke", "harness"], b"");
        assert_eq!(code, 0);
        let (code, _o, e) = run_ok(&[
            "svault",
            "--socket",
            &s,
            "--token-file",
            token_file.to_str().unwrap(),
            "secret",
            "list",
            "acme",
        ]);
        assert_eq!(code, 1);
        assert!(e.contains("authentication failed"));

        // Agent list shows status and prefix, never tokens.
        let (code, o, _e) = human(&["agent", "list"], b"");
        assert_eq!(code, 0);
        assert!(o.contains("harness (revoked"));
        assert!(!o.contains(&token));
    }

    #[test]
    fn unlock_with_wrong_passphrase_is_generic_error() {
        let dir = TestDir::new();
        let socket = spawn_daemon(&dir);
        let pf = pass_file(&dir, "pass", "correct horse battery");
        let s = socket.to_str().unwrap().to_string();
        run_ok(&[
            "svault",
            "--socket",
            &s,
            "--passphrase-file",
            pf.to_str().unwrap(),
            "init",
        ]);
        let bad = pass_file(&dir, "bad", "totally incorrect pass");
        let (code, _o, e) = run_ok(&[
            "svault",
            "--socket",
            &s,
            "--passphrase-file",
            bad.to_str().unwrap(),
            "unlock",
        ]);
        assert_eq!(code, 1);
        assert!(e.trim_end().ends_with("authentication failed"));
    }

    #[test]
    fn audit_verify_and_show_work_while_locked() {
        let dir = TestDir::new();
        let socket = spawn_daemon(&dir);
        let pf = pass_file(&dir, "pass", "correct horse battery");
        let s = socket.to_str().unwrap().to_string();
        run_ok(&[
            "svault",
            "--socket",
            &s,
            "--passphrase-file",
            pf.to_str().unwrap(),
            "init",
        ]);
        // audit.show is privileged: it needs the human proof even locked.
        let (code, o, _e) = run_ok(&[
            "svault",
            "--socket",
            &s,
            "--passphrase-file",
            pf.to_str().unwrap(),
            "audit",
            "show",
            "--tail",
            "5",
        ]);
        assert_eq!(code, 0);
        assert!(o.contains("vault.created"));
        let (code, o, _e) = run_ok(&[
            "svault",
            "--socket",
            &s,
            "--passphrase-file",
            pf.to_str().unwrap(),
            "audit",
            "verify",
        ]);
        assert_eq!(code, 0);
        assert!(o.contains("entries:"));
    }

    #[test]
    fn no_flag_accepts_token_or_passphrase_in_argv() {
        let mut parser_help = Cli::command();
        let help = parser_help.render_help().to_string();
        assert!(!help.contains("--token "));
        assert!(!help.contains("--passphrase "));
    }
}
