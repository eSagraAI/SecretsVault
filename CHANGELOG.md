# Changelog

This is the first public release of SecretsVault. No independent security audit has been performed.

## [Unreleased]

Changes for the next version land here while it is in development. The section is
closed with a version number and date during release preparation.

## 0.1.0 — 2026-09-19

### Added

- Vault core: versioned envelope (`SVAULT1`) holding Argon2id key slots; create (`init`), passphrase unlock, and lock; idle auto-lock after 15 minutes of inactivity (configurable, zero disables); key material kept in memory only while unlocked and wiped on lock; atomic writes where new content is fully written and synced before replacing the stored vault, with vault files created owner-only (0600); a per-vault exclusive lock so only one owner can mutate the vault at a time.
- Broker: local Unix domain socket with a same-user check on every connection (kernel-reported peer credentials must match the daemon owner); two credential kinds — agent tokens for agents and the vault passphrase as human proof, verified against the key slots on each privileged request; capability re-evaluated on every request from grants, leases, and lock state; a tamper-evident audit log where entries carry an authentication code while unlocked and every allowed or denied operation is recorded.
- Agent operations: `secrets.list` (key names and metadata, never values), `inject_file` (writes project secrets to a dotenv file beneath an authorized folder; returns path, count, and names only), `run_with_secrets` (spawns a child with project secrets in its environment) and `run_signal` (signals a live run).
- Human operations: create and list projects, add and remove authorized folders, set/list/delete secrets, enroll/revoke/list agents, and grant/revoke/list per-project operations.
- Approvals: an agent `reveal` first returns a pending approval; a human approves or denies it, and the agent claims the value exactly once inside its claim window. Approvals are single-use, bound to one agent, project, and key, and expire.
- Leases: a TTL-bound, revocable subset of the caller's own grant on a project, presented by a 256-bit credential; the public handle alone authorizes nothing, and leases narrow but never widen what the grant allows.
- MCP adapter: six tools over standard input/output — `list_secrets`, `inject_file`, `reveal`, `approval_status`, `lease_create`, `lease_revoke`. Semantic checks stay broker-side; lease credentials are held by the adapter process and never placed in tool results.
- Desktop dashboard: a graphical client over the same socket covering projects, secret metadata, agents, grants, approvals, leases, runs, and the audit log. It never starts the broker; first trust is established from the command line.
- Linux packaging: a `.deb` that ships both `svault` and `svault-dashboard`.

### Security notes

- The approved `reveal` claim is the only path that returns a secret value; listings, logs, error messages, and log entries carry names and metadata only.
- A spawned child and an injected file are agent-controlled channels: granting `run` permits use of those secrets through any child the agent starts, and an injected file is readable by any same-user process. Ending the run or revoking the grant stops further use but cannot recall copies already retained or sent elsewhere before that point.
- Agent tokens and lease credentials are never passed in `argv`, and token material never appears in logs or log entries.
- The full contract, including the complete list of non-guarantees, is in `docs/threat-model.md`.
