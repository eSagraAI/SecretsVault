# Architecture

## Overview

```text
   HUMAN (TTY)                                  AGENTS / HARNESS
   svault init|unlock|lock|set|grant|audit       svault <op> (CLI, token-file/fd)
        │                                               │
        │        svault mcp-serve   (stdio ↔ UDS; agent tools only)
        └──────────────┬────────────────────────────────┴──────────────┐
                       ▼                                               │
        $XDG_RUNTIME_DIR/svault/svault.sock  (0600, dir 0700, SO_PEERCRED)
                       │
        ┌──────────────▼───────────────────┐
        │  svault daemon (broker)          │    MEK / DEK / K_audit only in RAM,
        │  authn → policy → execution      │    zeroized on lock,
        │  · child spawning (run)          │    idle auto-lock (own timer)
        └──────┬───────────────┬───────────┘
               ▼               ▼
     vault.enc (AEAD)    audit.jsonl (hash chain + HMAC)
```

One binary, three modes (v0.1.0 feature-complete; release prepared, unpublished — no tag, no published artifact):

| Mode | Role |
|---|---|
| `svault daemon` | Broker: UDS listener, authentication, policy, vault I/O, child spawning |
| `svault <op>` | CLI for humans (setup, grants, audit, approvals) and agents (operations with a token) |
| `svault mcp-serve` | Synchronous MCP stdio adapter exposing exactly six agent tools (below); adds no dependency |

The core (crypto, model/policy, audit, broker) is synchronous `std` with a thread per connection. MCP types never appear below the adapter boundary; the MCP adapter is a stateless stdio↔UDS translator with no policy logic of its own — every authorization decision happens in the broker.

## MCP adapter (thin by design)

`svault mcp-serve` maps six agent-safe tools to wire ops and forwards them to
the broker over the UDS; it never authenticates, authorizes, evaluates
grants/leases/approvals, or filters values:

| MCP tool | Wire op |
|---|---|
| `list_secrets` | `secrets.list` |
| `inject_file` | `inject_file` |
| `reveal` | `reveal` |
| `approval_status` | `approvals.status` |
| `lease_create` | `lease.create` |
| `lease_revoke` | `lease.revoke` |

Human-only operations (`approvals.pending`/`approve`/`deny`, agents, grants,
projects, secret set/delete, audit) are never MCP tools. `run_with_secrets` /
`run_signal` stay CLI/broker-only because MCP stdio cannot supply the frozen
`SCM_RIGHTS` child-stdio contract (`docs/protocol.md`).

## Leases and approvals (lifecycle summary)

- **Leases:** TTL-bound grant subsets. `lease.create {project, ops, ttl_secs}`
  fails `E_PERMISSION` when `ops` exceeds the caller's current grant; calls
  presenting a lease send `params.lease` (the credential) and evaluate
  grant ∩ lease ∩ TTL ∩ unlocked (`E_LEASE_EXPIRED` for
  unknown/revoked/expired/grant-narrowed leases, `E_PERMISSION` for ops
  outside the active lease's subset).
- **Handle vs. credential:** `lease.create` returns a one-time 256-bit
  credential plus a public `lease_id` handle. Only the credential's SHA-256
  digest and an 8-hex display prefix persist in the encrypted document; the
  audit records the handle as actor (`lease:<id>`) and never the credential.
  A handle or prefix presented as a capability fails closed like an unknown
  one. The MCP adapter retains credentials in-process and substitutes them
  on the wire, so no capability reaches a model transcript.
- **Approvals:** async human-in-the-loop. `reveal` without `approval_id`
  returns `E_APPROVAL_PENDING` + `{approval_id, expires_in}`; the claim
  `reveal {project, key, approval_id}` binds (agent, project, key, reveal),
  is single-use, rechecks the grant at claim, and returns `{value}` exactly
  once — the only intentional secret-return path.
- **Invalidation:** agent revoke invalidates that agent's leases/approvals;
  grant revoke/reduction invalidates affected leases/approvals; `vault.lock`
  drains all live runs before zeroizing keys. Full state machines, wire
  shapes, and codes live in `docs/protocol.md`.

## Trust boundaries

1. **Disk ↔ daemon memory** — everything at rest is AEAD ciphertext; plaintext keys and values exist only in daemon RAM while unlocked.
2. **Daemon ↔ clients** — Unix domain socket with kernel peer credentials (`SO_PEERCRED`: peer UID must equal the daemon owner) plus application-level agent tokens/leases, plus the Ed25519 broker-identity handshake: the daemon proves possession of the `<vault>.broker-id` private key per connection (`broker.hello`: fresh client nonce + server nonce + socket-path bytes under `svault/broker-hello/v1`) and the client checks it against a per-socket public-key pin before writing any credential. The lock-holder check stays as defense in depth; the handshake is the authority. Bound: a same-UID reader of `<vault>.broker-id` forges proofs freely (see threat model I11).
3. **Daemon ↔ spawned children** — secrets reach the child only through its environment (the three passed stdio FDs carry child I/O, never secrets); the daemon never passes values back over the socket. The spawned child is created and controlled by the agent and may exfiltrate its own environment — granting `run` is granting use of and potential exfiltration through any child. `cwd` is directory selection only, not sandboxing or containment.
4. **Agent ↔ human** — unlocking, management, and approvals require an interactive human (TTY + passphrase / explicit CLI decisions). Agent tokens never unlock, never manage, never approve.

## Key hierarchy

```text
passphrase ──Argon2id(slot salt/params)──► KEK ──unwrap──► MEK ──unwrap──► DEK ──► vault document
                                              │                        └─(reserved)─► HKDF(project) sync subkeys
                     ┌────────────────────────┴───────────────────────┐
                     │ slot table — each slot wraps the MEK           │
                     │ passphrase (MVP) · backup · keychain · sync    │
agent tokens: random 256-bit → SHA-256 digest + display prefix (auth only, unrelated to encryption)
broker identity: Ed25519 keypair from `crypto::random_bytes::<32>()` (same OS CSPRNG, no new RNG); the private key signs every `broker.hello`, the public key is the pin/fingerprint. Rotation (`trust reset`) replaces the file; all pins fail closed until re-pinned
audit MAC key: HKDF-SHA256(MEK, info="svault/audit-mac/v1") — RAM only while unlocked
```

- Adding unlock methods (backup/keychain) or rotating the MEK only re-wraps; rotating the DEK re-encrypts the single vault document.
- Agent tokens are revocable authentication identities; leaking one exposes exactly the holder's grants, nothing more.

## On-disk layout

| Path | Content | Mode |
|---|---|---|
| `$XDG_DATA_HOME/svault/vault.enc` | envelope: `"SVAULT1"` magic + versioned JSON header (slots, DEK wrap) + DEK-encrypted JSON document | 0600 |
| `$XDG_DATA_HOME/svault/audit.jsonl` | append-only audit entries, plaintext, hash-chained, HMAC'd while unlocked | 0600 |
| `$XDG_CONFIG_HOME/svault/agents/<name>.token` | optional token files written by humans at enrollment | 0600 |
| `$XDG_RUNTIME_DIR/svault/svault.sock` | broker socket (dir 0700) | 0600 |
| `<vault-dir>/vault.enc.broker-id` | persistent Ed25519 broker identity (32-byte private key; fingerprint = hex of the public key) | 0600 |
| `$XDG_DATA_HOME/svault/pins/<sha256(canonical-socket-path)>.pin` | client pin: JSON `{socket, key_hex}` — canonical socket path + one broker public key per socket, written via `store::save_atomic` | 0600 |

Vault mutations are persisted atomically (temp file + fsync + rename); the temp name carries CSPRNG entropy and is created `O_EXCL`, so it cannot be pre-created or followed. The audit log is capped (`MAX_AUDIT_LEN`); appends past the ceiling fail closed with `E_AUDIT_WRITE` rather than truncating history, and rotation is post-MVP. Because the whole document is the write unit, exactly one owner may hold a vault at a time: the owner takes an exclusive `flock(2)` on `<vault>.lock` while it may write (I13), so a second session or daemon fails `E_BUSY` instead of later overwriting the owner's committed change. The whole-vault-document model is deliberate for MVP scale (hundreds of secrets); per-record storage is a post-MVP concern.

## Run execution (`run_with_secrets` / `run_signal`)

Exact wire shapes live in `docs/protocol.md`; this section records the mechanism the broker implements (synchronous `std` + `libc`, no new dependencies):

- **Request intake:** one NDJSON line on a held connection plus exactly three `SCM_RIGHTS` FDs (stdin/stdout/stderr). Receive uses `MSG_CMSG_CLOEXEC`: every delivered FD is CLOEXEC-owned from extraction, wrapped in `OwnedFd` immediately, and closed on any error (`MSG_TRUNC`/`MSG_CTRUNC`, oversize, malformed ancillary, bad JSON); trailing bytes after the first newline are rejected. Other counts fail with `E_INVALID_INPUT`. The three FDs transfer exactly once into the child (`Stdio::from`); the broker never reads or logs child stdio.
- **Params:** `project`, `executable` (spawned directly, ≤4096 bytes, no shell/interpolation), `argv` (1..256 entries, ≤128 KiB aggregate; full-argv convention — `argv[0]` is the child's `argv[0]` via `Command::arg0`, only `argv[1..]` are arguments), optional absolute `cwd`, optional `keys` (omitted = all project secrets; explicit `[]` = none; ≤256 names), optional `env` object (≤256 entries, ≤128 KiB aggregate), optional `timeout_secs` (1..86400).
- **Child environment (deny-by-default):** allowlisted caller passthrough (exact list: `PATH`, `HOME`, `TERM`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TMPDIR`, `SHELL`, `USER`, `XDG_RUNTIME_DIR`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`) plus the selected secrets. Caller entries colliding with a selected secret are rejected; forbidden (`SVAULT_TOKEN`, uppercase `SVAULT_*`, `*TOKEN*`, `*PASSPHRASE*`, `*INTERNAL*`, `LD_*`, `DYLD_*`) or non-allowlisted caller entries are silently dropped; secrets bypass the forbidden filter. NUL in any surviving key/value is rejected; resultant environment over 1 MiB is rejected.
- **Spawn:** `env_clear` + built env, stdio from the received FDs, dedicated process group (`setpgid(0,0)` in `pre_exec`, `pgid == pid`), optional `cwd_fd` applied via `fchdir` in `pre_exec` (no pathname, no TOCTOU). `cwd_fd` comes from `open_authorized_cwd` against the project's authorized roots (kernel `openat2` `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` from the pinned root fd). Cwd authorization selects the starting directory only — it is not sandboxing; the child keeps normal OS filesystem access including `..`.
- **Lifetime:** the `run` launch releases the `Session` mutex before and for the whole child lifetime; only the live-run registry entry (`run_id` → owner, pid, pgid) and the holding thread track the run. Responses on the held connection: `{"run_id","pid","status":"started"}` then `{"run_id","status":"exited","exit_code" | "signal"}`. `run_id` is unpredictable 128-bit CSPRNG hex. Registry removal is atomic: natural exit and capability withdrawal race to claim one entry, and only the winner owns group termination; the launch handler always waits/reaps its direct child.
- **Limits:** 4 live runs per agent / 16 daemon-wide (atomic check-and-insert; excess → `E_BUSY`); `timeout_secs` 1..86400 with a 24 h ceiling always enforced. Launch-connection disconnect or timeout kills the group, waits the direct child, and removes the registry entry; after direct-child exit the broker also kills leftover group descendants (`SIGTERM`, 250 ms grace, `SIGKILL` if alive). Registry entries hold safe metadata only (owner, pid, pgid — never secrets/argv/env/cwd).
- **Revocation:** successful `grants.revoke` atomically drains and terminates runs matching that agent/project; `agents.revoke` drains every run owned by the agent; `vault.lock` drains every live run before zeroizing keys. All reuse the bounded TERM → 250 ms grace → KILL lifecycle. A spawn reservation removed concurrently with revocation cannot become live: activation fails and the just-spawned group is terminated before a started response.
- **Signals:** separate agent-authenticated `run_signal {run_id, signal}` request (`{"run_id","signaled":true}` on success); the caller must own the live run and the current `run` grant is rechecked. Accepted names: `TERM`/`SIGTERM`/`15`, `KILL`/`SIGKILL`/`9`, `HUP`/`SIGHUP`/`1`, `INT`/`SIGINT`/`2`, `QUIT`/`SIGQUIT`/`3`. Delivery is `killpg` to the run's dedicated group.
- **Audit:** safe structured entries only (`started`/`exited`/`denied`/`revoked`): actor, `op:"run_with_secrets"`, project, key names, `run_id`, executable (allowed/started/exited only; scrubbed on denial/revocation), argv count (never argv), cwd, stable `E_*` reason, outcome token, numeric exit code. No field can carry argv, environment, or secret bytes; the broker never returns, logs, or audits secret values or child output.

## Concurrency model

Thread per connection; `run_with_secrets` holds one thread until the child exits. Vault state is a shared resource guarded by a lock; operations serialize on it — except a `run` launch, which releases the `Session` mutex before spawn and holds no vault lock for the child lifetime (live runs are tracked only in the run registry). No async runtime outside the MCP adapter. Connection cap (32) bounds held run threads alongside the 4-per-agent / 16-daemon run quotas. Intake is bounded on both ends: a new connection must produce its first request within 5 s (silent clients cannot pin a slot), and an established connection idles out after 30 s — `run_with_secrets` excepted, since it holds its connection for the child's lifetime. A passphrase request derives its KEKs before the session lock is taken, so an expensive-unlock attempt never blocks `vault.status`.
