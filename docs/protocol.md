# Protocol v1

Versioned contract between clients (CLI, MCP adapter) and the broker. Frozen for v0.1.0 (release prepared, unpublished — no tag, no published artifact); changes require a version bump.

## Transport

- Unix domain socket: `$XDG_RUNTIME_DIR/svault/svault.sock` (0600, containing dir 0700).
- Newline-delimited JSON, one request per connection, except `run_with_secrets` (two response lines on a held connection + control operations on separate connections).
- Limits: 1 MiB max message, 30 s per-operation timeouts; `run_with_secrets` holds its connection until the child exits subject to `timeout_secs` (1..86400) and a 24 h ceiling — expiry, disconnect, or timeout kills the process group (see below).
- Kernel authentication: `SO_PEERCRED` — the peer UID MUST equal the daemon owner, else `E_AUTH` (defense in depth over file permissions).
- **Single mutable owner per vault (I13).** A vault file may have only one owner at a time: the owner holds an exclusive `flock(2)` on `<vault>.lock` for as long as it may write, so a second opener — another session, or a second daemon that the socket lock does not cover because it listens elsewhere — fails with `E_BUSY` instead of loading a private copy that would later clobber the owner's committed writes. Released on drop or process death (the kernel owns it), so a crash never leaves the vault unopenable.
- **Single instance and positive server identity (I11).** The broker holds an exclusive `flock(2)` on `<socket>.lock` for its lifetime; starting a second broker on the same socket fails with `E_BUSY` rather than unlinking and replacing the live socket. Before sending any credential a client runs two gates: the kernel lock-holder check (`SO_PEERCRED` pid + `/proc/locks`, defense in depth) and the Ed25519 `broker.hello` handshake against its per-socket pin — and refuses with `E_BROKER_UNTRUSTED` otherwise. A listener that does not hold the broker identity private key therefore receives no credential byte; a same-UID process that can read `<vault>.broker-id` can forge proofs and is NOT stopped (see threat model I11). A stale socket left by a crash is safe to replace, because the kernel released the lock when that process died, and the pin (not the socket file) decides trust after rebind.

## Broker handshake (`broker.hello`, N1)

Credential-free by construction: the client sends one line carrying only a fresh 32-byte CSPRNG nonce, and the daemon answers on the SAME connection before the real request is read:

```jsonc
→ {"v":1,"id":"<hex16>","op":"broker.hello","params":{"client_nonce":"<hex64>"}}
← {"v":1,"id":"<hex16>","ok":true,"result":{
      "public_key":"<hex64>", "server_nonce":"<hex64>", "signature":"<hex128>"}}
```

`signature = Ed25519(domain ‖ client_nonce ‖ server_nonce ‖ canonical_socket_path_bytes)` with domain `svault/broker-hello/v1` (32-byte nonces, hex-encoded on the wire; the canonical path is `canonical_socket_path`: absolute + lexical normalization, never filesystem `canonicalize` — the socket may be absent; both daemon and client apply the identical function, so spelling variants of one socket agree and distinct sockets differ). The client nonce makes a recorded handshake useless against a fresh nonce (no replay); the canonical socket-path bytes stop a reply for socket A being replayed on socket B; the domain separator stops cross-protocol reuse. The client verifies the signature against its per-socket pin (`$XDG_DATA_HOME/svault/pins/<sha256(canonical-socket-path)>.pin`, JSON `{socket, key_hex}` holding the canonical path, public key only, mode 0600, written via `store::save_atomic`); pin key: pin exists + verifies → proceed; pin exists + mismatch → fail closed with `E_BROKER_UNTRUSTED`; no pin + interactive TTY human → explicit `yes` ceremony showing the fingerprint (a matching `--trust-fingerprint <hex>` only pre-compares inside that ceremony — a mismatch aborts before prompting), then pin; no pin + non-interactive → fail closed with `E_BROKER_UNTRUSTED`, flag or not (argv is agent-controlled, so the flag alone is never a trust root). Any failure is `E_BROKER_UNTRUSTED` with zero credential bytes written, and the client MUST NOT retry the request as a legacy direct first line (that fallback would reintroduce N1 in one line). Hello lines are never audited (unauthenticated, attacker-triggerable). Hello carries zero FDs (a hello with attached FDs is rejected); `run_with_secrets` is hello-first with zero FDs, then the run request with exactly 3 FDs on the second line. One-per-connection rule impact: the hello is a leading line on the connection that then carries the single real request (two lines total for ordinary ops); `run_with_secrets` still holds its connection after the handshake for the child lifetime with its exactly-3-FD contract unchanged.

## Authentication

Three identity states, with distinct outcomes:

- **Agent:** `auth: {"token": "…"}` — SHA-256 digest lookup (exact digest match against the active-agent map; the digest is a high-entropy 256-bit value, so the comparison has no useful timing signal to leak), active agents only. Grants evaluated per request.
- **Human:** `auth: {"passphrase": "…"}` or `auth: {"session": "…"}` — positive human proof. The passphrase is verified against the vault's key slots (Argon2id + AEAD unwrap) on **every** privileged request; the session credential is a 256-bit server-minted capability (see Human session) presented as `auth.session` and resolving to human identity only. Obtained interactively (TTY) or via secure file/fd — never argv or environment. There is deliberately **no public `session_id` handle**: the design is credential-only (only the credential authorizes; only its SHA-256 digest + 8-hex prefix persist).
- **Unauthenticated:** absent auth — only public ops answer it (`vault.status`); everything else fails closed with `E_AUTH`. Unauthenticated is **never** treated as human.

Rules: `auth` carries exactly one of `token` / `passphrase` / `session`; a request carrying two or more fails with `E_PROTOCOL`. Agent tokens on human-proof operations fail with `E_HUMAN_REQUIRED`; agent tokens are rejected on the session ops and cannot consume a session (session ops are human-only). Failed human proofs and unknown tokens produce the same generic `authentication failed` message (no oracle) and are audited with actor `unauthenticated` / `agent:unknown`. `auth.session` on `vault.unlock` fails with `E_SESSION_EXPIRED` (unlock needs the KEK, which only the passphrase can derive).

**Daemon mode:** `svault daemon` owns the vault and the socket; `vault.create` and `vault.unlock` carry the passphrase entered on the human's TTY (transmitted over the kernel-local socket to the same-uid daemon). Agent digests survive the lock state so locked-vault agent requests fail with `E_LOCKED` instead of `E_AUTH`.

**Token delivery (normative for clients):**

1. `--token-fd <n>` — read from a file descriptor (preferred),
2. `--token-file <path>` — mode-0600 file,
3. `SVAULT_TOKEN` environment variable (documented as inferior: same-uid `/proc/*/environ` is readable).

There is deliberately **no CLI flag that carries token material in argv**. Tokens MUST never appear in logs, transcripts of tool responses, or audit entries (audit records the agent id and token prefix only), and are never inherited by broker-spawned children.

## Message format

```jsonc
→ {"v":1,"id":"r1","op":"inject_file","auth":{"token":"…"},
   "params":{"project":"acme","path":".env","keys":["STRIPE_KEY"]}}
← {"v":1,"id":"r1","ok":true,"result":{"path":"/srv/acme/.env","count":1,"keys":["STRIPE_KEY"]}}
← {"v":1,"id":"r2","ok":false,"error":{"code":"E_PATH_NOT_AUTHORIZED","msg":"target outside approved folders for project 'acme'"}}
```

Error messages never contain secret values or token material.

## Audit entry format (one JSON object per line in `audit.jsonl`)

```json
{"ts":"2026-09-13T11:36:46.42Z","seq":7,"prev_hash":"<hex64>","hash":"<hex64>",
 "mac":"<hex64>|null","actor":"human","op":"secret.set","project":"acme",
 "keys":["STRIPE_KEY"],"target":null,"decision":"allowed","reason":null}
```

- `hash_i = SHA-256(prev_hash_i ‖ canonical(event_i))`; genesis `prev_hash` is 32 zero bytes.
- `mac_i = HMAC-SHA256(K_audit, prev_hash_i ‖ canonical(event_i))` with
  `K_audit = HKDF-SHA256(MEK, info="svault/audit-mac/v1")` — present only while
  unlocked. Authentication semantics: valid MAC = authenticated; `mac: null` =
  unauthenticated (a later MAC anchors its position/bytes, never its
  provenance; rendering marks such entries).
- Every committed vault mutation appends its audit entry first and then embeds the `{seq, hash}` checkpoint naming that entry in the encrypted document before saving it; the log is therefore ahead of the vault on every read/denial, on a crash between append and save, and when a revocation is applied without a record. Unlock fails closed when the log does not contain the checkpoint (the log is behind the vault). Entries beyond the checkpoint are legitimate but unconfirmed.
- An entry beyond the checkpoint is **not** proof that a mutation was applied.
  The log may be ahead of the vault for three reasons: reads/denials, a crash
  or write failure between the append and the vault save (the append is not a
  commit), or an authority-reducing operation whose entry could not be written
  at all. The log records what was *written*, never what was *applied* — treat
  entries past the checkpoint as unconfirmed. Correspondingly, the *absence* of
  an entry does not mean the change did not happen: a revocation applied at the
  ceiling persists without one. The vault document is the authority on what is
  authorized; the log is the authority on what was recorded.
- `reason` carries stable `E_*` codes only, never dynamic messages.
- Accepted v1 limits (see `threat-model.md`): truncation/forgery of the
  unauthenticated tail beyond the checkpoint is undetectable without an
  external anchor; a writer holding `K_audit` (root / unlocked daemon memory)
  can recompute MACs.

## Operations

| Op | Caller | Permission | Notes |
|---|---|---|---|
| `vault.status` | both | — | works while locked |
| `vault.create` | bootstrap | — | available ONLY while no vault exists; refuses overwrite (E_EXISTS). The provided passphrase becomes the first key-slot passphrase — this is a bootstrap exception, not an ordinary human-authenticated operation |
| `vault.unlock` | human only | — | TTY passphrase; agents always rejected; result EXTENDED additively when the seed succeeds: `{unlocked: true, session_credential, session_prefix, expires_at, expires_in, max_expires_at, max_expires_in}` (see Human session — unlock seeds a session so the passphrase is typed once). The seed is best-effort: at the audit soft ceiling the seed mint refuses with `E_AUDIT_FULL`, unlock still succeeds as `{unlocked: true}` with all six session fields ABSENT (no fake credential), and the skip is reported on stderr — a full log never blocks unlock |
| `vault.lock` | both | — | fail-safe direction: agents may lock; terminates all live runs before key zeroization |
| `secrets.set` / `secrets.delete` | human only | — | value via interactive prompt or piped stdin; wire names: `secret.set` / `secret.delete` |
| `secrets.list` | agent | `read` on project | params `{project, lease?}` → `{secrets:[{key, updated}]}` (names + metadata only, never values); human calls the same op without a grant check |
| `inject_file` | agent | `inject` + authorized folder | params `{project, path, keys?, lease?}` (omitted `keys` = all project secrets; a lease is presented as the `lease` credential, see Lease flow); returns path, count and key names only; kernel containment via `openat2` (RESOLVE_BENEATH\|NO_SYMLINKS\|NO_MAGICLINKS) from the authorized-folder dirfd; atomic 0600 replace; a symlink/device/FIFO destination is refused (`E_INVALID_INPUT`); a write failure (`ENOSPC`/`EFBIG`/`EDQUOT`/`EIO`) is reported as an error and leaves the previous file intact; ENOSYS → fail closed |
| `run_with_secrets` | agent | `run` | CLI/broker only (not on MCP): held connection, two-line response; exactly 3 SCM_RIGHTS FDs; cwd by fd, not sandbox |
| `run_signal` | agent (own run) | `run` (rechecked) | CLI/broker only (not on MCP): separate connection; owner-only signal relay to the live run's process group |
| `reveal` | agent | `reveal` + approval | first call → `E_APPROVAL_PENDING` + `{approval_id, expires_in}`; claim with `approval_id` → `{value}` once; see flow below |
| `reveal` | human (owner TTY) | — | direct, audited |
| `lease.create` | agent (own grant subset) | — | params `{project, ops, ttl_secs}` → `{lease_id, lease_prefix, lease_credential, expires_at, expires_in}`; `ops` comma-list must ⊆ current grant or `E_PERMISSION`. **`lease_credential` is returned exactly once** and only its SHA-256 digest/prefix persist |
| `lease.revoke` | agent (own) / human (any) | — | params `{lease_id}` (public handle); later use of the credential → `E_LEASE_EXPIRED` |
| `lease.list` | agent (self) / human (all) | — | params `{}` → `{leases:[{lease_id, lease_prefix, project, ops, expires_at, expires_in, status}]}`; agent sees own only; never carries a credential |
| `agents.add` / `agents.revoke` / `agents.list` | human only | — | token shown once; revoke terminates all runs owned by that agent and invalidates its leases/approvals |
| `grants.grant` / `grants.revoke` / `grants.list` | human only | — | agent × project × ops; revoke/reduction terminates matching agent/project runs and invalidates affected leases/approvals |
| `project.add` / `project.path.add` / `project.path.remove` / `project.list` (+ `project.remove`) | human only | — | canonical absolute folders; the wire name is `project.add` (singular) in every call — `src/broker.rs` `dispatch_op` has a `project.add` arm and no `projects.add` arm, so `projects.add` on the wire fails with `E_PROTOCOL unknown op`. (The human-only list contains no entry without a dispatch arm.) |
| `audit.show` | human only | — | works while locked; params `{tail?: 1..=1000, default 20, before_seq?: u64}` (out of range → `E_INVALID_INPUT`); result `{entries: [...], next_before_seq: u64\|null}` — at most `tail` entries in ascending seq order, taken from `seq <= before_seq` when present, else the newest entries backwards; `next_before_seq` walks to the previous (older) page, null when exhausted. Unchanged: human-only, the read appends its own audit entry, entry shape, HMAC chain and checkpoint semantics, no rewriting/truncation |
| `audit.verify` | human only | — | chain walk without a key; MACs are verified on every unlock |
| `approvals.pending` | human only | — | unlocked vault required; lists pending approvals |
| `approvals.approve` / `approvals.deny` | human only | — | unlocked vault required; params `{approval_id}` → `{approval_id, status: "approved"}` / `{approval_id, status: "denied"}` (source: `src/broker.rs` approve/deny arm) |
| `approvals.status` | agent (own approvals only) | — | params `{approval_id}` → `{status, project, key, expires_in}`; `status` ∈ `pending\|approved\|denied\|expired\|consumed` |
| `session.open` | human only (passphrase ONLY) | — | params `{ttl_secs?: 1..=1800, default 300}` (out of range → `E_INVALID_INPUT`); pre: vault unlocked, else `E_LOCKED`; result `{session_credential (base64url, 256-bit, returned ONCE), session_prefix (8 hex, display/audit only), expires_at, expires_in, max_expires_at, max_expires_in}`; errors `E_AUTH`, `E_HUMAN_REQUIRED`, `E_LOCKED`, `E_INVALID_INPUT`; see Human session |
| `session.touch` | human only (`auth.session`) | — | params `{}`; result `{expires_at, expires_in, max_expires_at, max_expires_in}`; errors `E_SESSION_EXPIRED`, `E_HUMAN_REQUIRED`. On a locked vault answers `E_SESSION_EXPIRED` (never `E_LOCKED` — the lock purges all sessions, so a live session cannot exist while locked); see Human session |
| `session.close` | human only (`auth.session`) | — | params `{}`; the FIRST successful close returns `{closed: true}`; ANY later presentation of that credential — including a `session.close` replay — fails `E_SESSION_EXPIRED`, exactly like an unknown credential (no oracle). Safe to retry: a retry reports expiry and changes nothing. Errors `E_SESSION_EXPIRED`, `E_HUMAN_REQUIRED`; see Human session |
| `runs.list` | human only | — | params `{}`; no lock gate (the lock drains all runs, so the list is empty by construction while locked); result `{runs: [{run_id, agent (name when resolvable, else id), project, pid, started_at, status: "running"}]}`; never argv, environment, secrets, stdio, cwd, pgid, or executable; no lifecycle change |
| `vault.health` | human only | — | params `{}`; works while LOCKED via `auth.passphrase` (passphrase verifies against the key slots whether or not the vault is open — never `E_LOCKED`); result `{locked, idle_lock_secs, idle_in\|null, audit_bytes, audit_soft_limit, audit_hard_limit, vault_bytes, vault_max_bytes, runs_active, leases_active\|null, approvals_pending\|null}`; `idle_in` is null when auto-lock is disabled or the vault is locked; `leases_active`/`approvals_pending` are null while locked (no decrypted document); `vault.status` is deliberately UNCHANGED (small and public) |

## Errors

`E_AUDIT_FULL` marks a refusal *before* any change (the audit log has reached its operational limit, so the operation was not applied); `E_AUDIT_WRITE` means a change was attempted and only its record failed. `E_AUTH · E_LOCKED · E_HUMAN_REQUIRED · E_PERMISSION · E_PATH_NOT_AUTHORIZED · E_NOT_FOUND · E_APPROVAL_PENDING · E_APPROVAL_DENIED · E_APPROVAL_CONSUMED · E_APPROVAL_EXPIRED · E_LEASE_EXPIRED · E_SESSION_EXPIRED · E_VAULT_CORRUPT · E_VAULT_TOO_LARGE · E_PROTOCOL · E_TOO_LARGE · E_INVALID_INPUT · E_BUSY · E_EXISTS · E_AUDIT_WRITE · E_AUDIT_FULL · E_IO · E_INSECURE_PARAMS · E_WEAK_PASSPHRASE · E_MISMATCH · E_BROKER_UNTRUSTED`

`E_BROKER_UNTRUSTED` is the client-side fail-closed refusal to send credentials to an unverified broker (pin mismatch, bad handshake, or first contact without explicit human trust) — zero credential bytes are written before it. `E_BUSY` covers two refusals: the run quota (4 live runs per agent / 16 daemon-wide) and a second owner of an already-owned vault (I13 — the socket lock `E_BUSY` is the same code for a second broker). `E_INVALID_INPUT` is structural validation (counts, names, NUL, collisions, bad `timeout_secs`/`signal`/params); aggregate overflows report `E_TOO_LARGE`. Lease failures: unknown/revoked/expired/grant-narrowed lease → `E_LEASE_EXPIRED`; active lease used for an op outside its subset, or `lease.create` with `ops` outside the current grant → `E_PERMISSION`. Approval failures: first `reveal` without `approval_id` → `E_APPROVAL_PENDING` + error data `{approval_id, expires_in}`; a claim whose terminal row has been reclaimed by the GC answers `E_NOT_FOUND` instead of `E_APPROVAL_CONSUMED` (same denial, no value revealed); claim on denied/consumed/expired approvals → `E_APPROVAL_DENIED` / `E_APPROVAL_CONSUMED` / `E_APPROVAL_EXPIRED`; claim after grant withdrawal → `E_PERMISSION` (grant is rechecked at claim); agent-token calls on `approvals.pending`/`approve`/`deny` → `E_HUMAN_REQUIRED`. Session failures: unknown, closed, or time-lapsed session credential → `E_SESSION_EXPIRED` — one indistinguishable failure, no oracle (same discipline as `E_LEASE_EXPIRED`); the message never contains credential material. Error messages never contain secret values or token material.

## run_with_secrets flow

Request (one NDJSON line on a held connection, plus exactly three `SCM_RIGHTS` FDs for stdin/stdout/stderr):

```jsonc
→ {"v":1,"id":"r1","op":"run_with_secrets","auth":{"token":"…"},
   "params":{"project":"acme","executable":"/usr/bin/python3",
     "argv":["python3","-c","print('hi')"],
     "cwd":"/srv/acme",
     "keys":["STRIPE_KEY"],
     "env":{"PATH":"/usr/bin:/bin"},
     "timeout_secs":60}}
// plus SCM_RIGHTS fds [stdin, stdout, stderr] on the same connection
← {"v":1,"id":"r1","ok":true,"result":{"run_id":"<hex32>","pid":123,"status":"started"}}
← {"v":1,"id":"r1","ok":true,"result":{"run_id":"<hex32>","status":"exited","exit_code":0}}
```

Field rules:

- `project`: existing project name; `executable`: filesystem path spawned directly, ≤4096 bytes, no NUL, no shell or interpolation.
- `argv`: non-empty array of strings, 1..256 entries, ≤128 KiB aggregate, no NUL. **Full-argv convention:** `argv[0]` is the child's `argv[0]`; only `argv[1..]` are command arguments (`Command::arg0`). `argv[0]` need not equal `executable`.
- `cwd` (optional): absolute path only. Authorized through `open_authorized_cwd` against the project's authorized roots (kernel `openat2` resolution `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` from the pinned root fd), applied in the child via `fchdir` from the resulting fd — no pathname, no TOCTOU. **Directory selection only, not sandboxing or containment:** the child keeps normal OS filesystem access (including `..`).
- `keys` (optional): array of secret names, ≤256. Omitted (or null) selects **all** secrets of the project; explicit `[]` selects none (allowlisted passthrough only).
- `env` (optional): object of string→string, ≤256 entries, ≤128 KiB aggregate (`key.len() + value.len()` summed). Deny-by-default passthrough allowlist (exact): `PATH`, `HOME`, `TERM`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TMPDIR`, `SHELL`, `USER`, `XDG_RUNTIME_DIR`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`. A caller entry colliding with a selected secret name is rejected (`E_INVALID_INPUT`); forbidden or non-allowlisted caller entries are silently dropped. Forbidden caller names (even if allowlisted in future): exact `SVAULT_TOKEN`, or uppercase-matched `SVAULT_*` prefix, `*TOKEN*`, `*PASSPHRASE*`, `*INTERNAL*`, `LD_*`, `DYLD_*`. Selected secrets bypass the forbidden filter (explicit selection wins). Any NUL in a surviving key/value is rejected; non-UTF8 secret bytes ride as Unix `OsString`. Resultant child environment over 1 MiB is rejected (`E_TOO_LARGE`).
- `timeout_secs` (optional): integer 1..86400 (24 h). Out of range is `E_INVALID_INPUT`. The daemon enforces the 24 h ceiling regardless; expiry kills the process group (below).
- FDs: exactly three `SCM_RIGHTS` FDs are required (`E_INVALID_INPUT` otherwise). Receive uses `MSG_CMSG_CLOEXEC`: every delivered FD is CLOEXEC-owned from extraction, wrapped in `OwnedFd` immediately, closed on any error (`MSG_TRUNC`/`MSG_CTRUNC`, oversize, malformed ancillary, bad JSON); trailing bytes after the first newline are rejected. The three FDs are transferred exactly once into the child (`Stdio::from`); the broker never reads or logs child stdio.

Execution:

1. Daemon checks agent authentication, the current `run` grant on the project, lock state, quotas (4 live runs per agent / 16 daemon-wide, atomic check-and-insert; excess → `E_BUSY`), and structural validation above.
2. Daemon resolves secrets (omitted `keys` = all), builds the child environment (allowlisted passthrough + selected secrets), pins `cwd` via `open_authorized_cwd` when given, reserves the `run_id` (unpredictable 128-bit CSPRNG hex), then spawns: `env_clear` + built env, stdio from the three received FDs, dedicated process group (`setpgid(0,0)` in `pre_exec`, so `pgid == pid`), `fchdir` to the cwd fd when present. No shell. The `Session` mutex is released before and for the whole child lifetime; only the live-run registry entry and the holding thread track the run.
3. Daemon answers `{"result":{"run_id":"…","pid":…,"status":"started"}}` (`run_id` correlates both lines; `pid` is the direct child pid, informational only).
4. Signals arrive only via a separate agent-authenticated `run_signal` request on its own connection: `params: {"run_id":"…","signal":"TERM"}` → `{"result":{"run_id":"…","signaled":true}}`. The caller must own the live run and the current `run` grant is rechecked. Accepted names (case-insensitive): `TERM`/`SIGTERM`/`15`, `KILL`/`SIGKILL`/`9`, `HUP`/`SIGHUP`/`1`, `INT`/`SIGINT`/`2`, `QUIT`/`SIGQUIT`/`3`; anything else is `E_INVALID_INPUT`. Delivery is `killpg` to the run's dedicated process group.
5. On direct-child exit the daemon answers `{"result":{"run_id":"…","status":"exited","exit_code":n}}` or `{"result":{"run_id":"…","status":"exited","signal":"…"}}` (`signal` names: `HUP (1)`, `INT (2)`, `KILL (9)`, `TERM (15)`, else `SIGn (n)`). Natural exit atomically removes the registry entry before cleaning leftover descendants; if capability withdrawal already removed it, that path owns termination instead, preventing double-kill. Launch-connection disconnect or timeout follows the same claim, kill, wait, and cleanup path. `grants.revoke` drains matching agent/project runs, `agents.revoke` drains all runs for that agent, and `vault.lock` drains all runs before zeroizing keys; each uses `SIGTERM`, 250 ms grace, then `SIGKILL`. The launch handler always waits/reaps its direct child.
6. Audit appends safe structured entries only — `started`, `exited`, `denied`, or capability-cleanup `revoked` — with fields `{actor, op:"run_with_secrets", project, keys (names only), run_id, executable (allowed/started/exited only; scrubbed on denial/revocation), arg_count (never argv), cwd, decision, reason (stable E_* code), result, exit_code}`. There is no field that can carry argv, environment, output, token, passphrase, or secret bytes.

## Client and CLI binding (shipped)

- Client (`src/client.rs`): `RunStarted { run_id: String, pid: i32 }`, `RunExit { run_id: String, exit_code: Option<i32>, signal: Option<String> }`, `RunSignaled { run_id: String, signaled: bool }`. `run_with_secrets_notify(&mut self, auth, params, stdio_fds, on_started) -> Result<(RunStarted, RunExit), VaultError>` is the core (structural `Request` + borrowed FDs via `fdpass::send_request_with_fds`; one `BufReader` validates started id+status then exited id+status; `on_started` fires between the two reads); `run_with_secrets(&mut self, auth, params, stdio_fds)` is the convenience wrapper without the callback; `run_signal(&mut self, auth, run_id, signal) -> Result<RunSignaled, VaultError>` is an ordinary `call` parsing `{run_id, signaled}`.
- CLI: `svault run <project> [--key NAME...] [--cwd PATH] [--env KEY=VALUE...] [--timeout-secs N] -- <executable> [args...]`. Wire `argv` is the full `[executable, args...]` vector (`argv[0]` is argv0); `--timeout-secs` maps to `timeout_secs`; repeatable `--key` maps to `keys` (omitted = all); `--cwd` maps to `cwd`. Wire `env` = process environment restricted to `crate::run::ALLOWED_ENV` and not `is_forbidden_env_name`, overridden by `--env KEY=VALUE` entries, then filtered the same way — never `SVAULT_*`/token/passphrase material. Stdio: the CLI passes its own FDs 0/1/2 via `SCM_RIGHTS`; therefore `run` rejects `--token-fd 0|1|2`, negative token FDs, and `--token-file -` so token-bearing input cannot alias child stdio. Child output owns stdout, run metadata goes to stderr only. On start the CLI prints `run_id`/`pid` to stderr via the notify callback before waiting; on exit it prints `exit_code`/`signal` to stderr and exits with the child `exit_code` (signaled child → exit 1). `svault run-signal <run_id> <signal>` passes the signal string through (broker accepts the five names in step 4, case-insensitive); agent token via a non-stdio token FD, regular token file, or environment, never argv; prints `run <run_id> signaled`.

**Boundary:** the broker does not transmit values to the agent process — but the spawned child is created and controlled by the agent and can read and exfiltrate its own environment (`printenv`, HTTP calls, files). Granting `run` *is* granting use of and potential exfiltration of those secrets through any child (see `threat-model.md`). Strong revocation stops continued execution of the daemon-managed process group; it cannot erase or recall a copy already retained or exfiltrated before revocation. The broker's guarantee is the narrower I1 boundary: values never appear in argv, in the CLI process, in responses, in logs, or in audit.

## Reveal / approvals flow (asynchronous HITL)

```text
agent:  reveal {project, key}
        ← E_APPROVAL_PENDING {approval_id, expires_in}     (no blocking, connection closes)
human:  approvals.pending {} → pending list (human only)
human:  approvals.approve {approval_id} → {approval_id, status: "approved"}
   or:  approvals.deny {approval_id} → {approval_id, status: "denied"}
agent:  approvals.status {approval_id} → {status, project, key, expires_in}
        → pending | approved | denied | expired | consumed (own approvals only)
agent:  reveal {project, key, approval_id} → {value} exactly once, approval consumed
```

Wire examples:

```jsonc
→ {"v":1,"id":"r1","op":"reveal","auth":{"token":"…"},"params":{"project":"acme","key":"API_KEY"}}
← {"v":1,"id":"r1","ok":false,"error":{"code":"E_APPROVAL_PENDING","msg":"…","data":{"approval_id":"<hex>","expires_in":600}}}
→ {"v":1,"id":"r2","op":"approvals.status","auth":{"token":"…"},"params":{"approval_id":"<hex>"}}
← {"v":1,"id":"r2","ok":true,"result":{"status":"approved","project":"acme","key":"API_KEY","expires_in":300}}
→ {"v":1,"id":"r3","op":"reveal","auth":{"token":"…"},"params":{"project":"acme","key":"API_KEY","approval_id":"<hex>"}}
← {"v":1,"id":"r3","ok":true,"result":{"value":"…"}}
```

State machine: `pending` → (`approve` → `approved` → (claim → `consumed` | window lapses → `expired`) | `deny` → `denied` | pending window lapses → `expired`). Terminal states (`denied`, `consumed`, `expired`) never transition; re-claim reports `E_APPROVAL_DENIED` / `E_APPROVAL_CONSUMED` / `E_APPROVAL_EXPIRED`.

- Claim binds (agent, project, key, reveal): claim by another agent, for another key, or without a live `reveal` grant fails (denied/consumed/expired codes, or `E_PERMISSION` when the grant is gone — the grant is rechecked at claim). Single-use; pending expiry is 600 s and the post-approval claim window is 300 s in v0.1.0.
- Approvals live in the encrypted document: approving and claiming require an unlocked vault.
- Every transition (created, approved, denied, claimed, expired) is audited; a completed reveal is a distinct loud event. Audit and error paths never carry the value.
- **The approved `reveal` claim returning `{value}` is the only path that intentionally returns a secret value.** `secrets.list`, `inject_file`, `run_with_secrets`/`run_signal`, audit, and errors never carry values.

## Lease flow

```text
agent:  lease.create {project, ops, ttl_secs}
        → {lease_id, lease_prefix, lease_credential, expires_at, expires_in}
        (lease_credential returned ONCE; only its digest/prefix persist)
agent:  <any op> {…, lease}     lease = the credential  → evaluated as grant ∩ lease ∩ TTL ∩ unlocked
agent:  lease.list {} → {leases:[{lease_id, lease_prefix, project, ops, expires_at, expires_in, status}]} (own only)
human:  lease.list {} → all leases
agent:  lease.revoke {lease_id}  → dropped; later use of the credential → E_LEASE_EXPIRED
```

Wire example:

```jsonc
→ {"v":1,"id":"l1","op":"lease.create","auth":{"token":"…"},"params":{"project":"acme","ops":"read,inject","ttl_secs":3600}}
← {"v":1,"id":"l1","ok":true,"result":{"lease_id":"<hex>","lease_prefix":"<8 hex>","lease_credential":"<43-char base64url>","expires_at":"2026-09-15T12:00:00Z","expires_in":3600}}
→ {"v":1,"id":"l2","op":"secrets.list","auth":{"token":"…"},"params":{"project":"acme","lease":"<lease_credential>"}}
← {"v":1,"id":"l2","ok":true,"result":{"secrets":[…names only…]}}
```

**Handle vs. credential.** `lease_id` is a public handle (listing, revocation, audit actor `lease:<id>`). Presenting a lease requires the *credential*, sent as `params.lease`; naming `lease_id` on a broker request is refused with `E_INVALID_INPUT` (it authorizes nothing, and ignoring it would run the call on the full grant); only its SHA-256 digest and an 8-hex display prefix are stored. A leaked vault document, audit log, listing, or LLM transcript therefore yields no usable capability, and a presented handle or prefix fails `E_LEASE_EXPIRED` exactly like an unknown credential (no oracle).

State and errors: `lease.create` with an `ops` comma-list outside the agent's current grant on that project fails with `E_PERMISSION` (a lease can only narrow, never escalate). Lifecycle: `active` → `revoked` (`lease.revoke`) / `expired` (TTL lapse) / `invalidated` (agent/grant/lock withdrawal); any later use of a non-active lease's credential fails `E_LEASE_EXPIRED`. Every leased call re-evaluates the current grant ∩ lease ops ∩ TTL ∩ unlocked: unknown/revoked/expired/TTL-lapsed/grant-narrowed lease → `E_LEASE_EXPIRED`; active lease used for an op outside its subset → `E_PERMISSION`.

## Human session

The human session lets the dashboard type the passphrase exactly once per window instead of once per request. It is a server-held, memory-only capability with credential-only design: there is deliberately **no public `session_id` handle**. Only the credential authorizes; only its SHA-256 digest and an 8-hex prefix persist; the credential is returned exactly once (at mint) and is never recoverable from the vault, the audit log, a listing, an error, or any response other than the minting one.

```text
human:  session.open {ttl_secs?} (auth.passphrase ONLY)
        → {session_credential, session_prefix, expires_at, expires_in, max_expires_at, max_expires_in}
human:  <any human op> with auth.session = the credential → same result as the passphrase path
human:  session.touch {} (auth.session) → {expires_at, expires_in, max_expires_at, max_expires_in}
human:  session.close {} (auth.session) → {closed: true}
```

Wire examples:

```jsonc
→ {"v":1,"id":"s1","op":"session.open","auth":{"passphrase":"…"},"params":{"ttl_secs":300}}
← {"v":1,"id":"s1","ok":true,"result":{"session_credential":"<base64url 256-bit>","session_prefix":"<8 hex>","expires_at":"2026-09-16T12:05:00Z","expires_in":300,"max_expires_at":"2026-09-16T12:30:00Z","max_expires_in":1800}}
→ {"v":1,"id":"s2","op":"session.touch","auth":{"session":"<session_credential>"},"params":{}}
← {"v":1,"id":"s2","ok":true,"result":{"expires_at":"2026-09-16T12:05:00Z","expires_in":300,"max_expires_at":"2026-09-16T12:30:00Z","max_expires_in":1800}}
→ {"v":1,"id":"s3","op":"session.close","auth":{"session":"<session_credential>"},"params":{}}
← {"v":1,"id":"s3","ok":true,"result":{"closed":true}}
(a replay of s3 with the same credential fails `E_SESSION_EXPIRED`, like an unknown credential)
```

Minting: `session.open` requires `auth.passphrase` ONLY (positive human proof) and an unlocked vault (else `E_LOCKED`); agent tokens are rejected (`E_HUMAN_REQUIRED`). `ttl_secs` is optional, default 300, valid range 1..=1800 — out of range fails with `E_INVALID_INPUT`, so there is no dead knob. `vault.unlock` seeds a session additively (its result carries `session_credential`, `session_prefix`, `expires_at`, `expires_in`, `max_expires_at`, `max_expires_in` alongside `unlocked: true`): unlock already introduces the passphrase once, so seeding the session there is what makes "type the passphrase exactly once" true — "unlock then `session.open`" would prompt twice. The seed is best-effort: if the seed mint fails (audit soft ceiling), unlock still succeeds and the six session fields are absent. `auth.session` on `vault.unlock` fails with `E_SESSION_EXPIRED` (unlock needs the KEK).

Renewal and clocks: sliding TTL 300 s default, enforced on the MONOTONIC clock; `expires_at` is wall-clock for display only. The sliding window renews only on `session.touch` or an allowed human op under a session; denials never renew it, and `E_SESSION_EXPIRED` never slides. `session.touch` renews and reports remaining life without performing a real operation, so `touch` is NOT redundant. Absolute ceiling 1800 s, fixed in v1 (not configurable), bounds the whole session from minting. `ttl_secs` above 1800 (or below 1) is refused with `E_INVALID_INPUT` — the ceiling is not extended and no silent clamping happens.

State machine: `live` → `closed` (first successful `session.close` returns `{closed: true}`; any later presentation of that credential — including a close replay — fails `E_SESSION_EXPIRED` like an unknown credential, so close is safe to retry: a retry reports expiry and changes nothing) / `idle-lapsed` (no use within the sliding TTL) / `absolute-lapsed` (absolute ceiling reached) / `lock-invalidated` (any explicit or idle vault lock purges ALL sessions) / `restart-lost` (daemon restart wipes the memory-only table). Purge points: `session.close`, both TTL lapses (checked per request, enforced), `vault.lock`/idle-lock (purges the whole registry), daemon restart (table is memory-only, never part of `vault.enc`). A session never survives a lock and never survives a daemon restart. `session.touch` on a locked vault answers `E_SESSION_EXPIRED`, never `E_LOCKED` (the lock already purged it).

Storage and hygiene: the registry is memory-only, never part of `vault.enc`. Only the SHA-256 digest and an 8-hex prefix are retained. The credential never reaches argv, audit, logs, errors, or any response other than the minting one. Audit actor split: `human` (passphrase path) vs `human(session:<prefix>)` (session path); every session use is audited exactly as a passphrase-proofed request is (no audit weakening). Session use does NOT extend the vault idle window — the daemon's autonomous idle auto-lock is the outer bound and it kills sessions.

Capacity: `MAX_SESSIONS = 256`, memory-only. Before minting — both `session.open` and the unlock seed — the daemon (1) sweeps every closed or time-lapsed entry, then (2) if still at the cap, evicts the entry with the oldest `last_used`: fail-closed for that holder, which answers `E_SESSION_EXPIRED` and can simply mint again. A mint MUST NOT fail for capacity; `vault.unlock` always returns a usable credential except when the seed mint itself is refused at the audit soft ceiling (best-effort seed — unlock still succeeds, session fields absent). A failed mint (bad passphrase, locked, out-of-range TTL, audit-full) stores nothing.

Audit priorities: `session.open` / `session.touch` are ORDINARY — at the audit soft ceiling they refuse with `E_AUDIT_FULL` and mint/renew nothing. `session.close` is LIFECYCLE and authority-reducing — it is applied even when its entry cannot be recorded, and still answers success, because a full log must never leave a capability alive (same rule as `lease.revoke`). The lock purge is lifecycle best-effort. Every other session use appends exactly like the passphrase path.

Precedence (request entry order): wire shape → exactly-one-credential (`E_PROTOCOL`, including a non-string `session`) → identity resolution → `session` on unlock/create → `E_SESSION_EXPIRED` → `HUMAN_ONLY` gate → lock/expiry → params → audit. An empty-string `session` is `E_SESSION_EXPIRED` (a string, but unusable), NOT `E_PROTOCOL`. `auth.session` on `vault.create` fails `E_SESSION_EXPIRED`, and `vault.create` never seeds a session.

Renewal and atomicity: the sliding window renews only on `session.touch` or an allowed human op under a session; denials never renew it, and `E_SESSION_EXPIRED` never slides. Expiry is validated at request entry under the same mutex that executes the op. Display vs enforcement: `expires_in` / `max_expires_in` derive from the monotonic remaining time; `expires_at` / `max_expires_at` are mint-wall + duration for display only — clients trust `expires_in`.

Scope: exactly the current human op set; no new powers. A session cannot widen privilege: it resolves to human identity only, never agent, never a new operation set. The unknown/closed/lapsed credential fails `E_SESSION_EXPIRED` — one indistinguishable failure, no oracle (same discipline as `E_LEASE_EXPIRED`); the message never contains credential material.

Residual risk, honestly: within its TTL a stolen session credential equals the human. TTL (300 s sliding) + absolute ceiling (1800 s) + lock + restart bound the window but do not contain a same-UID adversary (threat model A1 already wins there). The session's advantage over a client-cached passphrase is revocability + expiry + per-use audit, not containment.

## Invalidation

- Agent revoke invalidates that agent's leases and approvals (later use: `E_LEASE_EXPIRED` / `E_APPROVAL_DENIED`-family) and terminates all its live runs.
- Grant revoke — or a grant narrowed below a lease's ops — invalidates affected leases (`E_LEASE_EXPIRED`) and approvals (`E_PERMISSION` at claim), and terminates matching agent/project runs.
- Any explicit or idle vault lock invalidates leases, approvals, and ALL human sessions, and drains all live runs before zeroizing keys; locked-vault agent requests fail `E_LOCKED`. The idle lock is autonomous: the daemon runs its own wall-clock timer, so the vault closes when `idle_lock_secs` elapse even if no request ever arrives. The timeout is configurable with `--idle-lock-secs` (default 900; 0 disables).

## MCP adapter (`svault mcp-serve`)

The adapter is a stdio JSON-RPC↔UDS translator with no policy logic: it maps tool arguments to wire params, forwards them to the broker UDS, and returns the broker's answer. A tool call that supplies a `lease` credential directly is refused with `E_INVALID_INPUT` — only the adapter's own `lease_id` store may produce a credential, so a caller can never present one it was not issued. It never authenticates, authorizes, evaluates grants/leases/approvals, or filters values — every decision happens broker-side. Its one piece of state is the session-local lease credential store: `lease_create` mints a credential, the adapter keeps it keyed by the public `lease_id`, and later tool calls naming that handle have it substituted on the wire as `params.lease`. The credential is never returned to the model in any response. Exactly six agent-safe tools:

| MCP tool | Wire op | Args → wire params |
|---|---|---|
| `list_secrets` | `secrets.list` | `{project, lease_id?}` — the adapter resolves `lease_id` to the credential it holds and sends `lease` |
| `inject_file` | `inject_file` | `{project, path, keys?, lease_id?}` — same substitution |
| `reveal` | `reveal` | `{project, key, approval_id?, lease_id?}` — same substitution |
| `approval_status` | `approvals.status` | `{approval_id}` |
| `lease_create` | `lease.create` | `{project, ops, ttl_secs}` → the adapter retains `lease_credential` and returns only `lease_id`/`lease_prefix` to the model |
| `lease_revoke` | `lease.revoke` | `{lease_id}` — the public handle, passed through unchanged |

Excluded by design: human-only operations (`approvals.pending`/`approve`/`deny`, agents, grants, projects, secret set/delete, audit) are never MCP tools — a human decides them on a TTY. `run_with_secrets`/`run_signal` are CLI/broker-only because MCP stdio cannot supply the frozen `SCM_RIGHTS` child-stdio contract.

### Stdio framing

MCP stdio framing is newline-delimited JSON-RPC with the same 1 MiB cap as the broker transport (`wire::MAX_MESSAGE_LEN`), compared against the payload *without* the trailing newline. A malformed frame within cap (non-UTF-8 or non-JSON) yields one JSON-RPC `-32700 parse error` (`id: null`) and the session continues. An oversized frame (payload > 1 MiB) whose terminating newline (or EOF) arrives within a further 1 MiB drain budget yields one `-32700 "parse error: message too large"` and the session continues (on EOF, the next read sees clean EOF and the session closes). An oversized frame that never terminates within that budget yields the same single `-32700` and then the session closes cleanly (exit 0) rather than draining forever. At most `FRAME_CAP` plus one `BufReader` chunk (8 KiB at the `serve` call site) is ever buffered per frame; at most `FRAME_CAP + DRAIN_CAP` (each `MAX_MESSAGE_LEN`) plus two `BufReader` chunks of input is consumed per oversized frame. Empty lines and whitespace-only lines within cap are skipped silently; a whitespace-only line exceeding the cap is an oversized error, not a silent skip. Unterminated final lines at EOF are processed as one frame (as before). The adapter never returns an error or non-zero exit for peer-supplied bytes — only for stdin/stdout transport failures.

## Versioning

Requests carry `"v":1`. Unknown ops or versions fail with `E_PROTOCOL`. Additive changes (new ops, new params) keep `v:1`; behavior changes bump the version and the daemon announces supported versions in `vault.status`.
