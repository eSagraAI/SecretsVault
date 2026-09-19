# SecretsVault: what it protects, and what it does not

> Candidate documentation for a future release — nothing here is published.
> This page summarizes `docs/threat-model.md`. That document is the
> authority; this page is not. Read it before storing real secrets.

**Status: this project has not received an independent security audit.
Start with disposable credentials, keep independent backups, and read
`docs/threat-model.md` before storing real secrets.**
(`README.md` security boundaries; `docs/threat-model.md` assurance.)

## What it protects

Assets (`docs/threat-model.md` assets): secret values, key material in
daemon RAM (MEK, DEK, audit MAC key), agent tokens, confidentiality of
`vault.enc`, integrity of `audit.jsonl`. Availability is explicitly
lock-favoring: locking is an acceptable denial against oneself because it
protects confidentiality, never the reverse.

How, in plain language (invariants I1–I13, `docs/threat-model.md`):

- **I1 — No broker-side disclosure.** Values never appear in argv, the CLI
  process, broker responses, logs, error messages, or audit entries. The
  one intentional exception: the approved `reveal` claim returning
  `{value}` is the only path that returns a secret value.
- **I2 — Human unlock.** Unlocking needs an interactive TTY passphrase. No
  agent token can unlock. Passphrases are never accepted via argv or
  environment.
- **I3 — Positive human proof.** Absence of credentials is never treated as
  human. Management (vault create/unlock, enrollment, grants,
  project/folder config, secret set/delete, audit inspection, approvals
  pending/approve/deny) needs the vault passphrase verified against the
  key slots on every request. Agent tokens there are rejected
  (`E_HUMAN_REQUIRED`); credential-less requests are unauthenticated
  (`E_AUTH`), never human.
- **I4 — Encrypted at rest.** Values are XChaCha20-Poly1305 ciphertext
  under a DEK wrapped by a MEK derived through Argon2id. Tampering with
  `vault.enc` fails closed with `E_VAULT_CORRUPT`.
- **I5 — Kernel-contained writes.** Authorized-folder handles and
  `inject_file` destinations resolve through `openat2` with
  `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` from a
  pinned directory fd, mode 0600. Traversal, symlinks, and TOCTOU are
  enforced by the kernel, not re-checked by the application.
- **I6 — Per-request capability.** Effective capability is grants(t) ∩
  lease(t) ∩ lock-state, re-evaluated on every request. The `reveal`
  claim additionally rechecks the grant at claim time.
- **I7 — Tamper-evident audit.** Hash-chained entries; while unlocked they
  carry HMAC-SHA256 under a key derived from the MEK and held in RAM
  only. Every operation, allowed or denied, is audited. Entries never
  carry values or token material.
- **I8 — Immediate revocation.** Revoking an agent, lease, or approval
  invalidates it for all later requests; narrowing a grant invalidates
  affected leases/approvals; explicit and idle vault locks invalidate
  leases/approvals and drain all live runs before zeroizing keys. The
  idle lock is autonomous: the daemon arms its own wall-clock timer, so
  it fires with no client activity.
- **I9 — Capability hygiene.** No agent token or lease credential in argv
  (no such flag exists). Delivery is token-fd, then token-file, then
  `SVAULT_TOKEN` env, in that priority; lease credentials via
  `--lease-file`/stdin. Tokens are never logged, never audited, never
  inherited by broker-spawned children. A lease is presented by its
  256-bit credential (only digest + 8-hex prefix persist); the public
  `lease_id` handle authorizes nothing. The MCP adapter holds lease
  credentials in its own process and substitutes them on the wire, so a
  capability never reaches a model transcript.
- **I10 — Approval binding.** Approvals bind (agent, project, key, reveal),
  are single-use, expire, and are not transferable. First `reveal`
  returns `E_APPROVAL_PENDING` plus `{approval_id, expires_in}`; the
  claim returns `{value}` exactly once.
- **I11 — Local broker identity.** Exactly one broker serves a socket
  (exclusive `flock(2)` on `<socket>.lock`; a second broker fails
  `E_BUSY`). The lock-holder check (`SO_PEERCRED` + `/proc/locks`) is
  defense in depth only. The authority is the Ed25519 broker identity
  (`<vault>.broker-id`): per-connection signed handshake checked against
  a per-socket client pin before any credential byte. A same-UID process
  that can read the identity file forges proofs freely — impersonation
  is bounded, not eliminated.
- **I12 — Store-what-you-can-load.** No mutation is persisted unless the
  result would be accepted by the loader; oversize results are refused
  with `E_VAULT_TOO_LARGE` before commit, leaving the stored vault
  byte-identical. KDF bounds and the 8-slot cap are enforced before any
  derivation runs.
- **I13 — Single mutable owner per vault.** Exactly one owner may mutate
  `vault.enc` at a time (exclusive `flock(2)` on `<vault>.lock`); a
  second owner fails `E_BUSY` instead of silently discarding the first
  owner's committed change.

## Human vs agent: the line

- Agents cannot unlock, cannot manage (enrollment, grants, projects,
  secret set/delete, audit), cannot widen permissions, cannot read the
  audit log, and cannot reveal without an explicit human approval
  (`docs/threat-model.md` A2; `README.md` security boundaries).
- An approval lets the requesting agent CLAIM the value once. The value
  is never shown in the approvals inbox — approving there allows the
  claim; it does not display anything
  (`dashboard/ui/screens/approvals.ts`).
- A human reveal is a different, unapproved path: the owner reading their
  own secret directly at the TTY or through the dashboard reveal modal.
  The dashboard never performs the agent's claim
  (`dashboard/ui/screens/reveal.ts`).
- Management and approvals need positive human proof per request; the
  dashboard holds a time-boxed human session in Rust so the passphrase
  is typed once per window, not once per request (`docs/protocol.md`
  human session). The session adds revocability and expiry, not
  containment of a same-UID adversary.

## What it does NOT protect

The 11 numbered non-guarantees from `docs/threat-model.md`, without
softening. If any line here seems to promise more than the matching
numbered item there, the document wins.

1. **`run_with_secrets` does not keep secrets from the agent.** The
   broker does not transmit values to the agent process — the spawned
   child, however, is created and controlled by the agent and can read
   and exfiltrate its own environment (`printenv`, HTTP calls, files).
   Granting `run` permits use of and potential exfiltration of those
   secrets by the agent-controlled child. Revoking the grant or agent,
   or locking the vault, terminates continued daemon-managed execution
   but cannot erase or recall copies retained or exfiltrated before
   revocation. The narrower I1 boundary is all that is promised: values
   do not transit the CLI, responses, transcripts of tool results,
   logs, or disk.
2. **A `run` cwd is directory selection only, not sandboxing or
   containment.** `cwd` must be absolute and is authorized through
   `open_authorized_cwd` against the project's authorized roots (kernel
   `openat2` `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
   RESOLVE_NO_MAGICLINKS` from the pinned root fd, applied via `fchdir`
   — no pathname, no TOCTOU). The child keeps normal OS filesystem
   access, including `..` — the same non-sandbox status as an injected
   `.env`, which is readable by any same-UID process. Containing the
   agent is the job of the OS sandbox (container, user namespaces, the
   harness's isolation), not of the broker. `svault` is an
   access-control layer, not a sandbox.
3. **Agent tokens can leak into agent transcripts** (the LLM can read its
   own token file). Accepted residual risk: a leaked token grants
   exactly the holder's existing grants — no escalation — and revocation
   (I8) kills it.
4. **Run cleanup is bounded, not a sandbox kill.** Each child runs in a
   dedicated process group (`pgid == pid`) so signals and cleanup are
   scoped to that run. Launch-connection disconnect, timeout,
   `timeout_secs` expiry, matching grant revocation, agent revocation,
   or vault lock atomically drains the relevant registry entries and
   kills the groups with `SIGTERM`, 250 ms grace, then `SIGKILL`;
   launch handlers wait/reap direct children. A hostile child can still
   exfiltrate before the kill, and cleanup races a forking child — the
   promise is bounded cleanup scope and cessation of the managed
   process group, not isolation or recall of previously copied data.
5. **Run input and quota limits are fail-closed, not negotiated.**
   Exactly three `SCM_RIGHTS` FDs (stdin/stdout/stderr),
   CLOEXEC-owned from extraction and transferred once into the child —
   the broker never reads or logs child stdio. Caps: executable ≤4096
   bytes; `argv` 1..256 entries ≤128 KiB aggregate (`argv[0]` is the
   child's `argv[0]`); `keys` ≤256 (omitted = all project secrets);
   caller `env` ≤256 entries ≤128 KiB aggregate, resultant child
   environment ≤1 MiB; 1 MiB wire message; 4 live runs per agent / 16
   daemon-wide (excess → `E_BUSY`). Child environment is
   deny-by-default with an exact allowlist (`PATH`, `HOME`, `TERM`,
   `LANG`, `LC_ALL`, `LC_CTYPE`, `TMPDIR`, `SHELL`, `USER`,
   `XDG_RUNTIME_DIR`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`,
   `XDG_CACHE_HOME`) plus selected secrets; colliding, forbidden, or
   non-allowlisted caller entries are rejected or silently dropped as
   specified. Run audit carries safe structured fields only, never
   argv, environment, or secret bytes.
6. **Bounded audit growth, with the lifecycle exempt.** The log has two
   ceilings: an operational limit for ordinary operations
   (`AUDIT_SOFT_LIMIT`) and a higher hard cap (`MAX_AUDIT_LEN`). The
   bytes between them are reserved for lifecycle events — lock,
   auto-lock, capability revocation, run drain — so a full log can never
   prevent a protective action: runs are still terminated, capabilities
   invalidated, key material zeroized. Ordinary mutations are refused
   before anything changes; lifecycle events are best-effort (their
   audit failure is not propagated, so locking always completes).
   Authority-reducing events (revocations, narrowing grants) are applied
   even when their entry cannot be written — the cost is one unrecorded
   revocation, reported on stderr. An entry beyond the checkpoint does
   not prove the mutation landed; a missing entry does not prove it did
   not. The vault document is the authority on what is authorized; the
   log is the authority on what was recorded. Rotation and archival are
   the designed replacement, post-MVP — until they exist, a vault at the
   ceiling needs an operator.
7. **Audit MAC limits.** The HMAC protects history against any writer
   that does not hold `K_audit` (everyone without root or the unlocked
   daemon's memory). Entries with a valid MAC are authenticated;
   `mac: null` entries (written while locked, or forged at the tail)
   are **unauthenticated** — a later MAC anchors their position and
   bytes but never their provenance, and rendering marks them. Limits:
   (a) truncation or forgery of the unauthenticated tail beyond the
   vault's audit checkpoint is not detectable without an external
   anchor — truncation reaching checkpointed entries IS detected (the
   encrypted vault embeds the `{seq, hash}` checkpoint, and unlock fails
   closed when the log is behind); (b) a writer holding `K_audit`
   (root / unlocked daemon memory) can recompute MACs. `audit.verify`
   walks the chain without a key; it does not upgrade these limits.
8. **Unlock cost and connection intake are bounded.** A passphrase
   request costs one Argon2id derivation per key slot (≤8 slots, ≤256
   MiB, ≤10 passes), performed outside the session lock. A fresh
   connection must produce its first request within 5 s or it is
   dropped; an established connection idles out after 30 s
   (`run_with_secrets` excepted — it holds its connection for the
   child's lifetime). A client that keeps sending valid first requests
   still consumes CPU per derivation.
9. **Memory hygiene is best-effort, but coredumps are actively
   disabled.** Key types zeroize on drop and lock. The daemon clears its
   dumpability (`prctl(PR_SET_DUMPABLE, 0)`) and sets `RLIMIT_CORE` to
   zero before it can hold key material, so a fatal signal cannot yield
   a readable core of live keys; if either call fails the daemon still
   serves but logs a warning. `mlock`, swap encryption, and OS-level
   coredump policy remain deployment hardening, not promises.
10. **Storage failures and vault size are fail-closed, not silent.** A
    failing `write(2)` (ENOSPC, EFBIG, EDQUOT, EIO) surfaces as an error
    — never retried into a spin — the temp file is removed, the
    destination left byte-for-byte intact, the daemon still responsive.
    A mutation whose result would exceed the loader's caps is refused
    before commit with `E_VAULT_TOO_LARGE`.
11. **No recovery service.** Losing the passphrase loses the vault.
    Backup slots (reserved slot type) are the designed recovery path,
    post-MVP.

**Status repeated because it matters: no independent security audit.
Start with disposable credentials, keep independent backups, and read
`docs/threat-model.md` before storing real secrets.**
