# Security policy

## Supported versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 0.1.0   | Yes       | Linux x86-64 only. `svault` is a pre-1.0 project. |

There are no LTS commitments yet. Only the latest release is maintained.
No independent security audit has been performed.

## Reporting a vulnerability

Use GitHub private vulnerability reporting on the repository
(Security tab → Report a vulnerability). A dedicated security contact
address may be added later.

Do NOT open a public issue for a suspected vulnerability. Do NOT include
live credentials, vault files, agent tokens, machine keys, personal
paths, or full audit logs — send a minimal synthetic reproduction only.

## What to include in a report

- The affected version (`svault --version`) and your Linux distribution.
- A minimal synthetic reproduction (commands, config, exact error codes).
- Whether the vault was unlocked when the issue occurred.
- Whether the broker socket was reachable by the attacker in your
  scenario (same user account, another local user, or remote).

## Scope

In scope — what counts as a vulnerability here:

- Vault cryptography and envelope handling (decryption, key wrapping,
  tamper detection).
- Broker authentication and identity pinning (tokens, passphrase proof,
  human sessions, the Ed25519 broker-identity handshake).
- Grant, lease, and approval enforcement (capability checks, TTLs,
  single-use approvals, revocation).
- Audit integrity (hash chain, HMAC, checkpoint coherence).
- Injection containment for `inject_file` (path confinement, symlinks,
  TOCTOU).
- The dashboard IPC allowlist (named commands only, session held in Rust).

Out of scope:

- An attacker who already runs as your UID. A same-UID process is not
  contained: it can read your memory, files, keystrokes, and tokens.
- Root. Root owns everything.
- A compromised browser or webview process running the dashboard UI.
- The agent you granted `run` or `inject` to doing exactly what those
  grants allow (running a child with secrets, writing a file). That is
  authorized use, not a vulnerability.
- Distribution packaging outside this repository (OS packages, install
  scripts, third-party builds).

## Honest limits

These are the same limits stated in `docs/threat-model.md`. They are not
vulnerabilities; they are the design boundary:

- A same-UID process is not contained.
- Root owns everything.
- `run_with_secrets` is NOT a sandbox — the spawned child is controlled
  by the agent and can exfiltrate whatever it holds. Granting `run`
  permits use of and potential exfiltration of those secrets. Revocation
  and locking stop continued execution but cannot recall copies already
  taken.
- `inject_file` writes into files that same-UID processes can read.
- The human session in the dashboard is not containment (it adds
  revocability and expiry).
- Clipboard/reveal: a revealed value lives in the page and on your
  clipboard — clearing is best-effort and cannot clear what another
  application copied.
- Losing the passphrase loses the vault. There is no recovery service.

## Response expectations

Best-effort only. There is no SLA, no bug bounty, and no guaranteed
response time. This is a pre-1.0 project without an independent audit:
start with disposable credentials, keep independent backups, and read
`docs/threat-model.md` before storing real secrets.
