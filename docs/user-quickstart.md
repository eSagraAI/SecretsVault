# SecretsVault quickstart

> Candidate documentation for a future release — nothing here is published.
> Commands below are taken verbatim from `README.md` where they exist;
> anything else names the subcommand from `src/cli.rs` without inventing
> flags. If a spelling is not confirmed in the repo, it is omitted.

The shortest honest path from zero to a working setup. Steps 1–7 and 9–11
are human work at a real terminal; step 8 is the agent acting through its
own credential. The dashboard is a read/write client of the same broker over
the same socket — not a bypass: every dashboard operation authenticates the
same way the CLI does (`dashboard/src/backend.rs`, `docs/architecture.md`).

## 0. First trust (once per socket, before anything else)

On a fresh machine no pin exists for the socket. The first interactive
`svault` command at a TTY prints the broker fingerprint, asks you to verify
it out-of-band (compare with `svault trust show` on the broker host), and
writes the pin only after you type an explicit `yes` (`src/cli.rs`
`confirm_broker_pin`; `docs/protocol.md` broker handshake). Anything else —
agents, MCP, CI, pipes — fails closed with `E_BROKER_UNTRUSTED` and zero
credential bytes written.

The dashboard NEVER writes, resets, or rotates a pin
(`dashboard/ui/screens/gates.ts`, `dashboard/ui/screens/settings.ts`). Its
untrusted panel reads "First trust must be made from the CLI": run
`svault trust show` to read the fingerprint, compare it with the probed
value shown, run any interactive `svault` command and answer the
confirmation prompt, then press "Refresh (re-check for a CLI-made pin)".
Passive Refresh only re-checks for a CLI-made pin.

## 1. Start the daemon

```sh
svault daemon &                                   # owns the vault + socket
```

The daemon owns the vault file and the socket
(`$XDG_RUNTIME_DIR/svault/svault.sock` by default,
`src/broker_identity.rs` `default_socket_path`). The dashboard never starts
it: if the dashboard says the broker is offline, start the daemon yourself
and check `SVAULT_SOCKET` points at the same socket (see
`user-troubleshooting.md`).

## 2. Create the vault (first time only)

```sh
svault init                                       # first time only
```

You are prompted for a passphrase (with confirmation) on the TTY — never via
argv or environment (`src/cli.rs` `read_passphrase`, threat model I2).

## 3. Unlock

```sh
svault unlock                                     # TTY passphrase
```

The passphrase is verified against the key slots by the broker on every
privileged request (threat model I3). This MUST happen at a real terminal.

## 4. Add a project and an authorized folder

```sh
svault project add acme --path ~/acme
```

`--path` is repeatable; later folders are added with the `project path-add`
subcommand (`src/cli.rs` `ProjectCmd`). `cwd` authorization and `inject_file
containment both resolve against these roots through kernel `openat2`
(threat model I5).

## 5. Add a secret

```sh
svault secret set acme STRIPE_KEY                 # value via hidden prompt or piped stdin
```

The value is read from a hidden TTY prompt when interactive, otherwise one
line from piped stdin — never argv, never echoed (`src/cli.rs`
`read_value`). Names and metadata can be listed later; values never appear
in listings, logs, errors, or audit entries (threat model I1).

## 6. Enroll an agent

```sh
svault agent add bot --write-token-file ~/.config/svault/agents/bot.token
```

The token is shown once and cannot be recovered — copy it now. With
`--write-token-file` the broker saves it with `O_CREAT|O_EXCL`, mode 0600
(`src/cli.rs` `write_token_file`); without it, store what was printed
yourself. Token delivery afterwards is, in priority order (`README.md`,
`src/cli.rs` `agent_token`, threat model I9):

1. `--token-fd <n>` (preferred),
2. `--token-file <path>` (mode 0600),
3. `SVAULT_TOKEN` environment variable (inferior: same-UID
   `/proc/*/environ` is readable).

There is deliberately no argv flag for token material. The same applies to
the lease credential: `--lease-file <path>` (or `-` for stdin), never an
argument value.

## 7. Grant operations

```sh
svault grant add bot acme --ops read,inject
```

Ops are a comma list over `read,inject,run,reveal,manage` (`src/cli.rs`
`GrantCmd::Add`). Effective capability is always
grants ∩ lease ∩ lock-state, re-evaluated per request (threat model I6).
Granting `run` permits use of — and potential exfiltration through — any
child the agent spawns; granting `inject` permits a file readable by any
same-UID process (`README.md` security boundaries). A lease (`lease create`
with `--ops` / `--ttl-secs`) can only narrow this, never widen it
(`docs/protocol.md` lease flow).

## 8. Run, inject, or request a reveal (agent, with its token)

With the token delivered as above, the agent calls (subcommand names from
`src/cli.rs`; global `--token-file` / `--token-fd` / `--lease-file` supply
credentials, never argv):

- `run` — `svault run <project> [--key NAME...] [--cwd PATH]
  [--env KEY=VALUE...] [--timeout-secs N] -- <executable> [args...]`
  (`docs/protocol.md` client binding; `argv[0]` is the child's `argv[0]`).
- `inject` — writes project secrets to a dotenv file beneath an authorized
  folder (atomic 0600 replace); returns path, count, and key names only.
- `reveal` without an approval id — returns `E_APPROVAL_PENDING` plus
  `{approval_id, expires_in}` (no blocking). With an approved id the claim
  returns `{value}` exactly once. This approved claim is the only path that
  intentionally returns a secret value (`README.md`).

`secrets.list` returns names plus metadata only, never values.

## 9. Approve from the human surface (real terminal or dashboard)

Agent approvals MUST be decided by a human. At the terminal the human-only
subcommands are `approval pending`, `approval approve <id>`, and
`approval deny <id>` (`src/cli.rs` `ApprovalCmd`; wire names
`approvals.pending` / `approvals.approve` / `approvals.deny`,
`docs/protocol.md`). In the dashboard the same decision happens in the
Approvals inbox (`dashboard/ui/screens/approvals.ts`): "approving allows the
agent to claim the value once; the value itself is never shown here."

Agent and human reveals are different paths: an approval lets the requesting
agent CLAIM the value once; a human reveal (`svault reveal <project> <key>`
at the TTY, or the dashboard reveal modal) is a direct, audited owner action
that needs no approval. The dashboard never performs the agent's claim.

## 10. Inspect the audit log

```sh
svault audit show --tail 5
```

Human-only, works while locked; every read appends its own entry, so the
dashboard loads it on demand (route enter plus Refresh) and never polls it
(`dashboard/ui/screens/audit.ts`). `audit verify` walks the chain without a
key; MACs are verified on every unlock (`docs/protocol.md` operations
table). An entry beyond the vault's checkpoint is unconfirmed, and a missing
entry does not prove a change did not happen (`docs/protocol.md` audit
entry format) — the vault document is the authority on what is authorized,
the log on what was recorded.

## 11. Lock

```sh
svault lock
```

Drops key material, purges sessions, invalidates leases/approvals, and
drains all live runs before zeroizing (threat model I8; `docs/protocol.md`
invalidation). Agents may also lock (fail-safe direction); nothing else
about management is agent-reachable. Lock when you step away; the daemon's
idle timer locks on its own after the configured window, no request needed.
