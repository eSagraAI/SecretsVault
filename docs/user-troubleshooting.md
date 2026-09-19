# SecretsVault troubleshooting (Linux)

> Candidate documentation for a future release — nothing here is published.
> Each entry is symptom → cause → fix. Fixes never ask you to retry a
> fail-closed refusal into success, never touch the vault file by hand,
> and never use a wildcard delete.

## Blank white dashboard window on NVIDIA / Wayland

**Symptom:** the dashboard window opens but paints nothing (blank white),
and stderr shows `Failed to create GBM buffer`.

**Cause:** WebKitGTK's dmabuf renderer fails on NVIDIA. This is an
environment issue, not an app bug — no code change fixes it.

**Fix:** launch with the environment variables:

```sh
GDK_BACKEND=x11 WEBKIT_DISABLE_DMABUF_RENDERER=1
```

Full launch line from the same source (socket path adjusted to yours):

```sh
SVAULT_SOCKET=/tmp/ds/svault.sock GDK_BACKEND=x11 WEBKIT_DISABLE_DMABUF_RENDERER=1 ./target/debug/svault-dashboard
```

Without these variables the same binary navigates and loads fine
(WebKitWebProcess alive) but paints nothing. `SVAULT_SOCKET` selects
which daemon socket the dashboard talks to (`dashboard/src/main.rs`):
when set and non-empty it is used; otherwise the shared default
`$XDG_RUNTIME_DIR/svault/svault.sock` is used
(`src/broker_identity.rs` `default_socket_path`).

## Missing webview dependency (dashboard build fails)

**Symptom:** the dashboard link fails mentioning webkit, javascriptcore,
or gtk pieces.

**Cause:** the Tauri shell links the system WebKit (`webkit2gtk-4.1`;
`dashboard/tauri.conf.json` deb depends on `libwebkit2gtk-4.1-0` and
`libgtk-3-0`), which is not installed.

**Fix:** check that the webview dependency is present:

```sh
pkg-config --exists webkit2gtk-4.1 && pkg-config --modversion webkit2gtk-4.1
```

A failure means the `-dev` closure is missing — install the distro
`webkit2gtk-4.1` development packages first, then rebuild. A missing
`webkit2gtk-4.0` (the old line) is irrelevant: Tauri v2 uses the 4.1
line. Verified present here: `webkit2gtk-4.1` 2.52.6 (see
`user-install.md`).

## The dashboard says the broker is offline

**Symptom:** pills read `offline`, or Settings → Trust reads
`offline — daemon unreachable` (`dashboard/ui/screens/settings.ts`).

**Cause:** the daemon is not running at the socket the dashboard dialed,
or `SVAULT_SOCKET` (if set) points at a different socket than the one
the daemon bound. The dashboard never starts the daemon itself
(`dashboard/src/main.rs` only reads the socket path;
`dashboard/src/backend.rs` only dials it).

**Fix:**

1. Start the daemon yourself: `svault daemon &` (`README.md`).
2. Check `SVAULT_SOCKET` (if set) names the same socket the daemon
   serves (default `$XDG_RUNTIME_DIR/svault/svault.sock`;
   `src/broker_identity.rs`). The CLI selects the socket with its
   `--socket` flag or the same default (`src/cli.rs` `socket_path`).
3. Re-check from the dashboard (Reload / Refresh). If it is still
   offline, the daemon is not listening there — do not invent a second
   daemon on the same path; a second broker fails `E_BUSY` by design
   (`docs/protocol.md`).

## The dashboard says first trust is required

**Symptom:** the panel reads "First trust must be made from the CLI"
with "Blocked: this dashboard has no trust pin for the broker"
(`dashboard/ui/screens/gates.ts`).

**Cause:** no pin file exists for this socket. First contact without a
pin fails closed with `E_BROKER_UNTRUSTED` and zero credential bytes
written (`docs/protocol.md`, `src/cli.rs` `connect_client`).

**Fix (CLI + TTY only):**

1. At a real terminal on this machine, run `svault trust show` to read
   the broker fingerprint (credential-free handshake, no pin required;
   `src/cli.rs` `execute_trust`).
2. Compare it with the probed value the dashboard shows ("Show broker
   fingerprint" — display only; comparing there establishes nothing).
3. Run any interactive `svault` command: it prints the fingerprint and
   only an explicit `yes` (typed at `/dev/tty`) pins it; anything else
   fails closed (`src/cli.rs` `confirm_broker_pin`).
4. Back in the dashboard, press "Refresh (re-check for a CLI-made
   pin)". Passive Refresh only re-checks for a CLI-made pin — it will
   never pin for you, by design.

## "Broker identity mismatch"

**Symptom:** the dashboard shows "Broker identity mismatch" with
"SECURITY: the broker's identity has changed. This app's pinned
fingerprint no longer matches what the broker presents. The app refuses
to trust it." No passphrase is accepted or sent while this screen is
shown (`dashboard/ui/screens/gates.ts` `renderMismatch`).

**Cause:** the pinned fingerprint no longer matches the key the broker
presents. The pin file is per-socket JSON `{socket, key_hex}`
(`src/broker_identity.rs` `pin_path`), so this means the broker side
changed or something sits between you and it.

**Fix:** do not proceed. There is no re-pin button here and none will
be added. Investigate on the broker host: was the broker reinstalled,
its identity regenerated, or is something intercepting the connection?
(Those three suspects are quoted from the screen itself.) Rotation and
reset are CLI + TTY only (`svault trust reset` asks for an explicit
`ROTATE` confirmation at the terminal, `src/cli.rs`; every existing
pin then fails closed until the human re-pins, `docs/architecture.md`
key hierarchy). Compare with `svault trust show` before trusting
anything.

## Wrong passphrase / `E_AUTH`

**Symptom:** `authentication failed` (`E_AUTH`; `src/error.rs`).

**Cause:** wrong passphrase, unknown token, or no credential where one
is required. The message is generic by design: failed human proofs and
unknown tokens produce the same text, with no oracle
(`docs/protocol.md` authentication).

**Fix:** nothing was unlocked and nothing changed — retype the
passphrase at the TTY (it is never accepted via argv or environment;
threat model I2) or check the token source
(`--token-fd` / `--token-file` / `SVAULT_TOKEN`, `src/cli.rs`
`agent_token`). Do not script guesses around it; the generic message
will not tell you which part was wrong.

## `E_SESSION_EXPIRED`

**Symptom:** `session expired or revoked` (`E_SESSION_EXPIRED`;
`src/error.rs`), e.g. the dashboard's "Your session expired — unlock
again" notice (`dashboard/ui/screens/agents.ts`).

**Cause:** the human session lapsed: sliding TTL 300 s default,
absolute ceiling 1800 s from minting, fixed in v1
(`docs/protocol.md` human session). Any lock purges all sessions, and
a daemon restart wipes the memory-only table — those present the same
way, with no oracle.

**Fix:** unlock again at the terminal or through the dashboard Unlock
panel. An expired session is never refreshed automatically — only a
live session renews (on `session.touch` or an allowed human op).
Denials never renew it.

## `E_AUDIT_FULL`

**Symptom:** `audit log is full` (`E_AUDIT_FULL`;
`dashboard/src/backend.rs` `broker_message`).

**Cause:** the audit log reached its operational ceiling
(`AUDIT_SOFT_LIMIT`, below the hard cap `MAX_AUDIT_LEN`;
threat model §6). Ordinary mutations are refused *before* anything
changes (`docs/protocol.md` errors) — the refused operation was not
applied and the vault is untouched.

**Fix:** stop issuing mutations; the vault is not damaged. Protective
actions still work — lock, revocation, and run drain live in the
bytes reserved above the operational ceiling and their failures are
not propagated, so a full log can never block a lock
(threat model §6). Clearing the ceiling needs an operator, and log
rotation/archival is the designed post-MVP replacement — it does not
exist yet, so do not delete or edit `audit.jsonl` by hand (history is
append-only and byte-identical by design).

## `E_VAULT_CORRUPT`

**Symptom:** `vault file corrupted` (`E_VAULT_CORRUPT`;
`dashboard/src/backend.rs` `broker_message`). Any tampering with
`vault.enc` fails closed this way (threat model I4).

**Cause:** the vault file (or its header/KDF params) failed integrity
or format validation (`src/error.rs` `Corrupt`; threat model I12).

**Fix:** stop. Do not retry the operation and do not hand-edit
`vault.enc` — retries cannot heal a fail-closed integrity refusal.
Investigate the vault file (was it truncated, copied mid-write,
touched by another process?) and restore from an independent backup
(`README.md`: keep independent backups). A second owner of the same
vault is a different error (`E_BUSY` below), not this one.

## `E_BUSY`

**Symptom:** `too many concurrent operations` (`E_BUSY`;
`dashboard/src/backend.rs` `broker_message`).

**Cause — one of two refusals sharing this code**
(`docs/protocol.md` errors):

1. Run quota: 4 live runs per agent / 16 daemon-wide (excess refused;
   `docs/architecture.md` run execution). Wait for a run to exit or
   signal an owned live run, then retry.
2. A second owner of an already-owned vault (threat model I13): another
   session or a second daemon on any socket holds the exclusive
   `<vault>.lock`. The same code covers a second broker on one socket
   (`<socket>.lock`; threat model I11).

**Fix:** for (1), drain or wait, then retry. For (2), do not force it —
find the live owner first; the lock is per-vault because the danger is
the file, and the kernel releases it on process death, so a crash never
leaves the vault unopenable.
