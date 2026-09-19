# Uninstalling SecretsVault

> Candidate documentation for a future release — nothing here is published.
> Read this whole page before deleting anything. Deletion is irreversible:
> losing the vault file loses the secrets (threat model §11 — no
> recovery service).

## 1. Lock and stop the daemon

The daemon (`svault daemon`) owns the vault file and the socket and blocks
while serving (`src/cli.rs` `Cmd::Daemon` → `daemon.serve()`). There is no
`stop` subcommand — stopping means locking first, then terminating that
process. Everything below uses only what the package installs (`svault`
at `/usr/bin/svault` via `dashboard/tauri.conf.json:32-39`) plus POSIX tools:

```sh
svault lock
# then terminate the `svault daemon` process, e.g.:
kill <daemon-pid>
# confirm both facts before deleting anything:
svault status      # must report locked
pgrep -af 'svault( daemon)?' || true   # the daemon line must be gone
```

Lock first on purpose: locking drains all live runs, invalidates
leases/approvals/sessions, and zeroizes key material before anything is
removed (`docs/protocol.md` invalidation; threat model I8).

## 2. What to delete

Paths from the on-disk layout table in `docs/architecture.md`
(`$XDG_DATA_HOME` falls back to `$HOME/.local/share` when unset —
`src/store.rs` `default_vault_path`, `src/broker_identity.rs` `pin_dir`):

```sh
# Inspect first — these prints delete nothing:
ls -l ~/.local/share/svault/vault.enc \
      ~/.local/share/svault/vault.enc.broker-id \
      ~/.local/share/svault/audit.jsonl \
      ~/.local/share/svault/pins/
```

> ⚠️ Destructive. Deleting the vault without keeping what you need
> destroys the secrets it holds — there is no recovery service, and
> backup slots are a post-MVP design, not something you can use now
> (`docs/threat-model.md` §11). While still unlocked, copy out anything
> you must keep (reveal or read it through the normal human paths);
> after the files below are gone, they are gone.

```sh
rm ~/.local/share/svault/vault.enc \
   ~/.local/share/svault/vault.enc.broker-id \
   ~/.local/share/svault/audit.jsonl
rm ~/.local/share/svault/pins/<sha256(canonical-socket-path)>.pin
```

What each file is:

| Path | Content |
|---|---|
| `$XDG_DATA_HOME/svault/vault.enc` | the encrypted vault document |
| `<vault-dir>/vault.enc.broker-id` | the persistent Ed25519 broker identity (sibling of the vault) |
| `$XDG_DATA_HOME/svault/audit.jsonl` | the append-only audit log (sits next to the vault) |
| `$XDG_DATA_HOME/svault/pins/<sha256(canonical-socket-path)>.pin` | your client pin for one socket (`{socket, key_hex}`, mode 0600) |

Remove only the pin file for the socket you are retiring, or the whole
`pins/` directory if you are removing everything and use no other socket.
If you enrolled agents with `--write-token-file`, remove those token files
too (default location `$XDG_CONFIG_HOME/svault/agents/<name>.token`, mode
0600). Never use a wildcard or a recursive delete for any of this — name
each file explicitly.

## 3. What stays untouched

Your authorized project folders (e.g. `~/acme`) are yours, not the
vault's. Files the broker wrote there (injected dotenv files) and anything
a child process created stay exactly where they are — uninstalling the
broker does not clean them up and MUST NOT be done with a broad delete.
Remove or keep them yourself, per file, after checking their contents
(they may still hold secret material the broker wrote at your instruction).
