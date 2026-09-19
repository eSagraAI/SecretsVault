# Installing SecretsVault from source (Linux)

> Candidate documentation for a future release — nothing here is published.
> `svault` has no package, no tag, and no released artifact
> (`README.md` status line; `publish = false` in `Cargo.toml` and
> `dashboard/Cargo.toml`).

## Requirements

Stated as observed facts on this machine (2026-09-18), not guesses:

| Requirement | Declared | Observed here |
|---|---|---|
| Rust | `rust-version = "1.88"` is the floor (`Cargo.toml`, both crates) | 1.98.1 (`rustc --version`) |
| Webview (system WebKit the dashboard shell links against) | `dashboard/tauri.conf.json` declares no `bundle.linux.deb.depends` (only `files` under `bundle.linux.deb` — `dashboard/tauri.conf.json:32-39`); the Tauri v2 line needs `webkit2gtk-4.1` | `webkit2gtk-4.1` 2.52.6 via `pkg-config` |
| Node.js + npm (frontend build only) | `dashboard/package.json` → `typescript ^5.9.3`, `npm run build` runs `tsc -p tsconfig.json` | node v26.7.0, npm 11.19.0 |
| Tauri CLI v2 (app bundle/dev loop) | `dashboard/tauri.conf.json` is a Tauri v2 config (`"$schema": ".../config/2"`) | `cargo-tauri` 2.11.4 |

Check the webview dependency before building:

```sh
pkg-config --exists webkit2gtk-4.1 && pkg-config --modversion webkit2gtk-4.1
```

If the probe fails, the Tauri link
will fail too — install the distro `webkit2gtk-4.1` packages first. A missing
`webkit2gtk-4.0` (the old line) does not matter: Tauri v2 uses the 4.1 line.

## Two-crate layout

- Core `svault` crate at the repo root: vault, broker daemon, CLI, MCP
  adapter. Plain synchronous Rust, small dependency closure.
- Dashboard crate at `dashboard/`: Tauri shell plus the vanilla-TypeScript
  frontend in `dashboard/ui/`. It reuses the core as a library
  (`svault = { path = ".." }` in `dashboard/Cargo.toml`) — it never
  reimplements the protocol.

`dashboard/` has its own `[workspace]` and the root `[workspace]` sets
`exclude = ["dashboard"]`. This is deliberate packaging, not an accident:
`cargo build` / `cargo test` at the repo
root keep behaving exactly as before, and the Tauri dependency closure never
enters the core's `cargo-deny` / `cargo-audit` scope.

## Build commands

Core CLI (from the repo root):

```sh
cargo build
```

Dashboard frontend (from `dashboard/`; compiles `ui/*.ts` → `ui/dist/`):

```sh
cd dashboard && npm run build
```

Dashboard app (from `dashboard/`; the nested crate builds only via its own
manifest, using its own lockfile):

```sh
cargo build --manifest-path dashboard/Cargo.toml
# (or `cd dashboard && cargo build`)
```

The resulting debug binary runs as (the env vars are explained in
`user-troubleshooting.md`):

```sh
SVAULT_SOCKET=/tmp/ds/svault.sock GDK_BACKEND=x11 WEBKIT_DISABLE_DMABUF_RENDERER=1 ./target/debug/svault-dashboard
```

## Packaged install (`.deb`)

The `.deb` is self-sufficient: it installs the dashboard binary plus the CLI/daemon as `/usr/bin/svault` (extra file mapping in `dashboard/tauri.conf.json:32-39`; the dashboard binary itself travels the default bundler path, and the core binary is built by `beforeBuildCommand` in `dashboard/tauri.conf.json:9`). First run after installing the package:

```sh
svault daemon &    # the dashboard never starts the broker itself
svault trust show  # compare with the dashboard's probed fingerprint, then any interactive svault command + `yes` to pin (src/cli.rs:1152-1172)
svault init        # first time only
```

Only production frontend assets are embedded (`frontendDist: "./ui/dist"` in `dashboard/tauri.conf.json:7`; `dashboard/ui/index.html:14` loads `./app.js`): no `.ts` sources and no test bundle travel in the package (tests excluded in `dashboard/tsconfig.json`, test output redirected to `ui/.test-dist` in `dashboard/tsconfig.test.json`).

## Where things live on disk

From the on-disk layout table in `docs/architecture.md` (defaults; `--file`
and `--socket` override the vault and socket paths):

| Path | Content | Mode |
|---|---|---|
| `$XDG_DATA_HOME/svault/vault.enc` | envelope: `"SVAULT1"` magic + versioned JSON header + DEK-encrypted document | 0600 |
| `$XDG_DATA_HOME/svault/audit.jsonl` | append-only audit entries, plaintext, hash-chained, HMAC'd while unlocked | 0600 |
| `$XDG_CONFIG_HOME/svault/agents/<name>.token` | optional token files written by humans at enrollment | 0600 |
| `$XDG_RUNTIME_DIR/svault/svault.sock` | broker socket (containing dir 0700) | 0600 |
| `<vault-dir>/vault.enc.broker-id` | persistent Ed25519 broker identity (private key; fingerprint = hex of the public key) | 0600 |
| `$XDG_DATA_HOME/svault/pins/<sha256(canonical-socket-path)>.pin` | client pin: JSON `{socket, key_hex}` — one broker public key per socket | 0600 |

Defaults resolve per `src/store.rs` (`default_vault_path`,
`audit_path` next to the vault) and `src/broker_identity.rs`
(`default_socket_path`, `pin_dir`, `pin_path`): `$XDG_DATA_HOME` falls back
to `$HOME/.local/share`, and the socket defaults to
`$XDG_RUNTIME_DIR/svault/svault.sock`.
