# Contributing to SecretsVault

Short version: work on a branch, run the local gate, integrate into `develop`, and let `main` mean "the last published release" at all times.

## Branch model

| Branch | Starts from | Holds | Merges into | Lifetime |
|---|---|---|---|---|
| `main` | — | The last **stable, published** version. Always cloneable and usable; never incomplete work. Release tags are cut here | — | permanent |
| `develop` | `main`, after each release | Development of the **next** version (for example, after `v0.1.0` it prepares `v0.2.0`). May contain finished but unpublished features | `main`, only during release preparation | permanent |
| `feature/<slug>` | `develop` | One feature per branch | `develop`, after the gate | temporary; delete once integrated |
| `fix/<slug>` | `develop` (ordinary fixes) or `main` (urgent fix for the current release) | A correction | `develop` / `main` | temporary |
| `hotfix/<slug>` | `main` | An urgent fix for an **already published** version only | `main` → patch release → then also `develop` | temporary |

```text
develop
  ↓
feature/name
  ↓
implementation + tests + local gate
  ↓
merge into develop
  ↓
continue with other features
```

Do not merge into `main` until the whole version is ready for release.

## Local gate, before merging into `develop`

```sh
# core crate (repository root)
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo deny check
cargo audit

# dashboard crate
cd dashboard
npm ci                 # once per checkout
npm run build          # required before any cargo command: tauri::generate_context!
                       # reads frontendDist (./ui/dist) and fails if it does not exist
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
cargo audit
```

Run the parts that apply to your change. Frontend changes also need `npm run typecheck` and `npm test`. When a change touches behaviour, add a smoke test that exercises the real thing (start the daemon, run the command, watch the result) rather than only unit tests.

Do not repeat a full audit for every feature. A deeper review is warranted when a change touches: cryptography, authentication/authorization, the wire protocol or IPC, filesystem containment, process lifecycle, reveal/session/permission handling, platform porting, or immediately before a significant release.

## Release preparation

1. Freeze features on `develop`.
2. Run the complete local gate (`develop`).
3. Review the diff since the last release and audit where the change warrants it.
4. Fix blocking findings.
5. Bump the version (see below).
6. Close the `[Unreleased]` section in `CHANGELOG.md` with the version and date.
7. Build the packages (`cargo tauri build` produces the `.deb`; it builds the core first).
8. Merge `develop` into `main`.
9. Verify `main` (gate again on the merged result).
10. Tag: `git tag -s vX.Y.Z -m "..."` from `main`.
11. Create the GitHub Release for that tag, attaching the built `.deb`.
12. Record the artifact checksum in the release notes.
13. Confirm that `main` again represents exactly the last stable release.

Afterwards, `develop` continues from that new `main`.

## Versioning

SemVer, bumped only at release time (never per feature):

- `0.1.1`, `0.1.2` — compatible fixes in the current release line.
- `0.2.0` — new functionality or relevant changes.

The version lives in four files and they must move together:

- `Cargo.toml`
- `dashboard/Cargo.toml`
- `dashboard/tauri.conf.json`
- `dashboard/package.json`

`CHANGELOG.md` keeps an `## [Unreleased]` section while a version is in development; it is closed with the release date when that version ships.

## Commits

Format: `(type): concise description`, in the imperative. Types in use:

`feat`, `fix`, `docs`, `test`, `config`, `refactor`, `security`, `perf`, `style`, `chore`.

Examples:

```text
(feat): add Windows named pipe transport
(fix): reject stale broker session
(docs): document Windows trust model
(test): cover job object cleanup
```

Keep commits small and clear; there is no requirement to squash development into a single commit. Push is always explicit — nothing is pushed automatically.

## Integrating work

Even with a single maintainer:

- Work on branches; never commit directly to `main`.
- Review `git status` and the full diff before integrating.
- Prefer fast-forward or a clean rebase; avoid unnecessary merge commits.
- Never force-push `main`.
- Destructive operations (deleting a branch or worktree, `reset --hard`, history rewriting) require explicit authorization.

## Hotfix on a published version

If `v0.1.0` needs an urgent fix while `develop` already carries next-version work:

```text
main (v0.1.0)
 ↓
hotfix/bug
 ↓
main
 ↓
v0.1.1
 ↓
bring the fix to develop as well
```

The patch release follows the same release checklist, with the smallest possible diff.

## What does not belong in this repository

The public repository carries the product and its public documentation. Internal working material stays out: audit reports, private specifications and planning documents, prompts, agent tooling and local development context.
