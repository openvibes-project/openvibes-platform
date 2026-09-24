# AGENTS.md

Guidance for AI coding agents working in this repository.

Cross-repo status, decisions, and the handover routine shared by all AI tools live outside this repository in `../AGENTS.md`, `../status.md`, and `../decisions.md` (local only, never pushed). Read them at the start of a session.

Built: sub-project 1, the ingest service (agents connect on port 18423),
the admin CLI, the built-in PKI, storage, RPM packaging, and the
integration and load tests. See `docs/components/README.md`. Planned as
separate modules:
- rule distribution (sub-project 2; the spec is in `docs/specs/`);
- correlation;
- third-party and CMDB sync;
- the console on 443, specified by Codex on the `console` branch.

Everything exchanged with agents is specified in the `openvibes-protocol`
repository; build against its schemas and fixtures.

## Console frontend and `--all-features`

`openvibes-console`'s `embedded-ui` feature embeds the built web frontend,
so any build with `--all-features` (workspace clippy, docs, tests) needs a
current frontend build first: run `scripts/build-console.sh` (Node.js
22.23.1 and npm), then the cargo commands. Without it, `build.rs` stops with
a message saying so. Building without `--all-features` (or with explicit
features other than `embedded-ui`) needs no Node.js.

## Parallel work (Claude Code and Codex)

Two AI tools work in this repository at the same time, each in its own git
worktree and branch. Never work in the other tool's directory.

| Tool | Worktree | Branch | Owns |
|---|---|---|---|
| Claude Code | `../openvibes-platform` | `pm0-pm1`, then per milestone | `openvibes-ingest`, `openvibes-admin`, `platform-pki`, `platform-config` |
| Codex | `../openvibes-platform-console` | `console` | `openvibes-console` (admin API, RBAC, login, web UI) and its spec |

Rules:

- **Specs before code.** The console is designed in
  `docs/specs/<date>-console-design.md` and approved by the user before any
  implementation, like every sub-project (see the architecture spec).
- **Shared crates** (`platform-store`, `platform-config`): change them in
  small, separate commits that merge to `main` first; the other branch then
  rebases. Never change another tool's crate.
- **Migrations are append-only.** Never edit a migration that has reached
  `main`. If both branches add the same number, whoever merges second
  renumbers theirs.
- **Expected small conflicts**: workspace `members` in `Cargo.toml`,
  `Cargo.lock` (regenerate), `docs/components/README.md`. Resolve on rebase.
- **Component docs**: every crate or module gets its page in
  `docs/components/` in the same change.
- **Shared notes** (`../status.md`, `../decisions.md`, one directory with no
  branches): edit only your own tool's section of `status.md`, only append to
  `decisions.md`, and commit immediately after editing.
- Tests use `scripts/test-db.sh`, which keeps its cluster under the
  worktree's own `target/`, so worktrees never share a database.
