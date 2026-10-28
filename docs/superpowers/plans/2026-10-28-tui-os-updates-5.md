# TUI 5: Operating System Updates — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Maintenance › Operating system, on every install: distribution, kernel, last check, how many updates and how many for security, whether a restart is needed. Entries Update everything and Check again; the update keeps running when the screen is left; when it is done the bar offers Restart now or Later.

**Architecture:** Three new root helper verbs with no free arguments (`os-check`, which also asks `needs-restarting -r`, `os-update` and `os-restart`) run `dnf` and `needs-restarting` through the existing `Runner`. `os-check` writes the result to `/var/lib/openvibes/os-updates` (0644, plain `key=value`) so the TUI reads the last check and the menu value without a password; only Check again and Update ask for it. The TUI page follows Update OpenVIBES (`tui/maint/update.rs`): the standard question, a `Run`, the result line. The pure parsing of dnf's output lives in `platform-host` (`os_updates.rs`) so it is tested without a host.

**Tech Stack:** Rust, platform-host (`Program`, `Runner`, `Privileged`), openvibes-admin helper and ratatui TUI, packaging sudoers drop-in.

**Spec:** `docs/specs/2026-10-10-tui-rework-design.md` §6 (Operating system) and §10.2; `docs/specs/tui-rework/approved.md` rules 17-19; screens `docs/specs/tui-rework/osupdate.py` (copy verbatim, five screens).

## Global Constraints

- Copy screen text from `osupdate.py` exactly; each approved screen is a `TestBackend` fixture test at 80×24 (design §11).
- Helper verbs take no arguments, run nothing but the fixed argv, and refuse unless uid 0 (as the other verbs). Added to the sudoers drop-in one line each.
- Works on Fedora, AlmaLinux and Rocky (all dnf). A host without `dnf` shows "This system has no package manager OpenVIBES knows" and no entries.
- Files under 500 lines; `tui/maint/mod.rs` (466) and `helper.rs` get dispatch lines only, new code in new files.
- No new dependencies. Each component change updates its `docs/components/*.md` page.
- Cargo with `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0`; `openvibes-admin` and `platform-host` tests may fail in this container only (see memory), CI is the judge there.
- Commits use lime's noreply identity and end with the attribution lines.

## Rulings made while planning

- **Q1 Restart needed:** `dnf needs-restarting -r` exit 1 means a restart is needed (kernel, glibc, systemd, …), exit 0 not. Cost if wrong: the text of one line.
- **Q2 Security count:** `dnf updateinfo list --security` lines (unique packages), total from `dnf check-update` (exit 100 = updates, 0 = none, anything else = error). Cost if wrong: the numbers.
- **Q3 What Update everything runs:** `dnf -y upgrade --refresh`, all packages including OpenVIBES' own (the OpenVIBES update still has its own page with backup and migrations; an OS update that pulls a new OpenVIBES package is the same as `dnf upgrade` today, and the package scripts migrate). Cost if wrong: exclude `openvibes-*` with `--exclude`.
- **Q4 Services after the update:** nothing restarted by us; dnf and the RPM scriptlets restart what they restart, and `needs-restarting -r` plus the screen say the rest. The mockup's "restarts only the services whose packages changed" is the scriptlets' behaviour.
- **Q5 Last check:** the time `os-check` last finished, in the state file; Update also writes it. Not refreshed by a timer (no new unit); the menu shows the last known counts, "not checked yet" before the first check.
- **Q6 Leaving the screen:** the `Run` already outlives the page (Quit-while-running, design §10.11); Home shows the result as for Update. Restart now is `os-restart` (`systemctl reboot`), asked first with the standard question.
- **Q7 Logging:** each verb is journalled by sudo; `os-update` also logs the package count it installed.

## Review Focus

1. The helper verbs accept no argument and run only the fixed argv. (Task 2 `os_verbs_take_no_arguments`.)
2. dnf output edge cases: no updates, exit code 100, only security updates, kernel in the list, a repository error. (Task 1 tests.)
3. Check again and Update everything never run while another job runs or Update OpenVIBES is half done (`cannot_ask`).
4. Restart now is asked first and is not offered when no restart is needed.
5. The five screens match `osupdate.py` character for character.

---

### Task 1: Parsing and state (`platform-host/src/os_updates.rs`)

**Files:** Create `crates/platform-host/src/os_updates.rs` (+ tests inline-free in `tests/`); modify `lib.rs`, `docs/components/platform-host.md`.

**Produces:**
- `pub struct OsUpdates { pub total: u32, pub security: u32, pub kernel: bool, pub restart: bool, pub checked_at: i64 }`
- `pub fn parse_check_update(stdout: &str) -> u32`, `parse_security(stdout: &str) -> u32`, `OsUpdates::{to_file, from_file}` (`key=value`, unknown keys ignored).
- `pub fn os_release(text: &str) -> Option<String>` ("AlmaLinux 9.6 (Sage Margay)" from `PRETTY_NAME`).

- [ ] Step 1: failing tests for each (no updates, 23 updates with 4 security, kernel line counted, garbage ignored, file round trip, os-release with and without `PRETTY_NAME`).
- [ ] Step 2: run → FAIL. Step 3: implement. Step 4: PASS, clippy. Step 5: docs + commit.

### Task 2: Helper verbs (`openvibes-admin/src/helper_os.rs`)

**Files:** Create `helper_os.rs` (+ tests); modify `helper.rs` (flatten `OsCommand` like `Ca`), `platform-host/src/runner.rs` (`Program::NeedsRestarting` not needed: `dnf needs-restarting -r`), `setup.rs` (`Privileged::{OsCheck, OsUpdate, OsRestartNeeded, OsRestart}` and their helper arguments), `packaging/rpm/openvibes-sudoers` (4 lines), `docs/components/openvibes-admin.md`.

**Produces:** `os-check` (prints `done<TAB>total<TAB>security<TAB>restart`, writes the state file), `os-update` (runs the upgrade, then the check, prints as `os-check`), `os-restart-needed`, `os-restart`.

- [ ] Step 1: failing tests with the fake `Runner`: `os_verbs_take_no_arguments`, `check_counts_and_writes_the_state`, `exit_100_is_updates_not_an_error`, `a_repository_error_is_reported_and_state_kept`, `update_runs_upgrade_then_check`, `restart_needed_from_the_exit_code`, `refuses_without_root`.
- [ ] Step 2: FAIL. Step 3: implement. Step 4: PASS. Step 5: commit.

### Task 3: TUI call, kind and Host read

**Files:** Modify `tui/run.rs` (`Call::OsCheck`, `Call::OsUpdate`, `Call::OsRestart`; `execute`), `tui/kind.rs` (`Kind::Os { what }`: "Checking for updates", "Updating the operating system", "Restarting"), `platform-host` `Host` trait (`os_updates() -> Option<OsUpdates>` and `os_release()`; native reads the state file and `/etc/os-release`; fake host gets settable values).

- [ ] Tests: `execute` maps each call to its `Privileged`; fake host returns what was set; kind titles.
- [ ] Commit.

### Task 4: The page (`tui/maint/os.rs`)

**Files:** Create `tui/maint/os.rs`, `tui/maint/os_tests.rs`; modify `tui/maint/page.rs` (`Page::Os`), `tui/maint/mod.rs` (menu entry second after Update OpenVIBES, `Then::OsCheck/OsUpdate/OsRestart`, value text `"AlmaLinux 9.6 · 23 updates, 4 for security"`), `docs/specs/tui-rework/approved.md` (rule for what was built).

**Screens (fixtures from `osupdate.py`):** menu with the entry; available; the question `Install 23 updates?` (`restart after` when a restart will be needed); running with the spinner; done with restart needed (`Restart now` / `Later`); done without restart (`✓ 23 packages updated`, back to the entries); up to date; not checked yet; check failed (red, what to do).

- [ ] Step 1: fixture tests for each screen at 80×24, key-flow tests: Enter on Update everything asks; Yes runs; leaving and returning shows the run; done with restart needed → Restart now asks again; Later returns; Check again runs `OsCheck`; `cannot_ask` refusals.
- [ ] Step 2: FAIL. Step 3: implement. Step 4: PASS. Step 5: commit.

### Task 5: Home and Status hint

- [ ] Home shows the finished job's result as for Update (already generic: test that `Kind::Os` is covered) and, until the user restarts, `▲ Restart needed for the new kernel` on the Maintenance row's value. Tests; commit.

### Task 6: Gate and PR

- [ ] Full local gate (fmt, clippy, workspace tests with the container exceptions, console e2e not needed: no console change). Tick-off of the Review Focus list. Open the PR, board issue under the TUI epic, tell the coordinator for the Opus review.
