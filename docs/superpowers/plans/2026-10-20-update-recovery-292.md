# Update recovery when PostgreSQL is gone (#292) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A host whose PostgreSQL server was removed by hand can be updated, repaired or uninstalled from the admin tool, and every failure on the way says what is actually wrong.

**Architecture:** One small module (`setup/pg_health.rs`) diagnoses the PostgreSQL server (installed, cluster present, versions match, running) and puts it back when only the packages or the service are missing. Update calls it before it stops anything and again before it migrates, so Try again recovers a half-done update. Uninstall no longer refuses because of a half-done update, and skips the database work when there is no server. Smaller fixes: Update also restarts enabled units that were down, the journal carries each step's result text, Repair marks what it changed, and the upgrade-migrate unit stops claiming the schema may be refused.

**Tech Stack:** Rust (openvibes-admin, platform-host), the `Fake` runner in `crates/openvibes-admin/src/setup/fake.rs` for every test.

**Spec:** [platform #292](https://github.com/openvibes-project/openvibes-platform/issues/292) and its two comments (points 1-6). Lab host evidence: `dnf remove postgresql` on 2026-10-05, data folder intact (PostgreSQL 18), update failed at migrate for 20 minutes, Uninstall refused, recovered by `dnf install postgresql-server` + `systemctl enable --now postgresql` + Try again + Repair.

## Global Constraints

- No file over 500 lines (`update.rs` is 804 today: its tests move to `update_tests.rs` in Task 2, the `remove_tests.rs` pattern).
- Never `postgresql-setup --initdb` from Update or Uninstall: an empty cluster would hide lost data behind a "working" database.
- Nothing destructive happens before the PostgreSQL check passes; Update's Backup step (the first step) is where it runs.
- Step details are journalled from Task 5 on: no step detail may ever carry a password or token (today none does; the Ready step's detail has none).
- Copy is plain English, no jargon beyond what the TUI already shows ("Try again", "Repair", "Back up first").
- Builds: `CARGO_TARGET_DIR=~/.cache/openvibes-target-recovery CARGO_BUILD_JOBS=6 nice ionice -c3`, no debuginfo.
- Component docs: `docs/components/openvibes-admin.md` updated in the task that changes the behaviour.

## Rulings (decided here, the user may overrule)

1. **Update puts PostgreSQL back itself** (installs `postgresql-server`, `enable --now`) when the packages or service are missing but the data folder is there. Update is an explicit operator action, and "no commands for users" rules out telling them to run dnf.
2. **Point 1 is solved at the host, not in `StoreError`.** The admin tool diagnoses the server before migrate/backup; `StoreError::Unavailable` keeps its fixed text (no connection details leak, the store's rule). A failure with a running server still reads "database unavailable", now rare.
3. **Uninstall ignores a half-done update** (both Keep the data and Remove everything): uninstall never starts services, which is all the guard protects against. It takes the mark over and starts the agent the update had stopped (`update::resume_agent`) before its own Stop.
4. **Remove everything with no PostgreSQL server** skips dropping the database and roles and keeps `/var/lib/pgsql`, saying so: without a server nobody can tell whether the folder holds other databases.
5. **Update restarts enabled units too**, not only those active at Stop: an enabled unit that had failed starts again, as it would at boot. A disabled unit stays off.

## Review Focus

1. Data folder from an older PostgreSQL major than the reinstalled server: Update must stop before Stop with "made by PostgreSQL 18, the server is 19" and no service touched (Task 1 test `a_newer_server_than_the_data_is_refused`).
2. Data folder gone too: Update must refuse, never initdb (Task 1 test `no_cluster_is_refused_never_initialised`).
3. Try again from a half-done update after PostgreSQL vanished: Migrate puts it back and finishes (Task 2 test `migrate_puts_postgresql_back_first`).
4. Uninstall with "Back up first" ticked and no server: fails at Backup naming the cause and saying untick Back up first; nothing removed (Task 3 test `backup_without_a_server_says_untick_it`).
5. Remove everything after Uninstall took over an update mark, agent not among the components: the agent runs afterwards (Task 3 test `uninstall_after_a_half_done_update_starts_the_agent_again`).

---

### Task 1: PostgreSQL health check and put-back

**Files:**
- Create: `crates/openvibes-admin/src/setup/pg_health.rs` (with `#[cfg(test)] mod tests` inside, < 250 lines)
- Modify: `crates/openvibes-admin/src/setup/mod.rs` (add `mod pg_health;`)

**Interfaces:**
- Consumes: `base::{PG_VERSION (make pub(super)), postgres_apply}`, `Ctx::{succeeds, exists, read, stdout}`.
- Produces:
  - `pub(super) fn problem<R: Runner>(ctx: &Ctx<R>) -> Option<String>`: `None` when the server is installed, the cluster exists and `postgresql` is active; else the first of, in this order:
    - `"PostgreSQL is not installed (postgresql-server is missing)"`
    - `"the PostgreSQL data folder /var/lib/pgsql/data is gone"`
    - `"the database was made by PostgreSQL {data} and the installed server is {server}: upgrade the data with postgresql-setup --upgrade"`
    - `"PostgreSQL is not running"`
  - `pub(super) fn ensure<R: Runner>(ctx: &Ctx<R>) -> Result<Option<String>, String>`: `Ok(None)` when `problem` is `None`; `Err(problem)` when the cluster is gone or the versions differ (after installing, versions are compared again); otherwise runs `base::postgres_apply` and returns `Ok(Some("PostgreSQL was missing or stopped: installed and started it again".into()))`, or `Err` with `problem`'s text plus `": {apply error}"`.
  - Server major: `rpm -q --qf %{VERSION} postgresql-server`, text before the first `.`; data major: `/var/lib/pgsql/data/PG_VERSION` trimmed.

- [ ] **Step 1: Write the failing tests** in `pg_health.rs`, with `Fake` answering `rpm -q --quiet postgresql-server`, `systemctl is-active --quiet postgresql`, the `rpm -q --qf` version and a `var/lib/pgsql/data/PG_VERSION` file under `fake.root`:
  - `a_healthy_server_has_no_problem`: all present, `problem == None`, `ensure == Ok(None)`, no `dnf` call.
  - `a_removed_server_is_installed_and_started`: rpm -q fails, PG_VERSION `18`, after install rpm reports `18.6`; `ensure` returns `Ok(Some(..))`; calls include `dnf install -y postgresql-server` and `systemctl enable --now postgresql`; no `postgresql-setup` call.
  - `a_stopped_server_is_started`: installed, not active: `enable --now postgresql` called, no dnf.
  - `no_cluster_is_refused_never_initialised`: no PG_VERSION: `Err` contains `data folder /var/lib/pgsql/data is gone`, no `dnf`, no `postgresql-setup`.
  - `a_newer_server_than_the_data_is_refused`: PG_VERSION `18`, server `19.1`: `Err` contains `made by PostgreSQL 18 and the installed server is 19`; no `systemctl enable`.
- [ ] **Step 2:** `cargo test -p openvibes-admin pg_health`: FAIL (module missing).
- [ ] **Step 3:** Implement `problem` and `ensure` as above.
- [ ] **Step 4:** `cargo test -p openvibes-admin pg_health`: 5 passed.
- [ ] **Step 5:** Commit `admin: diagnose and put back a missing PostgreSQL server (#292)`.

### Task 2: Update checks PostgreSQL first and restarts enabled units

**Files:**
- Modify: `crates/openvibes-admin/src/setup/update.rs` (`run` Backup and Migrate arms, `stop`)
- Create: `crates/openvibes-admin/src/setup/update_tests.rs` (the existing `mod tests` moved out verbatim, `#[cfg(test)] #[path = "update_tests.rs"] mod tests;`)
- Modify: `crates/openvibes-admin/src/tui/maint/update.rs:277` (copy for a failed Migrate)
- Modify: `docs/components/openvibes-admin.md` (Update section)

**Interfaces:**
- Consumes: `pg_health::ensure` (Task 1).
- Produces: Backup step detail gains a `"; "`-joined prefix when `ensure` returned `Some(note)`; Migrate likewise.

- [ ] **Step 1: Move the tests** to `update_tests.rs`; `cargo test -p openvibes-admin setup::update`: same count passes as before the move.
- [ ] **Step 2: Write the failing tests** in `update_tests.rs`:
  - `a_missing_postgresql_stops_the_update_before_anything_stops`: rpm -q postgresql-server fails and no PG_VERSION; `run(Backup)` is `Failed` containing `data folder`; no `systemctl stop` call; no job mark (`job_guard(root, "setup").is_ok()`).
  - `the_backup_step_puts_postgresql_back`: server missing, PG_VERSION present: `run(Backup)` is not `Failed` and the dnf install came before any `systemctl stop`.
  - `migrate_puts_postgresql_back_first`: job mark `update` present, server missing, PG_VERSION `18`: `run(Migrate)` is `Done`, its detail starts with `PostgreSQL was missing or stopped`, and `dnf install` came before `openvibes-admin migrate`.
  - `an_enabled_unit_that_was_down_starts_again`: `openvibes-ingest.service` not active but `is-enabled --quiet` succeeds; after `Stop` then `Start`, `systemctl start` includes it.
  - Adjust `only_previously_active_units_are_started` so distribution is neither active nor enabled (rename `a_disabled_stopped_unit_stays_stopped`); its assertions otherwise unchanged.
- [ ] **Step 3:** run them: the four new ones FAIL.
- [ ] **Step 4: Implement:** Backup arm calls `pg_health::ensure` before the backup choice; Migrate calls it before `migrate`; `stop` remembers `running ∪ enabled ∪ earlier` (`is-enabled --quiet UNIT`), still stops only `running`.
- [ ] **Step 5: TUI copy** at `tui/maint/update.rs:277` becomes `"The packages are new but the database is not yet: Try again finishes it (it also puts PostgreSQL back if it is missing). The services stay stopped until then."`; update the TUI test that asserts the old text.
- [ ] **Step 6:** `cargo test -p openvibes-admin`: all pass. `wc -l` on `update.rs` < 500.
- [ ] **Step 7:** Docs (Update: PostgreSQL check, put-back, enabled units) and commit `update: check PostgreSQL before Stop and Migrate; restart enabled units (#292)`.

### Task 3: Uninstall works from a half-done update and without a server

**Files:**
- Modify: `crates/openvibes-admin/src/setup/remove.rs` (`run`, Backup arm, `purge`)
- Modify: `crates/openvibes-admin/src/setup/update.rs` (`pub(super) fn abandon<R: Runner>(ctx: &Ctx<R>)`: `resume_agent(ctx)` then remove `ACTIVE`)
- Test: `crates/openvibes-admin/src/setup/remove_tests.rs`
- Modify: `crates/openvibes-admin/src/tui/maint/repair.rs` (module doc line 5-6 still true; no change unless a test text moves), `docs/components/openvibes-admin.md` (Uninstall)

**Interfaces:**
- Consumes: `pg_health::problem` (Task 1), `update::abandon`.

- [ ] **Step 1: Write the failing tests** in `remove_tests.rs`:
  - `an_uninstall_runs_after_a_half_done_update`: job mark `update`; `run(Backup)` with no backup is `Skipped`, not `Failed`; `run(Stop)` rewrites the mark to `uninstall`.
  - `uninstall_after_a_half_done_update_starts_the_agent_again`: mark `update`, `run/openvibes-admin/update-agent` present, agent not in `--components`: `run(Stop)` calls `systemctl start openvibes-agent.service` and removes `run/openvibes-admin/update-active`.
  - `backup_without_a_server_says_untick_it`: server missing, backup path given: `Failed` containing `PostgreSQL is not installed` and `untick Back up first`; no `systemctl stop`.
  - `remove_everything_without_a_server_keeps_the_data_folder`: confirm = hostname, server missing, `var/lib/pgsql/data` present: `run(Purge)` is `Done` and contains `no PostgreSQL server: the database was not dropped and /var/lib/pgsql stays`; no `psql`/`dropdb` call; `var/lib/pgsql` still exists.
  - The existing "Remove everything is half done" test stays green (an `uninstall\neverything` mark still refuses Keep the data).
- [ ] **Step 2:** run them: FAIL.
- [ ] **Step 3: Implement:** in `run`, skip `job_guard` when the mark's first line is `update`; Stop arm calls `update::abandon` before `job_begin`; Backup arm maps an error to `"{problem}: untick Back up first to uninstall without a backup"` when `pg_health::problem` is `Some`; `purge` returns early from the database part (no psql, `postgresql()` not called) with ruling 4's text when `rpm -q postgresql-server` fails, and still removes the OpenVIBES folders, accounts and groups.
- [ ] **Step 4:** `cargo test -p openvibes-admin`: all pass; `remove.rs` < 500 lines.
- [ ] **Step 5:** Docs and commit `uninstall: run after a half-done update and without a PostgreSQL server (#292)`.

### Task 4: Repair marks what it changed; journal lines carry the detail

**Files:**
- Modify: `crates/openvibes-admin/src/setup/mod.rs` (`run_step`)
- Modify: `crates/platform-host/src/native.rs` (the step journal at lines ~251-266)
- Test: `crates/openvibes-admin/src/setup/run_tests.rs`, `crates/platform-host/tests/native.rs`

**Interfaces:**
- Produces: in repair mode (`ctx.repair`), a step whose check was `Todo` and whose apply returned `Done(d)` returns `Done(format!("repaired: {d}"))`. Setup (not repair) is unchanged.
- Journal line for `setup-step`/`update-step`/`remove-step`: `"{verb} {outcome}: {detail}"` with `detail` the helper's one-line detail cut to 300 chars; no `: ` part when the detail is empty. `audit note` arguments are unchanged.

- [ ] **Step 1: Write the failing tests:**
  - `run_tests.rs`: `repair_marks_an_applied_step`: repair ctx, firewall check `Todo`, apply `Done("opened 8443/tcp")` → `Done("repaired: opened 8443/tcp")`; `a_done_step_is_not_marked`: check `Done(x)` → `Done(x)`; `setup_does_not_mark`: same as the first with `repair: false` → no prefix.
  - `native.rs` test: helper prints `done\topened 8443/tcp`; the `logger` call's entry ends with `setup-step firewall --repair ok: opened 8443/tcp`; a 400-char detail is cut to 300.
- [ ] **Step 2:** run them: FAIL.
- [ ] **Step 3:** Implement both. If `native.rs` passes 500 lines, move its tests or the step-journal helper to a sibling file.
- [ ] **Step 4:** `cargo test -p openvibes-admin -p platform-host`: all pass. Update any TUI test that asserts a repair detail verbatim.
- [ ] **Step 5:** Commit `repair: mark what changed; journal step details (#292)`.

### Task 5: Upgrade-migrate stops crying wolf

**Files:**
- Modify: `crates/openvibes-admin/src/setup/auto_migrate.rs:51` and its test at ~399

- [ ] **Step 1:** Change the test's expectation to `Setup, Update or Repair is running and migrates the database itself: nothing to do here`; run: FAIL.
- [ ] **Step 2:** Change the log line to that text; run `cargo test -p openvibes-admin auto_migrate`: PASS.
- [ ] **Step 3:** Commit `upgrade-migrate: say plainly that a running Setup migrates itself (#292)`.

### Task 6: Gate, lab reproduction, PR

- [ ] **Step 1:** Run the local gate from `testing.md` (cargo test workspace, audit, vitest, e2e as listed); all green.
- [ ] **Step 2: Lab reproduction** on a Fedora 44 lab VM with 0.2.9 installed (openvibes-lab README): `dnf remove -y postgresql`, install this branch's RPMs into a local folder, run Update from the TUI with that folder. Expected: Backup step reports PostgreSQL put back, update finishes, Status shows no problems, no Repair needed. Then the half-done case: write `update` to `/run/openvibes-admin/job` by hand, remove PostgreSQL again, run `openvibes-admin setup --update` (it resumes at Migrate); expected: it puts PostgreSQL back and finishes. Then Uninstall › Remove everything with PostgreSQL removed: completes, `/var/lib/pgsql` kept and named.
- [ ] **Step 3:** Open the PR (`Fixes #292`), body lists rulings 1-5 and the lab results; wait for CI green.
