# TUI rework 2b-2: Console sign-in, Shell, the old Setup screen goes

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Maintenance gets Console sign-in (reset the admin password) and Shell. The old Setup screen keeps only the install path for a host that is not set up. A first install that stopped before the CA opens the install form again, filled in (#87). The 2a and #294 leftovers worth fixing are fixed.

**Architecture:**
- Both new pages are 2a/2b-1 style pages under `tui/maint/`. Each runs one privileged helper verb through `App::begin`, so the password is asked in the bar.
- The reset generates the password in the root helper. The helper calls `openvibes-admin user reset-password` as the admin account, with the password on stdin. Only the TUI screen ever shows the password.
- The shell is opened by the TUI's main loop. It restores the terminal, runs `Host::shell()` and re-initialises on exit.
- The Setup removal deletes every code path that only a set-up host could reach. The #87 case becomes an explicit start state in `App::lazy`.

**Tech Stack:** Rust (openvibes-admin TUI on ratatui, platform-host, platform-store). Tests run on `script_host::SetupHost` (80×24 `TestBackend`) and the setup `Fake` runner. The store tests use the test database (`scripts/test-db.sh`).

**Spec:** `docs/specs/2026-10-10-tui-rework-design.md` §6 (Console sign-in, Shell), §9 (functions survive), §10.9 (Shell), §12 step 2.
- The mockups are the contract:
  - `docs/specs/tui-rework/maint2b.py` (menu after 2b and Console sign-in, approved.md 48);
  - `shell.py` and `shellflow.py` (Shell, approved.md 44);
  - `maint3.py` / `general.py` (sign-in, approved.md 41).
- Outline: `docs/superpowers/plans/2026-10-11-tui-rework-2-maintenance.md` § "Sub-project 2b", items 4-7.
- Predecessor: `docs/superpowers/plans/2026-10-20-tui-rework-2b1-plan-pages.md` (merged as #295).

## Global Constraints

- **Copy is verbatim from the mockups.**
  - Console sign-in:
    - intro `"For when nobody can sign in to the console any more."`;
    - entry `"Reset the admin password"` / `"a new password, shown once"`;
    - after the reset, info rows `"Sign in as"` = `admin` and `"New password"` = `<password>  shown only now`, then `"You are asked to change it at the next sign-in."`;
    - bar `Enter Done`, with no ⭡⭣.
  - Shell:
    - menu value `"the operating system's command line, for experts"`;
    - bar `Enter Open the shell`;
    - question `"Open a shell?"` / `"for experts; logged"`;
    - password bar `"Your login password:"` … `Enter Open`, `Esc Cancel`;
    - shell header lines `"OpenVIBES shell · type exit to go back to the menu. Logged as <user>, <HH:MM>."` and `"Changes here are yours: Repair can put OpenVIBES' own files right again."`.
- Frame rules (approved.md 10-16, 30-32, 39-41): ⭡⭣ Move first in the bar, except while asking or typing. Questions sit in the bar with Yes/No, ⭠⭢ and Enter Confirm. Every question plus its detail fits in 40 columns (approved.md 50).
- No single sign-on row (it comes with SAML, spec step 7; spec §2: no key that does nothing).
- **The new password:**
  - It is never written to the journal, the audit detail, a file, or a log line.
  - It lives in a `Zeroizing<String>` and is dropped when the screen is left.
- `std::process::Command` only where clippy.toml allows it, or with `#[allow(clippy::disallowed_types)]` and a reason comment at the call site (spec §10.9).
- No file over 500 lines because of this plan. `tui/setup.rs` (669) and `tui/setup_tests.rs` (840) end under 500 (Task 4). `tui/maint/uninstall.rs` (513) ends under 500 (Task 5).
- **Builds:**
  - Every cargo command runs as `export CARGO_TARGET_DIR=$HOME/.cache/openvibes-scratch/target CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`, under `nice -n 19 ionice -c3`.
  - Never use `/tmp`.
  - The production host's own services and database are never touched. The store tests use `eval "$(scripts/test-db.sh)"`, then `scripts/test-db.sh stop`.
- Component docs (`docs/components/openvibes-admin.md`, and `platform-host.md` for `Host::shell`) are updated in the task that changes the behaviour.

## Rulings (Claude's, for the user's review)

1. **The reset question is `"Reset the admin password?"` / `"old one stops"`.** The mockups go straight from Enter to Yes without naming the question. This wording fits the 40 columns and says the consequence.
2. **The reset is break-glass: it also clears the admin's sign-in lock and re-enables a disabled admin**, audited as `user.unlocked` / `user.enabled`. The page exists "for when nobody can sign in". A reset that leaves the account locked or disabled would fail at exactly that moment. Cost if wrong: an admin someone disabled on purpose comes back through the host's root password, which is the break-glass contract anyway.
3. **The reset password is 4 groups of 4 characters**, e.g. `Tz4m-W8qH-n2cR-7kLp` (19 code points, 15+ rule), as in the approved mockup (approved.md 48). The characters come from `ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789` (no 0/O/1/l/I), read off a screen. Setup's own generated password is unchanged.
4. **The shell's password is sudo's.** The helper verb `shell-open` does nothing itself. `Host::privileged` journals and audit-notes it like every verb, and sudo checks the password ("your login password"). Under `sudo openvibes-admin`, no password is asked, as for every other verb (#82).
5. **Whose shell:**
   - Under sudo, it is the `SUDO_USER`'s login shell, through `runuser -l <user>`, never root's.
   - Otherwise it is the current user's login shell from the passwd entry, run with `-l`.
   - Root logged in directly gets root's own shell.
6. **#87 is decided at start.** A host with `setup.toml` and no `/etc/openvibes/pki/intermediate.crt` opens the install form, filled from the plan, with a free root key name. Without this the TUI lands on Home, where Repair refuses to make a CA. After a run stops (`Phase::Stopped`), Esc goes to the same filled form when there is no CA, and to Home when there is (Maintenance › Repair finishes it).
7. **"Settings files" stays on the menu** (approved.md 49), between Back up and Shell. The menu has eleven entries: maint2b.py's ten plus Settings files. Operating system comes in step 5.
8. **2a/#294 leftovers in this plan** (Task 5):
   - tables in the `postgres` database (data loss on Remove everything);
   - the `update-agent` mark left in `/run` after the agent is uninstalled;
   - the PG record write-back hiding `postgres_apply`'s error;
   - Update's wording after a stop at Stop services;
   - one remove helper;
   - splitting `uninstall.rs`.

   **Left for later:**
   - the backup's "still owned by root" note;
   - the folder browser on the UI thread;
   - the clean-up time of day on Database;
   - the one-column bar/list offset;
   - `base.rs` / `setup/update.rs` / `native.rs` sizes.

   Why: the first list is correctness or the file rule; the second is cosmetic or needs a new host call.

## Review Focus

1. **The new password never reaches the journal:** Task 1 test `the_reset_password_is_not_journalled`. `Host::privileged` journals `admin-reset admin` with no detail (`journal::step_suffix` only adds detail for setup/update/remove steps).
2. **A reset when the console database is down, or there is no `admin` user:** a red failed line with what to do (`"✗ There is no local account named admin."`, or the store error with `"Repair first."`), Enter Try again, and no password shown (Task 2 test `a_failed_reset_shows_no_password`).
3. **Leaving the page after a reset and coming back** shows the entry again, not the old password (Task 2 test `the_password_is_gone_after_leaving`).
4. **Shell while other work runs** (an Optional parts install in the background): refused like any other begin, `"Wait: other work is still running"` (Task 3 test `no_shell_while_work_runs`).
5. **A wrong login password three times** stops with `"three wrong passwords: nothing more was run"` and opens no shell (Task 3 test `three_wrong_passwords_open_no_shell`).

---

### Task 1: Reset the admin password (backend)

**Files:**
- Modify: `crates/platform-store/src/console_auth.rs`:
  - `replace_password` gains `must_change: bool`, setting `console_credentials.must_change` and `console_users.password_must_change` to it;
  - new `pub async fn enable_local_user(client, username, now, actor_id, actor_kind) -> Result<bool, StoreError>`, audited `user.enabled`.
- Modify: `crates/openvibes-admin/src/user.rs`:
  - `ResetPassword` gains `--password-stdin` and `--must-change` (same doc style as `Create`);
  - the handler enables a disabled user and unlocks it (`unlock_local_user`) before `replace_password`.
- Modify: `crates/platform-host/src/setup.rs` (`Privileged::AdminReset`, `args()` = `["admin-reset"]`, `journal()` = `"admin-reset admin"`).
- Modify: `crates/openvibes-admin/src/helper.rs` (verb `admin-reset`).
- New: `crates/openvibes-admin/src/setup/admin_reset.rs`. It holds:
  - `pub fn readable_password() -> Result<Zeroizing<String>, String>` (ruling 3, `ring::rand::SystemRandom`);
  - `pub fn admin_reset<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String>`, which runs `ctx.as_admin_with_input(&["user","reset-password","admin","--password-stdin","--must-change"], …)` and returns `Done(<password>)`.
- Test: store tests next to the existing `replace_password` tests; `tests/cli.rs` (reset-password with stdin); `setup/admin_reset_tests.rs`; platform-host journal test.

**Interfaces:**
- Produces:
  - `Privileged::AdminReset`;
  - `Call::AdminReset` in `tui/run.rs`, mapped by `execute` to `Privileged::AdminReset`. Its `Ok` text is the helper's `done\t<password>`, which `StepState::parse` turns into `Done(password)`.
- Every existing `replace_password` caller (user.rs, the console's own password change if it calls it) passes `false`.

- [ ] **Step 1: Write the failing tests:**
  - store `a_reset_with_must_change_makes_the_user_change_it`: after `replace_password(…, true)`, the user row reads `password_must_change = true`.
  - store `enable_local_user_enables_and_audits`: a disabled user is enabled, `user.enabled` is in the audit log, and the call returns `true`.
  - cli `reset_password_reads_stdin_and_sets_must_change`: `user reset-password admin --password-stdin --must-change` with one line on stdin succeeds without a terminal. The user must change at the next sign-in, and a locked, disabled admin is unlocked and enabled.
  - `readable_password_has_four_groups_from_the_alphabet`: matches `^[A-HJ-NP-Za-km-z2-9]{4}(-[A-HJ-NP-Za-km-z2-9]{4}){3}$` and is at least 15 code points.
  - `admin_reset_passes_the_password_on_stdin_only`: the Fake records `user reset-password admin --password-stdin --must-change` with the password as input. The argv does not contain the password, and the state is `Done(password)`.
  - platform-host `the_reset_password_is_not_journalled`: the recorded journal line for `AdminReset` is `admin-reset admin ok`, with no password.
- [ ] **Step 2:** Run (`-p platform-store`, `-p openvibes-admin`, `-p platform-host`, with the test database): FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** The tests pass. Then run the full suites of the three crates, clippy `-D warnings` and fmt.
- [ ] **Step 5:** Docs (the `user reset-password` flags; the helper verb). Commit `admin: reset the console admin password from the helper (2b-2)`.

### Task 2: Maintenance › Console sign-in

**Files:**
- Create: `crates/openvibes-admin/src/tui/maint/signin.rs`, `crates/openvibes-admin/src/tui/maint/signin_tests.rs`
- Modify: `crates/openvibes-admin/src/tui/maint/mod.rs`:
  - `Page::SignIn`;
  - every exhaustive match (`title`, `help`, `value`, `open_page`, `maint_key`, `draw`);
  - `Then::SignIn`, `maint_yes`;
  - `ENTRIES` gains `Console sign-in` after Database, with the value `"reset the admin password"`.
- Modify: `crates/openvibes-admin/src/tui/run.rs` (`Kind::SignIn`: title `"Resetting the admin password"`, `verb()` `"Reset"`, not background).
- Modify: `crates/openvibes-admin/src/tui/nav_tests.rs` (the one-gap test covers the page).

**Interfaces:**
- Consumes: Task 1 `Call::AdminReset`; `App::begin`.
- Produces: `Page::SignIn`. The page state holds `shown: Option<Zeroizing<String>>`; it is set from the run's `Done` text and cleared by `open_signin` and by every key that leaves.
- Screens: maint2b.py "Maintenance › Console sign-in" and the one after it, with the intro dim as in maint3.py. Question per ruling 1, Yes first.
- While the reset runs, the bar shows the spinner as on other single-call work.
- On failure: the red `✗ <helper text>`, and the bar `Enter Try again`.

- [ ] **Step 1: Write the failing tests** (`set_up(answers)` host; the fake answers `admin-reset` with `done\tTz4m-W8qH-n2cR-7kLp`):
  - `the_page_offers_the_reset`: the intro, the entry and its value, and the bar `"Reset the admin password"`.
  - `enter_asks_the_question`: the bar reads `"Reset the admin password?"` and `"old one stops"`, with Yes highlighted.
  - `yes_and_password_show_the_new_password_once`: after the password, `"Sign in as"`, `"admin"`, `"Tz4m-W8qH-n2cR-7kLp"`, `"shown only now"`, the change line and `"Done"`; the call log has `admin-reset`.
  - `the_password_is_gone_after_leaving`: Enter (Done), then Esc and open the page again: the screen does not contain the password.
  - `a_failed_reset_shows_no_password`: the fake fails with `no local user named admin`: red `"✗"`, no `"Sign in as"`, and the bar `"Try again"`.
  - `the_menu_lists_console_sign_in_after_database`.
- [ ] **Step 2:** Run: FAIL.
- [ ] **Step 3:** Implement on the `backup.rs` / `repair.rs` page pattern.
- [ ] **Step 4:** Tests pass. Run `--bins`, clippy and fmt.
- [ ] **Step 5:** Docs (Console sign-in). Commit `tui: Maintenance › Console sign-in (2b-2)`.

### Task 3: Maintenance › Shell

**Files:**
- Modify: `crates/platform-host/src/lib.rs`:
  - `Host::shell(&self) -> Result<(), HostError>`. The default is `Err(HostError::Failed("this host has no shell".into()))`.
  - `Privileged::ShellOpen` in `setup.rs`: `args()` = `["shell-open"]`, `journal()` = `"shell-open <operator>"`, where `<operator>` is the name `who()` gives.
- Create: `crates/platform-host/src/shell.rs`. It holds the native `shell()` (ruling 5), the one `#[allow(clippy::disallowed_types)]` with the reason `"Shell entry (spec §10.9): the operator's own login shell, on the inherited terminal"`, and `runuser` as a fixed path.
- Modify: `crates/openvibes-admin/src/helper.rs` (verb `shell-open`: prints `done\topened`).
- Create: `crates/openvibes-admin/src/tui/maint/shell.rs`, `crates/openvibes-admin/src/tui/maint/shell_tests.rs`.
- Modify: `crates/openvibes-admin/src/tui/maint/mod.rs`:
  - `ENTRIES` gains `Shell` after Settings files, with the value `"the operating system's command line, for experts"`;
  - Enter on the entry asks directly; there is no page (shell.py: the question is asked on the menu);
  - `Then::Shell`.
- Modify: `crates/openvibes-admin/src/tui/run.rs`, `work.rs`:
  - `Kind::Shell`, with `verb()` `"Open"`;
  - its password label is `"Your login password:"`, instead of `"Your password (sudo)"`;
  - no step-list screen: while it runs, the bar shows the spinner over Maintenance.
- Modify: `crates/openvibes-admin/src/tui/mod.rs`, the main loop:
  - After each key, `if app.take_shell()`: `ratatui::restore()`, then print the two header lines (teal / dim through ANSI, plain under `Theme` no-colour), then `app.host.shell()`, then `ratatui::init()` and a full redraw.
  - A `shell()` error is shown on Maintenance as red `"✗ The shell could not start: <error>"`.
- Modify: `crates/openvibes-admin/src/tui/script_host.rs`: `SetupHost` records `shell()` calls (test-only).
- Docs: `docs/components/openvibes-admin.md` (Shell), `docs/components/platform-host.md` (`Host::shell`).

**Interfaces:**
- Produces:
  - `App::take_shell(&mut self) -> bool`. It is true once after a `Kind::Shell` run ends `Done`, and resets.
  - `App::shell_header(&self, now: DateTime<Local>) -> [String; 2]` (the two lines; the user is `operator_from_env()` or `$USER`).
  - After the shell, the screen is Maintenance with Shell highlighted.

- [ ] **Step 1: Write the failing tests:**
  - `shell_is_second_to_last`: the menu order ends `… Back up, Settings files, Shell, Uninstall` (ruling 7). The bar on Shell reads `"Open the shell"`.
  - `enter_asks_open_a_shell`: `"Open a shell?"`, `"for experts; logged"`.
  - `yes_asks_the_login_password`: the bar has `"Your login password:"` and `"Open"`.
  - `the_password_opens_the_shell_and_comes_back`: after Enter, the call log has `shell-open`, and `take_shell()` is true once. After it, the screen is Maintenance with `▸ Shell`.
  - `three_wrong_passwords_open_no_shell`, `no_shell_while_work_runs` (Review Focus 4, 5).
  - `the_header_names_the_user_and_time`: `shell_header` with a fixed time gives the exact first line from Global Constraints.
  - platform-host: `shell_runs_the_sudo_users_login_shell` (a pure helper `shell_argv(uid, sudo_user, passwd_shell) -> Vec<String>` gives `["/usr/sbin/runuser","-l","alice"]` for uid 0 with SUDO_USER=alice, and `["/bin/zsh","-l"]` for uid 1000).
  - `the_shell_open_verb_is_journalled_with_the_operator`.
- [ ] **Step 2:** Run: FAIL.
- [ ] **Step 3:** Implement. Only `shell_argv` is unit-tested; the spawn itself is checked in the lab (Task 6).
- [ ] **Step 4:** Tests pass. Run `--bins`, `-p platform-host`, clippy (the new allow is the only one) and fmt.
- [ ] **Step 5:** Commit `tui: Maintenance › Shell (2b-2)`.

### Task 4: The old Setup screen keeps only the install (with #87)

**Files:**
- Modify: `crates/openvibes-admin/src/tui/setup.rs`, `setup_view.rs`, `setup_tests.rs`, `jobs.rs`, `app.rs`.
- Possibly create: `crates/openvibes-admin/src/tui/setup_form.rs` and/or `setup_form_tests.rs`, if the files would still pass 500 lines.
- Docs: `docs/components/openvibes-admin.md` (the `m`/#87 sentence at line 148 becomes the new start rule).

**Interfaces:**
- **Delete:**
  - `Phase::Status`;
  - `setup_status_key`'s `m`/`p`;
  - `may_change_setup`;
  - `change_ports`;
  - `Setup::previous`, `previous_agent_ports`, `then_remove`;
  - `Job::Repair`, `Job::Remove`;
  - the `previous` branches in `form_key`, `with_password`, `setup_tick` and `setup_view.rs`;
  - `App::setup_done`'s `previous` half;
  - `move_confirmed` and the port-move confirmation in `start_plan`, if only `previous_agent_ports` fed them.
- **Keep:** the install path (form, propose_ports, model prompt, password, running, `Stopped` with Try again, `Finished` with Enter back to Home). Also keep `change_components` under a new name: `fill_from_plan(&mut self)`. It is the #87 filler and always takes the install path (no `previous`), with `default_root_key`.
- **Start (ruling 6):**
  - `App::lazy` computes `set_up` and, when set up, `ca_exists()`.
  - Set up with a CA → `Screen::Home`.
  - Set up without a CA → `Screen::Legacy`, `Phase::Form` via `fill_from_plan`. A plan that does not parse shows its error on the form, which then starts empty.
  - Not set up → today's form.
- **`Phase::Stopped`:** Esc goes to `fill_from_plan` when there is no CA, and otherwise back to Home.

- [ ] **Step 1: Write the failing tests:**
  - `a_plan_without_a_ca_opens_the_install_form_filled`: `SetupHost` with a plan containing `# no ca` and set up. At start the screen is the form with the plan's host name, and the root key row is a free name. Enter → password → `setup-step` calls (Install, not Repair).
  - `a_set_up_host_with_a_ca_starts_on_home`.
  - `esc_after_a_stop_before_the_ca_returns_to_the_filled_form`.
  - `esc_after_a_stop_after_the_ca_goes_home`.
  - `no_m_or_p_on_a_finished_install`: after Finished, `m` and `p` do nothing, and Enter goes Home.
  - Delete or rewrite every `setup_tests.rs` test that drove `m`, `p`, `previous`, `then_remove` or the Repair job. Their behaviour now lives in Optional parts and Ports (2b-1). List the deleted test names in the commit message.
- [ ] **Step 2:** Run: FAIL (the new tests).
- [ ] **Step 3:** Implement the deletions and the start rule.
- [ ] **Step 4:** Tests pass. Run `--bins`, clippy and fmt. Then `wc -l crates/openvibes-admin/src/tui/setup*.rs crates/openvibes-admin/src/tui/jobs.rs`: every file is under 500.
- [ ] **Step 5:** Docs. Commit `tui: the old Setup screen keeps only the install; a stopped first install opens it again (#87)`.

### Task 5: Leftovers from 2a and #294 (ruling 8)

**Files:**
- Modify: `crates/openvibes-admin/src/setup/remove.rs`, `remove_admin.rs`, `pg_health.rs`, `update.rs` (only where named), `tui/maint/update.rs`, `tui/maint/uninstall.rs` (split into `uninstall.rs` + `uninstall_view.rs`, or along its existing seams).
- Test: `remove_pg_tests.rs`, `update_pg_tests.rs`, `remove_tests.rs`, `tui/maint/update_tests.rs`.

**Interfaces:**
1. **Remove everything also counts user tables in the `postgres` database.**
   - A second query, `SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')`, runs as postgres against `postgres`.
   - A non-zero count keeps PostgreSQL exactly like another database does.
   - The detail names it: `"the postgres database holds 3 tables"`.
2. **A remove that removes the agent also deletes `/run/openvibes-admin/update-agent`.** `AGENT_PENDING` becomes `pub(super)`.
3. **In `pg_health`, a failed write-back of `PG_RECORD` no longer hides `postgres_apply`'s error.** The apply error comes first, and the write-back error is appended as `"; could not restore the setup record: <e>"`.
4. **Update's rescue line after a stop at Stop services** no longer says `"the packages may be partly updated"`, since none were touched. It reads `"The services are started again; nothing was updated: Try again."` Other stops keep their text.
5. **One helper:** `remove_admin.rs::remove_path` goes, and its callers use `remove.rs::remove_file_or_dir` (made `pub(super)`).
6. **`tui/maint/uninstall.rs` ends under 500 lines,** with no behaviour change.

- [ ] **Step 1: Write the failing tests:**
  - `tables_in_the_postgres_database_keep_postgresql`;
  - `removing_the_agent_clears_the_update_agent_mark`;
  - `a_failed_record_write_back_keeps_the_apply_error`;
  - `a_stop_at_stop_services_says_nothing_was_updated`.
  - (5 and 6 are refactors: the existing tests stay green.)
- [ ] **Step 2:** Run: FAIL (the four new tests).
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `--bins`, clippy and fmt. `wc -l` shows that no touched file is over 500.
- [ ] **Step 5:** Commit `admin: 2a and #294 leftovers (postgres tables, update-agent mark, record error, rescue wording, one remove helper, uninstall split)`.

### Task 6: Gate, PR, lab walk

- [ ] **Step 1:** Run the local gate from `/home/lime/Projects/OpenVIBES/testing.md` §2 (test database, console build, fmt, names, folder READMEs, clippy, doc, workspace tests, audit). Everything must be green. Restore `web/dist/.gitkeep` afterwards.
- [ ] **Step 2:** Push and open the PR. The body carries rulings 1-8, the mockups it implements and the left-for-later list. Wait for CI to go green. (Pushing is the user's call; ask first.)
- [ ] **Step 3: Lab walk** with the PR's CI RPMs on a lab platform:
  - **Console sign-in:**
    - reset the password and sign in with it;
    - the console asks for a new password at sign-in;
    - `journalctl -t openvibes-admin` shows `admin-reset admin ok` and not the password.
  - **Shell over SSH:**
    - after the password, the header lines, then `id -un` shows the SSH user, not root;
    - `exit` returns to Maintenance with Shell highlighted;
    - the journal and the console's audit log show `shell-open`.
  - **#87:**
    - on a fresh VM, stop a careful-CA first install before the CA;
    - quit and start the TUI again: the install form opens filled in;
    - run it to the end.
  - Results go on the PR.
