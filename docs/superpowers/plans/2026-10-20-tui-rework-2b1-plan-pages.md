# TUI rework 2b-1: Optional parts, Ports and addresses, Certificates › Names

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The three Maintenance pages that change the setup plan (Optional parts, Ports and addresses, Certificates with Names) replace today's interim "Components and ports" entry, and removing a part leaves nothing of it on the host.

**Architecture:** Every page edits a copy of the current `Plan`. Apply runs `setup-plan` with every field re-passed (`Plan::args`), then Repair over every step, then `remove-step` for parts that were unticked. A grouped `Work` shows the approved short step list over those calls. Two backend changes support this. Purge of a part removes only that part's data and accounts. The Certificates step restarts the TLS services when it issues new certificates.

**Tech Stack:** Rust (openvibes-admin TUI on ratatui, platform-pki, platform-host); tests on the TUI's `script_host::SetupHost` (80×24 `TestBackend`) and the setup `Fake` runner.

**Spec:** `docs/specs/2026-10-10-tui-rework-design.md` §6, §12 step 2. The mockups are the contract: `docs/specs/tui-rework/maint2.py` (Optional parts, Ports: approved rule 31), `docs/specs/tui-rework/maint2b.py` (the 2b screens: approved rule 48), `docs/specs/tui-rework/approved.md` (rules 1-49). Outline: `docs/superpowers/plans/2026-10-11-tui-rework-2-maintenance.md` § "Sub-project 2b". **2b-2** (its own plan, after this one) covers Console sign-in, Shell, deleting today's Setup screen for set-up hosts (with board #87), the 2a deferred minors, and the lab walk.

## Global Constraints

- The approved mockup wording is copy, verbatim: screen titles, row names and values, help lines, questions (`"Install the assistant?"` / `"2.7 GB"`; `"Remove the agent from this host?"` / `"its data goes too"`, starting on **No**; `"Move agent connections to 18500?"` / `"agents need their install line again"`), result lines and red errors (`"✗ 8080 is used by another program on this host: choose another."`, `"✗ Not a DNS name or an address: letters, digits, dots and dashes."`).
- Frame rules (approved.md 10-16, 30-32): ⭡⭣ Move first in the bar except while asking or typing, one empty line between entries, one value column per screen, questions in the bar with Yes/No, ⭠⭢ and Enter Confirm; checkbox rows say `Space Select/deselect  Enter Confirm`.
- The sudo password is asked in the bar exactly as Update and Repair do (`App::begin`).
- `setup-plan` replaces the whole plan: every caller passes every field of the current plan (Task 1), never a subset.
- Removing a part leaves nothing of it behind (project rule: no leftovers); nothing else is ever removed by a part removal.
- No file over 500 lines because of this plan. New pages are new files under `tui/maint/`. `uninstall.rs` (513) and `setup.rs` / `setup_tests.rs` are only touched where a task says so.
- Builds: `CARGO_TARGET_DIR=$HOME/.cache/openvibes-target-tui2b CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 nice -n 10 ionice -c3`; never `/tmp`.
- Component docs: `docs/components/openvibes-admin.md` updated in the task that changes the behaviour.

## Rulings (Claude's, for the user's review)

1. **Step lists follow the real order of the work.** The approved step names are kept where they match the order Repair runs in. Optional parts, adding the assistant: `Save the choice`, `Install the assistant`, `Download the model`, `Ready`. Removing the agent: `Save the choice`, `Stop the agent`, `Remove the agent`, `Remove its data`, `Ready`. Ports: `Save the ports`, `Restart with the new port`, `Open the new port`, `Close the old port`, `Ready`. Names: `Save the names`, `New certificates`, `Restart services`, `Ready`. Each group maps onto real calls (Task 1, table in Task 3/4/5). Why: a label that runs before or after what it names would be a lie on screen.
2. **"Components and ports" leaves the menu in this plan** (Task 6); the Setup code behind it is deleted in 2b-2. Why: the new pages replace it; two ways to the same change would confuse.
3. **Part removal = `remove-step` whose components are only Agent and/or Assistant, none of them in the plan any more.** Its Purge removes that part's data and accounts without `--confirm`. Why: the plan is saved first, so the part is already out of it; the question on the page is the confirmation (approved.md 48).
4. **The assistant's console section goes with it** only when it points at the local model (what `assistant_setup::configure` wrote). A foreign backend the admin set up stays. Why: removing the local assistant must not delete someone's GPU server settings.
5. **"Free on this host" counts the port the plan already uses for that row as free.** The unprivileged check cannot name the holder, and the platform's own service holds it.

## Review Focus

1. A plan made by `setup --quick --repo-dir X --allow-unsigned-local` keeps both fields through an Apply (Task 1 test `every_field_survives_the_round_trip`).
2. A careful-CA plan: Apply must not pass `--root-key-out` (refused with careful) (Task 1 test `a_careful_plan_passes_no_root_key`).
3. Unticking the agent with the assistant also ticked: only agent data goes; `/var/lib/openvibes-llm` stays (Task 2 test `a_part_removal_removes_only_that_part`).
4. A foreign `[assistant]` backend in console.toml survives removing the local assistant (Task 2 test `a_foreign_assistant_backend_stays`).
5. Typing the port another row already uses: refused like a taken port, with the row named (Task 4 test `a_port_another_row_uses_is_refused`).

---

### Task 1: Plan round trip and grouped work

**Files:**
- Modify: `crates/openvibes-admin/src/setup/plan.rs` (472 lines: if it would pass 500, put `args` and its tests in `setup/plan_args.rs`)
- Modify: `crates/openvibes-admin/src/tui/run.rs` (`Call::SetupPlan`, `execute`), `crates/openvibes-admin/src/tui/run.rs` or a new `tui/groups.rs` (grouping)
- Modify: `crates/openvibes-admin/src/tui/ui/steps.rs` only if grouping needs it
- Test: `crates/openvibes-admin/src/setup/plan_tests.rs` (or the existing plan tests), `crates/openvibes-admin/src/tui/run_tests.rs`

**Interfaces:**
- Produces:
  - `impl Plan { pub fn args(&self) -> Vec<String> }`: argv for `helper setup-plan` that rebuilds exactly this plan (except `operator`, which `setup-plan` takes from SUDO_USER). It covers `--components` (comma-joined, `Component::name()`), `--hostname`, one `--san` per name, `--ca quick|careful`, `--root-key-out` only when `ca` is Quick and set, `--admin-password-file`, `--repo-dir`, `--allow-unsigned-local` when true, `--console-port`, `--ingest-port`, `--distribution-port`, `--model fetch|skip`.
  - `pub fn plan_of(text: &str) -> Result<Plan, String>` in `setup/plan.rs` (parses `Host::setup_plan()` text; the TUI uses it).
  - `Call::SetupPlan(Vec<String>)`: `execute` maps it to `Privileged::SetupPlan(&args)`.
  - Grouped work: `Work::grouped(kind: Kind, groups: Vec<(String, Vec<Call>)>) -> Work`. It flattens the calls and keeps `pub labels: Vec<(String, std::ops::Range<usize>)>` (each label with the call indices it covers). `Work::new` gives every call its own label (today's behaviour). Plus `pub fn label_states(run: &Run) -> Vec<Option<StepState>>`: a label is Done when all its calls finished, Failed when one failed (that call's state), None while not reached. The running label is the one holding `run.at`.
  - `Kind::Parts { what: String }` (doing/done/stopped/verb texts from the mockups: the title is `what`, e.g. "Installing the assistant"; `verb()` = "Apply"), `Kind::Ports`, `Kind::Names`. All are non-background.

- [ ] **Step 1: Write the failing tests.**
  - `every_field_survives_the_round_trip`: a Plan with every field set (Quick, root key, admin password file, repo dir, allow_unsigned_local, three ports, model Fetch, two SANs, components with Assistant). Parse `plan.args()` with `PlanArgs::try_parse_from(["setup-plan"].chain(args))` (clap), then `.plan(plan.operator.clone())` and assert equal to the original.
  - `a_careful_plan_passes_no_root_key`: ca Careful, `root_key_out: None`: `args()` contains no `--root-key-out` and the round trip holds.
  - `grouped_work_reports_one_state_per_label` (run_tests.rs): three labels over five calls; feed states for calls 0-2 (Done) and stop at call 3 Failed: label 0 Done, label 1 Failed with call 3's text, label 2 None.
- [ ] **Step 2:** `cargo test -p openvibes-admin --bins plan` and `run_tests`: FAIL.
- [ ] **Step 3:** Implement `Plan::args`, `plan_of`, `Call::SetupPlan`, `Work::grouped`, `label_states`, the three `Kind`s (every exhaustive `match Kind` in run.rs gets its arms).
- [ ] **Step 4:** Tests pass; full `--bins` suite, clippy `-D warnings`, fmt.
- [ ] **Step 5:** Commit `admin: re-pass a whole plan; grouped step lists (2b-1)`.

### Task 2: A removed part leaves nothing behind

**Files:**
- Modify: `crates/openvibes-admin/src/setup/remove.rs` (`purge`, 453 lines: the part logic goes in a new `setup/remove_part.rs`), `crates/openvibes-admin/src/assistant_setup.rs` (a `pub(crate) fn unconfigure(text: &str) -> Result<Option<String>, String>`)
- Test: new `crates/openvibes-admin/src/setup/remove_part_tests.rs`
- Docs: `docs/components/openvibes-admin.md` (Uninstall / Optional parts)

**Interfaces:**
- Consumes: `RemoveArgs { components, .. }`, `ctx.plan.components`.
- Produces: `pub(super) fn is_part_removal(plan: &Plan, components: &[Component]) -> bool`. It is true when `components` is non-empty, holds only `Agent`/`Assistant`, and none of them is in `plan.components`. In that case `purge` (no `--confirm` needed) removes exactly:
  - Agent: `/etc/openvibes-agent`, `/var/lib/openvibes-agent`, account `openvibes_agent` (user and group).
  - Assistant: `/var/lib/openvibes-llm` (incl. the model), `/etc/openvibes/llm-api-key`, account `openvibes-llm`, and the console's `[assistant]` section when `unconfigure` says it was the local one. Then `systemctl try-restart openvibes-console`.
  - The Done text: `"removed the agent's data and account"` / `"removed the assistant's data, model and account"`, joined with `"; "`.
  - Any other component list behaves as today (a keep-data uninstall still keeps everything).
- `unconfigure(console_toml)`: `Ok(Some(new_text))` when `[assistant]` points at the local model (the shape `configure` writes), `Ok(None)` when there is no section or a foreign backend.

- [ ] **Step 1: Write the failing tests** (Fake runner, files under `fake.root`):
  - `removing_the_agent_removes_its_data_and_account`: plan without Agent, `--components agent`: Purge Done with the agent text; both folders gone; `userdel openvibes_agent` called; nothing under `/var/lib/openvibes-llm` touched.
  - `a_part_removal_removes_only_that_part`: plan with Assistant, `--components agent`: `/var/lib/openvibes-llm` and `/etc/openvibes/llm-api-key` still exist.
  - `removing_the_assistant_removes_model_key_account_and_its_console_section`: console.toml written by `configure`: after Purge it has no `[assistant]`, the key file is gone, `try-restart openvibes-console` called.
  - `a_foreign_assistant_backend_stays`: console.toml with the foreign backend from `assistant_setup.rs`'s existing test: unchanged.
  - `a_keep_data_uninstall_still_keeps_everything`: whole-platform components, no confirm: Purge `Skipped("data kept")` as today.
  - `a_part_removal_clears_the_job_mark`: after all `RemoveStep::ALL` steps, `/run/openvibes-admin/job` is gone.
- [ ] **Step 2:** Run: FAIL.
- [ ] **Step 3:** Implement in `remove_part.rs`; `purge` calls it first when `is_part_removal`.
- [ ] **Step 4:** Tests pass; `--bins` suite, clippy, fmt; every touched file < 500 lines.
- [ ] **Step 5:** Docs, commit `uninstall: removing a part removes its data and account (2b-1)`.

### Task 3: Maintenance › Optional parts

**Files:**
- Create: `crates/openvibes-admin/src/tui/maint/parts.rs`, `crates/openvibes-admin/src/tui/maint/parts_tests.rs`
- Modify: `crates/openvibes-admin/src/tui/maint/mod.rs` (`Page::Parts`, `title`, `help`, `value`, `open_page`, `maint_key`, `Then::Parts`, `maint_yes`, draw dispatch)

**Interfaces:**
- Consumes: Task 1 (`plan_of`, `Plan::args`, `Work::grouped`, `Kind::Parts`, `label_states`), Task 2 (backend), `App::begin`.
- Produces: `Page::Parts`. State lives in `Maint` (or a `parts::Parts` field): the current plan, the agent and assistant ticks, the row.
- Screens: maint2.py #1-3, maint2b.py #4-12. Row values: `"watch this host too"`, `"local AI helper · 2.7 GB download"`. The Apply value is `"nothing changed yet"`, `"install the assistant"`, `"remove the agent"`, `"remove the assistant"`, or `"install the agent"`; with two changes they are joined with `" and "`. Help lines are verbatim from the mockups. Unticking the agent shows the help `"Removing the agent also removes its data from this host."` (the assistant gets the same sentence with "assistant").
- Apply with nothing changed: Enter does nothing (the row says so).
- Question: add only → `"Install the assistant?"` / `"2.7 GB"` (Yes first) or `"Install the agent?"` / `"watch this host too"`. Any removal → `"Remove the agent from this host?"` / `"its data goes too"` (No first); assistant likewise `"Remove the assistant from this host?"` / `"its data and model go too"`.
- Work (ruling 1): one grouped `Work` per Apply, groups in this order:
  1. `Save the choice` = `[Call::SetupPlan(new_plan.args())]`, with `model` Fetch when the assistant is added and not installed.
  2. For each removed part: `Stop the <part>` = `Remove(Backup)` (no `--backup`) + `Remove(Stop)`; `Remove the <part>` = `Remove(Firewall)` + `Remove(Packages)`; `Remove its data` = `Remove(Purge)` + `Remove(Admin)`; all with `--components <part>` (both parts removed: `--components agent,assistant`, with the labels saying "the agent and the assistant").
  3. When a part is added: `Install the <part>` = `Repair` of `Packages` through `Agent`, then `Download the model` = `Repair(AssistantModel)` (only when the assistant is added).
  4. `Ready` = the remaining Repair calls not yet listed (all of `Step::ALL` for a removal only; `Ready` and `AssistantModel` after an add without the assistant) + `Status`.
  Every Apply therefore runs each `Step::ALL` Repair exactly once (test it).
- Result lines: `"Assistant installed · ask it in the console (<took>)"`, `"Agent removed · nothing of it is left on this host (<took>)"`, `"Agent installed · this host reports to the console (<took>)"`, `"Assistant removed · nothing of it is left on this host (<took>)"`.

- [ ] **Step 1: Write the failing tests** (parts_tests.rs, `set_up(...)` host, PLAN with agent, no assistant):
  - `the_page_shows_what_is_installed`: screen contains `"[x] Agent on this host"`, `"[ ] Assistant"`, `"nothing changed yet"` and the bar `"Space"` `"Select/deselect"`.
  - `ticking_the_assistant_says_what_apply_does`: ⭣, Space: `"install the assistant"`; Enter on Apply → bar `"Install the assistant?"`, `"2.7 GB"`.
  - `apply_saves_the_whole_plan_then_repairs`: Yes, type the password, Enter: the first call is `"setup-plan --components ingest,console,distribution,vulns,rules,agent,assistant --hostname platform.example.com --ca quick … --model fetch"`, then `"setup-step packages --repair"` and the rest in `Step::ALL` order; the step list shows the four labels.
  - `unticking_the_agent_asks_starting_on_no`: the question text and No highlighted; Enter right away does nothing.
  - `removing_the_agent_runs_remove_steps_for_the_agent_only`: the calls include `"remove-step purge --components agent"`; the result line is `"Agent removed · nothing of it is left on this host"`.
  - `nothing_changed_enter_does_nothing`: Enter on Apply with no change: no question, no call.
- [ ] **Step 2:** Run: FAIL.
- [ ] **Step 3:** Implement `parts.rs` on the 2a page pattern (`backup.rs`/`update.rs`: `open`, `<page>_key`, `draw`). Draw the running and finished states with `steps::lines` over `label_states`.
- [ ] **Step 4:** Tests pass; `--bins`, clippy, fmt.
- [ ] **Step 5:** Commit `tui: Maintenance › Optional parts (2b-1)`.

### Task 4: Maintenance › Ports and addresses

**Files:**
- Create: `crates/openvibes-admin/src/tui/maint/ports.rs`, `crates/openvibes-admin/src/tui/maint/ports_tests.rs`
- Modify: `crates/openvibes-admin/src/tui/maint/mod.rs` (as Task 3: `Page::Ports`, `Then::Ports`)

**Interfaces:**
- Consumes: Task 1, `Host::listeners`, `crate::setup::ports::check_ports`.
- Produces: `pub fn port_note<H: Host>(host: &H, plan: &Plan, row: PortRow, typed: &str) -> Result<String, String>`, where `enum PortRow { Console, Ingest, Distribution }`:
  - `Ok("<p> is free on this host.")` when the port is free, or when it is the one the plan already uses for this row (ruling 5).
  - `Err("✗ <p> is used by another program on this host: choose another.")` when `listeners` shows a listener.
  - `Err("✗ <p> is already used here for <row name>.")` when another row has it.
  - `Err("✗ <check_ports message>.")` when it is reserved, zero, or not a number.
- Rows: `Console` (`"<port> · https://<hostname>[:<port>]"`; the `:port` only when not 443), `Agent connections`, `Rule distribution`, `Network devices` (`"514/udp"`, an information row Enter skips). A changed row is drawn `"* <name>"` (yellow star) with `"<new> · was <old>"`. The `Apply` row appears only when something changed.
- Help lines are verbatim from maint2.py #4-6 (the console row: `"The console's port; the web address follows it."`). Apply's help: `"Agents on other hosts need their install line again after this."` when an agent port moved; `"The console's web address changes to https://…"` when only the console moved.
- Typing: Enter on a port row starts typing (digits only, at most 5). The bar is `Bar::edit("<Row name>:", "type a port", …)` as maint2.py #5. The note under the list is red on Err. Enter while Err does nothing. Esc keeps the old value.
- Question: one agent port → `"Move agent connections to <p>?"` / `"agents need their install line again"` (Rule distribution: `"Move rule distribution to <p>?"`); console only → `"Move the console to <p>?"` / `"its web address changes"`; several → `"Move <n> ports?"` / `"agents need their install line again"`.
- Work: `Save the ports` = `[SetupPlan]`; `Restart with the new port` = Repair `Packages` through `Services`; `Open the new port` = Repair `Firewall` through `Agent`; `Close the old port` = `Repair(Ready)` (which closes the moved-from ports); `Ready` = `Repair(AssistantModel)` + `Status`.
- Result line: `"Moved to <p> · new install line: console › Enrollment (<took>)"` for agent ports; `"Console moved to <p> · https://… (<took>)"` for the console.

- [ ] **Step 1: Write the failing tests** (`app_taken(set_up, answers, vec![8080])`):
  - `the_page_lists_every_port`: four rows with the values above; Network devices has no Change in the bar.
  - `a_taken_port_is_said_at_once`: Enter on Agent connections, Backspace ×5, type 8080: the red text; Enter changes nothing.
  - `a_free_port_is_said_free`: 18500 → `"18500 is free on this host."`; Enter → `"* Agent connections"`, `"18500 · was 18423"`, the Apply row.
  - `a_port_another_row_uses_is_refused`: 18424 in Agent connections → `"✗ 18424 is already used here for Rule distribution."`.
  - `its_own_port_counts_as_free`: typing 18423 back into Agent connections (taken in the fake) → free, and no change.
  - `apply_moves_the_port`: Yes, password: the first call is `setup-plan` with `--ingest-port 18500` and every other field as before; the step labels; the result line.
- [ ] **Step 2:** Run: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Tests pass; `--bins`, clippy, fmt.
- [ ] **Step 5:** Docs (Ports and addresses), commit `tui: Maintenance › Ports and addresses (2b-1)`.

### Task 5: Maintenance › Certificates and Names

**Files:**
- Modify: `crates/platform-pki/src/ca.rs` (`pub fn issuer_common_name(cert_pem: &str) -> Result<Option<String>, PkiError>`, 284 lines)
- Modify: `crates/openvibes-admin/src/setup/pki.rs` (`certificates_apply`: after issuing, `systemctl try-restart openvibes-ingest openvibes-distribution openvibes-console`, since services read their certificate at start)
- Create: `crates/openvibes-admin/src/tui/maint/certs.rs`, `crates/openvibes-admin/src/tui/maint/names.rs`, `crates/openvibes-admin/src/tui/maint/certs_tests.rs`
- Modify: `crates/openvibes-admin/src/tui/maint/mod.rs` (`Page::Certificates`, `Page::Names`, `Then::Names`)

**Interfaces:**
- Consumes: `Host::certificates()` (PEM per path), `platform_pki::{not_after, subject_alt_names, issuer_common_name}`, Task 1.
- Produces:
  - The report rows (maint2b.py #18):
    - `Web and agents`: `"valid until <date> · <n> days left"` (from `/etc/openvibes/tls/ingest.crt`; red `"expired <date>"` when past).
    - `Names`: the SANs, comma-joined.
    - `Intermediate`: `"signed by <issuer CN> · until <date>"`.
    - For a quick CA, `Root key` = `"offline: needed only to replace the intermediate"`.
    - With no certificate yet: one line `"No certificates yet: run Repair."`
  - One entry, `Names` (`"add or remove a name agents use"`), with the help `"Names agents and browsers may use to reach this host."`
  - The Names page (maint2b.py #19-23): `Host name` (the plan's hostname), one `Other name` row per SAN, `Add a name` (`"an address or DNS name"`), and `Apply` (`"new certificates with these names"`) when changed. A new name is drawn `"* Other name"` with `"<name> · new"`. Checked as typed:
    - a valid DNS name (same rule as `plan::check_name`, lowercase) → `"A valid DNS name."`
    - an IP address → `"An address."`
    - anything else → red `"✗ Not a DNS name or an address: letters, digits, dots and dashes."`
    - Enter on an emptied Other name removes it; the Host name cannot be emptied (red `"✗ The host name is needed."`).
    - The 16-SAN limit: Add a name is refused past 16 (`"✗ At most 16 other names."`).
  - Question: `"Issue new certificates?"` / `"for these names"`. Work: `Save the names` = `[SetupPlan]`; `New certificates` = Repair `Packages` through `Certificates`; `Restart services` = Repair `Console` through `Agent`; `Ready` = `Repair(Ready)`, `Repair(AssistantModel)`, `Status`. Result: `"New certificates with <n> names · valid until <date> (<took>)"` (the date read again after the run; `"(<took>)"` alone if unreadable).

- [ ] **Step 1: Write the failing tests:**
  - platform-pki: `issuer_common_name_reads_the_signer` (generate_root + sign_intermediate: the intermediate's issuer CN is the root's).
  - setup/pki tests: `new_certificates_restart_the_tls_services` (the Fake records `try-restart` for the three units after issuing).
  - certs_tests.rs (fake PEMs from `platform_pki::generate_root`/`sign_intermediate`/`issue_server`, served by a test-only `SetupHost` field for `certificates()`): `the_report_shows_dates_names_and_signer`, `no_certificates_says_run_repair`, `a_bad_name_is_said_at_once`, `adding_a_name_then_apply_passes_every_san` (the `setup-plan` call carries `--san 192.168.1.10 --san openvibes.lime.lan` and every other field unchanged), `emptying_an_other_name_removes_it`, `the_host_name_cannot_be_emptied`.
- [ ] **Step 2:** Run: FAIL.
- [ ] **Step 3:** Implement (the `SetupHost` change is test-only).
- [ ] **Step 4:** Tests pass (`-p platform-pki`, `-p openvibes-admin --bins`); clippy, fmt.
- [ ] **Step 5:** Docs (Certificates), commit `tui: Maintenance › Certificates and Names (2b-1)`.

### Task 6: The Maintenance menu after 2b-1

**Files:**
- Modify: `crates/openvibes-admin/src/tui/maint/mod.rs` (`ENTRIES`, `value`), `crates/openvibes-admin/src/tui/home.rs` (Help text if it lists entries), `crates/openvibes-admin/src/tui/nav_tests.rs`
- Docs: `docs/components/openvibes-admin.md`

**Interfaces:**
- `ENTRIES` becomes, in this order: Update OpenVIBES, Repair, Optional parts, Ports and addresses, Certificates, Database, Back up, Settings files (kept until step 6, approved.md 49), Uninstall. Console sign-in and Shell come in 2b-2. Row values are from maint2b.py #2: `"agent on this host · assistant"` (live: the installed parts, e.g. `"agent on this host"`, `"agent on this host · assistant"`, `"none"`); `"console <c>, agents <i> and <d>, devices 514"`; `"signed by <issuer CN> · until <date>"`, or `"no certificates yet"`.
- `Entry::Legacy(Tab::Setup)` ("Components and ports") is removed (ruling 2). The legacy Setup screen stays reachable only on a host that is not set up (unchanged until 2b-2).

- [ ] **Step 1: Write the failing tests:** `the_menu_lists_the_2b1_entries_in_order` (the names in order), `no_components_and_ports_entry`, and an `every_screen_has_exactly_one_empty_line_under_its_title` case for each new page (`nav_tests.rs:347`).
- [ ] **Step 2:** Run: FAIL.
- [ ] **Step 3:** Implement; delete tests that drove "Components and ports" from the menu, or point them at the new pages.
- [ ] **Step 4:** `--bins`, clippy, fmt.
- [ ] **Step 5:** Docs (the Maintenance list), commit `tui: the Maintenance menu after 2b-1`.

### Task 7: Gate, lab check, PR

- [ ] **Step 1:** Run the local gate from `/home/lime/Projects/OpenVIBES/testing.md` §2 (test database, console build, fmt, names, folder READMEs, clippy, doc, workspace tests, audit); all green. Run `git submodule update --init` in the worktree first.
- [ ] **Step 2:** Open the PR (body: rulings 1-5, the mockups it implements); wait for CI green.
- [ ] **Step 3: Lab check** with the PR's CI RPMs on a 0.2.9 lab platform (`./lab up platform`, then `rpm -Uvh` of the CI packages):
  - Optional parts: add the assistant (or, without 4 GB free, add and remove the agent). After removing the agent, no `/etc/openvibes-agent`, no `/var/lib/openvibes-agent`, no `openvibes_agent` account.
  - Ports: move agent connections to 18500; `ss -ltn` shows 18500 and not 18423; the firewall matches.
  - Names: add a name; `openssl x509 -in /etc/openvibes/tls/ingest.crt -noout -ext subjectAltName` lists it, and ingest serves the new certificate.
  - Results go on the PR.
