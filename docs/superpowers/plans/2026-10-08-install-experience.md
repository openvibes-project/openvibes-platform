# Install Experience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new user installs the platform with Setup and adds hosts from the console without confusion: Setup shows progress at once and ends on a short, clear screen; hosts are added from the console's Enrollment page with a copyable command or a fully offline install package.

**Architecture:** Four parts that ship separately. **A** (platform, `openvibes-admin` TUI) fixes the Start freeze, the progress screen and the final screen, and drops the agent line from Setup. **B** (platform console) adds the copyable install command to Enrollment. **C** (install script repo + platform RPM) quiets the install output. **D** (offline install package) is a design step first: it touches the agent's release artefacts, the platform's packaging and the console, and has choices for the user; its own plan follows the design. **E** updates the quick-setup guide once A–C ship.

**Tech Stack:** Rust (ratatui TUI in `crates/openvibes-admin/src/tui`, axum console in `crates/openvibes-console`), React/TypeScript (console web), POSIX sh (`install.sh` in `openvibes-project.github.io`, `packaging/rpm/rename-account.sh`).

**Spec:** none written; this plan argues from the first manual install walkthrough (2026-10-08, released 0.2.5, lab `--bare`, the user driving): findings in the workspace `status.md` ("To do", item 1), decision in `decisions.md` ("Setup installs the platform; hosts are added from the console").

## Global Constraints

- The interface comes first: fast, uncluttered, clear (workspace `decisions.md`, design principles).
- Setup's screen stays usable at 80×24 (`setup_view.rs` header: "Draws the Setup tab at 80×24").
- Secrets: the generated admin password is shown once, on the final screen only; never in the step list, never in logs.
- `openvibes-admin agent command` stays (the lab and scripts use it: `openvibes-lab/lib/install.sh:166`).
- Root-only host changes stay in Setup/CLI; the console only shows and hands out what a host needs to enroll.
- Every component change updates its `docs/components/` page in the same change; PRs only after the `testing.md` gate.
- Commits end with `Co-Authored-By: Claude <noreply@anthropic.com>`.

## Review Focus

1. **A narrow terminal** (80×24, the minimum): the final screen's command, password and key path must stay readable and copyable, never cut mid-value (Task A3 test at 80×24).
2. **Setup started without the console component** (`--components ingest,agent`): the final screen must not promise a console URL or password (Task A3 test).
3. **A failed step after Start** (e.g. dnf fails offline): the immediate redraw must not hide the failure; the run stops at that step as today (Task A1 test).
4. **Repair/update/remove runs** reuse the finished screen: they keep listing every step's outcome (Task A3 keeps that branch, test unchanged).
5. **A console user without `tokens.create`** must not see the install command (it carries the standing token) (Task B1 test).

---

## Part A: Setup in the TUI (platform repo)

### Task A1: Start shows progress at once

**Files:** Modify `crates/openvibes-admin/src/tui/setup.rs` (`start_job`, `setup_tick`), `crates/openvibes-admin/src/tui/setup_view.rs` (`checklist`, keys); Test: `crates/openvibes-admin/src/tui/setup_tests.rs`.

**Cause:** the main loop (`tui/mod.rs:143`) handles Enter (which sets `Phase::Running(0)`) and then calls `setup_tick()` in the same turn, before the next draw, so `dnf install` runs while the form is still on screen.

**Interfaces:** Produces `SetupState.drawn: bool` (set false by `start_job`, true by `draw`); `setup_tick` returns without running when `!drawn`.

- [ ] **Step 1: Failing test** in `setup_tests.rs`:

```rust
#[test]
fn start_draws_the_checklist_before_the_first_step_runs() {
    let mut app = app(false, vec![Ok("written\n".into()), Ok("done\tinstalled\n".into())]);
    start(&mut app, "pw");
    // The turn that started the run must not run a step: the screen first.
    app.setup_tick();
    assert_eq!(app.setup.phase, Phase::Running(0));
    let text = screen(&app); // draws, which marks the screen drawn
    assert!(text.contains("Install packages") && text.contains("running"), "{text}");
    assert!(text.contains("can take a few minutes"), "{text}");
    app.setup_tick();
    assert_eq!(app.setup.phase, Phase::Running(1));
}
```

Run `cargo test -p openvibes-admin --bins start_draws_the_checklist` → FAIL (the first tick runs step 0).

- [ ] **Step 2: Implement.** In `start_job`: `self.setup.drawn = false;`. At the top of `setup_tick`: `if !self.setup.drawn { return; }` and, after each step, `self.setup.drawn = false;` so every step is drawn as "running…" before it blocks. In `setup_view::draw`: the view takes `&App`, so record drawing from the loop instead: in `tui/mod.rs`, after `terminal.draw(...)`, call `app.setup.drawn = true;`; the test helper `screen` does the same. In `checklist`, under the running step add one dim line: `Installing packages can take a few minutes (dnf downloads them).` when the running step is `Step::Packages` (the title list is `app.setup.job.titles()`; compare the step, not the text). While `Phase::Running(_)`, the footer is `RUNNING_KEYS = "Working: keys wait until this step ends  q quit after it"` (not `DONE_KEYS`).
- [ ] **Step 3: Run** the test and `cargo test -p openvibes-admin --bins` → PASS. Also assert in the test that the footer while running has no "uninstall".
- [ ] **Step 4: Commit** `setup: draw the checklist before a step blocks; say packages take minutes`.

### Task A2: The progress list keeps secrets and keys out

**Files:** `setup_view.rs` (`checklist`), tests.

- [ ] **Step 1: Failing test:** after the Console step returns the password detail (as in `rules_bring_distribution_and_the_finished_screen_shows_the_login`), while the run is still on a later step, `screen(&app)` must not contain `Abc123` and must contain `admin account ready (password on the last screen)`.
- [ ] **Step 2: Implement:** in `checklist`, for `Step::Console` with a `Done` state show `admin account ready (password on the last screen)` instead of the detail; other steps unchanged.
- [ ] **Step 3: Run, commit** `setup: the step list never shows the admin password`.

### Task A3: A short, clear final screen; no agent line

**Files:** `setup_view.rs` (`finished`), `crates/openvibes-admin/src/setup/run.rs:316` (Ready detail), `setup_tests.rs`, `crates/openvibes-admin/src/setup/run_tests.rs` (a new Ready-detail test), `docs/components/openvibes-admin.md`.

**Interfaces:** Produces `fn keep(states) -> Keep { console: Option<String>, password: Option<String>, root_key: Option<String>, relogin: Option<String> }`, parsed from the step details that the helper already sends (one parser per producer, each beside its producer's format and tested against it; unparsable → `None`, and the raw detail is shown instead, so a wording change degrades, never hides).

- [ ] **Step 1: Failing tests** (`setup_tests.rs`, 80×24):

```rust
#[test]
fn the_finished_screen_lists_what_to_keep_and_what_next() {
    let app = finished_app(); // install job finished with Console, Ca, Operators details
    let text = screen(&app);
    for want in [
        "Setup finished",
        "Console   https://platform.example.com",
        "Sign in   admin / Abc123",
        "Root key  /home/alice/openvibes-root-ca.key",
        "Next: sign in, change the password, then add hosts under Enrollment",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    assert!(!text.contains("curl"), "no agent line in Setup: hosts are added from the console");
    assert!(!text.contains('…'), "nothing cut at 80x24");
}

#[test]
fn without_the_console_the_finished_screen_promises_no_login() {
    let app = finished_app_without(Component::Console);
    let text = screen(&app);
    assert!(!text.contains("Sign in") && !text.contains("Enrollment"), "{text}");
}
```

`finished_app()` builds on `rules_bring_distribution_and_the_finished_screen_shows_the_login` (answers per step, `start`, ticks); the Ca answer is `"done\troot key saved to /home/alice/openvibes-root-ca.key: keep it offline; root certificate /etc/openvibes/pki/root.crt, SHA-256 AA:BB\n"`, the Operators answer `"done\talice added to openvibes-operators; log in again for it to take effect\n"`.

- [ ] **Step 2: Implement `finished` for `Job::Install`** as a few labelled rows, each value on its own line when it does not fit:

```
Setup finished. Write the password down: it is shown only now.

Console   https://platform.example.com
Sign in   admin / Abc123
Root key  /home/alice/openvibes-root-ca.key
          The only copy. Move it to offline storage, then delete it here.

Next: sign in, change the password, then add hosts under Enrollment.
alice can run openvibes-admin without sudo after logging in again.
```

Style: labels dim, the password bold. The root certificate fingerprint moves off this screen (the console and `openvibes-admin agent command` carry it where it is needed).
- [ ] **Step 3: Ready detail** (`run.rs:316`): `ready: {units}` only; delete the agent command and token text from it (the `agent_install_command` call goes; `agent command` keeps its own). No test asserts the agent line today: add one in `run_tests.rs` that a finished Ready step's detail contains no `curl` and no token.
- [ ] **Step 4: Run** `cargo test -p openvibes-admin` → PASS; **docs**: `openvibes-admin.md` Setup section (final screen, no agent line; `agent command` for scripts); **commit** `setup: a short final screen (console, sign-in, root key, next); hosts are added from the console`.

### Task A4: The form explains itself

**Files:** `setup_view.rs` (`form`), tests.

- [ ] **Step 1: Failing test:** at 80×24, with the cursor on the CA row the screen contains `quick: the root CA is made here and its key written once to the file below` and on the Root key row `the only copy of the root key; move it offline after Setup`; components that are always installed (`ingest`, `console`) render as `[•]` not `[x]`.
- [ ] **Step 2: Implement:** one help line under the form for the selected row (a `fn help(row) -> &'static str` table: each component, hostname, other names, CA, root key, console port, agent ports, Start: `Installs the ticked components; takes a few minutes`); always-on components drawn `[•]` (the `Component` already knows: its `about()` says "(always)"; add `Component::always()` and use it in both places).
- [ ] **Step 3: Run, commit** `setup: the form says what each field means`.

## Part B: Console Enrollment (platform repo)

### Task B1: Copyable install command beside the install package

**Files:** `crates/openvibes-console/src/agent_package.rs` (`pub fn command(spec) -> Result<String, PackageError>`, sharing `installer_args` with the token inline), `crates/openvibes-console/src/router.rs` (route `GET /api/v1/agent-command`, same auth as `/api/v1/agent-package`: `tokens.create`), `api.rs` (`AgentCommandView { command: String, standing_token_note: String }`), OpenAPI snapshot + `generated.ts`, `web/src/views/Admin.tsx` (`Enrollment`), demo server, a new test file `crates/openvibes-console/tests/agent_command_http.rs` (modelled on `alarms_http.rs`: an admin and a viewer session; no HTTP test covers `/api/v1/agent-package` today, so add one for it there too), `docs/components/console-web.md`, `openvibes-console.md`.

- [ ] **Step 1: Failing tests:** HTTP: with a standing token, `GET /api/v1/agent-command` as an admin returns a command starting `curl -fsSL https://openvibes-project.github.io/install.sh | sudo sh -s -- --agent --platform ` and containing `--ca-sha256 `; as a viewer (no `tokens.create`) → 403. Unit (`agent_package.rs`): `command()` equals `openvibes-admin agent command`'s output for the same inputs (copy the expected line from `crates/openvibes-admin/src/setup/command_tests.rs`).
- [ ] **Step 2: Implement** the endpoint and, on Enrollment, a section above the token table: "Add a host" with the command in the wrapped code block + copy button (the `code code--wrap` + `icon-button` pattern from `AgentPanel.tsx` `ThreatAlarms`), the install package download beside it, and one line: "Run it as root on the new host. It carries the standing token: anyone with it can enroll a host."
- [ ] **Step 3: Gate** (`testing.md` §2, regenerate the API snapshot), demo e2e, look at it in Firefox (desktop + phone); **commit** `console: Enrollment shows the install command to copy`.

## Part C: Quieter install output

### Task C1: No PostgreSQL warning on a fresh install (platform repo)

**Files:** `packaging/rpm/rename-account.sh` (line 20–24), its test `scripts/test-rename-account.sh`.

- [ ] **Step 1: Failing test** in `test-rename-account.sh`: with no `postgres` user and no `psql` on PATH, the script prints nothing and exits 0.
- [ ] **Step 2: Implement:** before the `psql` call: `command -v psql >/dev/null 2>&1 && id postgres >/dev/null 2>&1 || exit 0` (no PostgreSQL here: nothing to rename). The warning stays for a PostgreSQL that exists but cannot be reached.
- [ ] **Step 3: Run** `bash scripts/test-rename-account.sh`; **commit** `rpm: no rename warning where PostgreSQL is not installed`.

### Task C2: install.sh shows steps, not dnf's scriptlets (openvibes-project.github.io repo)

**Files:** `install.sh` (lines 154–158, 189), its tests in `tests/`.

- [ ] **Step 1:** `say "Installing openvibes-admin (a minute or two)…"` then `dnf install -y -q openvibes-admin`; the same for the agent at line 189. dnf `-q` still prints errors. Test (existing `tests/` style, stubbed `dnf`): the script calls `dnf install -y -q`.
- [ ] **Step 2:** run the repo's tests; **commit**; PR in that repo.

## Part D: Fully offline install package (design first)

The user wants the console's install package to need no internet on the host, only a route to the platform. Today the package (`agent_package.rs::render`) is a script that fetches `install.sh` from GitHub and the agent from the package repository.

**Shape (user, 2026-10-08):** one installer script, the same everywhere; one settings file per platform; one native agent package per distribution.

- **Installer script:** generic, versioned with the agent, no secrets. It detects the distribution, installs the package beside it (or fetches it from the platform), writes the settings, and enrolls.
- **Settings file** (per platform): platform URL and ports, the root certificate itself (not only its fingerprint, so a fully offline host needs no first contact to trust it), the rule-set trust lines, and the enrollment token. The token is a secret: the script installs it readable by root only, and the agent drops it once enrolled. The console warns that the file can enroll hosts.
- **Agent package per distribution:** the normal signed release artefacts (RPM today; `.deb` and an Arch package to be built and released by the agent repository). Checksums and signatures are verified by the script; updates go through the distribution's package manager, a local mirror, or config management.
- **Console:** Enrollment offers one download per distribution, an archive holding the script, the settings file and that package. The one-line command fetches the same pieces from the platform (distribution port, CA pinned), never from the internet.

Still to settle in the design session: where the platform gets the packages (shipped with a platform package, or fetched once by Setup), the settings file format (TOML, so the agent can read it as is, or shell variables), how offline hosts receive agent updates, and the build and release of `.deb` and Arch packages (agent repository; this also retires the lab's `guest/agent-generic.sh` stand-in). Then this part gets its own plan.

## Part E: Quick-setup guide

### Task E1: docs/quick-setup.md matches what a user sees

After A–C: remove the "Draft… no packages until v0.1.0" note and the "(not yet run)" marks (the walkthrough ran it), describe the new final screen, and replace "the last screen shows… the command that installs an agent" with "add hosts from the console: Enrollment → Add a host". Commit `docs: quick setup after the first real walkthrough`.

---

## Order

A1, A2, A3, A4 (one platform PR), B1 (platform PR; can run beside A), C1 (with A or B), C2 (site PR), E1 (with the last of them). D: design session with the user, then its own plan. Afterwards, a second walkthrough in the lab (`--bare`, the user driving) to check the result.
