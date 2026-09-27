# Admin TUI PR 1: host library and Services screen — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (native) or superpowers:subagent-driven-development. Steps use checkboxes.

**Goal:** Plain `openvibes-admin` opens a TUI whose Services screen shows the OpenVIBES units and lets an operator (group `openvibes-operators`) start, stop and restart them and read their logs, without a password.

**Architecture:** A new crate `platform-host` holds the host operations behind a `Host` trait (`Native` for systemd, a fake for tests); every command goes through one `Runner` with fixed argument vectors. `openvibes-admin` gains `src/tui/` (ratatui) and a hidden root-only `helper` subcommand (verb `logs` in this PR). The RPM adds the group, a polkit rule for start/stop/restart of the allow-listed units, and a sudoers drop-in for `helper logs` and for running `openvibes-admin` as `openvibes-admin`.

**Tech Stack:** Rust (ratatui 0.30 with its crossterm backend, clap), polkit JavaScript rules, sudoers, systemd, bash e2e.

**Spec:** `docs/specs/2026-09-27-admin-tui-design.md` (§3 users and privileges, §4 architecture, §5 Services, §11 failure behaviour, §12 testing, §13 PR 1).

## Global Constraints

- The TUI runs as the invoking user; no network listener; keyboard only; usable at 80×24; state is written as text, not colour alone.
- Allow-listed units only: `openvibes-ingest.service`, `openvibes-distribution.service`, `openvibes-vulns.service`, `openvibes-llm.service`, `openvibes-maintenance.timer`. `Unit` is an enum; no free-form unit names anywhere.
- Commands are argument vectors with absolute program paths (`/usr/bin/systemctl`, `/usr/bin/sudo`, `/usr/bin/openvibes-admin`, `/usr/bin/journalctl`, `/usr/bin/logger`); never a shell string.
- Operators: group `openvibes-operators` (sysusers `g`). Password-free rights in this PR: polkit `manage-units` for start/stop/restart of the allow-list; sudoers `helper logs` as root and `openvibes-admin` as `openvibes-admin`.
- Enable/disable are **not** offered in PR 1: systemd's `manage-unit-files` polkit action carries no unit name, so it cannot be restricted to the allow-list; they become password-prompted privileged steps in PR 4 (spec amended in Task 4).
- `helper` refuses unless the effective uid is 0 (read from `/proc/self/status`, no `unsafe`).
- Every action is logged to the journal via `logger -t openvibes-admin` with the user, uid, unit, action and outcome.
- New dependency: `ratatui = "0.30"` (default features, crossterm backend) in `openvibes-admin` only; `cargo audit` stays clean.
- Files under 500 lines; `docs/components/platform-host.md` new, `openvibes-admin.md` and `README.md` index updated; commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Build with `CARGO_NET_GIT_FETCH_WITH_CLI=true`; test DB via `eval "$(scripts/test-db.sh)"`.

## Review Focus

- Not an operator (not in the group): actions fail with a message naming the group, not a raw polkit or sudo error (Task 1 test on error mapping; Task 4 e2e as a non-member).
- A unit that is not installed (llm, distribution optional): shown as "not installed", with no actions offered (Task 1 parse test; Task 3 snapshot).
- Terminal smaller than 80×24, or stdout not a terminal (`openvibes-admin | cat`, cron): a clear message, no garbled screen, exit non-zero when not a terminal (Task 3 tests).
- A panic or Ctrl-C inside the TUI: the terminal is restored (raw mode off, alternate screen left) (Task 3 test of the guard).
- `helper logs` with a unit outside the allow-list, a line count of 0 or 100000, or run without root: refused (Task 2 tests; Task 4 e2e).

---

### Task 1: `platform-host` crate

**Files:**
- Create: `crates/platform-host/Cargo.toml`, `src/lib.rs` (types, `Host`, `HostError`), `src/runner.rs` (`Runner`, `SystemRunner`), `src/native.rs` (`Native`), `src/unit.rs` (`Unit`), `tests/native.rs` (with a `FakeRunner`)
- Modify: `Cargo.toml` (workspace member)

**Interfaces — Produces:**

```rust
// unit.rs
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Unit { Ingest, Distribution, Vulns, Llm, Maintenance }
impl Unit {
    pub const ALL: [Unit; 5];
    pub fn name(self) -> &'static str;          // "openvibes-ingest.service", …, "openvibes-maintenance.timer"
    pub fn label(self) -> &'static str;         // "ingest", "distribution", "vulns", "llm", "maintenance"
    pub fn ready_url(self) -> Option<&'static str>; // http://127.0.0.1:18480/ready, 18481, 18483, 18430/health, None
    pub fn parse(name: &str) -> Option<Unit>;   // exact name() match only
}
// lib.rs
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceAction { Start, Stop, Restart }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceStatus {
    pub unit: Unit,
    pub installed: bool,
    pub enabled: bool,
    pub active: String,      // "active", "inactive", "failed", "activating", …
    pub ready: Option<bool>, // None when the unit has no readiness endpoint or is not active
    pub since: Option<String>,
}
#[derive(Debug, Eq, PartialEq)]
pub enum HostError { NotOperator, Failed(String), Io(String) }
pub trait Host {
    fn services(&self) -> Result<Vec<ServiceStatus>, HostError>;
    fn service_action(&self, unit: Unit, action: ServiceAction) -> Result<(), HostError>;
    fn logs(&self, unit: Unit, lines: u16) -> Result<Vec<String>, HostError>;
}
// runner.rs
pub struct Output { pub status: i32, pub stdout: String, pub stderr: String }
pub trait Runner { fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output>; }
pub struct SystemRunner; // std::process::Command, no shell, stdin null
// native.rs
pub struct Native<R: Runner> { pub runner: R }
impl<R: Runner> Host for Native<R> { … }
```

- [ ] **Step 1:** Create the crate (no dependencies) with the types above and `impl Host for Native` whose three methods are `unimplemented!()`, so the tests compile and fail. Write `tests/native.rs`:

```rust
use std::cell::RefCell;
use platform_host::{Host, HostError, ServiceAction, Unit, native::Native, runner::{Output, Runner}};

/// Answers from a script of (program, args prefix) -> Output and records every call.
struct FakeRunner { calls: RefCell<Vec<Vec<String>>>, answers: Vec<(Vec<&'static str>, Output)> }
impl Runner for FakeRunner {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output> {
        let mut call = vec![program.to_owned()];
        call.extend(args.iter().map(|a| (*a).to_owned()));
        self.calls.borrow_mut().push(call.clone());
        for (prefix, out) in &self.answers {
            if call.iter().zip(prefix).all(|(a, b)| a == b) && call.len() >= prefix.len() {
                return Ok(Output { status: out.status, stdout: out.stdout.clone(), stderr: out.stderr.clone() });
            }
        }
        Ok(Output { status: 1, stdout: String::new(), stderr: "unexpected call".into() })
    }
}
fn out(status: i32, stdout: &str, stderr: &str) -> Output {
    Output { status, stdout: stdout.into(), stderr: stderr.into() }
}
fn fake(answers: Vec<(Vec<&'static str>, Output)>) -> Native<FakeRunner> {
    Native { runner: FakeRunner { calls: RefCell::new(Vec::new()), answers } }
}

#[test]
fn services_parse_systemctl_show() {
    // systemctl show prints one block per unit, separated by a blank line, in argument order.
    let show = "Id=openvibes-ingest.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\nActiveEnterTimestamp=Sun 2026-09-27 10:00:00 UTC\n\n\
                Id=openvibes-distribution.service\nLoadState=not-found\nActiveState=inactive\nUnitFileState=\nActiveEnterTimestamp=\n\n\
                Id=openvibes-vulns.service\nLoadState=loaded\nActiveState=failed\nUnitFileState=enabled\nActiveEnterTimestamp=\n\n\
                Id=openvibes-llm.service\nLoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\nActiveEnterTimestamp=\n\n\
                Id=openvibes-maintenance.timer\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\nActiveEnterTimestamp=Sun 2026-09-27 09:00:00 UTC\n";
    let host = fake(vec![
        (vec!["/usr/bin/systemctl", "show"], out(0, show, "")),
        (vec!["/usr/bin/curl", "--silent", "--fail", "--max-time", "1", "--output", "/dev/null", "http://127.0.0.1:18480/ready"], out(0, "", "")),
    ]);
    let services = host.services().unwrap();
    assert_eq!(services[0].ready, Some(true));
    assert_eq!(services[2].ready, None, "not active: not probed");
    assert_eq!(services.len(), 5);
    assert_eq!((services[0].unit, services[0].installed, services[0].enabled, services[0].active.as_str()), (Unit::Ingest, true, true, "active"));
    assert!(!services[1].installed, "not-found means not installed");
    assert_eq!(services[2].active, "failed");
    assert_eq!(services[4].since.as_deref(), Some("Sun 2026-09-27 09:00:00 UTC"));
    let calls = host.runner.calls.borrow();
    assert_eq!(calls[0][..3], ["/usr/bin/systemctl", "show", "--property=Id,LoadState,ActiveState,UnitFileState,ActiveEnterTimestamp"]);
    assert_eq!(calls[0][3..], Unit::ALL.map(|u| u.name().to_owned()));
}

#[test]
fn actions_are_exact_argument_vectors() {
    let host = fake(vec![(vec!["/usr/bin/systemctl"], out(0, "", "")), (vec!["/usr/bin/logger"], out(0, "", ""))]);
    host.service_action(Unit::Vulns, ServiceAction::Restart).unwrap();
    let calls = host.runner.calls.borrow();
    assert_eq!(calls[0], ["/usr/bin/systemctl", "--no-ask-password", "restart", "openvibes-vulns.service"]);
    assert_eq!(calls[1][..3], ["/usr/bin/logger", "-t", "openvibes-admin"]);
    assert!(calls[1][3].contains("restart openvibes-vulns.service ok"), "{:?}", calls[1]);
}

#[test]
fn polkit_refusal_names_the_group() {
    let host = fake(vec![
        (vec!["/usr/bin/systemctl"], out(1, "", "Failed to restart openvibes-vulns.service: Access denied\n")),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    assert_eq!(host.service_action(Unit::Vulns, ServiceAction::Restart), Err(HostError::NotOperator));
}

#[test]
fn logs_go_through_the_helper() {
    let host = fake(vec![(vec!["/usr/bin/sudo"], out(0, "line one\nline two\n", ""))]);
    assert_eq!(host.logs(Unit::Ingest, 50).unwrap(), ["line one", "line two"]);
    assert_eq!(host.runner.calls.borrow()[0],
        ["/usr/bin/sudo", "-n", "/usr/bin/openvibes-admin", "helper", "logs", "openvibes-ingest.service", "50"]);
    let denied = fake(vec![(vec!["/usr/bin/sudo"], out(1, "", "sudo: a password is required\n"))]);
    assert_eq!(denied.logs(Unit::Ingest, 50), Err(HostError::NotOperator));
}

#[test]
fn unit_names_round_trip_and_nothing_else_parses() {
    for unit in Unit::ALL { assert_eq!(Unit::parse(unit.name()), Some(unit)); }
    for bad in ["sshd.service", "openvibes-ingest", "openvibes-ingest.service ", "../openvibes-ingest.service"] {
        assert_eq!(Unit::parse(bad), None, "{bad}");
    }
}
```

- [ ] **Step 2:** `cargo test -q -p platform-host` → FAIL (unimplemented / missing items).
- [ ] **Step 3:** Implement:
  - `services`: one `systemctl show --property=… UNITS…` call; split stdout on blank lines; map `Id` to `Unit::parse`; `installed = LoadState != "not-found"`; `enabled = UnitFileState == "enabled"`; `since` = non-empty `ActiveEnterTimestamp` when active. Readiness, through the runner so tests stay offline: for active units with `ready_url()`, `/usr/bin/curl --silent --fail --max-time 1 --output /dev/null URL`; `ready = Some(status == 0)`. Mark with `// ponytail: default ports; read them from each service's config once the Configuration screen (PR 2) parses configs.` (`curl` is in every Fedora install; add `Requires: curl` to `openvibes-admin` in Task 2.)
  - `service_action`: `systemctl --no-ask-password VERB NAME`; then `logger -t openvibes-admin "user=$USER uid=$UID VERB NAME ok|failed"` (user from `$USER`, uid from `/proc/self/status`); map stderr containing `Access denied` or `Interactive authentication required` to `NotOperator`, other non-zero to `Failed(stderr trimmed, control characters escaped)`.
  - `logs`: `sudo -n /usr/bin/openvibes-admin helper logs NAME LINES`; stderr containing `password is required` or `not allowed` → `NotOperator`.
  - `HostError` `Display`: `NotOperator` → "this needs membership of the openvibes-operators group (ask an administrator: usermod -aG openvibes-operators $USER, then log in again)".
- [ ] **Step 4:** `cargo test -q -p platform-host` → PASS; clippy clean.
- [ ] **Step 5:** `docs/components/platform-host.md` (purpose, interfaces, the allow-list, failure behaviour, how to test) and a line in `docs/components/README.md`. Commit `platform-host: Host trait, Native systemd backend`.

### Task 2: `helper logs` and the RPM's operator rights

**Files:**
- Create: `crates/openvibes-admin/src/helper.rs`, `crates/openvibes-admin/tests/helper.rs`
- Modify: `crates/openvibes-admin/src/main.rs` (hidden `Helper` subcommand, dispatched before config/database loading), `crates/openvibes-admin/Cargo.toml` (`platform-host`)
- Create: `packaging/rpm/openvibes-operators.polkit.rules`, `packaging/rpm/openvibes-operators.sudoers`
- Modify: `packaging/rpm/openvibes-admin.sysusers` (+ `g openvibes-operators -`), `packaging/rpm/openvibes-platform.spec` (install both files in `openvibes-admin`; `Requires: sudo polkit`), `scripts/check-rpm.sh`

- [ ] **Step 1:** `tests/helper.rs` (runs the binary as the test user, who is not root):

```rust
//! `openvibes-admin helper`: root-only verbs with closed arguments.
#![allow(clippy::disallowed_types)]
use std::process::Command;
fn helper(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_openvibes-admin")).arg("helper").args(args).output().unwrap()
}
#[test]
fn refuses_without_root() {
    let out = helper(&["logs", "openvibes-ingest.service", "10"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("helper must run as root"));
}
#[test]
fn refuses_units_outside_the_allow_list_and_bad_counts_before_anything_else() {
    for args in [["logs", "sshd.service", "10"], ["logs", "openvibes-ingest.service", "0"], ["logs", "openvibes-ingest.service", "100000"], ["logs", "openvibes-ingest.service", "x"]] {
        let out = helper(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("not allowed"), "{args:?}");
    }
}
#[test]
fn unknown_verbs_are_refused() {
    assert_eq!(helper(&["shell"]).status.code(), Some(2));
}
```

- [ ] **Step 2:** `cargo test -q -p openvibes-admin --test helper` → FAIL (no `helper` subcommand).
- [ ] **Step 3:** `helper.rs`: clap `HelperCommand::Logs { unit: String, lines: String }` (`#[command(hide = true)]` on `Helper`). Validate first: `Unit::parse(&unit)` and `lines.parse::<u16>()` in `1..=500`, else print `helper: not allowed: …` and exit 2. Then require root: parse `/proc/self/status` `Uid:` line, second field (effective) `== "0"`, else `helper must run as root` exit 1. Then exec `/usr/bin/journalctl -u NAME -n LINES -o short-iso --no-pager` (plain `Command`, inherit stdout). In `main.rs`, handle `Command::Helper` right after parsing, before any config or database access.
- [ ] **Step 4:** RPM files:

```js
// packaging/rpm/openvibes-operators.polkit.rules → /usr/share/polkit-1/rules.d/50-openvibes-operators.rules
// Members of openvibes-operators may start, stop and restart the OpenVIBES
// units without a password (admin TUI spec §3). Nothing else.
polkit.addRule(function (action, subject) {
    if (action.id != "org.freedesktop.systemd1.manage-units" ||
        !subject.isInGroup("openvibes-operators")) {
        return polkit.Result.NOT_HANDLED;
    }
    var units = ["openvibes-ingest.service", "openvibes-distribution.service",
                 "openvibes-vulns.service", "openvibes-llm.service",
                 "openvibes-maintenance.timer"];
    var verbs = ["start", "stop", "restart"];
    if (units.indexOf(action.lookup("unit")) >= 0 && verbs.indexOf(action.lookup("verb")) >= 0) {
        return polkit.Result.YES;
    }
    return polkit.Result.NOT_HANDLED;
});
```

```
# packaging/rpm/openvibes-operators.sudoers → /etc/sudoers.d/openvibes-operators (0440 root:root)
# Operators run the admin CLI as its service account (database work) and the
# root helper's fixed verbs, which check their own arguments (admin TUI §3).
%openvibes-operators ALL=(openvibes-admin) NOPASSWD: /usr/bin/openvibes-admin
%openvibes-operators ALL=(root) NOPASSWD: /usr/bin/openvibes-admin helper logs *
```

In the spec: install with `install -D -m 0644 …polkit.rules %{buildroot}%{_datadir}/polkit-1/rules.d/50-openvibes-operators.rules` and `install -D -m 0440 …sudoers %{buildroot}%{_sysconfdir}/sudoers.d/openvibes-operators`; `%files -n openvibes-admin`: `%{_datadir}/polkit-1/rules.d/50-openvibes-operators.rules` and `%config(noreplace) %attr(0440, root, root) %{_sysconfdir}/sudoers.d/openvibes-operators`; `Requires: sudo polkit curl`. `check-rpm.sh`: `getent group openvibes-operators`, `visudo -cf /etc/sudoers.d/openvibes-operators`, the rules file exists.
- [ ] **Step 5:** `cargo test -q -p openvibes-admin --test helper` → PASS; `visudo -cf packaging/rpm/openvibes-operators.sudoers` → parsed OK. Commit `Admin: root helper (logs); operators group, polkit rule, sudoers`.

### Task 3: The TUI and its Services screen

**Files:**
- Create: `crates/openvibes-admin/src/tui/mod.rs` (terminal setup, guard, event loop), `src/tui/app.rs` (state, key handling), `src/tui/services.rs` (rendering), `src/tui/tests.rs` (unit tests: the crate is a binary, so the tests live beside the code)
- Modify: `crates/openvibes-admin/src/main.rs` (`mod tui;`, `command: Option<Command>`; `None` → TUI), `crates/openvibes-admin/Cargo.toml` (`ratatui = "0.30"`)

**Interfaces:**
- Consumes: Task 1 `Host`, `ServiceStatus`, `ServiceAction`, `Unit`, `HostError`.
- Produces:

```rust
pub struct App<H: Host> { pub host: H, pub services: Vec<ServiceStatus>, pub selected: usize,
                          pub confirm: Option<(Unit, ServiceAction)>, pub message: Option<String>,
                          pub logs: Vec<String>, pub quit: bool }
impl<H: Host> App<H> {
    pub fn new(host: H) -> Self;            // loads services and the first unit's logs
    pub fn key(&mut self, key: char);       // j/k or arrows (mapped by the loop), s start, t stop, r restart, y/n confirm, R refresh, q quit
}
pub fn render<H: Host>(frame: &mut ratatui::Frame, app: &App<H>);
```

- [ ] **Step 1:** `src/tui/tests.rs` (`#[cfg(test)] mod tests;` in `tui/mod.rs`) with a `FakeHost` (records actions; returns fixed statuses: ingest active+ready, distribution not installed, vulns failed, llm inactive, maintenance timer active):
  - `renders_services_at_80x24`: `ratatui::backend::TestBackend::new(80, 24)`, `Terminal::draw(|f| render(f, &app))`; the buffer text contains `ingest`, `active`, `ready`, `distribution`, `not installed`, `vulns`, `failed`, the key line `s start  t stop  r restart  R refresh  q quit`, and the first log line.
  - `restart_asks_first`: `key('r')` on vulns → `confirm == Some((Vulns, Restart))`, rendered text contains `Restart openvibes-vulns.service? y/n`; `key('n')` → no action recorded; `key('r'); key('y')` → exactly one `(Vulns, Restart)` recorded and services reloaded.
  - `not_installed_offers_nothing`: select distribution, `key('s')` → no confirm, message `not installed`.
  - `not_an_operator_is_explained`: FakeHost returns `NotOperator` → message contains `openvibes-operators`.
  - `too_small`: `TestBackend::new(60, 20)` → text contains `needs at least 80×24`.
- [ ] **Step 2:** `cargo test -q -p openvibes-admin --bin openvibes-admin tui` → FAIL.
- [ ] **Step 3:** Implement `app.rs` and `services.rs` (a table: unit, installed/enabled, state, ready, since; below it the selected unit's last 50 log lines; bottom: key help and `message`). `mod.rs`: refuse with `openvibes-admin: the administration TUI needs a terminal; run a subcommand (see --help)` and exit 2 when `!std::io::stdout().is_terminal()`; otherwise `ratatui::init()` / `ratatui::restore()` in a guard struct whose `Drop` restores (and a panic hook via `ratatui::init`'s default); loop: poll events 250 ms, map arrows to `j`/`k`, refresh every 5 s. `main.rs`: `command: Option<Command>`; `None` → `tui::run(Native { runner: SystemRunner })`, before loading any config (the Services screen needs no database).
- [ ] **Step 4:** `cargo test -q -p openvibes-admin` → PASS (all admin tests; existing subcommand tests unchanged); clippy clean; `cargo audit` clean; `wc -l` < 500 per file.
- [ ] **Step 5:** Docs: `openvibes-admin.md` gains "Administration TUI": how to open it, who can use it (operators), the Services keys, what is not offered yet (enable/disable in PR 4). Commit `Admin: TUI with the Services screen`.

### Task 4: End to end as an operator; spec amendment

**Files:**
- Modify: `scripts/systemd-e2e.sh` (image adds `polkit sudo`), `docs/specs/2026-09-27-admin-tui-design.md` (§3 table: enable/disable are privileged steps; §13 PR 1 wording)

- [ ] **Step 1:** In `systemd-e2e.sh`, after the vulns checks (section 7), add:

```bash
# 7c. Operators (admin TUI PR 1): a member of openvibes-operators restarts a
# unit through polkit and reads its log through the helper, without a
# password; a non-member cannot, and the helper refuses other units.
in_c 'useradd -m -G openvibes-operators alice && useradd -m bob' || fail "operator users"
in_c 'systemctl start polkit' >/dev/null 2>&1 || true
in_c 'runuser -u alice -- systemctl --no-ask-password restart openvibes-vulns.service' || fail "operator restart through polkit"
wait_for "vulns ready after the operator's restart" 30 'curl -fsS http://127.0.0.1:18483/ready'
in_c 'runuser -u bob -- systemctl --no-ask-password restart openvibes-vulns.service' 2>/dev/null && fail "a non-operator restarted a unit"
in_c 'runuser -u alice -- systemctl --no-ask-password restart sshd.service' 2>/dev/null && fail "an operator restarted a unit outside the allow-list"
in_c 'runuser -u alice -- sudo -n /usr/bin/openvibes-admin helper logs openvibes-vulns.service 5' | grep -q . || fail "operator log read"
in_c 'runuser -u alice -- sudo -n /usr/bin/openvibes-admin helper logs sshd.service 5' 2>/dev/null && fail "helper read a unit outside the allow-list"
in_c 'runuser -u bob -- sudo -n /usr/bin/openvibes-admin helper logs openvibes-vulns.service 5' 2>/dev/null && fail "a non-operator read logs"
in_c 'journalctl -t openvibes-admin -o cat | grep -q .' || true
ok "operators restart units and read logs without a password; others cannot"
```

(The e2e cannot drive the full-screen TUI; the screen is covered by Task 3's snapshots. It checks the rights the TUI relies on, exactly as the TUI calls them.)
- [ ] **Step 2:** Run locally if podman and the CI RPMs are at hand (`gh run download` the `rpms` artifact of the branch's run), else rely on CI → all `ok`.
- [ ] **Step 3:** Spec §3 table: service lifecycle row says start, stop, restart; add "Enable and disable are privileged steps (password): systemd's `manage-unit-files` polkit action does not name the unit, so it cannot be limited to OpenVIBES units." §13 PR 1: "start, stop, restart".
- [ ] **Step 4:** Commit `E2E: operators through polkit and the helper; spec: enable/disable are privileged`; push; open PR "Admin TUI PR 1: Services screen, operators".
