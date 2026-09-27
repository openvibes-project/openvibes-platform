# Admin TUI PR 4: Setup install — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (native) or superpowers:subagent-driven-development. Steps use checkboxes.

**Goal:** From a host with only `openvibes-admin` installed, the TUI's Setup tab (or `openvibes-admin setup --quick` as root) installs the chosen components and takes the host through PostgreSQL, database, schema, CA, server certificates, console and admin account, services, firewall, baseline rules, the local agent and readiness, one resumable step at a time.

**Architecture:** `platform-host` gains the closed list of Setup steps (`Step`), their states (`StepState`), the password a Setup run holds (`Secret`), the password-gated helper verbs (`Privileged`) and `Host::privileged`, which runs `sudo -S -k -p '' openvibes-admin helper VERB` with the password on stdin. The root side lives in `openvibes-admin/src/setup/`: `plan.rs` (`/etc/openvibes/setup.toml`), `system.rs` (`Ctx`: commands through `platform_host::runner::Runner`, files under a root directory so tests use a temp dir), and one module per group of steps. Each step has a `check` (is it done?) and an `apply` (do it); `run_step` checks and applies only when needed, so every step is safe to re-run. The helper verbs `setup-plan`, `setup-status`, `setup-step`, `unit-enable`, `unit-disable` and the root CLI `setup --quick` call the same functions. The TUI gets a Setup tab (form, password prompt, one step per event-loop tick, stop and retry) and the Services screen gets enable/disable at boot.

**Tech Stack:** Rust (ratatui 0.30, clap, toml 1.1, toml_edit 0.25, zeroize 1.9, ring, platform-pki), dnf5, systemd, firewalld, bash e2e (podman, systemd as PID 1).

**Spec:** `docs/specs/2026-09-27-admin-tui-design.md` (§3 privileged steps and Setup's verbs, §4 `Host`, §6.1–6.3 and §6.6 Setup, §11 failure behaviour, §12 testing, §13 PR 4).

## Global Constraints

- Steps, in order: `packages`, `postgres`, `operators`, `database`, `schema`, `ca`, `certificates`, `console`, `services`, `firewall`, `rules`, `agent`, `ready` (`Step` enum; no other name can be expressed).
- Components (`Component`, clap and TOML name in brackets): Ingest (`ingest`), Console (`console`), Distribution (`distribution`), Vulns (`vulns`), Assistant (`assistant`), Rules (`rules`), Agent (`agent`). `--components` must include `ingest`; `rules` needs `distribution`. The TUI always includes ingest and console.
- Packages: ingest → `openvibes-ingest openvibes-admin`; console → `openvibes-console`; distribution → `openvibes-distribution`; vulns → `openvibes-vulns`; assistant → `openvibes-llm`; rules → `openvibes-rules-baseline` (its own step); agent → `openvibes-agent` (its own step). Signature checks stay on: `--nogpgcheck` is never passed; local files get `--setopt=localpkg_gpgcheck=1` unless `--allow-unsigned-local`.
- `/etc/openvibes/setup.toml` (mode 0644, `deny_unknown_fields`) holds the plan; it is written only from checked arguments. Hostname and addresses: lowercase DNS names (labels 1–63 of `a-z0-9-`, no leading or trailing `-`, at most 253 characters, last label not all digits) or IP addresses; at most 16 `--san`. Paths must be absolute.
- The password is sent only on sudo's stdin (`sudo -S -k -p ''`), never in argv, the journal, `setup.toml` or step output; it is held in `Secret` (`zeroize`) for one Setup run and dropped when the run finishes, stops or fails. Three wrong passwords close the prompt.
- Password-gated verbs (`setup-plan`, `setup-status`, `setup-step`, `unit-enable`, `unit-disable`) have no sudoers entry: they run only with the user's own sudo rights. They check their arguments before the root check, like the existing verbs.
- CA files: root certificate `/etc/openvibes/pki/root.crt` (0644), intermediate `/etc/openvibes/pki/intermediate.crt` (0644), intermediate key `/var/lib/openvibes-ingest/intermediate.key` (0600 openvibes-ingest). Staging only in `/run/openvibes-ca` (tmpfs, 0700 openvibes-admin), removed after use. The root key is written only to `--root-key-out` (0600, never overwriting an existing file), otherwise deleted.
- Server certificates: ingest `/etc/openvibes/tls/ingest.{crt,key}` (key 0600 openvibes-ingest), distribution `/etc/openvibes/tls/distribution.{crt,key}` (key 0600 openvibes-distribution), console `/etc/openvibes/tls/console-chain.pem` and `console-key.pem` (both 0640 root:openvibes-console, chain = certificate then intermediate). Names: hostname, then each `--san`, then `localhost` and `127.0.0.1` (for an agent on this host), without duplicates.
- Helper output: `setup-step` prints one line `STATE<TAB>DETAIL`; `setup-status` prints `STEP<TAB>STATE<TAB>DETAIL` per step. States: `done`, `todo`, `waiting`, `skipped`, `failed`. Details are one line (control characters replaced by spaces).
- `std::process::Command` only in `SystemRunner` and the helper's `logs` (clippy `disallowed_types`); every Setup command goes through `Runner` with a fixed argument vector, never a shell.
- Files under 500 lines; component docs updated in the same task; commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Gate: `testing.md` §2 in this worktree, plus §3 (Fedora job) because `scripts/systemd-e2e.sh` changes.

## Review Focus

- A step that failed half-way is run again: a stale `/run/openvibes-ca` from the failed CA run must not block the retry, and nothing already installed is redone (Task 5 `a_stale_staging_directory_is_replaced`; Task 3 `a_done_step_is_not_run_again`).
- The chosen root key file already exists (an old key on the USB stick): it is never overwritten; the step fails and says so before any CA material is created (Task 5 `an_existing_root_key_file_is_not_overwritten`).
- Wrong password during the plan write or in the middle of a run, and three wrong passwords: nothing runs, the prompt says why, the run resumes at the same step (Task 10 `wrong_password_mid_run_asks_again_and_resumes`, `three_wrong_passwords_close_the_prompt`).
- A local package folder holding `openvibes-llm` and `openvibes-llm-vulkan`, or two versions of one package: the right file is chosen or a clear error names the package (Task 3 `local_packages_pick_the_exact_name_and_refuse_duplicates`).
- The password never appears in argv, the journal or the screen (Task 1 `privileged_verbs_pass_the_password_on_stdin_only`; Task 10 `the_password_is_masked`).

---

### Task 1: `platform-host`: steps, states, secret, privileged verbs

**Files:**
- Create: `crates/platform-host/src/setup.rs`
- Modify: `crates/platform-host/{Cargo.toml,src/lib.rs,src/runner.rs,src/native.rs,tests/native.rs}`, `crates/openvibes-admin/src/tui/tests.rs` (FakeHost gains the new trait methods), `docs/components/platform-host.md`

**Interfaces — Produces:**

```rust
// setup.rs
pub const SETUP_FILE: &str = "/etc/openvibes/setup.toml";
pub enum Step { Packages, Postgres, Operators, Database, Schema, Ca, Certificates, Console, Services, Firewall, Rules, Agent, Ready }
impl Step { pub const ALL: [Step; 13]; pub fn name(self) -> &'static str; pub fn title(self) -> &'static str; pub fn parse(name: &str) -> Option<Step>; }
pub enum StepState { Done(String), Todo, Waiting(String), Skipped(String), Failed(String) }
impl StepState { pub fn line(&self) -> String; pub fn parse(line: &str) -> Option<StepState>; pub fn finished(&self) -> bool; pub fn label(&self) -> &'static str; pub fn detail(&self) -> &str; }
pub struct Secret(/* Zeroizing<String> */);
impl Secret { pub fn new(text: String) -> Secret; pub fn expose(&self) -> &str; }
pub enum Privileged<'a> { SetupPlan(&'a [String]), SetupStatus, SetupStep(Step), UnitEnable(Unit), UnitDisable(Unit) }
impl Privileged<'_> { pub fn args(&self) -> Vec<String>; pub fn journal(&self) -> String; }
// runner.rs: Program gains Dnf, Rpm, Runuser, PostgresqlSetup, Usermod, FirewallCmd, Admin
// lib.rs: HostError gains WrongPassword, NotSudoer; Host gains
fn is_set_up(&self) -> bool;
fn privileged(&self, verb: Privileged<'_>, password: &Secret) -> Result<String, HostError>;
```

- [ ] **Step 1: Failing tests.** Append to `crates/platform-host/tests/native.rs` (extend the `use platform_host::{…}` list with `Privileged, Secret, Step, StepState`):

```rust
#[test]
fn privileged_verbs_pass_the_password_on_stdin_only() {
    let host = fake(vec![
        (
            vec!["/usr/bin/sudo", "-S", "-k", "-p", "", "/usr/bin/openvibes-admin", "helper", "setup-step", "ca"],
            out(0, "done\tintermediate imported\n", ""),
        ),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    let password = Secret::new("hunter2 hunter2".into());
    assert_eq!(
        host.privileged(Privileged::SetupStep(Step::Ca), &password).unwrap(),
        "done\tintermediate imported\n"
    );
    assert_eq!(*host.runner.inputs.borrow(), ["hunter2 hunter2\n"]);
    let calls = host.runner.calls.borrow();
    assert!(
        calls.iter().all(|call| !call.iter().any(|arg| arg.contains("hunter2"))),
        "{calls:?}"
    );
    let journal = calls.iter().find(|call| call[0] == "/usr/bin/logger").unwrap();
    assert!(journal[3].ends_with(" setup-step ca ok"), "{journal:?}");
    assert_eq!(format!("{password:?}"), "Secret(..)");
}

#[test]
fn wrong_password_and_missing_sudo_rights_are_told_apart() {
    let host = fake(vec![
        (
            vec!["/usr/bin/sudo", "-S", "-k", "-p", "", "/usr/bin/openvibes-admin", "helper", "setup-status"],
            out(1, "", "sudo: 1 incorrect password attempt\n"),
        ),
        (
            vec!["/usr/bin/sudo", "-S", "-k", "-p", "", "/usr/bin/openvibes-admin", "helper", "unit-enable"],
            out(1, "", "alice is not in the sudoers file.\n"),
        ),
        (
            vec!["/usr/bin/sudo", "-S", "-k", "-p", "", "/usr/bin/openvibes-admin", "helper", "unit-disable"],
            out(1, "", "openvibes-admin helper: not allowed: not an OpenVIBES unit\n"),
        ),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    let password = Secret::new("wrong".into());
    assert_eq!(host.privileged(Privileged::SetupStatus, &password), Err(HostError::WrongPassword));
    assert_eq!(
        host.privileged(Privileged::UnitEnable(Unit::Ingest), &password),
        Err(HostError::NotSudoer)
    );
    assert_eq!(
        host.privileged(Privileged::UnitDisable(Unit::Ingest), &password),
        Err(HostError::Failed(
            "openvibes-admin helper: not allowed: not an OpenVIBES unit".into()
        ))
    );
}

#[test]
fn verbs_steps_and_states_are_closed_lists() {
    let args = ["--components".to_owned(), "ingest".to_owned()];
    assert_eq!(Privileged::SetupPlan(&args).args(), ["setup-plan", "--components", "ingest"]);
    assert_eq!(Privileged::SetupPlan(&args).journal(), "setup-plan");
    assert_eq!(
        Privileged::UnitEnable(Unit::Vulns).args(),
        ["unit-enable", "openvibes-vulns.service"]
    );
    for step in Step::ALL {
        assert_eq!(Step::parse(step.name()), Some(step));
    }
    for bad in ["", "Packages", "packages ", "../ca", "all"] {
        assert_eq!(Step::parse(bad), None, "{bad}");
    }
    for state in [
        StepState::Done("x y".into()),
        StepState::Todo,
        StepState::Waiting("sign it".into()),
        StepState::Skipped("not chosen".into()),
        StepState::Failed("boom".into()),
    ] {
        assert_eq!(StepState::parse(&state.line()), Some(state));
    }
    assert_eq!(StepState::Done("a\tb\nc".into()).line(), "done\ta b c");
    assert_eq!(StepState::parse("maybe\tx"), None);
}
```

- [ ] **Step 2: Run, expect a compile failure.**

Run: `cargo test -p platform-host --test native`
Expected: FAIL to compile (`Privileged`, `Secret`, `Step`, `StepState` do not exist).

- [ ] **Step 3: Implement.** `crates/platform-host/Cargo.toml`: add

```toml
[dependencies]
zeroize = "=1.9.0"
```

`crates/platform-host/src/setup.rs`:

```rust
//! Setup's steps and their states (admin TUI spec §6.3), the password a
//! Setup run holds, and the password-gated helper verbs (§3).

use zeroize::Zeroizing;

use crate::Unit;

/// The plan Setup works from (§6.2).
pub const SETUP_FILE: &str = "/etc/openvibes/setup.toml";

/// One Setup step, in the order Setup runs them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Step {
    Packages,
    Postgres,
    Operators,
    Database,
    Schema,
    Ca,
    Certificates,
    Console,
    Services,
    Firewall,
    Rules,
    Agent,
    Ready,
}

impl Step {
    /// Every step, in order.
    pub const ALL: [Step; 13] = [
        Step::Packages,
        Step::Postgres,
        Step::Operators,
        Step::Database,
        Step::Schema,
        Step::Ca,
        Step::Certificates,
        Step::Console,
        Step::Services,
        Step::Firewall,
        Step::Rules,
        Step::Agent,
        Step::Ready,
    ];

    /// The name the helper takes.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Step::Packages => "packages",
            Step::Postgres => "postgres",
            Step::Operators => "operators",
            Step::Database => "database",
            Step::Schema => "schema",
            Step::Ca => "ca",
            Step::Certificates => "certificates",
            Step::Console => "console",
            Step::Services => "services",
            Step::Firewall => "firewall",
            Step::Rules => "rules",
            Step::Agent => "agent",
            Step::Ready => "ready",
        }
    }

    /// The title screens show.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Step::Packages => "Install packages",
            Step::Postgres => "PostgreSQL",
            Step::Operators => "Operator group",
            Step::Database => "Database and role",
            Step::Schema => "Schema",
            Step::Ca => "Certificate authority",
            Step::Certificates => "Server certificates",
            Step::Console => "Console and admin account",
            Step::Services => "Start services",
            Step::Firewall => "Firewall",
            Step::Rules => "Baseline rules",
            Step::Agent => "Agent on this host",
            Step::Ready => "Readiness",
        }
    }

    /// The step with exactly this name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Step> {
        Step::ALL.into_iter().find(|step| step.name() == name)
    }
}

/// What a step's check found, or what running it achieved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepState {
    /// Done; what is in place.
    Done(String),
    /// Not done yet.
    Todo,
    /// Needs something from the user first (careful CA: the signed
    /// certificate); what to do.
    Waiting(String),
    /// Does not apply to this plan or host; why.
    Skipped(String),
    /// Could not be checked or done; the error.
    Failed(String),
}

fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_owned()
}

impl StepState {
    /// The helper's output: `STATE<TAB>DETAIL`, on one line.
    #[must_use]
    pub fn line(&self) -> String {
        format!("{}\t{}", self.label_word(), one_line(self.detail()))
    }

    /// The state the helper printed.
    #[must_use]
    pub fn parse(line: &str) -> Option<StepState> {
        let (state, detail) = line.split_once('\t').unwrap_or((line, ""));
        let detail = detail.to_owned();
        Some(match state {
            "done" => StepState::Done(detail),
            "todo" => StepState::Todo,
            "waiting" => StepState::Waiting(detail),
            "skipped" => StepState::Skipped(detail),
            "failed" => StepState::Failed(detail),
            _ => return None,
        })
    }

    /// Whether the run may go on to the next step.
    #[must_use]
    pub fn finished(&self) -> bool {
        matches!(self, StepState::Done(_) | StepState::Skipped(_))
    }

    fn label_word(&self) -> &'static str {
        match self {
            StepState::Done(_) => "done",
            StepState::Todo => "todo",
            StepState::Waiting(_) => "waiting",
            StepState::Skipped(_) => "skipped",
            StepState::Failed(_) => "failed",
        }
    }

    /// A word for screens.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            StepState::Todo => "to do",
            other => other.label_word(),
        }
    }

    /// The detail, empty for `Todo`.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            StepState::Done(text)
            | StepState::Waiting(text)
            | StepState::Skipped(text)
            | StepState::Failed(text) => text,
            StepState::Todo => "",
        }
    }
}

/// The user's password during one Setup run; zeroed when dropped (§3).
pub struct Secret(Zeroizing<String>);

impl Secret {
    #[must_use]
    pub fn new(text: String) -> Secret {
        Secret(Zeroizing::new(text))
    }

    /// The password, for sudo's stdin only.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// A helper verb that needs the user's password (§3).
#[derive(Clone, Copy, Debug)]
pub enum Privileged<'a> {
    /// `setup-plan ARGS…`: checks the arguments and writes `setup.toml`.
    SetupPlan(&'a [String]),
    /// `setup-status`: every step's state.
    SetupStatus,
    /// `setup-step STEP`: checks the step and runs it unless done.
    SetupStep(Step),
    /// `unit-enable UNIT`: start at boot.
    UnitEnable(Unit),
    /// `unit-disable UNIT`: do not start at boot.
    UnitDisable(Unit),
}

impl Privileged<'_> {
    /// The helper's arguments after `helper`.
    #[must_use]
    pub fn args(&self) -> Vec<String> {
        match self {
            Privileged::SetupPlan(args) => {
                let mut all = vec!["setup-plan".to_owned()];
                all.extend(args.iter().cloned());
                all
            }
            Privileged::SetupStatus => vec!["setup-status".into()],
            Privileged::SetupStep(step) => vec!["setup-step".into(), step.name().into()],
            Privileged::UnitEnable(unit) => vec!["unit-enable".into(), unit.name().into()],
            Privileged::UnitDisable(unit) => vec!["unit-disable".into(), unit.name().into()],
        }
    }

    /// What the journal records (no arguments of `setup-plan`).
    #[must_use]
    pub fn journal(&self) -> String {
        match self {
            Privileged::SetupPlan(_) => "setup-plan".into(),
            other => other.args().join(" "),
        }
    }
}
```

`crates/platform-host/src/lib.rs`: add `pub mod setup;` and `pub use setup::{Privileged, SETUP_FILE, Secret, Step, StepState};`. In `HostError` add, after `NotOperator`:

```rust
    /// sudo refused the password.
    WrongPassword,
    /// The user may not use sudo at all.
    NotSudoer,
```

and in its `Display`:

```rust
            HostError::WrongPassword => f.write_str("wrong password"),
            HostError::NotSudoer => f.write_str(
                "this needs sudo rights (on Fedora: membership of wheel); ask an administrator",
            ),
```

and in `trait Host`:

```rust
    /// Whether Setup has run on this host (`/etc/openvibes/setup.toml`).
    fn is_set_up(&self) -> bool;
    /// Runs a password-gated helper verb through sudo; its standard output.
    fn privileged(&self, verb: Privileged<'_>, password: &Secret) -> Result<String, HostError>;
```

`crates/platform-host/src/runner.rs`: extend `Program` and `path` (keep the doc comment style):

```rust
    /// Packages (Setup, as root).
    Dnf,
    /// Package queries.
    Rpm,
    /// Commands as a service account (Setup, as root).
    Runuser,
    /// PostgreSQL's first initialisation.
    PostgresqlSetup,
    /// Operator group membership.
    Usermod,
    /// Firewall ports.
    FirewallCmd,
    /// The admin CLI itself (offline CA commands as root).
    Admin,
```

```rust
            Program::Dnf => "/usr/bin/dnf",
            Program::Rpm => "/usr/bin/rpm",
            Program::Runuser => "/usr/sbin/runuser",
            Program::PostgresqlSetup => "/usr/bin/postgresql-setup",
            Program::Usermod => "/usr/sbin/usermod",
            Program::FirewallCmd => "/usr/bin/firewall-cmd",
            Program::Admin => "/usr/bin/openvibes-admin",
```

and change the `SystemRunner::run` comment "one of the four `Program`s" to "one of the `Program`s".

`crates/platform-host/src/native.rs`: import `Privileged, Secret, SETUP_FILE` and `zeroize::Zeroizing`; add to `impl<R: Runner> Host for Native<R>`:

```rust
    fn is_set_up(&self) -> bool {
        std::path::Path::new(SETUP_FILE).exists()
    }

    fn privileged(&self, verb: Privileged<'_>, password: &Secret) -> Result<String, HostError> {
        let args = verb.args();
        // -S: password from stdin; -k: never a cached credential; -p '': no
        // prompt text mixed into the output.
        let mut argv = vec!["-S", "-k", "-p", "", ADMIN, "helper"];
        argv.extend(args.iter().map(String::as_str));
        let mut input = Zeroizing::new(password.expose().as_bytes().to_vec());
        input.push(b'\n');
        let out = self
            .runner
            .run_with_input(Sudo, &argv, &input)
            .map_err(|error| HostError::Io(format!("{}: {error}", Sudo.path())))?;
        let outcome = if out.status == 0 { "ok" } else { "failed" };
        self.journal(&format!("{} {outcome}", verb.journal()));
        if out.status == 0 {
            Ok(out.stdout)
        } else if out.stderr.contains("incorrect password") || out.stderr.contains("Sorry, try again") {
            Err(HostError::WrongPassword)
        } else if out.stderr.contains("not in the sudoers file")
            || out.stderr.contains("may not run sudo")
            || out.stderr.contains("is not allowed to run sudo")
        {
            Err(HostError::NotSudoer)
        } else {
            Err(HostError::Failed(printable(&out.stderr)))
        }
    }
```

`crates/openvibes-admin/src/tui/tests.rs`: import `Privileged, Secret` from `platform_host` and add to `impl Host for FakeHost`:

```rust
    fn is_set_up(&self) -> bool {
        true
    }
    fn privileged(&self, verb: Privileged<'_>, _password: &Secret) -> Result<String, HostError> {
        Err(HostError::Failed(format!("{} is not used in this test", verb.journal())))
    }
```

`docs/components/platform-host.md`: add a "Setup" section: `Step`, `StepState` and their line format, `Secret`, `Privileged` and the `sudo -S -k -p ''` call (password on stdin only, journal entry `VERB ok|failed`, `WrongPassword`/`NotSudoer`), the new `Program`s.

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p platform-host && cargo test -p openvibes-admin --bin openvibes-admin tui`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/platform-host crates/openvibes-admin/src/tui/tests.rs docs/components/platform-host.md Cargo.lock
git commit -m "platform-host: Setup steps, states, secret and privileged verbs

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: The Setup plan (`setup.toml`)

**Files:**
- Create: `crates/openvibes-admin/src/setup/mod.rs` (only `pub mod plan;` for now), `crates/openvibes-admin/src/setup/plan.rs`
- Modify: `crates/openvibes-admin/src/main.rs` (`mod setup;`)

**Interfaces — Produces:**

```rust
pub enum Component { Ingest, Console, Distribution, Vulns, Assistant, Rules, Agent } // Ord in this order; clap ValueEnum; serde kebab-case
impl Component { pub const ALL: [Component; 7]; pub fn name(self) -> &'static str; pub fn packages(self) -> &'static [&'static str]; pub fn units(self) -> &'static [Unit]; pub fn about(self) -> &'static str; }
pub enum CaMode { Quick, Careful }
pub struct Plan { pub components: Vec<Component>, pub hostname: String, pub sans: Vec<String>, pub ca: CaMode,
                  pub root_key_out: Option<PathBuf>, pub admin_password_file: Option<PathBuf>,
                  pub repo_dir: Option<PathBuf>, pub allow_unsigned_local: bool, pub operator: Option<String> }
impl Plan { pub fn has(&self, c: Component) -> bool; pub fn names(&self) -> Vec<String>;
            pub fn load(root: &Path) -> Result<Plan, String>; pub fn save(&self, root: &Path) -> Result<(), String>; }
#[derive(clap::Args)] pub struct PlanArgs { components, hostname, san, ca, root_key_out, admin_password_file, repo_dir, allow_unsigned_local }
impl PlanArgs { pub fn plan(&self, operator: Option<String>) -> Result<Plan, String>; }
pub fn operator_from_env() -> Option<String>;
```

- [ ] **Step 1: Failing tests** at the end of `plan.rs` (write the file with only `#[cfg(test)] mod tests` and the `use` lines first):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn args(components: &[Component], hostname: &str, sans: &[&str]) -> PlanArgs {
        PlanArgs {
            components: components.to_vec(),
            hostname: hostname.into(),
            san: sans.iter().map(|s| (*s).to_owned()).collect(),
            ca: CaMode::Quick,
            root_key_out: None,
            admin_password_file: None,
            repo_dir: None,
            allow_unsigned_local: false,
        }
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ov-plan-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_plan_is_sorted_saved_and_loaded() {
        use Component::*;
        let plan = args(&[Agent, Ingest, Vulns, Ingest], "platform.example.com", &["10.0.0.5"])
            .plan(Some("alice".into()))
            .unwrap();
        assert_eq!(plan.components, [Ingest, Vulns, Agent]);
        assert_eq!(
            plan.names(),
            ["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"]
        );
        let root = temp("roundtrip");
        plan.save(&root).unwrap();
        let file = root.join("etc/openvibes/setup.toml");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o644);
        assert_eq!(Plan::load(&root).unwrap(), plan);
        std::fs::write(&file, "components = [\"ingest\"]\nhostname = \"a\"\nca = \"quick\"\nextra = 1\n").unwrap();
        assert!(Plan::load(&root).is_err(), "unknown fields are refused");
    }

    #[test]
    fn bad_plans_are_refused() {
        use Component::*;
        let host = "platform.example.com";
        for (args, want) in [
            (args(&[Console], host, &[]), "must include ingest"),
            (args(&[Ingest, Rules], host, &[]), "rules need distribution"),
            (args(&[Ingest], "Platform.example.com", &[]), "lowercase DNS name"),
            (args(&[Ingest], "platform..example.com", &[]), "lowercase DNS name"),
            (args(&[Ingest], "-platform.example.com", &[]), "lowercase DNS name"),
            (args(&[Ingest], "platform.example.com.", &[]), "lowercase DNS name"),
            (args(&[Ingest], "1.2.3", &[]), "lowercase DNS name"),
            (args(&[Ingest], host, &["bad name"]), "lowercase DNS name"),
            (args(&[Ingest], host, &["a"; 17]), "at most 16"),
        ] {
            let error = args.plan(None).unwrap_err();
            assert!(error.contains(want), "{error} should contain {want}");
        }
        let mut relative = args(&[Ingest], host, &[]);
        relative.root_key_out = Some("root.key".into());
        assert!(relative.plan(None).unwrap_err().contains("not an absolute path"));
        assert!(args(&[Ingest], host, &["10.0.0.5", "fd00::5", "ingest.lan"]).plan(None).is_ok());
    }

    #[test]
    fn every_component_names_its_packages() {
        for component in Component::ALL {
            assert!(!component.packages().is_empty(), "{component:?}");
            assert!(component.packages().iter().all(|p| p.starts_with("openvibes-")));
        }
        assert_eq!(Component::Ingest.packages(), ["openvibes-ingest", "openvibes-admin"]);
        assert_eq!(Component::Ingest.units(), [Unit::Ingest, Unit::Maintenance]);
    }
}
```

- [ ] **Step 2: Run, expect a compile failure.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::plan`
Expected: FAIL to compile.

- [ ] **Step 3: Implement** `plan.rs` above the tests:

```rust
//! What Setup installs (admin TUI spec §6.2): `/etc/openvibes/setup.toml`,
//! written by `helper setup-plan` or `setup --quick` from checked arguments,
//! read by every step.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use clap::ValueEnum;
use platform_host::{SETUP_FILE, Unit};
use serde::{Deserialize, Serialize};

/// A part of the platform Setup can install.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum Component {
    Ingest,
    Console,
    Distribution,
    Vulns,
    Assistant,
    Rules,
    Agent,
}

impl Component {
    pub const ALL: [Component; 7] = [
        Component::Ingest,
        Component::Console,
        Component::Distribution,
        Component::Vulns,
        Component::Assistant,
        Component::Rules,
        Component::Agent,
    ];

    /// The name `--components` takes.
    pub fn name(self) -> &'static str {
        match self {
            Component::Ingest => "ingest",
            Component::Console => "console",
            Component::Distribution => "distribution",
            Component::Vulns => "vulns",
            Component::Assistant => "assistant",
            Component::Rules => "rules",
            Component::Agent => "agent",
        }
    }

    /// What it is, for the Setup screen.
    pub fn about(self) -> &'static str {
        match self {
            Component::Ingest => "agent enrollment and findings (always)",
            Component::Console => "web console (always)",
            Component::Distribution => "rules delivered to agents",
            Component::Vulns => "vulnerability feeds and matching",
            Component::Assistant => "local LLM for the console (heavy; needs a model)",
            Component::Rules => "OpenVIBES baseline rules (needs distribution)",
            Component::Agent => "the agent on this host",
        }
    }

    /// Its packages.
    pub fn packages(self) -> &'static [&'static str] {
        match self {
            Component::Ingest => &["openvibes-ingest", "openvibes-admin"],
            Component::Console => &["openvibes-console"],
            Component::Distribution => &["openvibes-distribution"],
            Component::Vulns => &["openvibes-vulns"],
            Component::Assistant => &["openvibes-llm"],
            Component::Rules => &["openvibes-rules-baseline"],
            Component::Agent => &["openvibes-agent"],
        }
    }

    /// The units Setup enables and starts for it. The assistant's model
    /// server is left stopped: it refuses to start without a model.
    pub fn units(self) -> &'static [Unit] {
        match self {
            Component::Ingest => &[Unit::Ingest, Unit::Maintenance],
            Component::Console => &[Unit::Console],
            Component::Distribution => &[Unit::Distribution],
            Component::Vulns => &[Unit::Vulns],
            Component::Assistant | Component::Rules | Component::Agent => &[],
        }
    }
}

/// How the CA is created (§6.3 step 6).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum CaMode {
    /// Root created here, its key written out once, then deleted.
    Quick,
    /// Root stays offline; the intermediate request is signed elsewhere.
    Careful,
}

/// `setup.toml`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub components: Vec<Component>,
    pub hostname: String,
    #[serde(default)]
    pub sans: Vec<String>,
    pub ca: CaMode,
    #[serde(default)]
    pub root_key_out: Option<PathBuf>,
    #[serde(default)]
    pub admin_password_file: Option<PathBuf>,
    #[serde(default)]
    pub repo_dir: Option<PathBuf>,
    #[serde(default)]
    pub allow_unsigned_local: bool,
    /// The user who ran Setup through sudo; becomes an operator.
    #[serde(default)]
    pub operator: Option<String>,
}

impl Plan {
    pub fn has(&self, component: Component) -> bool {
        self.components.contains(&component)
    }

    /// Names for server certificates: the hostname, the extra names, then
    /// `localhost` and `127.0.0.1` for an agent on this host.
    pub fn names(&self) -> Vec<String> {
        let mut names = vec![self.hostname.clone()];
        for extra in self
            .sans
            .iter()
            .map(String::as_str)
            .chain(["localhost", "127.0.0.1"])
        {
            if !names.iter().any(|name| name == extra) {
                names.push(extra.to_owned());
            }
        }
        names
    }

    fn file(root: &Path) -> PathBuf {
        root.join(SETUP_FILE.trim_start_matches('/'))
    }

    pub fn load(root: &Path) -> Result<Plan, String> {
        let path = Plan::file(root);
        let text = fs::read_to_string(&path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => {
                format!("{}: no Setup plan yet (run Setup first)", path.display())
            }
            _ => format!("{}: {error}", path.display()),
        })?;
        toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
    }

    pub fn save(&self, root: &Path) -> Result<(), String> {
        let path = Plan::file(root);
        let dir = path.parent().ok_or("no directory for setup.toml")?;
        let fail = |error: std::io::Error| format!("{}: {error}", path.display());
        fs::create_dir_all(dir).map_err(fail)?;
        let text = toml::to_string(self).map_err(|error| error.to_string())?;
        let temp = dir.join(".setup.toml.new");
        let _ = fs::remove_file(&temp);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temp)
            .map_err(fail)?;
        file.write_all(format!("# Written by openvibes-admin setup (admin TUI spec §6.2).\n{text}").as_bytes())
            .and_then(|()| file.sync_all())
            .and_then(|()| fs::rename(&temp, &path))
            .map_err(fail)
    }
}

/// Setup's arguments, shared by `helper setup-plan` and `setup --quick`.
#[derive(clap::Args, Clone, Debug)]
pub struct PlanArgs {
    /// Components, comma-separated: ingest (required), console,
    /// distribution, vulns, assistant, rules, agent.
    #[arg(long, value_delimiter = ',', required = true, value_enum)]
    pub components: Vec<Component>,
    /// This host's DNS name, put in the server certificates.
    #[arg(long)]
    pub hostname: String,
    /// More DNS names or IP addresses for the server certificates.
    #[arg(long)]
    pub san: Vec<String>,
    /// quick: root created here; careful: root kept offline.
    #[arg(long, value_enum, default_value = "quick")]
    pub ca: CaMode,
    /// Where the quick CA's root key is written once (e.g. a USB stick);
    /// without it the root key is deleted.
    #[arg(long)]
    pub root_key_out: Option<PathBuf>,
    /// File holding the console admin's password (otherwise generated).
    #[arg(long)]
    pub admin_password_file: Option<PathBuf>,
    /// Install from this folder of package files instead of the repository.
    #[arg(long)]
    pub repo_dir: Option<PathBuf>,
    /// With --repo-dir: accept unsigned package files (test builds only).
    #[arg(long)]
    pub allow_unsigned_local: bool,
}

/// A lowercase DNS name.
pub fn check_name(name: &str) -> Result<(), String> {
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let numeric_top = name
        .rsplit('.')
        .next()
        .is_some_and(|last| !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()));
    if name.len() <= 253 && name.split('.').all(label_ok) && !numeric_top {
        Ok(())
    } else {
        Err(format!("{name:?} is not a lowercase DNS name"))
    }
}

fn check_san(san: &str) -> Result<(), String> {
    if san.parse::<IpAddr>().is_ok() {
        Ok(())
    } else {
        check_name(san)
    }
}

impl PlanArgs {
    /// The checked plan; `operator` is who ran Setup through sudo.
    pub fn plan(&self, operator: Option<String>) -> Result<Plan, String> {
        let mut components = self.components.clone();
        components.sort();
        components.dedup();
        if !components.contains(&Component::Ingest) {
            return Err("--components must include ingest".into());
        }
        if components.contains(&Component::Rules) && !components.contains(&Component::Distribution) {
            return Err("rules need distribution (agents fetch rules from it)".into());
        }
        check_name(&self.hostname)?;
        if self.san.len() > 16 {
            return Err("at most 16 --san".into());
        }
        for san in &self.san {
            check_san(san)?;
        }
        for path in [&self.root_key_out, &self.admin_password_file, &self.repo_dir]
            .into_iter()
            .flatten()
        {
            if !path.is_absolute() {
                return Err(format!("{} is not an absolute path", path.display()));
            }
        }
        Ok(Plan {
            components,
            hostname: self.hostname.clone(),
            sans: self.san.clone(),
            ca: self.ca,
            root_key_out: self.root_key_out.clone(),
            admin_password_file: self.admin_password_file.clone(),
            repo_dir: self.repo_dir.clone(),
            allow_unsigned_local: self.allow_unsigned_local,
            operator,
        })
    }
}

/// The person who ran Setup, from sudo's `SUDO_USER` (not root).
pub fn operator_from_env() -> Option<String> {
    let user = std::env::var("SUDO_USER").ok()?;
    let valid = !user.is_empty()
        && user.len() <= 32
        && user != "root"
        && user.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_lowercase()
                || b == b'_'
                || (i > 0 && (b.is_ascii_digit() || b == b'-' || b == b'.'))
        });
    valid.then_some(user)
}
```

`src/setup/mod.rs`:

```rust
//! The root side of Setup (admin TUI spec §6).

pub mod plan;
```

`main.rs`: add `mod setup;` to the module list.

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::plan`
Expected: PASS (3 tests). Unused-item warnings are fine until Task 3 uses the plan.

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin/src/setup crates/openvibes-admin/src/main.rs
git commit -m "admin: Setup plan (setup.toml) from checked arguments

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Step engine, test runner, packages and PostgreSQL

**Files:**
- Create: `crates/openvibes-admin/src/setup/{system.rs,base.rs,fake.rs}`
- Modify: `crates/openvibes-admin/src/setup/mod.rs`

**Interfaces — Produces:**

```rust
// system.rs
pub type Owner<'a> = Option<(&'a str, &'a str)>; // (user, group); None: the caller (root on a host)
pub struct Ctx<'a, R: Runner> { pub runner: &'a R, pub plan: &'a Plan, pub root: &'a Path, pub pause: Duration }
impl<R: Runner> Ctx<'_, R> {
    pub fn path(&self, abs: &str) -> PathBuf;
    pub fn exists(&self, abs: &str) -> bool;
    pub fn read(&self, abs: &str) -> Result<String, String>;
    pub fn ok(&self, program: Program, args: &[&str]) -> Result<String, String>;
    pub fn ok_with_input(&self, program: Program, args: &[&str], input: &[u8]) -> Result<String, String>;
    pub fn succeeds(&self, program: Program, args: &[&str]) -> bool;
    pub fn as_admin(&self, args: &[&str]) -> Result<String, String>;              // runuser -u openvibes-admin -- /usr/bin/openvibes-admin ARGS
    pub fn as_admin_with_input(&self, args: &[&str], input: &[u8]) -> Result<String, String>;
    pub fn as_postgres(&self, args: &[&str]) -> Result<String, String>;           // runuser -u postgres -- ARGS
    pub fn put(&self, abs: &str, contents: &[u8], owner: Owner<'_>, mode: u32) -> Result<(), String>;
    pub fn copy(&self, from: &str, to: &str, owner: Owner<'_>, mode: u32) -> Result<(), String>;
    pub fn chown(&self, abs: &str, owner: Owner<'_>) -> Result<(), String>;
    pub fn pause(&self);
}
// base.rs
pub fn install<R: Runner>(ctx: &Ctx<R>, names: &[&str]) -> Result<(), String>;
pub fn packages_check / packages_apply / postgres_check / postgres_apply  (ctx) -> Result<StepState, String>
// mod.rs
pub fn check<R: Runner>(ctx: &Ctx<R>, step: Step) -> StepState;
pub fn apply<R: Runner>(ctx: &Ctx<R>, step: Step) -> StepState;
pub fn run_step<R: Runner>(ctx: &Ctx<R>, step: Step) -> StepState;
pub fn run_all<R: Runner>(ctx: &Ctx<R>, report: impl FnMut(Step, &StepState)) -> bool;
// fake.rs (#[cfg(test)])
pub struct Fake { pub root: PathBuf, pub calls: RefCell<Vec<Vec<String>>>, pub inputs: RefCell<Vec<String>>, … }
impl Fake { pub fn new(test: &str) -> Fake; pub fn answer(&self, prefix: &[&str], status: i32, stdout: &str);
            pub fn effect(&self, prefix: &[&str], effect: impl Fn(&Path) + 'static);
            pub fn file(&self, abs: &str, text: &str); pub fn text(&self, abs: &str) -> String;
            pub fn called(&self, prefix: &[&str]) -> bool; pub fn call(&self, prefix: &[&str]) -> Vec<String>;
            pub fn ctx<'a>(&'a self, plan: &'a Plan) -> Ctx<'a, Fake>; }
pub fn plan(components: &[Component]) -> Plan; // hostname platform.example.com, san 10.0.0.5, quick CA, operator alice
```

- [ ] **Step 1: Write the test runner** `src/setup/fake.rs` (test support, no behaviour of its own):

```rust
//! A scripted `Runner` and a temp root directory for the step tests.

use std::{cell::RefCell, os::unix::fs::MetadataExt, path::{Path, PathBuf}, time::Duration};

use platform_host::runner::{Output, Program, Runner};

use super::{Ctx, plan::{CaMode, Component, Plan}};

type Effect = Box<dyn Fn(&Path)>;

pub struct Fake {
    pub root: PathBuf,
    pub calls: RefCell<Vec<Vec<String>>>,
    pub inputs: RefCell<Vec<String>>,
    answers: RefCell<Vec<(Vec<String>, Output, Option<Effect>)>>,
}

/// Users and groups the steps look up; all map to the test's own ids, so
/// chown succeeds without root.
const ACCOUNTS: [&str; 9] = [
    "root", "postgres", "alice", "openvibes-admin", "openvibes-ingest",
    "openvibes-distribution", "openvibes-console", "openvibes_agent", "openvibes-operators",
];

impl Fake {
    pub fn new(test: &str) -> Fake {
        let root = std::env::temp_dir().join(format!("ov-setup-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc")).unwrap();
        let meta = std::fs::metadata(&root).unwrap();
        let (uid, gid) = (meta.uid(), meta.gid());
        let passwd: String = ACCOUNTS.iter().map(|n| format!("{n}:x:{uid}:{gid}::/:/sbin/nologin\n")).collect();
        let group: String = ACCOUNTS.iter().map(|n| format!("{n}:x:{gid}:\n")).collect();
        std::fs::write(root.join("etc/passwd"), passwd).unwrap();
        std::fs::write(root.join("etc/group"), group).unwrap();
        Fake {
            root,
            calls: RefCell::new(Vec::new()),
            inputs: RefCell::new(Vec::new()),
            answers: RefCell::new(Vec::new()),
        }
    }

    /// Calls starting with `prefix` exit with `status` and print `stdout`.
    /// The first matching answer wins, so add specific ones first.
    pub fn answer(&self, prefix: &[&str], status: i32, stdout: &str) {
        self.answers.borrow_mut().push((
            prefix.iter().map(|s| (*s).to_owned()).collect(),
            Output { status, stdout: stdout.into(), stderr: if status == 0 { String::new() } else { format!("{} failed", prefix.join(" ")) } },
            None,
        ));
    }

    /// Calls starting with `prefix` succeed and run `effect` on the root.
    pub fn effect(&self, prefix: &[&str], effect: impl Fn(&Path) + 'static) {
        self.answers.borrow_mut().push((
            prefix.iter().map(|s| (*s).to_owned()).collect(),
            Output::default(),
            Some(Box::new(effect)),
        ));
    }

    pub fn file(&self, abs: &str, text: &str) {
        let path = self.root.join(abs.trim_start_matches('/'));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    pub fn text(&self, abs: &str) -> String {
        std::fs::read_to_string(self.root.join(abs.trim_start_matches('/'))).unwrap()
    }

    pub fn called(&self, prefix: &[&str]) -> bool {
        self.calls.borrow().iter().any(|call| starts(call, prefix))
    }

    /// The first call starting with `prefix`.
    pub fn call(&self, prefix: &[&str]) -> Vec<String> {
        let calls = self.calls.borrow();
        calls.iter().find(|call| starts(call, prefix)).cloned().unwrap_or_else(|| panic!("no call {prefix:?} in {calls:?}"))
    }

    pub fn ctx<'a>(&'a self, plan: &'a Plan) -> Ctx<'a, Fake> {
        Ctx { runner: self, plan, root: &self.root, pause: Duration::ZERO }
    }
}

fn starts<S: AsRef<str>>(call: &[String], prefix: &[S]) -> bool {
    call.len() >= prefix.len() && call.iter().zip(prefix).all(|(a, b)| a == b.as_ref())
}

impl Runner for Fake {
    fn run(&self, program: Program, args: &[&str]) -> std::io::Result<Output> {
        let mut call = vec![program.path().to_owned()];
        call.extend(args.iter().map(|a| (*a).to_owned()));
        self.calls.borrow_mut().push(call.clone());
        for (prefix, out, effect) in self.answers.borrow().iter() {
            if starts(&call, prefix) {
                if let Some(effect) = effect {
                    effect(&self.root);
                }
                return Ok(out.clone());
            }
        }
        Ok(Output { status: 1, stdout: String::new(), stderr: "unexpected call".into() })
    }

    fn run_with_input(&self, program: Program, args: &[&str], input: &[u8]) -> std::io::Result<Output> {
        self.inputs.borrow_mut().push(String::from_utf8_lossy(input).into_owned());
        self.run(program, args)
    }
}

/// A plan for tests: platform.example.com, 10.0.0.5, quick CA, run by alice.
pub fn plan(components: &[Component]) -> Plan {
    let mut components = components.to_vec();
    components.sort();
    Plan {
        components,
        hostname: "platform.example.com".into(),
        sans: vec!["10.0.0.5".into()],
        ca: CaMode::Quick,
        root_key_out: None,
        admin_password_file: None,
        repo_dir: None,
        allow_unsigned_local: false,
        operator: Some("alice".into()),
    }
}
```

- [ ] **Step 2: Failing tests** at the end of `base.rs` (create the file with the module doc and this test module):

```rust
#[cfg(test)]
mod tests {
    use platform_host::{Step, StepState};

    use crate::setup::{fake::{Fake, plan}, plan::Component::*, run_step};

    #[test]
    fn packages_are_installed_from_the_repository() {
        let fake = Fake::new("packages-repo");
        fake.answer(&["/usr/bin/rpm"], 1, "");
        fake.answer(&["/usr/bin/dnf", "install"], 0, "");
        let plan = plan(&[Ingest, Console, Vulns, Rules, Agent, Distribution]);
        let state = run_step(&fake.ctx(&plan), Step::Packages);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert_eq!(
            fake.call(&["/usr/bin/dnf"]),
            ["/usr/bin/dnf", "install", "-y", "openvibes-ingest", "openvibes-admin",
             "openvibes-console", "openvibes-distribution", "openvibes-vulns"]
        );
    }

    #[test]
    fn a_done_step_is_not_run_again() {
        let fake = Fake::new("packages-done");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet"], 0, "");
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Packages);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(!fake.called(&["/usr/bin/dnf"]));
    }

    #[test]
    fn local_packages_pick_the_exact_name_and_refuse_duplicates() {
        let fake = Fake::new("packages-local");
        for file in [
            "openvibes-ingest-0.1.0-1.fc44.x86_64.rpm",
            "openvibes-admin-0.1.0-1.fc44.x86_64.rpm",
            "openvibes-llm-0.1.0-1.fc44.x86_64.rpm",
            "openvibes-llm-vulkan-0.1.0-1.fc44.x86_64.rpm",
            "openvibes-ingest-0.1.0-1.fc44.src.rpm",
        ] {
            fake.file(&format!("/srv/rpms/{file}"), "");
        }
        fake.answer(&["/usr/bin/rpm"], 1, "");
        fake.answer(&["/usr/bin/dnf", "install"], 0, "");
        let mut plan = plan(&[Ingest, Assistant]);
        plan.repo_dir = Some("/srv/rpms".into());
        assert!(matches!(run_step(&fake.ctx(&plan), Step::Packages), StepState::Done(_)));
        assert_eq!(
            fake.call(&["/usr/bin/dnf"]),
            ["/usr/bin/dnf", "install", "-y", "--setopt=localpkg_gpgcheck=1",
             "/srv/rpms/openvibes-ingest-0.1.0-1.fc44.x86_64.rpm",
             "/srv/rpms/openvibes-admin-0.1.0-1.fc44.x86_64.rpm",
             "/srv/rpms/openvibes-llm-0.1.0-1.fc44.x86_64.rpm"]
        );

        plan.allow_unsigned_local = true;
        fake.calls.borrow_mut().clear();
        run_step(&fake.ctx(&plan), Step::Packages);
        assert_eq!(fake.call(&["/usr/bin/dnf"])[3], "--setopt=localpkg_gpgcheck=0");

        fake.file("/srv/rpms/openvibes-ingest-0.2.0-1.fc44.x86_64.rpm", "");
        let state = run_step(&fake.ctx(&plan), Step::Packages);
        assert!(state.detail().contains("several openvibes-ingest packages in /srv/rpms"), "{state:?}");

        plan.components.push(Console);
        std::fs::remove_file(fake.root.join("srv/rpms/openvibes-ingest-0.2.0-1.fc44.x86_64.rpm")).unwrap();
        let state = run_step(&fake.ctx(&plan), Step::Packages);
        assert!(state.detail().contains("no openvibes-console package in /srv/rpms"), "{state:?}");
    }

    #[test]
    fn postgres_is_installed_initialised_and_started() {
        let fake = Fake::new("postgres");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "postgresql-server"], 1, "");
        fake.answer(&["/usr/bin/dnf", "install", "-y", "postgresql-server"], 0, "");
        fake.effect(&["/usr/bin/postgresql-setup", "--initdb"], |root| {
            std::fs::create_dir_all(root.join("var/lib/pgsql/data")).unwrap();
            std::fs::write(root.join("var/lib/pgsql/data/PG_VERSION"), "17\n").unwrap();
        });
        fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
        fake.answer(&["/usr/bin/systemctl", "enable", "--now", "postgresql"], 0, "");
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Postgres);
        assert_eq!(state, StepState::Done("PostgreSQL installed and running".into()));
        assert!(fake.root.join("var/lib/pgsql/data/PG_VERSION").exists());
    }
}
```

- [ ] **Step 3: Run, expect a compile failure.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::base`
Expected: FAIL to compile (`Ctx`, `run_step`, `base` do not exist).

- [ ] **Step 4: Implement.** `src/setup/system.rs`:

```rust
//! What a step may do to the host: run a command through the `Runner`, and
//! write files under `root` ("/" on a host, a temp dir in tests) with an
//! owner and mode, atomically.

use std::{
    fs::{self, OpenOptions, Permissions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use platform_host::runner::{
    Output,
    Program::{self, Admin, Runuser},
    Runner,
};

use super::plan::Plan;

/// A file's owner: (user, group). `None` keeps the caller's (root on a host).
pub type Owner<'a> = Option<(&'a str, &'a str)>;

pub struct Ctx<'a, R: Runner> {
    pub runner: &'a R,
    pub plan: &'a Plan,
    pub root: &'a Path,
    /// Between readiness polls: one second on a host, none in tests.
    pub pause: Duration,
}

/// The last lines of an error, on one line, control characters escaped.
fn tail(text: &str) -> String {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    lines[lines.len().saturating_sub(5)..]
        .join(" / ")
        .chars()
        .map(|c| if c.is_control() { c.escape_default().to_string() } else { c.to_string() })
        .collect()
}

impl<R: Runner> Ctx<'_, R> {
    pub fn path(&self, abs: &str) -> PathBuf {
        self.root.join(abs.trim_start_matches('/'))
    }

    pub fn exists(&self, abs: &str) -> bool {
        self.path(abs).exists()
    }

    pub fn read(&self, abs: &str) -> Result<String, String> {
        fs::read_to_string(self.path(abs)).map_err(|error| format!("{abs}: {error}"))
    }

    fn run(&self, program: Program, args: &[&str], input: Option<&[u8]>) -> Result<Output, String> {
        match input {
            Some(input) => self.runner.run_with_input(program, args, input),
            None => self.runner.run(program, args),
        }
        .map_err(|error| format!("{}: {error}", program.path()))
    }

    fn checked(&self, program: Program, args: &[&str], input: Option<&[u8]>) -> Result<String, String> {
        let out = self.run(program, args, input)?;
        if out.status == 0 {
            Ok(out.stdout)
        } else {
            let text = if out.stderr.trim().is_empty() { &out.stdout } else { &out.stderr };
            Err(format!("{} {}: {}", program.path(), args.join(" "), tail(text)))
        }
    }

    /// Runs the command; its stdout, or an error naming it.
    pub fn ok(&self, program: Program, args: &[&str]) -> Result<String, String> {
        self.checked(program, args, None)
    }

    pub fn ok_with_input(&self, program: Program, args: &[&str], input: &[u8]) -> Result<String, String> {
        self.checked(program, args, Some(input))
    }

    /// Whether the command ran and exited 0 (a missing program is `false`).
    pub fn succeeds(&self, program: Program, args: &[&str]) -> bool {
        self.run(program, args, None).is_ok_and(|out| out.status == 0)
    }

    fn admin_argv<'b>(args: &[&'b str]) -> Vec<&'b str> {
        let mut argv = vec!["-u", "openvibes-admin", "--", Admin.path()];
        argv.extend_from_slice(args);
        argv
    }

    /// The admin CLI as `openvibes-admin` (peer login, audit log).
    pub fn as_admin(&self, args: &[&str]) -> Result<String, String> {
        self.ok(Runuser, &Self::admin_argv(args))
    }

    pub fn as_admin_with_input(&self, args: &[&str], input: &[u8]) -> Result<String, String> {
        self.ok_with_input(Runuser, &Self::admin_argv(args), input)
    }

    /// A PostgreSQL tool as `postgres`; `args[0]` is its absolute path.
    pub fn as_postgres(&self, args: &[&str]) -> Result<String, String> {
        let mut argv = vec!["-u", "postgres", "--"];
        argv.extend_from_slice(args);
        self.ok(Runuser, &argv)
    }

    /// A numeric id from `etc/passwd` (field 2) or `etc/group` (field 2).
    fn id(&self, file: &str, name: &str) -> Result<u32, String> {
        self.read(file)?
            .lines()
            .find_map(|line| {
                let mut fields = line.split(':');
                (fields.next() == Some(name)).then(|| fields.nth(1)?.parse().ok())?
            })
            .ok_or_else(|| format!("{name} is not in {file}"))
    }

    pub fn chown(&self, abs: &str, owner: Owner<'_>) -> Result<(), String> {
        let Some((user, group)) = owner else { return Ok(()) };
        let uid = self.id("/etc/passwd", user)?;
        let gid = self.id("/etc/group", group)?;
        std::os::unix::fs::chown(self.path(abs), Some(uid), Some(gid))
            .map_err(|error| format!("{abs}: {error}"))
    }

    /// Writes `abs` atomically: a temp file in the same directory, owner,
    /// mode, fsync, rename. Creates missing directories (0755).
    pub fn put(&self, abs: &str, contents: &[u8], owner: Owner<'_>, mode: u32) -> Result<(), String> {
        let path = self.path(abs);
        let fail = |error: std::io::Error| format!("{abs}: {error}");
        let dir = path.parent().ok_or_else(|| format!("{abs}: no directory"))?;
        fs::create_dir_all(dir).map_err(fail)?;
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
        let temp_abs = format!("{}/.{name}.setup", abs.rsplit_once('/').map_or("", |(d, _)| d));
        let temp = self.path(&temp_abs);
        let _ = fs::remove_file(&temp);
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp).map_err(fail)?;
        let result = file
            .write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(fail)
            .and_then(|()| self.chown(&temp_abs, owner))
            .and_then(|()| fs::set_permissions(&temp, Permissions::from_mode(mode)).map_err(fail))
            .and_then(|()| fs::rename(&temp, &path).map_err(fail));
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    pub fn copy(&self, from: &str, to: &str, owner: Owner<'_>, mode: u32) -> Result<(), String> {
        let contents = fs::read(self.path(from)).map_err(|error| format!("{from}: {error}"))?;
        self.put(to, &contents, owner, mode)
    }

    pub fn pause(&self) {
        std::thread::sleep(self.pause);
    }
}
```

`src/setup/base.rs` (above its tests):

```rust
//! Steps 1–2 (and, from Task 4, 3–5): packages, PostgreSQL.

use platform_host::{
    StepState,
    runner::{Program::{Dnf, PostgresqlSetup, Rpm, Systemctl}, Runner},
};

use super::{Ctx, plan::{Component, Plan}};

/// The platform packages; the rules and agent packages have their own steps.
fn platform_packages(plan: &Plan) -> Vec<&'static str> {
    plan.components
        .iter()
        .filter(|c| !matches!(c, Component::Rules | Component::Agent))
        .flat_map(|c| c.packages())
        .copied()
        .collect()
}

/// The one file for package `name` in `dir` (`NAME-VERSION-….rpm`, not a
/// source package and not `NAME-other-…`).
fn local_rpm<R: Runner>(ctx: &Ctx<R>, dir: &std::path::Path, name: &str) -> Result<String, String> {
    let prefix = format!("{name}-");
    let shown = dir.display();
    let entries = std::fs::read_dir(ctx.root.join(dir.strip_prefix("/").unwrap_or(dir)))
        .map_err(|error| format!("{shown}: {error}"))?;
    let mut found: Vec<String> = entries
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|file| {
            file.strip_prefix(&prefix).is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
                && file.ends_with(".rpm")
                && !file.ends_with(".src.rpm")
        })
        .collect();
    match found.len() {
        0 => Err(format!("no {name} package in {shown}")),
        1 => Ok(dir.join(found.remove(0)).display().to_string()),
        _ => Err(format!("several {name} packages in {shown}; keep one")),
    }
}

/// `dnf install` from the repository, or the files in `repo_dir`.
pub fn install<R: Runner>(ctx: &Ctx<R>, names: &[&str]) -> Result<(), String> {
    let mut args = vec!["install".to_owned(), "-y".to_owned()];
    match &ctx.plan.repo_dir {
        None => args.extend(names.iter().map(|name| (*name).to_owned())),
        Some(dir) => {
            let check = if ctx.plan.allow_unsigned_local { "0" } else { "1" };
            args.push(format!("--setopt=localpkg_gpgcheck={check}"));
            for name in names {
                args.push(local_rpm(ctx, dir, name)?);
            }
        }
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    ctx.ok(Dnf, &args).map(drop)
}

pub fn packages_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let names = platform_packages(ctx.plan);
    let mut args = vec!["-q", "--quiet"];
    args.extend(&names);
    Ok(if ctx.succeeds(Rpm, &args) {
        StepState::Done(format!("installed: {}", names.join(" ")))
    } else {
        StepState::Todo
    })
}

pub fn packages_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let names = platform_packages(ctx.plan);
    install(ctx, &names)?;
    Ok(StepState::Done(format!("installed: {}", names.join(" "))))
}

const PG_VERSION: &str = "/var/lib/pgsql/data/PG_VERSION";

pub fn postgres_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let done = ctx.succeeds(Rpm, &["-q", "--quiet", "postgresql-server"])
        && ctx.exists(PG_VERSION)
        && ctx.succeeds(Systemctl, &["is-active", "--quiet", "postgresql"]);
    Ok(if done { StepState::Done("PostgreSQL installed and running".into()) } else { StepState::Todo })
}

pub fn postgres_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.succeeds(Rpm, &["-q", "--quiet", "postgresql-server"]) {
        ctx.ok(Dnf, &["install", "-y", "postgresql-server"])?;
    }
    if !ctx.exists(PG_VERSION) {
        ctx.ok(PostgresqlSetup, &["--initdb"])?;
    }
    ctx.ok(Systemctl, &["enable", "--now", "postgresql"])?;
    Ok(StepState::Done("PostgreSQL installed and running".into()))
}
```

`src/setup/mod.rs`:

```rust
//! The root side of Setup (admin TUI spec §6): each step's check and
//! action, run by `helper setup-step` (the TUI, through sudo) and
//! `setup --quick` (as root). Every step checks first, so re-running is
//! safe and resumes.

mod base;
#[cfg(test)]
mod fake;
pub mod plan;
mod system;

use platform_host::{Step, StepState, runner::Runner};

pub use system::Ctx;

/// Whether the step is done (a check that cannot run is `Failed`).
pub fn check<R: Runner>(ctx: &Ctx<R>, step: Step) -> StepState {
    let result = match step {
        Step::Packages => base::packages_check(ctx),
        Step::Postgres => base::postgres_check(ctx),
        // Removed in Task 8, when every step has its module.
        other => Err(format!("{} is not implemented yet", other.name())),
    };
    result.unwrap_or_else(StepState::Failed)
}

/// Does the step.
pub fn apply<R: Runner>(ctx: &Ctx<R>, step: Step) -> StepState {
    let result = match step {
        Step::Packages => base::packages_apply(ctx),
        Step::Postgres => base::postgres_apply(ctx),
        other => Err(format!("{} is not implemented yet", other.name())),
    };
    result.unwrap_or_else(StepState::Failed)
}

/// Checks the step and does it unless it is done or skipped.
pub fn run_step<R: Runner>(ctx: &Ctx<R>, step: Step) -> StepState {
    match check(ctx, step) {
        state @ (StepState::Done(_) | StepState::Skipped(_)) => state,
        _ => apply(ctx, step),
    }
}

/// Runs every step in order until one fails or waits; true when all
/// finished.
pub fn run_all<R: Runner>(ctx: &Ctx<R>, mut report: impl FnMut(Step, &StepState)) -> bool {
    for step in Step::ALL {
        let state = run_step(ctx, step);
        report(step, &state);
        if !state.finished() {
            return false;
        }
    }
    true
}
```

- [ ] **Step 5: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::`
Expected: PASS (plan and base tests).

- [ ] **Step 6: Commit.**

```bash
git add crates/openvibes-admin/src/setup
git commit -m "admin: Setup step engine, packages and PostgreSQL steps

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Operator group, database and schema steps

**Files:**
- Modify: `crates/openvibes-admin/src/setup/{base.rs,mod.rs}`

**Interfaces — Produces:** `operators_check/apply`, `database_check/apply`, `schema_check/apply` in `base.rs`, dispatched from `mod.rs`.

- [ ] **Step 1: Failing tests** in `base.rs`'s test module:

```rust
    #[test]
    fn the_invoking_user_joins_the_operators() {
        let fake = Fake::new("operators");
        fake.answer(&["/usr/sbin/usermod", "-aG", "openvibes-operators", "alice"], 0, "");
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Operators);
        assert!(state.detail().contains("log in again"), "{state:?}");
        assert!(fake.called(&["/usr/sbin/usermod"]));

        let fake = Fake::new("operators-member");
        fake.file("/etc/group", "openvibes-operators:x:990:bob,alice\n");
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Operators);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(!fake.called(&["/usr/sbin/usermod"]));

        let mut as_root = plan(&[Ingest]);
        as_root.operator = None;
        assert!(matches!(run_step(&fake.ctx(&as_root), Step::Operators), StepState::Skipped(_)));
    }

    #[test]
    fn the_database_and_role_are_created_only_when_missing() {
        let fake = Fake::new("database");
        let psql = ["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql", "-Atqc"];
        fake.answer(&[&psql[..], &["SELECT 1 FROM pg_roles WHERE rolname = 'openvibes-admin'"]].concat(), 0, "1\n");
        fake.answer(&[&psql[..], &["SELECT 1 FROM pg_database WHERE datname = 'openvibes'"]].concat(), 0, "");
        fake.answer(&["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/createdb", "-O", "openvibes-admin", "openvibes"], 0, "");
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Database);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(!fake.called(&["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/createuser"]));
        assert!(fake.called(&["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/createdb"]));
    }

    #[test]
    fn the_schema_is_migrated_and_partitions_created() {
        let fake = Fake::new("schema");
        let admin = ["/usr/sbin/runuser", "-u", "openvibes-admin", "--", "/usr/bin/openvibes-admin"];
        fake.answer(&[&admin[..], &["status"]].concat(), 1, "");
        fake.answer(&[&admin[..], &["migrate"]].concat(), 0, "schema version 24\n");
        fake.answer(&[&admin[..], &["maintenance"]].concat(), 0, "created 97 partitions\n");
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Schema);
        assert_eq!(state, StepState::Done("schema version 24; created 97 partitions".into()));
    }
```

- [ ] **Step 2: Run, expect FAIL** (the steps still answer "is not implemented yet").

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::base`
Expected: FAIL in the three new tests.

- [ ] **Step 3: Implement** in `base.rs` (add `Usermod` to the `Program` imports):

```rust
const OPERATORS: &str = "openvibes-operators";

pub fn operators_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let Some(user) = &ctx.plan.operator else {
        return Ok(StepState::Skipped(
            "no invoking user: Setup was run as root directly".into(),
        ));
    };
    let groups = ctx.read("/etc/group")?;
    let members = groups
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{OPERATORS}:")))
        .ok_or("group openvibes-operators is missing: is openvibes-admin installed?")?
        .rsplit(':')
        .next()
        .unwrap_or("");
    Ok(if members.split(',').any(|member| member == user) {
        StepState::Done(format!("{user} is an operator"))
    } else {
        StepState::Todo
    })
}

pub fn operators_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let Some(user) = &ctx.plan.operator else {
        return operators_check(ctx);
    };
    ctx.ok(Usermod, &["-aG", OPERATORS, user])?;
    Ok(StepState::Done(format!(
        "{user} added to {OPERATORS}; log in again for it to take effect"
    )))
}

fn query<R: Runner>(ctx: &Ctx<R>, sql: &str) -> Result<bool, String> {
    Ok(ctx.as_postgres(&["/usr/bin/psql", "-Atqc", sql])?.trim() == "1")
}

const ROLE: &str = "SELECT 1 FROM pg_roles WHERE rolname = 'openvibes-admin'";
const DATABASE: &str = "SELECT 1 FROM pg_database WHERE datname = 'openvibes'";

pub fn database_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    Ok(if query(ctx, ROLE)? && query(ctx, DATABASE)? {
        StepState::Done("database openvibes owned by openvibes-admin".into())
    } else {
        StepState::Todo
    })
}

pub fn database_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !query(ctx, ROLE)? {
        ctx.as_postgres(&["/usr/bin/createuser", "--createrole", "openvibes-admin"])?;
    }
    if !query(ctx, DATABASE)? {
        ctx.as_postgres(&["/usr/bin/createdb", "-O", "openvibes-admin", "openvibes"])?;
    }
    Ok(StepState::Done("database openvibes owned by openvibes-admin".into()))
}
```

```rust
pub fn schema_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    // `status` refuses unless the schema is current.
    Ok(if ctx.as_admin(&["status"]).is_ok() {
        StepState::Done("schema current".into())
    } else {
        StepState::Todo
    })
}

pub fn schema_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let migrated = ctx.as_admin(&["migrate"])?;
    let maintained = ctx.as_admin(&["maintenance"])?;
    Ok(StepState::Done(format!("{}; {}", migrated.trim(), maintained.trim())))
}
```

In `mod.rs`, add the arms to `check` and `apply`:

```rust
        Step::Operators => base::operators_check(ctx),
        Step::Database => base::database_check(ctx),
        Step::Schema => base::schema_check(ctx),
```

```rust
        Step::Operators => base::operators_apply(ctx),
        Step::Database => base::database_apply(ctx),
        Step::Schema => base::schema_apply(ctx),
```

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin/src/setup
git commit -m "admin: Setup operator group, database and schema steps

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: CA and server certificate steps

**Files:**
- Create: `crates/openvibes-admin/src/setup/pki.rs`
- Modify: `crates/openvibes-admin/src/setup/mod.rs`

**Interfaces — Produces:** `pub const ROOT_CERT: &str = "/etc/openvibes/pki/root.crt";`, `pub fn fingerprint(pem: &str) -> Result<String, String>` (uppercase hex pairs joined by `:`), `ca_check/apply`, `certificates_check/apply`.

- [ ] **Step 1: Failing tests** at the end of `pki.rs`:

```rust
#[cfg(test)]
mod tests {
    use platform_host::{Step, StepState};

    use crate::setup::{fake::{Fake, plan}, plan::{CaMode, Component::*}, run_step};

    const ADMIN: [&str; 5] = ["/usr/sbin/runuser", "-u", "openvibes-admin", "--", "/usr/bin/openvibes-admin"];

    fn with(prefix: &[&str], rest: &[&str]) -> Vec<&'static str> {
        prefix.iter().chain(rest).map(|s| &*Box::leak((*s).to_owned().into_boxed_str())).collect()
    }

    /// The CA commands as fakes that write what the real ones write.
    fn ca_commands(fake: &Fake) {
        fake.effect(&["/usr/bin/openvibes-admin", "ca", "init-root"], |root| {
            let dir = root.join("run/openvibes-ca/root");
            std::fs::create_dir_all(&dir).unwrap();
            let ca = platform_pki::generate_root(chrono::Utc::now()).unwrap();
            std::fs::write(dir.join("root.crt"), &ca.cert_pem).unwrap();
            std::fs::write(dir.join("root.key"), &ca.key_pem).unwrap();
        });
        fake.effect(&with(&ADMIN, &["ca", "intermediate-request"]), |root| {
            let dir = root.join("run/openvibes-ca/int");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("intermediate.csr"), "CSR").unwrap();
            std::fs::write(dir.join("intermediate.key"), "INTERMEDIATE KEY").unwrap();
        });
        fake.effect(&["/usr/bin/openvibes-admin", "ca", "sign-intermediate"], |root| {
            std::fs::write(root.join("run/openvibes-ca/int/intermediate.crt"), "INTERMEDIATE").unwrap();
        });
        fake.answer(&with(&ADMIN, &["ca", "import-intermediate"]), 0, "");
    }

    #[test]
    fn quick_ca_keeps_only_the_root_certificate_and_the_chosen_key_copy() {
        let fake = Fake::new("ca-quick");
        ca_commands(&fake);
        fake.file("/run/openvibes-ca/stale", "left by a failed run");
        let mut plan = plan(&[Ingest]);
        plan.root_key_out = Some("/media/usb/openvibes-root.key".into());
        std::fs::create_dir_all(fake.root.join("media/usb")).unwrap();
        let state = run_step(&fake.ctx(&plan), Step::Ca);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(state.detail().contains("/media/usb/openvibes-root.key"), "{state:?}");
        assert!(state.detail().contains("SHA-256 "), "{state:?}");
        assert!(fake.text("/etc/openvibes/pki/root.crt").contains("BEGIN CERTIFICATE"));
        assert_eq!(fake.text("/etc/openvibes/pki/intermediate.crt"), "INTERMEDIATE");
        assert_eq!(fake.text("/var/lib/openvibes-ingest/intermediate.key"), "INTERMEDIATE KEY");
        assert!(fake.text("/media/usb/openvibes-root.key").contains("PRIVATE KEY"));
        assert!(!fake.root.join("run/openvibes-ca").exists(), "staging removed");
        use std::os::unix::fs::PermissionsExt;
        let mode = |abs: &str| std::fs::metadata(fake.root.join(abs.trim_start_matches('/'))).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode("/var/lib/openvibes-ingest/intermediate.key"), 0o600);
        assert_eq!(mode("/media/usb/openvibes-root.key"), 0o600);
        assert_eq!(mode("/etc/openvibes/pki/root.crt"), 0o644);
        // Done now: a second run changes nothing.
        let calls = fake.calls.borrow().len();
        assert!(matches!(run_step(&fake.ctx(&plan), Step::Ca), StepState::Done(_)));
        assert_eq!(fake.calls.borrow().len(), calls);
    }

    #[test]
    fn a_stale_staging_directory_is_replaced() {
        let fake = Fake::new("ca-stale");
        ca_commands(&fake);
        fake.file("/run/openvibes-ca/root/root.crt", "half-written by a failed run");
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Ca);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(state.detail().contains("root key deleted"), "{state:?}");
    }

    #[test]
    fn an_existing_root_key_file_is_not_overwritten() {
        let fake = Fake::new("ca-existing-key");
        ca_commands(&fake);
        fake.file("/media/usb/openvibes-root.key", "an older root key");
        let mut plan = plan(&[Ingest]);
        plan.root_key_out = Some("/media/usb/openvibes-root.key".into());
        let state = run_step(&fake.ctx(&plan), Step::Ca);
        assert!(state.detail().contains("already exists"), "{state:?}");
        assert_eq!(fake.text("/media/usb/openvibes-root.key"), "an older root key");
        assert!(!fake.called(&["/usr/bin/openvibes-admin", "ca", "init-root"]), "checked before any CA material");
    }

    #[test]
    fn careful_ca_waits_for_the_signed_certificate() {
        let fake = Fake::new("ca-careful");
        ca_commands(&fake);
        let mut plan = plan(&[Ingest]);
        plan.ca = CaMode::Careful;
        let state = run_step(&fake.ctx(&plan), Step::Ca);
        assert!(matches!(state, StepState::Waiting(_)), "{state:?}");
        assert!(state.detail().contains("sign-intermediate"), "{state:?}");
        assert!(!fake.called(&["/usr/bin/openvibes-admin", "ca", "init-root"]));
        assert!(matches!(run_step(&fake.ctx(&plan), Step::Ca), StepState::Waiting(_)));
        let root = platform_pki::generate_root(chrono::Utc::now()).unwrap();
        fake.file("/run/openvibes-ca/int/intermediate.crt", "INTERMEDIATE");
        fake.file("/run/openvibes-ca/int/root.crt", &root.cert_pem);
        let state = run_step(&fake.ctx(&plan), Step::Ca);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(fake.called(&with(&ADMIN, &["ca", "import-intermediate"])));
    }

    #[test]
    fn certificates_are_issued_for_every_name_and_installed() {
        let fake = Fake::new("certificates");
        fake.file("/etc/openvibes/pki/intermediate.crt", "INTERMEDIATE\n");
        fake.file("/var/lib/openvibes-ingest/intermediate.key", "INTERMEDIATE KEY");
        fake.effect(&with(&ADMIN, &["ca", "issue-server"]), |root| {
            for service in ["ingest", "distribution", "console"] {
                let dir = root.join(format!("run/openvibes-ca/{service}"));
                if dir.exists() && !dir.join("platform.example.com.crt").exists() {
                    std::fs::write(dir.join("platform.example.com.crt"), format!("{service} CERT\n")).unwrap();
                    std::fs::write(dir.join("platform.example.com.key"), format!("{service} KEY")).unwrap();
                    return;
                }
            }
            panic!("no output directory");
        });
        let state = run_step(&fake.ctx(&plan(&[Ingest, Console, Distribution])), Step::Certificates);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        let issue = fake.call(&with(&ADMIN, &["ca", "issue-server"]));
        assert_eq!(
            issue[7..],
            ["platform.example.com", "--san", "10.0.0.5", "--san", "localhost", "--san", "127.0.0.1",
             "--issuer-cert", "/run/openvibes-ca/issuer.crt", "--issuer-key", "/run/openvibes-ca/issuer.key",
             "--out", "/run/openvibes-ca/ingest"]
        );
        assert_eq!(fake.text("/etc/openvibes/tls/ingest.crt"), "ingest CERT\n");
        assert_eq!(fake.text("/etc/openvibes/tls/console-chain.pem"), "console CERT\nINTERMEDIATE\n");
        use std::os::unix::fs::PermissionsExt;
        let mode = |abs: &str| std::fs::metadata(fake.root.join(abs.trim_start_matches('/'))).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode("/etc/openvibes/tls/ingest.key"), 0o600);
        assert_eq!(mode("/etc/openvibes/tls/distribution.key"), 0o600);
        assert_eq!(mode("/etc/openvibes/tls/console-key.pem"), 0o640);
        assert_eq!(mode("/etc/openvibes/tls/console-chain.pem"), 0o640);
        assert!(!fake.root.join("run/openvibes-ca").exists());
    }
}
```

The `issue-server` effect relies on the steps creating each service's output directory right before its `issue-server` call (see `stage_dir` below); the effect fills the first created directory without files.

- [ ] **Step 2: Run, expect a compile failure.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::pki`
Expected: FAIL to compile (`pki` module missing).

- [ ] **Step 3: Implement** `pki.rs` above the tests:

```rust
//! Steps 6–7: the CA (quick or careful) and the server certificates, staged
//! in `/run/openvibes-ca` (tmpfs, so key copies never reach disk) and
//! installed where the services read them (packaging.md "First install").

use std::{fs, io::Write, os::unix::fs::OpenOptionsExt};

use platform_host::{StepState, runner::{Program::Admin, Runner}};

use super::{Ctx, plan::{CaMode, Component}};

const STAGE: &str = "/run/openvibes-ca";
const INT: &str = "/run/openvibes-ca/int";
const ROOT_DIR: &str = "/run/openvibes-ca/root";
const INTERMEDIATE: &str = "/etc/openvibes/pki/intermediate.crt";
/// The root certificate agents trust.
pub const ROOT_CERT: &str = "/etc/openvibes/pki/root.crt";
const INTERMEDIATE_KEY: &str = "/var/lib/openvibes-ingest/intermediate.key";
const ADMIN_OWNER: Option<(&str, &str)> = Some(("openvibes-admin", "openvibes-admin"));

/// `AB:CD:…`, the SHA-256 of a certificate.
pub fn fingerprint(pem: &str) -> Result<String, String> {
    let digest = platform_pki::sha256_fingerprint(pem).map_err(|error| format!("root certificate: {error:?}"))?;
    Ok(digest.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"))
}

fn root_summary<R: Runner>(ctx: &Ctx<R>) -> Result<String, String> {
    Ok(format!("root certificate {ROOT_CERT}, SHA-256 {}", fingerprint(&ctx.read(ROOT_CERT)?)?))
}

fn careful_help() -> String {
    format!(
        "sign {INT}/intermediate.csr on the offline machine (openvibes-admin ca sign-intermediate \
         --root ROOT_DIR --csr intermediate.csr --out intermediate.crt), then copy intermediate.crt \
         and root.crt into {INT} and run this step again; the request is lost on reboot"
    )
}

pub fn ca_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if ctx.exists(INTERMEDIATE) && ctx.exists(ROOT_CERT) && ctx.exists(INTERMEDIATE_KEY) {
        return Ok(StepState::Done(root_summary(ctx)?));
    }
    let signed = ctx.exists(&format!("{INT}/intermediate.crt")) && ctx.exists(&format!("{INT}/root.crt"));
    if ctx.plan.ca == CaMode::Careful && ctx.exists(&format!("{INT}/intermediate.csr")) && !signed {
        return Ok(StepState::Waiting(careful_help()));
    }
    Ok(StepState::Todo)
}

/// A fresh staging directory, 0700 openvibes-admin (a stale one from a
/// failed run is removed: it is in tmpfs and only ever ours).
fn fresh_stage<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    let path = ctx.path(STAGE);
    if path.exists() {
        fs::remove_dir_all(&path).map_err(|error| format!("{STAGE}: {error}"))?;
    }
    stage_dir(ctx, STAGE)
}

/// Creates `abs` (0700, openvibes-admin) for a command run as that user.
fn stage_dir<R: Runner>(ctx: &Ctx<R>, abs: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let path = ctx.path(abs);
    fs::create_dir_all(&path).map_err(|error| format!("{abs}: {error}"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|error| format!("{abs}: {error}"))?;
    ctx.chown(abs, ADMIN_OWNER)
}

fn remove_stage<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    fs::remove_dir_all(ctx.path(STAGE)).map_err(|error| format!("{STAGE}: {error}"))
}

/// Imports the signed intermediate and installs the CA files.
fn import_and_install<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    for file in ["intermediate.crt", "root.crt"] {
        ctx.chown(&format!("{INT}/{file}"), ADMIN_OWNER)?;
    }
    ctx.as_admin(&[
        "ca", "import-intermediate",
        "--cert", &format!("{INT}/intermediate.crt"),
        "--key", &format!("{INT}/intermediate.key"),
        "--root-cert", &format!("{INT}/root.crt"),
    ])?;
    ctx.copy(&format!("{INT}/intermediate.crt"), INTERMEDIATE, None, 0o644)?;
    ctx.copy(&format!("{INT}/root.crt"), ROOT_CERT, None, 0o644)?;
    ctx.copy(&format!("{INT}/intermediate.key"), INTERMEDIATE_KEY, Some(("openvibes-ingest", "openvibes-ingest")), 0o600)?;
    remove_stage(ctx)
}

/// Writes the root key once to `root_key_out` (never over an existing
/// file); what happened to it.
fn keep_root_key<R: Runner>(ctx: &Ctx<R>) -> Result<String, String> {
    let Some(out) = &ctx.plan.root_key_out else {
        return Ok("root key deleted (a new intermediate will need a new root)".into());
    };
    let key = fs::read(ctx.path(&format!("{ROOT_DIR}/root.key"))).map_err(|error| format!("root key: {error}"))?;
    let shown = out.display().to_string();
    let path = ctx.path(&shown);
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)
        .map_err(|error| format!("{shown}: {error}"))?;
    file.write_all(&key).and_then(|()| file.sync_all()).map_err(|error| format!("{shown}: {error}"))?;
    if let Some(user) = &ctx.plan.operator {
        ctx.chown(&shown, Some((user, user)))?;
    }
    Ok(format!("root key saved to {shown}: keep it offline"))
}

fn quick<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if let Some(out) = &ctx.plan.root_key_out
        && ctx.path(&out.display().to_string()).exists()
    {
        return Err(format!("{} already exists; choose another file for the root key", out.display()));
    }
    fresh_stage(ctx)?;
    ctx.ok(Admin, &["ca", "init-root", "--out", ROOT_DIR])?;
    ctx.as_admin(&["ca", "intermediate-request", "--out", INT])?;
    ctx.ok(Admin, &[
        "ca", "sign-intermediate",
        "--root", ROOT_DIR,
        "--csr", &format!("{INT}/intermediate.csr"),
        "--out", &format!("{INT}/intermediate.crt"),
    ])?;
    ctx.copy(&format!("{ROOT_DIR}/root.crt"), &format!("{INT}/root.crt"), ADMIN_OWNER, 0o644)?;
    let kept = keep_root_key(ctx)?;
    import_and_install(ctx)?;
    Ok(StepState::Done(format!("{kept}; {}", root_summary(ctx)?)))
}

fn careful<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if ctx.exists(&format!("{INT}/intermediate.crt")) && ctx.exists(&format!("{INT}/root.crt")) {
        import_and_install(ctx)?;
        return Ok(StepState::Done(root_summary(ctx)?));
    }
    if !ctx.exists(&format!("{INT}/intermediate.csr")) {
        fresh_stage(ctx)?;
        ctx.as_admin(&["ca", "intermediate-request", "--out", INT])?;
    }
    Ok(StepState::Waiting(careful_help()))
}

pub fn ca_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    match ctx.plan.ca {
        CaMode::Quick => quick(ctx),
        CaMode::Careful => careful(ctx),
    }
}

/// Where one service's certificate goes.
struct Tls {
    component: Component,
    stem: &'static str,
    cert: &'static str,
    key: &'static str,
    /// Console: certificate then intermediate in one file, both 0640
    /// root:openvibes-console; otherwise the key belongs to the service.
    console: bool,
    owner: &'static str,
}

const TLS: [Tls; 3] = [
    Tls { component: Component::Ingest, stem: "ingest", cert: "/etc/openvibes/tls/ingest.crt", key: "/etc/openvibes/tls/ingest.key", console: false, owner: "openvibes-ingest" },
    Tls { component: Component::Distribution, stem: "distribution", cert: "/etc/openvibes/tls/distribution.crt", key: "/etc/openvibes/tls/distribution.key", console: false, owner: "openvibes-distribution" },
    Tls { component: Component::Console, stem: "console", cert: "/etc/openvibes/tls/console-chain.pem", key: "/etc/openvibes/tls/console-key.pem", console: true, owner: "openvibes-console" },
];

fn chosen<R: Runner>(ctx: &Ctx<R>) -> impl Iterator<Item = &'static Tls> + '_ {
    TLS.iter().filter(|tls| ctx.plan.has(tls.component))
}

pub fn certificates_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    Ok(if chosen(ctx).all(|tls| ctx.exists(tls.cert) && ctx.exists(tls.key)) {
        StepState::Done(format!("server certificates for {}", ctx.plan.names().join(", ")))
    } else {
        StepState::Todo
    })
}

pub fn certificates_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let names = ctx.plan.names();
    fresh_stage(ctx)?;
    ctx.copy(INTERMEDIATE, &format!("{STAGE}/issuer.crt"), ADMIN_OWNER, 0o644)?;
    ctx.copy(INTERMEDIATE_KEY, &format!("{STAGE}/issuer.key"), ADMIN_OWNER, 0o600)?;
    for tls in chosen(ctx) {
        let out = format!("{STAGE}/{}", tls.stem);
        stage_dir(ctx, &out)?;
        let mut args = vec!["ca", "issue-server", names[0].as_str()];
        for san in &names[1..] {
            args.extend(["--san", san.as_str()]);
        }
        let issuer_cert = format!("{STAGE}/issuer.crt");
        let issuer_key = format!("{STAGE}/issuer.key");
        args.extend(["--issuer-cert", &issuer_cert, "--issuer-key", &issuer_key, "--out", &out]);
        ctx.as_admin(&args)?;
        let crt = format!("{out}/{}.crt", names[0]);
        let key = format!("{out}/{}.key", names[0]);
        if tls.console {
            let chain = format!("{}{}", ctx.read(&crt)?, ctx.read(INTERMEDIATE)?);
            let owner = Some(("root", tls.owner));
            ctx.put(tls.cert, chain.as_bytes(), owner, 0o640)?;
            ctx.copy(&key, tls.key, owner, 0o640)?;
        } else {
            ctx.copy(&crt, tls.cert, None, 0o644)?;
            ctx.copy(&key, tls.key, Some((tls.owner, tls.owner)), 0o600)?;
        }
    }
    remove_stage(ctx)?;
    Ok(StepState::Done(format!("server certificates for {} (valid 90 days)", names.join(", "))))
}
```

`intermediate-request --out INT` creates `INT` as openvibes-admin inside the 0700 staging directory it owns (as the e2e script does today).

In `mod.rs`: `mod pki;` and the arms:

```rust
        Step::Ca => pki::ca_check(ctx),
        Step::Certificates => pki::certificates_check(ctx),
```

```rust
        Step::Ca => pki::ca_apply(ctx),
        Step::Certificates => pki::certificates_apply(ctx),
```

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin/src/setup
git commit -m "admin: Setup CA (quick and careful) and server certificate steps

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Console step and `user create --password-stdin`

**Files:**
- Create: `crates/openvibes-admin/src/setup/console.rs`
- Modify: `crates/openvibes-admin/src/user.rs`, `crates/openvibes-admin/src/setup/mod.rs`, `crates/openvibes-admin/tests/{cli.rs,common/mod.rs}`, `docs/components/openvibes-admin.md`

**Interfaces — Produces:** `openvibes-admin user create … --password-stdin` (one line from stdin, no confirmation; same rules as the prompt); `console_check/apply`.

- [ ] **Step 1: Failing tests.** In `setup/console.rs`:

```rust
#[cfg(test)]
mod tests {
    use platform_host::{Step, StepState};

    use crate::setup::{fake::{Fake, plan}, plan::Component::*, run_step};

    const ADMIN: [&str; 5] = ["/usr/sbin/runuser", "-u", "openvibes-admin", "--", "/usr/bin/openvibes-admin"];

    fn console(fake: &Fake) {
        fake.file("/etc/openvibes/console.toml", include_str!("../../../../packaging/rpm/console.toml"));
        fake.answer(&[&ADMIN[..], &["user", "list"]].concat(), 0, "USERNAME\tSTATUS\tROLES\tDISPLAY NAME\tLAST SEEN\n");
        fake.answer(&[&ADMIN[..], &["user", "create"]].concat(), 0, "created admin\n");
    }

    #[test]
    fn the_origin_is_set_and_an_admin_created_with_a_generated_password() {
        let fake = Fake::new("console");
        console(&fake);
        let state = run_step(&fake.ctx(&plan(&[Ingest, Console])), Step::Console);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(fake.text("/etc/openvibes/console.toml").contains("public_origin = \"https://platform.example.com\""));
        assert!(fake.text("/etc/openvibes/console.toml").contains("# "), "comments kept");
        let create = fake.call(&[&ADMIN[..], &["user", "create"]].concat());
        assert_eq!(create[5..], ["user", "create", "--username", "admin", "--display-name", "Administrator", "--role", "admin", "--password-stdin"]);
        let password = fake.inputs.borrow()[0].trim_end().to_owned();
        assert_eq!(password.len(), 24);
        assert!(state.detail().contains(&password), "the generated password is shown once");
    }

    #[test]
    fn a_password_file_is_used_and_not_shown() {
        let fake = Fake::new("console-password-file");
        console(&fake);
        fake.file("/root/admin-password", "correct horse battery staple\n");
        let mut plan = plan(&[Ingest, Console]);
        plan.admin_password_file = Some("/root/admin-password".into());
        let state = run_step(&fake.ctx(&plan), Step::Console);
        assert_eq!(fake.inputs.borrow()[0], "correct horse battery staple\n");
        assert!(!state.detail().contains("correct horse"), "{state:?}");
    }

    #[test]
    fn without_the_console_the_step_is_skipped() {
        let fake = Fake::new("console-skipped");
        assert!(matches!(run_step(&fake.ctx(&plan(&[Ingest])), Step::Console), StepState::Skipped(_)));
    }
}
```

In `tests/common/mod.rs`, add to `impl Fixture` (next to `run_with`):

```rust
    /// As `run`, with `input` on standard input.
    pub fn run_input(&self, args: &[&str], input: &str) -> Output {
        use std::io::Write;
        let mut child = Command::new(env!("CARGO_BIN_EXE_openvibes-admin"))
            .arg("--config")
            .arg(&self.config)
            .args(args)
            .env("USER", "ov-test")
            .env_remove("SUDO_USER")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    }
```

and in `tests/cli.rs`:

```rust
#[tokio::test]
async fn user_create_reads_one_password_line_from_stdin() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let create = |name: &'static str| {
        ["user", "create", "--username", name, "--display-name", "Example", "--password-stdin"]
    };
    let out = fixture.run_input(&create("admin"), "correct horse battery staple\n");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout(&fixture.run(&["user", "list"])).lines().any(|l| l.starts_with("admin\t")));
    let short = fixture.run_input(&create("bob"), "short\n");
    assert!(!short.status.success());
    assert!(String::from_utf8_lossy(&short.stderr).contains("15 to 128"));
    fixture.drop().await;
}
```

- [ ] **Step 2: Run, expect FAIL.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::console; cargo test -p openvibes-admin --test cli user_create_reads`
Expected: FAIL (module missing; `--password-stdin` unknown).

- [ ] **Step 3: Implement.** `user.rs`: add to `UserCommand::Create`:

```rust
        /// Read the password from one line of standard input instead of
        /// prompting twice (for scripts and Setup).
        #[arg(long)]
        password_stdin: bool,
```

and where `Create` reads the password, use:

```rust
            let password = if *password_stdin { password_from_stdin() } else { confirmed_password() };
            let password = match password {
```

(keeping the existing error handling), with:

```rust
/// One line of standard input as the new password (at most 1 KiB).
fn password_from_stdin() -> Result<NormalizedPassword, String> {
    use std::io::{BufRead, Read};
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .take(1024)
        .read_line(&mut line)
        .map_err(|_| "could not read the password from standard input".to_owned())?;
    let password = line.trim_end_matches(['\n', '\r']);
    NormalizedPassword::new(password).map_err(|_| {
        "password must be 15 to 128 Unicode characters and not a blocked common passphrase".into()
    })
}
```

(The error text must match `confirmed_password`'s so both paths read the same.)

`setup/console.rs` above the tests:

```rust
//! Step 8: the console's public origin and the first admin account
//! (packaging.md "Console RPM setup"). The TLS files come from step 7.

use platform_host::{Service, StepState, runner::Runner};
use ring::rand::{SecureRandom, SystemRandom};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use super::{Ctx, plan::Component};
use crate::config_file;

const CONSOLE_TOML: &str = "/etc/openvibes/console.toml";

fn origin<R: Runner>(ctx: &Ctx<R>) -> String {
    format!("https://{}", ctx.plan.hostname)
}

fn origin_set<R: Runner>(ctx: &Ctx<R>) -> Result<bool, String> {
    let table: toml::Table = toml::from_str(&ctx.read(CONSOLE_TOML)?).map_err(|error| format!("{CONSOLE_TOML}: {error}"))?;
    Ok(table.get("public_origin").and_then(toml::Value::as_str) == Some(origin(ctx).as_str()))
}

fn admin_exists<R: Runner>(ctx: &Ctx<R>) -> Result<bool, String> {
    Ok(ctx
        .as_admin(&["user", "list"])?
        .lines()
        .skip(1)
        .any(|line| line.split('\t').next() == Some("admin")))
}

pub fn console_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Console) {
        return Ok(StepState::Skipped("console not chosen".into()));
    }
    Ok(if origin_set(ctx)? && admin_exists(ctx)? {
        StepState::Done(format!("{} · console admin: admin", origin(ctx)))
    } else {
        StepState::Todo
    })
}

/// 24 characters, base64url of 18 random bytes.
fn generated_password() -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new([0_u8; 18]);
    SystemRandom::new().fill(&mut *bytes).map_err(|_| "could not generate a password".to_owned())?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(*bytes)))
}

pub fn console_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Console) {
        return console_check(ctx);
    }
    if !origin_set(ctx)? {
        let mut doc: toml_edit::DocumentMut = ctx.read(CONSOLE_TOML)?.parse().map_err(|error| format!("{CONSOLE_TOML}: {error}"))?;
        doc["public_origin"] = toml_edit::value(origin(ctx));
        config_file::replace(&ctx.path("/etc/openvibes"), Service::Console, &doc.to_string())?;
    }
    let mut shown = "console admin: admin".to_owned();
    if !admin_exists(ctx)? {
        let (password, generated) = match &ctx.plan.admin_password_file {
            Some(file) => {
                let text = Zeroizing::new(ctx.read(&file.display().to_string())?);
                (Zeroizing::new(text.lines().next().unwrap_or("").to_owned()), false)
            }
            None => (generated_password()?, true),
        };
        let input = Zeroizing::new(format!("{}\n", *password));
        ctx.as_admin_with_input(
            &["user", "create", "--username", "admin", "--display-name", "Administrator", "--role", "admin", "--password-stdin"],
            input.as_bytes(),
        )?;
        if generated {
            shown = format!("console admin: admin, password {} (shown only now; change it after logging in)", *password);
        }
    }
    Ok(StepState::Done(format!("{} · {shown}", origin(ctx))))
}
```

In `mod.rs`: `mod console;` and the arms `Step::Console => console::console_check(ctx)` / `console::console_apply(ctx)`.

`docs/components/openvibes-admin.md`: document `user create --password-stdin`.

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup:: && eval "$(scripts/test-db.sh)" && cargo test -p openvibes-admin --test cli user_create_reads`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin docs/components/openvibes-admin.md
git commit -m "admin: Setup console step; user create --password-stdin

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Services, firewall and readiness steps

**Files:**
- Create: `crates/openvibes-admin/src/setup/run.rs`
- Modify: `crates/openvibes-admin/src/setup/mod.rs`

**Interfaces — Produces:** `services_check/apply`, `firewall_check/apply`, `ready_check/apply`; `pub fn token_from(output: &str) -> Result<String, String>` (the 43-character token from `token create`'s `token X` line).

- [ ] **Step 1: Failing tests** at the end of `run.rs`:

```rust
#[cfg(test)]
mod tests {
    use platform_host::{Step, StepState};

    use crate::setup::{fake::{Fake, plan}, plan::Component::*, run_step};

    const TOKEN: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

    #[test]
    fn chosen_services_are_enabled_and_started() {
        let fake = Fake::new("services");
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
        fake.answer(&["/usr/bin/systemctl", "enable", "--now"], 0, "");
        let state = run_step(&fake.ctx(&plan(&[Ingest, Vulns, Assistant])), Step::Services);
        assert!(state.detail().contains("openvibes-llm"), "the model server is left to the user: {state:?}");
        assert_eq!(
            fake.call(&["/usr/bin/systemctl", "enable"]),
            ["/usr/bin/systemctl", "enable", "--now", "openvibes-ingest.service",
             "openvibes-maintenance.timer", "openvibes-vulns.service"]
        );
    }

    #[test]
    fn firewall_ports_are_opened_or_the_step_skipped() {
        let fake = Fake::new("firewall");
        fake.file("/etc/openvibes/console.toml", "development_listen = \"0.0.0.0:8443\"\ntransport_mode = \"direct_tls\"\n");
        fake.answer(&["/usr/bin/firewall-cmd", "--state"], 0, "running\n");
        fake.answer(&["/usr/bin/firewall-cmd", "--permanent", "--query-port", "18423/tcp"], 0, "yes\n");
        fake.answer(&["/usr/bin/firewall-cmd", "--permanent", "--query-port"], 1, "no\n");
        fake.answer(&["/usr/bin/firewall-cmd", "--permanent", "--add-port"], 0, "success\n");
        fake.answer(&["/usr/bin/firewall-cmd", "--reload"], 0, "success\n");
        let state = run_step(&fake.ctx(&plan(&[Ingest, Console, Distribution])), Step::Firewall);
        assert_eq!(state, StepState::Done("open: 18423/tcp 18424/tcp 8443/tcp".into()));
        let added: Vec<String> = fake.calls.borrow().iter()
            .filter(|c| c.get(2).is_some_and(|a| a == "--add-port")).map(|c| c[3].clone()).collect();
        assert_eq!(added, ["18424/tcp", "8443/tcp"], "18423 was already open");
        assert!(fake.called(&["/usr/bin/firewall-cmd", "--reload"]));

        let fake = Fake::new("firewall-off");
        assert!(matches!(run_step(&fake.ctx(&plan(&[Ingest])), Step::Firewall), StepState::Skipped(_)));
    }

    #[test]
    fn readiness_waits_then_creates_an_endpoint_token() {
        let fake = Fake::new("ready");
        fake.answer(&["/usr/bin/curl"], 0, "");
        fake.answer(
            &["/usr/sbin/runuser", "-u", "openvibes-admin", "--", "/usr/bin/openvibes-admin", "token", "create", "--expires", "24h", "--uses", "10"],
            0,
            &format!("id 7\ntoken {TOKEN}\n"),
        );
        // The check finds everything ready: Done without a token.
        assert!(matches!(run_step(&fake.ctx(&plan(&[Ingest])), Step::Ready), StepState::Done(_)));
        assert!(!fake.called(&["/usr/sbin/runuser"]));
        let state = crate::setup::apply(&fake.ctx(&plan(&[Ingest])), Step::Ready);
        assert!(state.detail().contains(TOKEN), "{state:?}");

        let fake = Fake::new("not-ready");
        fake.answer(&["/usr/bin/curl"], 7, "");
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Ready);
        assert!(state.detail().contains("openvibes-ingest.service is not ready"), "{state:?}");
    }

    #[test]
    fn tokens_are_read_from_token_create() {
        assert_eq!(super::token_from(&format!("id 1\ntoken {TOKEN}\n")).unwrap(), TOKEN);
        assert!(super::token_from("token short\n").is_err());
        assert!(super::token_from("nothing\n").is_err());
    }
}
```

- [ ] **Step 2: Run, expect a compile failure.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::run`
Expected: FAIL to compile.

- [ ] **Step 3: Implement** `run.rs`:

```rust
//! Steps 9, 10 and 13: services enabled and started, firewall ports,
//! readiness and an endpoint enrollment token.

use platform_host::{StepState, Unit, runner::{Program::{Curl, FirewallCmd, Systemctl}, Runner}};

use super::{Ctx, plan::Component};

const READY_ATTEMPTS: u32 = 30;

fn units<R: Runner>(ctx: &Ctx<R>) -> Vec<Unit> {
    ctx.plan.components.iter().flat_map(|c| c.units()).copied().collect()
}

fn names(units: &[Unit]) -> Vec<&'static str> {
    units.iter().map(|u| u.name()).collect()
}

pub fn services_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let units = units(ctx);
    let running = units.iter().all(|unit| {
        ctx.succeeds(Systemctl, &["is-enabled", "--quiet", unit.name()])
            && ctx.succeeds(Systemctl, &["is-active", "--quiet", unit.name()])
    });
    Ok(if running { StepState::Done(done_text(ctx, &units)) } else { StepState::Todo })
}

fn done_text<R: Runner>(ctx: &Ctx<R>, units: &[Unit]) -> String {
    let mut text = format!("enabled and started: {}", names(units).join(" "));
    if ctx.plan.has(Component::Assistant) {
        text.push_str("; start openvibes-llm after installing a model (docs/components/openvibes-llm.md)");
    }
    text
}

pub fn services_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let units = units(ctx);
    let mut args = vec!["enable", "--now"];
    args.extend(names(&units));
    ctx.ok(Systemctl, &args)?;
    Ok(StepState::Done(done_text(ctx, &units)))
}

fn console_port<R: Runner>(ctx: &Ctx<R>) -> Result<Option<String>, String> {
    let table: toml::Table = toml::from_str(&ctx.read("/etc/openvibes/console.toml")?).map_err(|error| error.to_string())?;
    if table.get("transport_mode").and_then(toml::Value::as_str) != Some("direct_tls") {
        return Ok(None); // behind a proxy: the proxy's port is not ours to open
    }
    let listen = table.get("development_listen").and_then(toml::Value::as_str).unwrap_or("0.0.0.0:443");
    let port = listen.parse::<std::net::SocketAddr>().map_err(|error| format!("development_listen: {error}"))?.port();
    Ok(Some(format!("{port}/tcp")))
}

fn ports<R: Runner>(ctx: &Ctx<R>) -> Result<Vec<String>, String> {
    let mut ports = vec!["18423/tcp".to_owned()];
    if ctx.plan.has(Component::Distribution) {
        ports.push("18424/tcp".into());
    }
    if ctx.plan.has(Component::Console) {
        ports.extend(console_port(ctx)?);
    }
    Ok(ports)
}

pub fn firewall_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let ports = ports(ctx)?;
    if !ctx.succeeds(FirewallCmd, &["--state"]) {
        return Ok(StepState::Skipped(format!(
            "firewalld is not running; if another firewall is used, open {}",
            ports.join(" ")
        )));
    }
    let open = ports.iter().all(|port| ctx.succeeds(FirewallCmd, &["--permanent", "--query-port", port]));
    Ok(if open { StepState::Done(format!("open: {}", ports.join(" "))) } else { StepState::Todo })
}

pub fn firewall_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let ports = ports(ctx)?;
    for port in &ports {
        if !ctx.succeeds(FirewallCmd, &["--permanent", "--query-port", port]) {
            ctx.ok(FirewallCmd, &["--permanent", "--add-port", port])?;
        }
    }
    ctx.ok(FirewallCmd, &["--reload"])?;
    Ok(StepState::Done(format!("open: {}", ports.join(" "))))
}

fn ready<R: Runner>(ctx: &Ctx<R>, unit: Unit) -> bool {
    unit.ready_url().is_none_or(|url| {
        ctx.succeeds(Curl, &["--silent", "--fail", "--max-time", "2", "--output", "/dev/null", url])
    })
}

pub fn ready_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let units = units(ctx);
    Ok(if units.iter().all(|unit| ready(ctx, *unit)) {
        StepState::Done(format!("ready: {}", names(&units).join(" ")))
    } else {
        StepState::Todo
    })
}

/// The token from `token create`'s `token X` line.
pub fn token_from(output: &str) -> Result<String, String> {
    output
        .lines()
        .find_map(|line| line.strip_prefix("token "))
        .filter(|token| token.len() == 43 && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        .map(str::to_owned)
        .ok_or_else(|| "token create printed no token".into())
}

pub fn ready_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let units = units(ctx);
    for unit in &units {
        let mut attempts = 0;
        while !ready(ctx, *unit) {
            attempts += 1;
            if attempts == READY_ATTEMPTS {
                return Err(format!("{} is not ready after {READY_ATTEMPTS} seconds; see journalctl -u {}", unit.name(), unit.name()));
            }
            ctx.pause();
        }
    }
    let token = token_from(&ctx.as_admin(&["token", "create", "--expires", "24h", "--uses", "10"])?)?;
    Ok(StepState::Done(format!(
        "ready: {}; endpoint enrollment token (24 hours, 10 uses): {token}",
        names(&units).join(" ")
    )))
}
```

In `mod.rs`: `mod run;` and arms for `Step::Services`, `Step::Firewall`, `Step::Ready` (`run::services_check`/`run::services_apply`, …).

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin/src/setup
git commit -m "admin: Setup services, firewall and readiness steps

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Baseline rules and agent-on-this-host steps

**Files:**
- Create: `crates/openvibes-admin/src/setup/fleet.rs`
- Modify: `crates/openvibes-admin/src/setup/mod.rs` (last arms; the "not implemented yet" arm is removed, so the `match` is exhaustive)

**Interfaces — Produces:** `rules_check/apply`, `agent_check/apply`. Rules package contract (sub-project 2 builds the package): `/usr/share/openvibes/rules/baseline.json` (signed envelope) and `/usr/share/openvibes/rules/baseline.key` (one line `RULE_SET ISSUER_KEY_ID PUBLIC_KEY`).

- [ ] **Step 1: Failing tests** at the end of `fleet.rs`:

```rust
#[cfg(test)]
mod tests {
    use platform_host::{Step, StepState};

    use crate::setup::{fake::{Fake, plan}, plan::Component::*, run_step};

    const ADMIN: [&str; 5] = ["/usr/sbin/runuser", "-u", "openvibes-admin", "--", "/usr/bin/openvibes-admin"];
    const TOKEN: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
    const KEY: &str = "baseline org.rules AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn admin(rest: &[&str]) -> Vec<&'static str> {
        ADMIN.iter().chain(rest).map(|s| &*Box::leak((*s).to_owned().into_boxed_str())).collect()
    }

    #[test]
    fn rules_are_skipped_until_their_package_exists() {
        let fake = Fake::new("rules-missing");
        fake.answer(&admin(&["rules", "list"]), 0, "");
        fake.answer(&["/usr/bin/rpm"], 1, "");
        std::fs::create_dir_all(fake.root.join("srv/rpms")).unwrap();
        let mut plan = plan(&[Ingest, Distribution, Rules]);
        plan.repo_dir = Some("/srv/rpms".into());
        let state = run_step(&fake.ctx(&plan), Step::Rules);
        assert!(matches!(state, StepState::Skipped(_)), "{state:?}");
    }

    #[test]
    fn rules_are_trusted_and_published() {
        let fake = Fake::new("rules");
        fake.answer(&admin(&["rules", "list"]), 0, "");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-rules-baseline"], 0, "");
        fake.file("/usr/share/openvibes/rules/baseline.key", &format!("{KEY}\n"));
        fake.answer(&admin(&["rules", "trust", "add"]), 0, "trusted\n");
        fake.answer(&admin(&["rules", "publish"]), 0, "published baseline v1\n");
        let state = run_step(&fake.ctx(&plan(&[Ingest, Distribution, Rules])), Step::Rules);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert_eq!(
            fake.call(&admin(&["rules", "trust"]))[5..],
            ["rules", "trust", "add", "baseline", "org.rules", "--", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
        );
        assert_eq!(fake.call(&admin(&["rules", "publish"]))[7], "/usr/share/openvibes/rules/baseline.json");
    }

    #[test]
    fn the_local_agent_is_configured_started_and_awaited() {
        let fake = Fake::new("agent");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 0, "");
        fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
        fake.answer(&admin(&["token", "create", "--expires", "1h"]), 0, &format!("id 3\ntoken {TOKEN}\n"));
        fake.answer(&["/usr/bin/systemctl", "enable", "openvibes-agent"], 0, "");
        fake.answer(&["/usr/bin/systemctl", "restart", "openvibes-agent"], 0, "");
        fake.answer(&admin(&["agent", "list"]), 0, "a1b2  active  last seen now  version 0.1.0\n");
        fake.file("/etc/openvibes/pki/root.crt", "ROOT\n");
        fake.file("/usr/share/openvibes/rules/baseline.key", &format!("{KEY}\n"));
        let state = run_step(&fake.ctx(&plan(&[Ingest, Distribution, Rules, Agent])), Step::Agent);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert_eq!(fake.text("/etc/openvibes-agent/token"), format!("{TOKEN}\n"));
        assert_eq!(fake.text("/etc/openvibes-agent/platform-ca.crt"), "ROOT\n");
        let config = fake.text("/etc/openvibes-agent/agent.toml");
        for want in [
            "platform_url = \"https://localhost\"",
            "distribution_url = \"https://localhost\"",
            "id = \"baseline\"",
            "issuer_key_id = \"org.rules\"",
        ] {
            assert!(config.contains(want), "{want} missing in\n{config}");
        }
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(fake.root.join("etc/openvibes-agent/token")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn an_agent_that_never_reports_fails_the_step() {
        let fake = Fake::new("agent-silent");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-agent"], 0, "");
        fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
        fake.answer(&admin(&["token", "create"]), 0, &format!("token {TOKEN}\n"));
        fake.answer(&["/usr/bin/systemctl"], 0, "");
        fake.answer(&admin(&["agent", "list"]), 0, "");
        fake.file("/etc/openvibes/pki/root.crt", "ROOT\n");
        let state = run_step(&fake.ctx(&plan(&[Ingest, Agent])), Step::Agent);
        assert!(state.detail().contains("journalctl -u openvibes-agent"), "{state:?}");
    }
}
```

- [ ] **Step 2: Run, expect a compile failure.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::fleet`
Expected: FAIL to compile.

- [ ] **Step 3: Implement** `fleet.rs`:

```rust
//! Steps 11–12: the baseline rules and the agent on this host.

use platform_host::{StepState, runner::{Program::{Rpm, Systemctl}, Runner}};

use super::{Ctx, base::install, pki::ROOT_CERT, plan::Component, run::token_from};

const RULES: &str = "/usr/share/openvibes/rules";
const AGENT: &str = "/etc/openvibes-agent";
const AGENT_WAIT: u32 = 60;

/// `RULE_SET ISSUER_KEY_ID PUBLIC_KEY` from `baseline.key`.
fn baseline_key<R: Runner>(ctx: &Ctx<R>) -> Result<[String; 3], String> {
    let text = ctx.read(&format!("{RULES}/baseline.key"))?;
    let fields: Vec<String> = text.split_whitespace().map(str::to_owned).collect();
    <[String; 3]>::try_from(fields).map_err(|_| format!("{RULES}/baseline.key: want RULE_SET ISSUER_KEY_ID PUBLIC_KEY"))
}

fn published<R: Runner>(ctx: &Ctx<R>, set: &str) -> Result<bool, String> {
    Ok(ctx.as_admin(&["rules", "list"])?.lines().any(|line| line.starts_with(&format!("{set} v"))))
}

pub fn rules_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Rules) {
        return Ok(StepState::Skipped("baseline rules not chosen".into()));
    }
    let set = baseline_key(ctx).map_or_else(|_| "baseline".to_owned(), |[set, _, _]| set);
    Ok(if published(ctx, &set)? { StepState::Done(format!("rule set {set} published")) } else { StepState::Todo })
}

pub fn rules_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Rules) {
        return rules_check(ctx);
    }
    if !ctx.succeeds(Rpm, &["-q", "--quiet", "openvibes-rules-baseline"]) {
        match install(ctx, &["openvibes-rules-baseline"]) {
            Ok(()) => {}
            Err(error) if error.contains("No match for argument") || error.starts_with("no openvibes-rules-baseline package") => {
                return Ok(StepState::Skipped("the baseline rules package is not available yet".into()));
            }
            Err(error) => return Err(error),
        }
    }
    let [set, issuer, key] = baseline_key(ctx)?;
    ctx.as_admin(&["rules", "trust", "add", &set, &issuer, "--", &key])?;
    ctx.as_admin(&["rules", "publish", &format!("{RULES}/baseline.json")])?;
    Ok(StepState::Done(format!("rule set {set} published")))
}

fn agent_toml<R: Runner>(ctx: &Ctx<R>) -> String {
    let mut text = String::from(
        "# Written by openvibes-admin setup: the agent on the platform host.\n\
         state_dir = \"/var/lib/openvibes-agent\"\n\
         platform_url = \"https://localhost\"\n\
         platform_ca_file = \"/etc/openvibes-agent/platform-ca.crt\"\n\
         enrollment_token_file = \"/etc/openvibes-agent/token\"\n",
    );
    if ctx.plan.has(Component::Rules)
        && let Ok([set, issuer, key]) = baseline_key(ctx)
    {
        text.push_str(&format!(
            "distribution_url = \"https://localhost\"\n\n[[rule_sets]]\nid = \"{set}\"\n\
             trusted_keys = [{{ issuer_key_id = \"{issuer}\", public_key = \"{key}\" }}]\n"
        ));
    }
    text
}

pub fn agent_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Agent) {
        return Ok(StepState::Skipped("agent on this host not chosen".into()));
    }
    let configured = ctx.read(&format!("{AGENT}/agent.toml")).is_ok_and(|text| text.contains("platform_url = \"https://localhost\""));
    Ok(if configured && ctx.succeeds(Systemctl, &["is-active", "--quiet", "openvibes-agent"]) {
        StepState::Done("the agent on this host is running".into())
    } else {
        StepState::Todo
    })
}

fn reporting<R: Runner>(ctx: &Ctx<R>) -> bool {
    ctx.as_admin(&["agent", "list"])
        .is_ok_and(|list| list.lines().any(|line| line.split("  ").nth(1) == Some("active")))
}

pub fn agent_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Agent) {
        return agent_check(ctx);
    }
    if !ctx.succeeds(Rpm, &["-q", "--quiet", "openvibes-agent"]) {
        install(ctx, &["openvibes-agent"])?;
    }
    let token = token_from(&ctx.as_admin(&["token", "create", "--expires", "1h"])?)?;
    let agent = Some(("openvibes_agent", "openvibes_agent"));
    ctx.copy(ROOT_CERT, &format!("{AGENT}/platform-ca.crt"), None, 0o644)?;
    ctx.put(&format!("{AGENT}/token"), format!("{token}\n").as_bytes(), agent, 0o600)?;
    ctx.put(&format!("{AGENT}/agent.toml"), agent_toml(ctx).as_bytes(), Some(("root", "openvibes_agent")), 0o640)?;
    ctx.ok(Systemctl, &["enable", "openvibes-agent"])?;
    ctx.ok(Systemctl, &["restart", "openvibes-agent"])?;
    for _ in 0..AGENT_WAIT {
        if reporting(ctx) {
            return Ok(StepState::Done("the agent on this host enrolled and is reporting".into()));
        }
        ctx.pause();
    }
    Err(format!(
        "the agent did not show as active within {AGENT_WAIT} seconds; see journalctl -u openvibes-agent"
    ))
}
```

In `mod.rs`: `mod fleet;`, the arms for `Step::Rules` and `Step::Agent`, and delete both `other => Err(… "is not implemented yet")` arms.

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::`
Expected: PASS; the `match` in `check` and `apply` now lists all 13 steps.

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin/src/setup
git commit -m "admin: Setup baseline rules and local agent steps

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Helper verbs and `setup --quick`

**Files:**
- Modify: `crates/openvibes-admin/src/{helper.rs,main.rs,setup/mod.rs}`, `crates/openvibes-admin/tests/helper.rs`, `docs/components/openvibes-admin.md`

**Interfaces — Produces:** `helper setup-plan PLANARGS`, `helper setup-status`, `helper setup-step STEP`, `helper unit-enable UNIT`, `helper unit-disable UNIT`; `openvibes-admin setup --quick PLANARGS`; `pub(crate) fn effective_uid() -> Option<String>` in `helper.rs`; `pub fn quick(args: &PlanArgs) -> ExitCode` in `setup/mod.rs`.

- [ ] **Step 1: Failing tests** in `tests/helper.rs`:

```rust
#[test]
fn setup_verbs_check_their_arguments_before_the_root_check() {
    for args in [
        vec!["setup-step", "everything"],
        vec!["setup-step", "../ca"],
        vec!["unit-enable", "sshd.service"],
        vec!["unit-disable", "openvibes-ingest"],
        vec!["setup-plan", "--components", "console", "--hostname", "platform.example.com"],
        vec!["setup-plan", "--components", "ingest", "--hostname", "Bad Name"],
    ] {
        let out = helper(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("not allowed"), "{args:?}");
    }
    let out = helper(&["setup-step", "packages"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("helper must run as root"));
}

#[test]
fn setup_quick_needs_root_and_checks_its_plan() {
    let run = |args: &[&str]| Command::new(env!("CARGO_BIN_EXE_openvibes-admin")).args(args).output().unwrap();
    let out = run(&["setup", "--quick", "--components", "ingest", "--hostname", "platform.example.com"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("must run as root"));
    let out = run(&["setup", "--quick", "--components", "vulns", "--hostname", "platform.example.com"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("must include ingest"));
    let out = run(&["setup", "--components", "ingest", "--hostname", "platform.example.com"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--quick"));
}
```

- [ ] **Step 2: Run, expect FAIL.**

Run: `cargo test -p openvibes-admin --test helper`
Expected: FAIL (unknown subcommands).

- [ ] **Step 3: Implement.** `helper.rs`: make `effective_uid` `pub(crate)`; add to `HelperCommand`:

```rust
    /// Checks Setup's arguments and writes /etc/openvibes/setup.toml.
    SetupPlan {
        #[command(flatten)]
        args: crate::setup::plan::PlanArgs,
    },
    /// Prints every Setup step's state.
    SetupStatus,
    /// Checks one Setup step and runs it unless it is done.
    SetupStep {
        /// packages, postgres, operators, database, schema, ca,
        /// certificates, console, services, firewall, rules, agent, ready.
        step: String,
    },
    /// Starts an OpenVIBES unit at boot.
    UnitEnable { unit: String },
    /// Stops starting an OpenVIBES unit at boot.
    UnitDisable { unit: String },
```

to `Verb`:

```rust
    SetupPlan(Box<crate::setup::plan::Plan>),
    SetupStatus,
    SetupStep(Step),
    UnitFile(Unit, bool),
```

to `verb()`:

```rust
        HelperCommand::SetupPlan { args } => {
            // The plan's own checks; SUDO_USER is set by sudo, not the caller.
            match args.plan(crate::setup::plan::operator_from_env()) {
                Ok(plan) => Verb::SetupPlan(Box::new(plan)),
                Err(_) => return Err("invalid Setup arguments (see openvibes-admin setup --help)"),
            }
        }
        HelperCommand::SetupStatus => Verb::SetupStatus,
        HelperCommand::SetupStep { step } => Verb::SetupStep(Step::parse(step).ok_or("not a Setup step")?),
        HelperCommand::UnitEnable { unit } => Verb::UnitFile(Unit::parse(unit).ok_or("not an OpenVIBES unit")?, true),
        HelperCommand::UnitDisable { unit } => Verb::UnitFile(Unit::parse(unit).ok_or("not an OpenVIBES unit")?, false),
```

and to `run()`'s `match verb` (after the root check):

```rust
        Verb::SetupPlan(plan) => match plan.save(Path::new("/")) {
            Ok(()) => {
                println!("{} written", platform_host::SETUP_FILE);
                ExitCode::SUCCESS
            }
            Err(error) => failed(&error),
        },
        Verb::SetupStatus => crate::setup::status(),
        Verb::SetupStep(step) => crate::setup::step(step),
        Verb::UnitFile(unit, enable) => {
            let action = if enable { "enable" } else { "disable" };
            match platform_host::runner::SystemRunner.run(platform_host::runner::Program::Systemctl, &[action, unit.name()]) {
                Ok(out) if out.status == 0 => ExitCode::SUCCESS,
                Ok(out) => failed(out.stderr.trim()),
                Err(error) => failed(&error.to_string()),
            }
        }
```

(import `platform_host::{Step, runner::Runner}`; update the module doc to list the new verbs and say they need the user's password.)

`setup/mod.rs`: add

```rust
use std::{path::Path, process::ExitCode, time::Duration};

use platform_host::runner::SystemRunner;

use plan::{Plan, PlanArgs};

fn host_ctx<'a>(plan: &'a Plan) -> Ctx<'a, SystemRunner> {
    Ctx { runner: &SystemRunner, plan, root: Path::new("/"), pause: Duration::from_secs(1) }
}

/// `helper setup-status`: `STEP<TAB>STATE<TAB>DETAIL` per step.
pub fn status() -> ExitCode {
    let plan = match Plan::load(Path::new("/")) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("openvibes-admin helper: {error}");
            return ExitCode::FAILURE;
        }
    };
    let ctx = host_ctx(&plan);
    for step in Step::ALL {
        println!("{}\t{}", step.name(), check(&ctx, step).line());
    }
    ExitCode::SUCCESS
}

/// `helper setup-step STEP`: `STATE<TAB>DETAIL`; exit 0 whatever the state.
pub fn step(step: Step) -> ExitCode {
    let plan = match Plan::load(Path::new("/")) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("openvibes-admin helper: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("{}", run_step(&host_ctx(&plan), step).line());
    ExitCode::SUCCESS
}

/// `setup --quick`: as root, writes the plan and runs every step; exit 0
/// when all finished, 3 when a step waits (careful CA), 1 on failure.
pub fn quick(args: &PlanArgs) -> ExitCode {
    let plan = match args.plan(plan::operator_from_env()) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("openvibes-admin: {error}");
            return ExitCode::from(2);
        }
    };
    if crate::helper::effective_uid().as_deref() != Some("0") {
        eprintln!("openvibes-admin: setup --quick must run as root");
        return ExitCode::from(1);
    }
    if let Err(error) = plan.save(Path::new("/")) {
        eprintln!("openvibes-admin: {error}");
        return ExitCode::FAILURE;
    }
    let mut waiting = false;
    let finished = run_all(&host_ctx(&plan), |step, state| {
        waiting = matches!(state, StepState::Waiting(_));
        println!("{}: {} {}", step.title(), state.label(), state.detail());
    });
    match (finished, waiting) {
        (true, _) => ExitCode::SUCCESS,
        (false, true) => ExitCode::from(3),
        (false, false) => ExitCode::FAILURE,
    }
}
```

`main.rs`: add to `Command`:

```rust
    /// Install and set up the platform on this host without screens (as
    /// root). Without --quick, run openvibes-admin with no arguments.
    Setup {
        /// Run every Setup step now.
        #[arg(long)]
        quick: bool,
        #[command(flatten)]
        plan: setup::plan::PlanArgs,
    },
```

`Command::name`: `Self::Setup { .. } => "setup",`; add `| Command::Setup { .. }` to the `unreachable!` arm in `run`; in `main`, right after the helper branch:

```rust
    if let Command::Setup { quick, plan } = command {
        if !*quick {
            eprintln!("openvibes-admin: setup needs --quick; run openvibes-admin with no arguments for the Setup screen");
            return ExitCode::from(2);
        }
        return setup::quick(plan);
    }
```

If clippy reports `large_enum_variant` for `Command::Setup`, box the field (`plan: Box<setup::plan::PlanArgs>`; clap flattens `Box<T>`).

`docs/components/openvibes-admin.md`: a "Setup" section: `setup --quick` and its options, exit codes 0/1/2/3, the helper verbs and their output format, `setup.toml`.

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --test helper && cargo clippy -p openvibes-admin --all-targets -- -D warnings`
Expected: PASS, no warnings.

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin docs/components/openvibes-admin.md
git commit -m "admin: Setup helper verbs and setup --quick

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: The TUI's Setup tab

**Files:**
- Create: `crates/openvibes-admin/src/tui/{password.rs,setup.rs,setup_view.rs,setup_tests.rs}`
- Modify: `crates/openvibes-admin/src/tui/{mod.rs,app.rs,configuration.rs,tests.rs}`

**Interfaces — Produces:**

```rust
// password.rs
#[derive(Default)] pub struct PasswordPrompt { pub failures: u8, /* typed: Zeroizing<String> */ }
pub enum Typed { Pending, Cancelled, Entered(Secret) }
impl PasswordPrompt { pub fn key(&mut self, key: Key) -> Typed; pub fn masked(&self) -> String; }
// setup.rs
pub enum Phase { Form, Password(After), Running(usize), Stopped(usize), Finished, Status }
pub enum After { Plan, Run(usize), Status }
pub struct Setup { pub components: BTreeSet<Component>, pub row: usize, pub hostname: String, pub sans: String,
                   pub ca: CaMode, pub root_key_out: String, pub editing: bool, pub prompt: PasswordPrompt,
                   pub password: Option<Secret>, pub states: [Option<StepState>; 13], pub phase: Phase }
impl Setup { pub fn new(set_up: bool, hostname: String, home: Option<String>) -> Setup; pub fn plan_args(&self) -> Vec<String>; }
impl<H: Host> App<H> { pub fn setup_key(&mut self, key: Key); pub fn setup_tick(&mut self); }
// app.rs: Tab::Setup; App { setup: Setup, … }; App::new opens Setup when !host.is_set_up()
// configuration.rs: Then::Setup; Tab from Configuration goes to Setup
```

Tab order: Setup → Services → Configuration → Setup.

- [ ] **Step 1: Failing tests** `tui/setup_tests.rs` (add `#[cfg(test)] mod setup_tests;` in `tui/mod.rs`):

```rust
//! The Setup tab against a scripted host.

use std::{cell::RefCell, collections::VecDeque};

use platform_host::{Host, HostError, Privileged, Secret, Service, ServiceAction, ServiceStatus, Step, Unit};
use ratatui::{Terminal, backend::TestBackend};

use super::{app::{App, Key, Tab}, render, setup::Phase};

struct SetupHost {
    set_up: bool,
    /// What each privileged call returns, in order.
    answers: RefCell<VecDeque<Result<String, HostError>>>,
    /// (verb, password) of each call.
    calls: RefCell<Vec<(String, String)>>,
}

impl Host for SetupHost {
    fn services(&self) -> Result<Vec<ServiceStatus>, HostError> { Ok(Vec::new()) }
    fn service_action(&self, _: Unit, _: ServiceAction) -> Result<(), HostError> { Ok(()) }
    fn logs(&self, _: Unit, _: u16) -> Result<Vec<String>, HostError> { Ok(Vec::new()) }
    fn read_config(&self, _: Service) -> Result<String, HostError> { Err(HostError::NotOperator) }
    fn write_config(&self, _: Service, _: &str) -> Result<(), HostError> { Err(HostError::NotOperator) }
    fn is_set_up(&self) -> bool { self.set_up }
    fn privileged(&self, verb: Privileged<'_>, password: &Secret) -> Result<String, HostError> {
        self.calls.borrow_mut().push((verb.args().join(" "), password.expose().to_owned()));
        self.answers.borrow_mut().pop_front().unwrap_or(Ok("done\tok\n".into()))
    }
}

fn app(set_up: bool, answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    let mut app = App::new(SetupHost { set_up, answers: RefCell::new(answers.into()), calls: RefCell::new(Vec::new()) });
    app.setup.hostname = "platform.example.com".into();
    app.setup.root_key_out = "/home/alice/openvibes-root-ca.key".into();
    app
}

fn screen(app: &App<SetupHost>) -> String {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| render(frame, app)).unwrap();
    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>() + "\n")
        .collect()
}

fn type_text(app: &mut App<SetupHost>, text: &str) {
    for c in text.chars() {
        app.key(Key::Char(c));
    }
}

/// From the form: Start, then the password.
fn start(app: &mut App<SetupHost>, password: &str) {
    while app.setup.row != super::setup::START_ROW {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    type_text(app, password);
    app.key(Key::Enter);
}

#[test]
fn a_new_host_opens_on_setup_with_the_components() {
    let app = app(false, vec![]);
    assert_eq!(app.tab, Tab::Setup);
    let text = screen(&app);
    for want in ["[Setup]", "[x] ingest", "[x] agent", "[ ] assistant", "platform.example.com", "Start"] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn a_set_up_host_opens_on_services() {
    assert_eq!(app(true, vec![]).tab, Tab::Services);
}

#[test]
fn start_writes_the_plan_with_the_password_then_runs_one_step_per_tick() {
    let mut app = app(false, vec![Ok("setup.toml written\n".into()), Ok("done\tinstalled\n".into()), Ok("failed\tdnf: no network\n".into())]);
    start(&mut app, "pw pw pw");
    {
        let calls = app.host.calls.borrow();
        assert_eq!(
            calls[0].0,
            "setup-plan --components ingest,console,distribution,vulns,rules,agent --hostname platform.example.com --ca quick --root-key-out /home/alice/openvibes-root-ca.key"
        );
        assert_eq!(calls[0].1, "pw pw pw");
    }
    assert_eq!(app.setup.phase, Phase::Running(0));
    app.setup_tick();
    assert_eq!(app.setup.phase, Phase::Running(1));
    app.setup_tick();
    assert_eq!(app.setup.phase, Phase::Stopped(1));
    assert!(app.setup.password.is_none(), "the password is dropped when the run stops");
    let text = screen(&app);
    assert!(text.contains("dnf: no network"), "{text}");
    assert_eq!(app.host.calls.borrow()[2].0, format!("setup-step {}", Step::Postgres.name()));
}

#[test]
fn wrong_password_mid_run_asks_again_and_resumes() {
    let mut app = app(false, vec![Ok("written\n".into()), Err(HostError::WrongPassword), Ok("done\tok\n".into())]);
    start(&mut app, "first");
    app.setup_tick();
    assert!(matches!(app.setup.phase, Phase::Password(_)), "{:?}", app.setup.phase);
    type_text(&mut app, "second");
    app.key(Key::Enter);
    app.setup_tick();
    assert_eq!(app.setup.phase, Phase::Running(1));
    let calls = app.host.calls.borrow();
    assert_eq!(calls[2], ("setup-step packages".into(), "second".into()));
}

#[test]
fn three_wrong_passwords_close_the_prompt() {
    let mut app = app(false, vec![Err(HostError::WrongPassword), Err(HostError::WrongPassword), Err(HostError::WrongPassword)]);
    start(&mut app, "a");
    type_text(&mut app, "b");
    app.key(Key::Enter);
    type_text(&mut app, "c");
    app.key(Key::Enter);
    assert_eq!(app.setup.phase, Phase::Form);
    assert!(screen(&app).contains("three wrong passwords"));
}

#[test]
fn the_password_is_masked() {
    let mut app = app(false, vec![]);
    while app.setup.row != super::setup::START_ROW {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    type_text(&mut app, "secret");
    let text = screen(&app);
    assert!(text.contains("******"), "{text}");
    assert!(!text.contains("secret"), "{text}");
}

#[test]
fn rules_bring_distribution_and_the_finished_screen_shows_the_login() {
    let mut app = app(false, vec![]);
    // Untick distribution: rules go too.
    while app.setup.row != 2 {
        app.key(Key::Down);
    }
    app.key(Key::Char(' '));
    assert!(!app.setup.components.contains(&crate::setup::plan::Component::Rules));
    let mut answers: Vec<Result<String, HostError>> = vec![Ok("written\n".into())];
    for step in Step::ALL {
        answers.push(Ok(match step {
            Step::Console => "done\thttps://platform.example.com · console admin: admin, password Abc123 (shown only now; change it after logging in)\n".into(),
            _ => "done\tok\n".into(),
        }));
    }
    *app.host.answers.borrow_mut() = answers.into();
    start(&mut app, "pw");
    for _ in Step::ALL {
        app.setup_tick();
    }
    assert_eq!(app.setup.phase, Phase::Finished);
    assert!(screen(&app).contains("Abc123"), "the generated password is on the finished screen");
}
```

In `tui/tests.rs` change the Configuration tab test's last assertion (`app.key(Key::Tab); assert_eq!(app.tab, Tab::Services);`) to `Tab::Setup`.

- [ ] **Step 2: Run, expect a compile failure.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin tui`
Expected: FAIL to compile.

- [ ] **Step 3: Implement.** `tui/password.rs`:

```rust
//! The password prompt for privileged steps (admin TUI spec §3): typed text
//! is masked, held in zeroized memory, and handed over once.

use platform_host::Secret;
use zeroize::Zeroizing;

use super::app::Key;

const MAX: usize = 256;

#[derive(Default)]
pub struct PasswordPrompt {
    typed: Zeroizing<String>,
    /// Wrong passwords so far; three close the prompt.
    pub failures: u8,
}

pub enum Typed {
    Pending,
    Cancelled,
    Entered(Secret),
}

impl PasswordPrompt {
    pub fn key(&mut self, key: Key) -> Typed {
        match key {
            Key::Char(c) if self.typed.chars().count() < MAX => {
                self.typed.push(c);
                Typed::Pending
            }
            Key::Backspace => {
                self.typed.pop();
                Typed::Pending
            }
            Key::Esc => {
                self.typed.clear();
                Typed::Cancelled
            }
            Key::Enter => Typed::Entered(Secret::new(std::mem::take(&mut *self.typed))),
            _ => Typed::Pending,
        }
    }

    pub fn masked(&self) -> String {
        "*".repeat(self.typed.chars().count())
    }
}
```

`tui/setup.rs`:

```rust
//! The Setup tab's state and keys (admin TUI spec §6.3): a form, the
//! password once per run, then one step per event-loop tick through
//! `helper setup-step`, stopping at the first step that fails or waits.

use std::collections::BTreeSet;

use platform_host::{Host, HostError, Privileged, Secret, Step, StepState};

use super::{app::{App, Key}, password::{PasswordPrompt, Typed}};
use crate::setup::plan::{CaMode, Component};

pub const HOSTNAME_ROW: usize = 7;
pub const SANS_ROW: usize = 8;
pub const CA_ROW: usize = 9;
pub const KEY_ROW: usize = 10;
pub const START_ROW: usize = 11;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum After {
    Plan,
    Run(usize),
    Status,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Form,
    Password(After),
    Running(usize),
    Stopped(usize),
    Finished,
    /// A set-up host: `c` checks every step.
    Status,
}

pub struct Setup {
    pub components: BTreeSet<Component>,
    pub row: usize,
    pub hostname: String,
    pub sans: String,
    pub ca: CaMode,
    pub root_key_out: String,
    pub editing: bool,
    pub prompt: PasswordPrompt,
    pub password: Option<Secret>,
    pub states: [Option<StepState>; 13],
    pub phase: Phase,
}

impl Setup {
    pub fn new(set_up: bool, hostname: String, home: Option<String>) -> Setup {
        use Component::*;
        Setup {
            components: [Ingest, Console, Distribution, Vulns, Rules, Agent].into(),
            row: 0,
            hostname,
            sans: String::new(),
            ca: CaMode::Quick,
            root_key_out: home.map(|home| format!("{home}/openvibes-root-ca.key")).unwrap_or_default(),
            editing: false,
            prompt: PasswordPrompt::default(),
            password: None,
            states: Default::default(),
            phase: if set_up { Phase::Status } else { Phase::Form },
        }
    }

    pub fn plan_args(&self) -> Vec<String> {
        let components: Vec<&str> = self.components.iter().map(|c| c.name()).collect();
        let mut args = vec!["--components".into(), components.join(","), "--hostname".into(), self.hostname.trim().into()];
        for san in self.sans.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            args.extend(["--san".into(), san.into()]);
        }
        args.extend(["--ca".into(), match self.ca { CaMode::Quick => "quick", CaMode::Careful => "careful" }.into()]);
        if self.ca == CaMode::Quick && !self.root_key_out.trim().is_empty() {
            args.extend(["--root-key-out".into(), self.root_key_out.trim().into()]);
        }
        args
    }

    fn toggle(&mut self, component: Component) {
        use Component::*;
        if matches!(component, Ingest | Console) {
            return; // always installed
        }
        if !self.components.remove(&component) {
            self.components.insert(component);
            if component == Rules {
                self.components.insert(Distribution);
            }
        } else if component == Distribution {
            self.components.remove(&Rules);
        }
    }

    fn field(&mut self) -> Option<&mut String> {
        match self.row {
            HOSTNAME_ROW => Some(&mut self.hostname),
            SANS_ROW => Some(&mut self.sans),
            KEY_ROW => Some(&mut self.root_key_out),
            _ => None,
        }
    }
}

impl<H: Host> App<H> {
    pub fn setup_key(&mut self, key: Key) {
        match self.setup.phase {
            Phase::Password(after) => self.password_key(key, after),
            Phase::Form => self.form_key(key),
            Phase::Running(_) => {}
            Phase::Stopped(at) => match key {
                Key::Char('r') => self.ask_password(After::Run(at)),
                Key::Tab => self.leave_setup(),
                Key::Char('q') => self.quit = true,
                _ => {}
            },
            Phase::Finished | Phase::Status => match key {
                Key::Char('c') => self.ask_password(After::Status),
                Key::Tab => self.leave_setup(),
                Key::Char('q') => self.quit = true,
                _ => {}
            },
        }
    }

    fn leave_setup(&mut self) {
        self.tab = super::app::Tab::Services;
        self.message = None;
        self.refresh();
    }

    fn ask_password(&mut self, after: After) {
        self.setup.prompt = PasswordPrompt::default();
        self.setup.phase = Phase::Password(after);
        self.message = None;
    }

    fn form_key(&mut self, key: Key) {
        if self.setup.editing {
            let Some(field) = self.setup.field() else { return };
            match key {
                Key::Char(c) if field.len() < 512 => field.push(c),
                Key::Backspace => {
                    field.pop();
                }
                Key::Enter | Key::Esc => self.setup.editing = false,
                _ => {}
            }
            return;
        }
        match key {
            Key::Char('j') | Key::Down if self.setup.row < START_ROW => self.setup.row += 1,
            Key::Char('k') | Key::Up => self.setup.row = self.setup.row.saturating_sub(1),
            Key::Char(' ') if self.setup.row < Component::ALL.len() => self.setup.toggle(Component::ALL[self.setup.row]),
            Key::Char(' ') | Key::Enter if self.setup.row == CA_ROW => {
                self.setup.ca = match self.setup.ca { CaMode::Quick => CaMode::Careful, CaMode::Careful => CaMode::Quick };
            }
            Key::Enter if self.setup.row == START_ROW => self.ask_password(After::Plan),
            Key::Enter if self.setup.field().is_some() => self.setup.editing = true,
            Key::Tab => self.leave_setup(),
            Key::Char('q') => self.quit = true,
            _ => {}
        }
    }

    fn password_key(&mut self, key: Key, after: After) {
        let secret = match self.setup.prompt.key(key) {
            Typed::Pending => return,
            Typed::Cancelled => {
                self.setup.phase = match after { After::Plan => Phase::Form, After::Run(at) => Phase::Stopped(at), After::Status => Phase::Status };
                return;
            }
            Typed::Entered(secret) => secret,
        };
        match after {
            After::Run(at) => {
                self.setup.password = Some(secret);
                self.setup.phase = Phase::Running(at);
            }
            After::Plan => {
                let args = self.setup.plan_args();
                match self.host.privileged(Privileged::SetupPlan(&args), &secret) {
                    Ok(_) => {
                        self.setup.prompt.failures = 0;
                        self.setup.states = Default::default();
                        self.setup.password = Some(secret);
                        self.setup.phase = Phase::Running(0);
                    }
                    Err(HostError::WrongPassword) => self.wrong_password(after),
                    Err(error) => {
                        self.message = Some(error.to_string());
                        self.setup.phase = Phase::Form;
                    }
                }
            }
            After::Status => {
                match self.host.privileged(Privileged::SetupStatus, &secret) {
                    Ok(out) => {
                        for line in out.lines() {
                            let Some((name, rest)) = line.split_once('\t') else { continue };
                            if let (Some(step), Some(state)) = (Step::parse(name), StepState::parse(rest)) {
                                let index = Step::ALL.iter().position(|s| *s == step).unwrap_or(0);
                                self.setup.states[index] = Some(state);
                            }
                        }
                        self.setup.phase = Phase::Status;
                    }
                    Err(HostError::WrongPassword) => self.wrong_password(after),
                    Err(error) => {
                        self.message = Some(error.to_string());
                        self.setup.phase = Phase::Status;
                    }
                }
            }
        }
    }

    fn wrong_password(&mut self, after: After) {
        self.setup.prompt.failures += 1;
        if self.setup.prompt.failures >= 3 {
            self.message = Some("three wrong passwords; try again later".into());
            self.setup.prompt = PasswordPrompt::default();
            self.setup.phase = match after { After::Plan => Phase::Form, After::Run(at) => Phase::Stopped(at), After::Status => Phase::Status };
        } else {
            self.message = Some(HostError::WrongPassword.to_string());
            self.setup.phase = Phase::Password(after);
        }
    }

    /// Runs the next step, if a run is going (called once per loop turn).
    pub fn setup_tick(&mut self) {
        let Phase::Running(next) = self.setup.phase else { return };
        let Some(password) = &self.setup.password else {
            self.setup.phase = Phase::Stopped(next);
            return;
        };
        let step = Step::ALL[next];
        let state = match self.host.privileged(Privileged::SetupStep(step), password) {
            Ok(out) => StepState::parse(out.trim_end())
                .unwrap_or_else(|| StepState::Failed(format!("unexpected helper output: {}", out.trim()))),
            Err(HostError::WrongPassword) => {
                self.setup.password = None;
                self.wrong_password(After::Run(next));
                return;
            }
            Err(error) => StepState::Failed(error.to_string()),
        };
        // The password worked: wrong ones are counted per attempt.
        self.setup.prompt.failures = 0;
        let finished = state.finished();
        self.setup.states[next] = Some(state);
        self.setup.phase = if !finished {
            self.setup.password = None;
            Phase::Stopped(next)
        } else if next + 1 == Step::ALL.len() {
            self.setup.password = None;
            Phase::Finished
        } else {
            Phase::Running(next + 1)
        };
    }
}
```

`tui/setup_view.rs`:

```rust
//! Draws the Setup tab at 80×24: the form, the password prompt, the
//! checklist while running or stopped, and what to keep when finished.

use platform_host::{Host, Step};
use ratatui::{Frame, layout::{Constraint, Layout, Rect}, style::{Modifier, Style}, text::Line, widgets::{Block, Borders, Paragraph, Wrap}};

use super::{app::App, setup::{CA_ROW, HOSTNAME_ROW, KEY_ROW, Phase, SANS_ROW, START_ROW}};
use crate::setup::plan::{CaMode, Component};

const FORM_KEYS: &str = "Tab screens  j/k move  space toggle  Enter edit/start  q quit";
const RUN_KEYS: &str = "r retry from the failed step  Tab screens  q quit";
const DONE_KEYS: &str = "c check every step  Tab screens  q quit";

pub fn draw<H: Host>(frame: &mut Frame, area: Rect, app: &App<H>) {
    let [body, status, keys] = Layout::vertical([Constraint::Min(3), Constraint::Length(1), Constraint::Length(1)]).areas(area);
    let setup = &app.setup;
    let (lines, help): (Vec<Line>, &str) = match setup.phase {
        Phase::Form => (form(app), FORM_KEYS),
        Phase::Password(_) => (vec![Line::raw(format!("Your password (for sudo; used for this run only): {}", setup.prompt.masked()))], "Enter confirm  Esc cancel"),
        Phase::Running(_) | Phase::Stopped(_) | Phase::Status => (checklist(app), if matches!(setup.phase, Phase::Stopped(_)) { RUN_KEYS } else { DONE_KEYS }),
        Phase::Finished => (finished(app), DONE_KEYS),
    };
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(Block::new().borders(Borders::ALL).title(" setup ")),
        body,
    );
    frame.render_widget(Paragraph::new(app.message.clone().unwrap_or_default()), status);
    frame.render_widget(Paragraph::new(help), keys);
}

fn mark(selected: bool, line: String) -> Line<'static> {
    if selected { Line::styled(line, Style::new().add_modifier(Modifier::REVERSED)) } else { Line::raw(line) }
}

fn form<H: Host>(app: &App<H>) -> Vec<Line<'static>> {
    let setup = &app.setup;
    let mut lines: Vec<Line> = Component::ALL
        .iter()
        .enumerate()
        .map(|(row, c)| {
            let tick = if setup.components.contains(c) { "x" } else { " " };
            mark(setup.row == row, format!("[{tick}] {:<13}{}", c.name(), c.about()))
        })
        .collect();
    let edit = |row: usize| if setup.editing && setup.row == row { "_" } else { "" };
    lines.push(mark(setup.row == HOSTNAME_ROW, format!("Hostname:  {}{}", setup.hostname, edit(HOSTNAME_ROW))));
    lines.push(mark(setup.row == SANS_ROW, format!("Other names or addresses (comma-separated):  {}{}", setup.sans, edit(SANS_ROW))));
    let ca = match setup.ca { CaMode::Quick => "quick (root created here, key written once)", CaMode::Careful => "careful (root stays offline)" };
    lines.push(mark(setup.row == CA_ROW, format!("CA:  {ca}")));
    lines.push(mark(setup.row == KEY_ROW, format!("Root key file:  {}{}", setup.root_key_out, edit(KEY_ROW))));
    lines.push(mark(setup.row == START_ROW, "[ Start ]".into()));
    lines
}

fn checklist<H: Host>(app: &App<H>) -> Vec<Line<'static>> {
    Step::ALL
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let (label, detail) = match (&app.setup.states[index], app.setup.phase) {
                (_, Phase::Running(next)) if next == index => ("running…".to_owned(), String::new()),
                (Some(state), _) => (state.label().to_owned(), state.detail().to_owned()),
                (None, _) => (String::new(), String::new()),
            };
            Line::raw(format!("{:<26}{label:<9}{detail}", step.title()))
        })
        .collect()
}

fn finished<H: Host>(app: &App<H>) -> Vec<Line<'static>> {
    let mut lines = vec![Line::raw("Setup finished. Keep what follows: the password is shown only now.")];
    for (index, step) in Step::ALL.iter().enumerate() {
        if matches!(step, Step::Ca | Step::Console | Step::Operators | Step::Ready)
            && let Some(state) = &app.setup.states[index]
        {
            lines.push(Line::raw(format!("{}: {}", step.title(), state.detail())));
        }
    }
    lines
}
```

`app.rs`: `Tab` gains `Setup`; `App` gains `pub setup: Setup`; in `App::new`:

```rust
        let set_up = host.is_set_up();
        let hostname = std::fs::read_to_string("/etc/hostname").map(|h| h.trim().to_lowercase()).unwrap_or_default();
        let setup = Setup::new(set_up, hostname, std::env::var("HOME").ok());
        let mut app = App {
            host,
            tab: if set_up { Tab::Services } else { Tab::Setup },
            setup,
            …
```

and in `key`: `Tab::Setup => self.setup_key(key),`.

`configuration.rs`: add `Then::Setup` (`/// The Setup screen.`); `Key::Tab => self.leave(Then::Setup)`; in `go`: `Then::Setup => { self.tab = Tab::Setup; self.message = None; }`.

`tui/mod.rs`: `mod password; mod setup; mod setup_view;` (`pub mod setup` if the tests need `START_ROW` via `super::setup`); the tab line:

```rust
    let tabs = match app.tab {
        Tab::Setup => "[Setup]  Services  Configuration",
        Tab::Services => "Setup  [Services]  Configuration",
        Tab::Configuration => "Setup  Services  [Configuration]",
    };
```

`Tab::Setup => setup_view::draw(frame, body, app),` in the body match; in `run()`'s loop, after the key handling: `if app.tab == Tab::Setup { app.setup_tick(); }` with the comment `// One Setup step per turn: the screen is redrawn between steps (a step blocks while it runs, e.g. dnf).`

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin tui`
Expected: PASS (existing tests with the Tab change, and the new Setup tests).

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin/src/tui
git commit -m "admin TUI: Setup tab with password prompt and step-by-step run

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: Services screen: enable and disable at boot

**Files:**
- Modify: `crates/openvibes-admin/src/tui/{app.rs,services.rs,mod.rs,tests.rs}`

**Interfaces — Produces:** `App.boot: Option<(Unit, bool, PasswordPrompt)>`; keys `e` (enable) and `d` (disable) on the Services screen.

- [ ] **Step 1: Failing test** in `tui/tests.rs`: give `FakeHost` a field `privileged_calls: RefCell<Vec<(String, String)>>` (initialised in `app()`), record `(verb.args().join(" "), password.expose().to_owned())` in `privileged` and return `Ok(String::new())`; then add:

```rust
#[test]
fn enable_at_boot_asks_for_the_password() {
    let mut app = app(false);
    select(&mut app, Unit::Vulns);
    app.key(Key::Char('e'));
    for c in "pw".chars() {
        app.key(Key::Char(c));
    }
    assert!(screen(&app, 80, 24).contains("Enable openvibes-vulns.service at boot: your password: **"));
    app.key(Key::Enter);
    assert_eq!(
        *app.host.privileged_calls.borrow(),
        [("unit-enable openvibes-vulns.service".to_owned(), "pw".to_owned())]
    );
    assert_eq!(message(&app), "enabled openvibes-vulns.service at boot");
}
```

Also update `renders_services_at_80x24`'s expected key help to `"s start  t stop  r restart  e/d boot  R refresh  q quit"`.

- [ ] **Step 2: Run, expect FAIL.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin tui::tests`
Expected: FAIL.

- [ ] **Step 3: Implement.** `services.rs`: `const KEYS: &str = "Tab screens  j/k  s start  t stop  r restart  e/d boot  R refresh  q quit";` and in `draw`'s status line, before the other cases:

```rust
    let line = match (&app.boot, &app.confirm, &app.message) {
        (Some((unit, enable, prompt)), _, _) => format!(
            "{} {} at boot: your password: {}",
            if *enable { "Enable" } else { "Disable" },
            unit.name(),
            prompt.masked()
        ),
        (None, Some((unit, action)), _) => format!("{} {}? y/n", capitalised(*action), unit.name()),
        (None, None, Some(message)) => message.clone(),
        (None, None, None) => String::new(),
    };
```

`app.rs`: field `pub boot: Option<(Unit, bool, PasswordPrompt)>` (initialised `None`); at the top of `services_key`:

```rust
        if let Some((unit, enable, mut prompt)) = self.boot.take() {
            match prompt.key(key) {
                Typed::Pending => self.boot = Some((unit, enable, prompt)),
                Typed::Cancelled => {}
                Typed::Entered(secret) => {
                    let verb = if enable { Privileged::UnitEnable(unit) } else { Privileged::UnitDisable(unit) };
                    let done = if enable { "enabled" } else { "disabled" };
                    self.message = Some(match self.host.privileged(verb, &secret) {
                        Ok(_) => format!("{done} {} at boot", unit.name()),
                        Err(error) => error.to_string(),
                    });
                    self.refresh();
                }
            }
            return;
        }
```

and in its key match: `Key::Char('e') => self.ask_boot(true), Key::Char('d') => self.ask_boot(false),` with

```rust
    fn ask_boot(&mut self, enable: bool) {
        let Some(status) = self.services.get(self.selected) else { return };
        if status.installed {
            self.boot = Some((status.unit, enable, PasswordPrompt::default()));
            self.message = None;
        } else {
            self.message = Some(format!("{} is not installed", status.unit.name()));
        }
    }
```

`mod.rs`: the periodic refresh also waits while a password is typed: `… && app.confirm.is_none() && app.boot.is_none() && …`.

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin tui`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin/src/tui
git commit -m "admin TUI: enable and disable units at boot with the password

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: End to end with `setup --quick`, and the docs

**Files:**
- Modify: `scripts/systemd-e2e.sh`, `docs/components/{openvibes-admin.md,packaging.md,platform-host.md}`

- [ ] **Step 1: Replace the e2e's manual install.** In `scripts/systemd-e2e.sh`, replace the blocks "1-2. PostgreSQL, the platform RPMs, database and schema." (the four `in_c` calls and their `ok`), "3-4, 7. CA: …" (the whole `in_c 'set -e … rm -r $S'` and its `ok`) and "5-7. Services." (the `enable --now` and the two `wait_for`) with, in the position of "1-2":

```bash
# 1-7. As the install script will: install openvibes-admin, then Setup
# without screens (admin TUI spec §6.6) from the RPMs in /test: PostgreSQL,
# the platform packages, database, schema, quick CA, server certificates
# for localhost and 127.0.0.1, services, readiness. The console and the
# agent are installed further down (upgrade check, and the vulnerability
# must open through the re-match); the container has no firewalld.
in_c 'dnf -q -y install /test/openvibes-admin-*.rpm' >/dev/null 2>&1 || fail "install openvibes-admin"
SETUP='openvibes-admin setup --quick --components ingest,distribution,vulns --hostname localhost \
       --san 127.0.0.1 --repo-dir /test --allow-unsigned-local --root-key-out /root/ca-root.key'
in_c "$SETUP" > "$W/setup.out" 2>&1 || { cat "$W/setup.out"; fail "setup --quick"; }
grep -q '^Readiness: done' "$W/setup.out" || { cat "$W/setup.out"; fail "setup did not finish"; }
grep -q '^Firewall: skipped' "$W/setup.out" || fail "firewall step should be skipped without firewalld"
[[ "$(in_c 'stat -c "%a %U" /var/lib/openvibes-ingest/intermediate.key /root/ca-root.key')" == $'600 openvibes-ingest\n600 root' ]] ||
    fail "CA key files have the wrong owner or mode"
in_c '! test -e /run/openvibes-ca' || fail "CA staging directory left behind"
# Re-running is safe: every step is already done and nothing is redone.
in_c "$SETUP --root-key-out /root/ca-root-2.key" > "$W/setup2.out" 2>&1 || { cat "$W/setup2.out"; fail "second setup --quick"; }
! grep -qE ': (to do|failed|waiting)' "$W/setup2.out" || { cat "$W/setup2.out"; fail "second run redid a step"; }
in_c '! test -e /root/ca-root-2.key' || fail "second run created another root"
ok "platform installed and set up by setup --quick (and re-run safely)"
```

(`--root-key-out` given twice: clap takes the last; the second path must not be created because the CA step is already done.) Then:

- in the vulnerabilities block, change `systemctl enable --now openvibes-vulns` to `systemctl restart openvibes-vulns` (Setup already started it with the online defaults);
- in the agent block, change `/root/ca-root/root.crt` to `/etc/openvibes/pki/root.crt`.

Keep the console block (it runs after the database exists, as before) and everything after the agent unchanged.

- [ ] **Step 2: Docs.** `docs/components/packaging.md` "First install on Fedora": open with "The quickest path is Setup: `sudo dnf install openvibes-admin`, then `openvibes-admin` (the Setup tab) or `sudo openvibes-admin setup --quick …` (openvibes-admin.md). The steps below are what Setup runs, for hosts set up by hand." `docs/components/openvibes-admin.md`: the Setup tab (form, password once per run, checklist, retry, finished screen), enable/disable at boot on Services. `docs/components/platform-host.md`: confirm Task 1's section matches the final code.

- [ ] **Step 3: Run the gate.** Everything in `testing.md` §2, then §3 (the Fedora job: RPM build and `scripts/systemd-e2e.sh`), from this worktree.

Expected: all green; `setup.out` shows every step `done` or `skipped` (firewall, operators, console, rules, agent).

- [ ] **Step 4: Commit.**

```bash
git add scripts/systemd-e2e.sh docs/components
git commit -m "e2e: install through setup --quick and check a safe re-run; docs

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## After the tasks

- Open the PR ("Admin TUI PR 4: Setup install") with the Validation section listing exactly what ran (§2 and §3), and wait for the user's merge approval (spec §13).
- PR 5 (repair, change components, uninstall, life-cycle e2e) gets its own plan.
