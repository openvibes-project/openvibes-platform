# Admin TUI PR 5: Setup repair, change components, update, uninstall — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (native) or superpowers:subagent-driven-development. Steps use checkboxes.

**Goal:** On a set-up host the TUI's Setup tab (and `openvibes-admin setup --repair|--update|--uninstall` as root) repairs every step without ever replacing the CA, adds and removes components, updates the OpenVIBES packages (the local agent too) with the services stopped and the database migrated in between, and uninstalls keeping the data or removing everything.

**Architecture:** Builds on PR 4 (platform #43, branch `tui-setup-spec`). `platform-host` gains the step lists `UpdateStep` and `RemoveStep`, the verbs `Privileged::{Repair, Update, Remove}`, `Host::packages` (installed OpenVIBES packages and newer versions, no password) and `Host::setup_plan`. The root side gains `setup/backup.rs` (a `pg_dump` the user keeps), `setup/update.rs`, `setup/remove.rs`, a repair mode on `Ctx` (the CA step refuses to make a new CA), a run lock, and certificate name and expiry checks. The helper gets `setup-step STEP --repair`, `update-step`, `remove-step`; the CLI gets `setup --repair|--update|--uninstall`. The TUI runs any of these as a `Job`, one step per tick, with Update and Uninstall screens. A new systemd e2e script runs the whole life cycle.

**Tech Stack:** Rust (ratatui 0.30, clap, toml 1.1, toml_edit, platform-pki, chrono), PostgreSQL tools (`pg_dump`, `pg_dumpall`, `pg_restore`, `dropdb`, `dropuser`), dnf5, systemd, firewalld, bash e2e (podman, systemd as PID 1), GitHub Actions.

**Spec:** `docs/specs/2026-09-27-admin-tui-design.md` (§3 Setup verbs, §6.4 Repair and change components, §6.5 Uninstall, §6.5a Update, §6.6 without screens, §11, §12 life cycle and update e2e, §13 PR 5). Deferred minors from platform #43 are folded in where cheap (Task 1, 2, 3, 7).

## Global Constraints

- Everything from PR 4's plan still holds: closed step lists, password only on sudo's stdin, arguments checked before the root check, files written atomically with owner and mode through the open handle, `std::process::Command` only in `SystemRunner` and the helper's `logs`, files under 500 lines, component docs in the same task, commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Update steps, in order: `backup`, `stop`, `upgrade`, `migrate`, `start`, `ready`. Remove steps, in order: `backup`, `stop`, `firewall`, `packages`, `purge`.
- Repair never creates a CA: with the CA files missing, the `ca` step fails and says how to recover (restore from a backup, or remove everything and set up again). Certificates are re-issued only when missing or issued for other names than the plan's; one that expires within 14 days is reported, not replaced.
- Backups: `pg_dump --format=custom` of `openvibes` plus `pg_dumpall --roles-only --no-role-passwords` (`PATH.roles.sql`), both written only to new files (never over existing ones), 0600, owned by the operator when there is one; checked with `pg_restore --list`. Staging in `/var/tmp/openvibes-backup` (0700 postgres), removed afterwards.
- Update upgrades exactly the installed `openvibes-*` packages (debuginfo excluded); `--repo-dir DIR` on `update-step` or `setup --update` overrides the plan's for local test builds. Only units that were active before `stop` are started again (`/run/openvibes-admin/update-active`).
- Remove never removes `openvibes-admin` itself (the TUI is running); the last line tells the user `sudo dnf remove openvibes-admin`. `purge` needs `--confirm` equal to the plan's hostname and the whole platform's components; it drops the `openvibes` database and every `openvibes-*` role, deletes `/etc/openvibes`, `/etc/openvibes-agent`, `/var/lib/openvibes-*`, and the service accounts and groups (also `openvibes-admin` and `openvibes-operators`); PostgreSQL stays installed.
- One Setup run at a time: `/run/openvibes-admin/setup.lock` (`File::try_lock`), held by each helper step and for a whole `--quick|--repair|--update|--uninstall` run.
- `SystemRunner` runs every command with `LC_ALL=C` (sudo's and dnf's messages are parsed).
- Gate: `testing.md` §2, plus §3: both `scripts/systemd-e2e.sh` and the new `scripts/setup-lifecycle-e2e.sh` run locally from RPMs built on this Fedora host.

## Review Focus

- Repair on a host whose CA files were deleted by hand: it must stop at the CA step with the recovery text and never run `ca init-root` (Task 3 `repair_never_makes_a_new_ca`).
- A backup path that already exists (last month's dump): refused before anything is stopped, nothing overwritten (Task 4 `an_existing_backup_file_is_not_overwritten`; Task 5 `update_stops_nothing_when_the_backup_fails`).
- `remove-step purge` with a wrong or missing hostname, or for only some components: nothing deleted (Task 6 `purge_needs_the_hostname_and_the_whole_platform`).
- An update when a unit was stopped on purpose (e.g. distribution): it must stay stopped afterwards (Task 5 `only_previously_active_units_are_started`).
- Two Setup runs at once (the TUI and `setup --quick`): the second is refused with a clear message instead of racing (Task 3 `a_second_run_is_refused`; Task 7 helper test).

---

### Task 1: `platform-host`: update and remove steps, verbs, packages, plan read, journal state

**Files:**
- Modify: `crates/platform-host/src/{setup.rs,lib.rs,native.rs,runner.rs}`, `crates/platform-host/tests/native.rs`, `crates/openvibes-admin/src/tui/{tests.rs,setup_tests.rs}` (fake hosts gain the new trait methods), `docs/components/platform-host.md`

**Interfaces — Produces:**

```rust
// setup.rs
pub enum UpdateStep { Backup, Stop, Upgrade, Migrate, Start, Ready }   // ALL, name(), title(), parse()
pub enum RemoveStep { Backup, Stop, Firewall, Packages, Purge }        // ALL, name(), title(), parse()
pub enum Privileged<'a> { SetupPlan(&'a [String]), SetupStatus, SetupStep(Step), Repair(Step),
    Update(UpdateStep, &'a [String]), Remove(RemoveStep, &'a [String]), UnitEnable(Unit), UnitDisable(Unit) }
// lib.rs
pub struct PackageUpdate { pub name: String, pub installed: String, pub available: Option<String> }
trait Host { … fn packages(&self) -> Result<Vec<PackageUpdate>, HostError>; fn setup_plan(&self) -> Result<String, HostError>; }
// runner.rs: Program gains Userdel, Groupdel; SystemRunner sets LC_ALL=C
```

- [ ] **Step 1: Failing tests** in `crates/platform-host/tests/native.rs` (add `PackageUpdate, RemoveStep, UpdateStep` to the imports):

```rust
#[test]
fn update_and_remove_verbs_carry_their_arguments_but_journal_only_the_step() {
    let args = ["--backup".to_owned(), "/home/alice/b.dump".to_owned()];
    assert_eq!(
        Privileged::Update(UpdateStep::Backup, &args).args(),
        ["update-step", "backup", "--backup", "/home/alice/b.dump"]
    );
    assert_eq!(Privileged::Update(UpdateStep::Backup, &args).journal(), "update-step backup");
    let remove = ["--components".to_owned(), "vulns".to_owned()];
    assert_eq!(Privileged::Remove(RemoveStep::Stop, &remove).args(), ["remove-step", "stop", "--components", "vulns"]);
    assert_eq!(Privileged::Remove(RemoveStep::Purge, &remove).journal(), "remove-step purge");
    assert_eq!(Privileged::Repair(Step::Ca).args(), ["setup-step", "ca", "--repair"]);
    for step in UpdateStep::ALL {
        assert_eq!(UpdateStep::parse(step.name()), Some(step));
    }
    for step in RemoveStep::ALL {
        assert_eq!(RemoveStep::parse(step.name()), Some(step));
    }
    assert_eq!(RemoveStep::parse("everything"), None);
}

#[test]
fn packages_lists_installed_versions_and_newer_ones() {
    let host = fake(vec![
        (
            vec!["/usr/bin/rpm", "-qa"],
            out(0, "openvibes-ingest 0.1.0-1.fc44\nopenvibes-agent 0.1.0-1.fc44\nopenvibes-ingest-debuginfo 0.1.0-1.fc44\n", ""),
        ),
        (
            vec!["/usr/bin/dnf", "-q", "list", "--upgrades"],
            out(0, "Available upgrades\nopenvibes-ingest.x86_64 0.2.0-1.fc44 openvibes\n", ""),
        ),
    ]);
    assert_eq!(
        host.packages().unwrap(),
        [
            PackageUpdate { name: "openvibes-agent".into(), installed: "0.1.0-1.fc44".into(), available: None },
            PackageUpdate { name: "openvibes-ingest".into(), installed: "0.1.0-1.fc44".into(), available: Some("0.2.0-1.fc44".into()) },
        ]
    );
}

#[test]
fn the_journal_records_the_state_a_step_ended_in() {
    let host = fake(vec![
        (
            vec!["/usr/bin/sudo", "-S", "-k", "-p", "", "/usr/bin/openvibes-admin", "helper", "setup-step", "ca"],
            out(0, "failed\tdatabase down\n", ""),
        ),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    host.privileged(Privileged::SetupStep(Step::Ca), &Secret::new("pw".into())).unwrap();
    let calls = host.runner.calls.borrow();
    let journal = calls.iter().find(|call| call[0] == "/usr/bin/logger").unwrap();
    assert!(journal[3].ends_with(" setup-step ca failed"), "{journal:?}");
}
```

In `crates/openvibes-admin/src/tui/tests.rs` (`FakeHost`) and `crates/openvibes-admin/src/tui/setup_tests.rs` (`SetupHost`) add, importing `PackageUpdate`:

```rust
    fn packages(&self) -> Result<Vec<PackageUpdate>, HostError> {
        Ok(Vec::new())
    }
    fn setup_plan(&self) -> Result<String, HostError> {
        Err(HostError::Failed("not set up".into()))
    }
```

- [ ] **Step 2: Run, expect a compile failure.**

Run: `cargo test -p platform-host --test native`
Expected: FAIL to compile (`UpdateStep`, `RemoveStep`, `PackageUpdate`, `Privileged::Update`, `packages` missing).

- [ ] **Step 3: Implement.** In `setup.rs`, after `Step`:

```rust
/// One step of Update (§6.5a), in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum UpdateStep {
    Backup,
    Stop,
    Upgrade,
    Migrate,
    Start,
    Ready,
}

impl UpdateStep {
    pub const ALL: [UpdateStep; 6] = [
        UpdateStep::Backup,
        UpdateStep::Stop,
        UpdateStep::Upgrade,
        UpdateStep::Migrate,
        UpdateStep::Start,
        UpdateStep::Ready,
    ];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            UpdateStep::Backup => "backup",
            UpdateStep::Stop => "stop",
            UpdateStep::Upgrade => "upgrade",
            UpdateStep::Migrate => "migrate",
            UpdateStep::Start => "start",
            UpdateStep::Ready => "ready",
        }
    }

    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            UpdateStep::Backup => "Database backup",
            UpdateStep::Stop => "Stop services",
            UpdateStep::Upgrade => "Upgrade packages",
            UpdateStep::Migrate => "Migrate the database",
            UpdateStep::Start => "Start services",
            UpdateStep::Ready => "Readiness",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<UpdateStep> {
        UpdateStep::ALL.into_iter().find(|step| step.name() == name)
    }
}

/// One step of removing components or uninstalling (§6.5), in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RemoveStep {
    Backup,
    Stop,
    Firewall,
    Packages,
    Purge,
}

impl RemoveStep {
    pub const ALL: [RemoveStep; 5] = [
        RemoveStep::Backup,
        RemoveStep::Stop,
        RemoveStep::Firewall,
        RemoveStep::Packages,
        RemoveStep::Purge,
    ];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            RemoveStep::Backup => "backup",
            RemoveStep::Stop => "stop",
            RemoveStep::Firewall => "firewall",
            RemoveStep::Packages => "packages",
            RemoveStep::Purge => "purge",
        }
    }

    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            RemoveStep::Backup => "Database backup",
            RemoveStep::Stop => "Stop and disable services",
            RemoveStep::Firewall => "Close firewall ports",
            RemoveStep::Packages => "Remove packages",
            RemoveStep::Purge => "Remove all data",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<RemoveStep> {
        RemoveStep::ALL.into_iter().find(|step| step.name() == name)
    }
}
```

In `Privileged`, after `SetupStep(Step)`:

```rust
    /// `setup-step STEP --repair`: as `SetupStep`, but never makes a new CA.
    Repair(Step),
    /// `update-step STEP [--backup PATH]`.
    Update(UpdateStep, &'a [String]),
    /// `remove-step STEP --components LIST [--backup PATH] [--confirm HOSTNAME]`.
    Remove(RemoveStep, &'a [String]),
```

and in `args()` / `journal()`:

```rust
            Privileged::Repair(step) => vec!["setup-step".into(), step.name().into(), "--repair".into()],
            Privileged::Update(step, args) => {
                let mut all = vec!["update-step".to_owned(), step.name().to_owned()];
                all.extend(args.iter().cloned());
                all
            }
            Privileged::Remove(step, args) => {
                let mut all = vec!["remove-step".to_owned(), step.name().to_owned()];
                all.extend(args.iter().cloned());
                all
            }
```

```rust
    pub fn journal(&self) -> String {
        match self {
            Privileged::SetupPlan(_) => "setup-plan".into(),
            Privileged::Update(step, _) => format!("update-step {}", step.name()),
            Privileged::Remove(step, _) => format!("remove-step {}", step.name()),
            other => other.args().join(" "),
        }
    }
```

`lib.rs`: export `RemoveStep, UpdateStep`; add

```rust
/// An installed OpenVIBES package and the newer version the repository has.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageUpdate {
    pub name: String,
    /// `VERSION-RELEASE`.
    pub installed: String,
    /// A newer `VERSION-RELEASE`, when there is one.
    pub available: Option<String>,
}
```

and to `trait Host`:

```rust
    /// Installed OpenVIBES packages with any newer version (no password).
    fn packages(&self) -> Result<Vec<PackageUpdate>, HostError>;
    /// `/etc/openvibes/setup.toml` as text (world-readable, no secrets).
    fn setup_plan(&self) -> Result<String, HostError>;
```

`runner.rs`: `Program` gains `Userdel` (`/usr/sbin/userdel`) and `Groupdel` (`/usr/sbin/groupdel`), documented "Service accounts (Remove everything)". In both `SystemRunner` methods add `.env("LC_ALL", "C")` after `.args(args)`, with the comment `// C locale: sudo's, dnf's and systemctl's messages are parsed.`

`native.rs`: in `privileged`, replace the `outcome` line with

```rust
        // A step that ran but failed exits 0 with its state first.
        let outcome = match (out.status, out.stdout.split('\t').next()) {
            (0, Some(state @ ("failed" | "waiting" | "todo"))) => state,
            (0, _) => "ok",
            _ => "failed",
        };
```

and add to `impl Host for Native`:

```rust
    fn packages(&self) -> Result<Vec<PackageUpdate>, HostError> {
        let out = self.run(Rpm, &["-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n", "openvibes-*"])?;
        if out.status != 0 {
            return Err(HostError::Failed(printable(&out.stderr)));
        }
        let mut packages: Vec<PackageUpdate> = out
            .stdout
            .lines()
            .filter_map(|line| {
                let (name, version) = line.split_once(' ')?;
                (!name.ends_with("-debuginfo") && !name.ends_with("-debugsource")).then(|| PackageUpdate {
                    name: name.into(),
                    installed: version.into(),
                    available: None,
                })
            })
            .collect();
        packages.sort_by(|a, b| a.name.cmp(&b.name));
        // ponytail: dnf as the user reads its own metadata cache; offline or
        // failing, the list simply shows no newer versions.
        let upgrades = self.run(Dnf, &["-q", "list", "--upgrades", "openvibes-*"])?;
        if upgrades.status == 0 {
            for line in upgrades.stdout.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                let [full, version, _repo] = fields[..] else { continue };
                let name = full.rsplit_once('.').map_or(full, |(name, _arch)| name);
                if let Some(package) = packages.iter_mut().find(|p| p.name == name) {
                    package.available = Some(version.to_owned());
                }
            }
        }
        Ok(packages)
    }

    fn setup_plan(&self) -> Result<String, HostError> {
        std::fs::read_to_string(SETUP_FILE).map_err(|error| HostError::Failed(format!("{SETUP_FILE}: {error}")))
    }
```

(import `Dnf, Rpm` from `runner::Program` and `PackageUpdate`). `docs/components/platform-host.md`: extend the Setup section with `UpdateStep`, `RemoveStep`, the new verbs, `packages`, `setup_plan`, the journal's state word and `LC_ALL=C`.

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p platform-host && cargo test -p openvibes-admin --bin openvibes-admin tui`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/platform-host crates/openvibes-admin/src/tui docs/components/platform-host.md
git commit -m "platform-host: update and remove steps, packages, setup plan read

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Plan arguments checked in the plan, meaningless flags refused

**Files:**
- Modify: `crates/openvibes-admin/src/setup/plan.rs`

**Interfaces — Produces:** `PlanArgs.components` and `PlanArgs.hostname` are no longer required by clap (so `setup --repair|--update|--uninstall` can flatten `PlanArgs`); `PlanArgs::plan` checks them.

- [ ] **Step 1: Failing test** in `plan.rs`'s tests, added to `bad_plans_are_refused`'s loop:

```rust
            (args(&[], host, &[]), "--components is required"),
            (args(&[Ingest], "", &[]), "--hostname is required"),
```

and after the loop:

```rust
        let mut unsigned = args(&[Ingest], host, &[]);
        unsigned.allow_unsigned_local = true;
        assert!(unsigned.plan(None).unwrap_err().contains("needs --repo-dir"));
        let mut careful = args(&[Ingest], host, &[]);
        careful.ca = CaMode::Careful;
        careful.root_key_out = Some("/media/usb/root.key".into());
        assert!(careful.plan(None).unwrap_err().contains("quick CA"));
```

- [ ] **Step 2: Run, expect FAIL.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::plan`
Expected: FAIL (`bad_plans_are_refused`).

- [ ] **Step 3: Implement.** In `PlanArgs`: `#[arg(long, value_delimiter = ',', value_enum)] pub components: Vec<Component>,` (no `required`) and `#[arg(long, default_value = "")] pub hostname: String,`. At the top of `PlanArgs::plan`:

```rust
        if self.components.is_empty() {
            return Err("--components is required".into());
        }
        if self.hostname.is_empty() {
            return Err("--hostname is required".into());
        }
        if self.allow_unsigned_local && self.repo_dir.is_none() {
            return Err("--allow-unsigned-local needs --repo-dir".into());
        }
        if self.root_key_out.is_some() && self.ca == CaMode::Careful {
            return Err("--root-key-out is for the quick CA (a careful CA's root stays offline)".into());
        }
```

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup:: && cargo test -p openvibes-admin --test helper`
Expected: PASS (the helper tests still see exit 2 for bad plans).

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin/src/setup/plan.rs
git commit -m "admin: Setup plan checks required and meaningless arguments itself

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Repair mode, certificate names and expiry, run lock

**Files:**
- Create: `crates/openvibes-admin/src/setup/pki_tests.rs` (the tests moved out of `pki.rs`, which is over 500 lines)
- Modify: `crates/openvibes-admin/src/setup/{system.rs,pki.rs,mod.rs,fake.rs}`

**Interfaces — Produces:** `Ctx.repair: bool`; `pub fn lock(root: &Path) -> Result<std::fs::File, String>` in `system.rs`; `TLS_NAMES = "/etc/openvibes/tls/setup-names"`; `mod.rs`: `host_ctx(plan, repair: bool)`.

- [ ] **Step 1: Move the tests.** Cut `pki.rs`'s `#[cfg(test)] mod tests { … }` body into `src/setup/pki_tests.rs` (as a plain module: the `use` lines, `const ADMIN`, `with`, `ca_commands` and the tests, without the `mod tests {` wrapper), and in `mod.rs` add `#[cfg(test)] mod pki_tests;`. Run `cargo test -p openvibes-admin --bin openvibes-admin setup::pki_tests` — PASS (nothing changed but the place).

- [ ] **Step 2: Failing tests** in `pki_tests.rs`:

```rust
#[test]
fn repair_never_makes_a_new_ca() {
    let fake = Fake::new("ca-repair");
    ca_commands(&fake);
    let plan = plan(&[Ingest]);
    let mut ctx = fake.ctx(&plan);
    ctx.repair = true;
    let state = run_step(&ctx, Step::Ca);
    assert!(state.detail().contains("never makes a new CA"), "{state:?}");
    assert!(!fake.called(&["/usr/bin/openvibes-admin", "ca", "init-root"]));
}

/// A real certificate for NAMES, valid until NOW + DAYS.
fn certificate(names: &[&str], days_left: i64) -> String {
    let now = chrono::Utc::now();
    let root = platform_pki::generate_root(now - chrono::Duration::days(100)).unwrap();
    let issuer = platform_pki::Issuer::load(&root.cert_pem, &root.key_pem).unwrap();
    // Server certificates live 90 days.
    let issued = now - chrono::Duration::days(90 - days_left);
    let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
    issuer.issue_server(&names, issued).unwrap().cert_pem
}

fn installed_certificates(fake: &Fake, names: &[&str], days_left: i64) {
    for (cert, key) in [("ingest.crt", "ingest.key"), ("distribution.crt", "distribution.key")] {
        fake.file(&format!("/etc/openvibes/tls/{cert}"), &certificate(names, days_left));
        fake.file(&format!("/etc/openvibes/tls/{key}"), "KEY");
    }
    fake.file("/etc/openvibes/tls/setup-names", &format!("{}\n", names.join("\n")));
}

#[test]
fn certificates_for_other_names_are_issued_again() {
    let fake = Fake::new("certs-renamed");
    installed_certificates(&fake, &["old.example.com", "10.0.0.5", "localhost", "127.0.0.1"], 60);
    let state = crate::setup::check(&fake.ctx(&plan(&[Ingest, Distribution])), Step::Certificates);
    assert_eq!(state, StepState::Todo);
}

#[test]
fn a_certificate_about_to_expire_is_reported_not_replaced() {
    let fake = Fake::new("certs-expiring");
    installed_certificates(&fake, &["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"], 5);
    let state = run_step(&fake.ctx(&plan(&[Ingest, Distribution])), Step::Certificates);
    assert!(matches!(state, StepState::Failed(_)), "{state:?}");
    assert!(state.detail().contains("renew"), "{state:?}");
    assert!(!fake.called(&["/usr/sbin/runuser"]), "nothing re-issued");
    installed_certificates(&fake, &["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"], 60);
    assert!(matches!(run_step(&fake.ctx(&plan(&[Ingest, Distribution])), Step::Certificates), StepState::Done(_)));
}

#[test]
fn a_second_run_is_refused() {
    let fake = Fake::new("lock");
    let first = crate::setup::system::lock(&fake.root).unwrap();
    let second = crate::setup::system::lock(&fake.root).unwrap_err();
    assert!(second.contains("another Setup run"), "{second}");
    drop(first);
    assert!(crate::setup::system::lock(&fake.root).is_ok());
}
```

In `certificates_are_issued_for_every_name_and_installed` add at the end:

```rust
    assert_eq!(
        fake.text("/etc/openvibes/tls/setup-names"),
        "platform.example.com\n10.0.0.5\nlocalhost\n127.0.0.1\n"
    );
```

- [ ] **Step 3: Run, expect FAIL** (compile: `ctx.repair`, `system::lock` missing).

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::`

- [ ] **Step 4: Implement.** `system.rs`: `Ctx` gains

```rust
    /// Repair: steps may reinstall and restart, never make a new CA.
    pub repair: bool,
```

and add

```rust
/// Holds `/run/openvibes-admin/setup.lock` while one Setup run works; a
/// second is refused rather than racing (e.g. both staging a CA).
pub fn lock(root: &Path) -> Result<fs::File, String> {
    let dir = root.join("run/openvibes-admin");
    fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let path = dir.join("setup.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => Err("another Setup run is in progress on this host; wait for it to finish".into()),
        Err(fs::TryLockError::Error(error)) => Err(format!("{}: {error}", path.display())),
    }
}
```

`fake.rs`'s `ctx()` and `mod.rs`'s `host_ctx` set `repair`: `host_ctx(plan: &Plan, repair: bool)` and its callers pass `false` for now (`status`, `step`, `quick`).

`pki.rs`: at the top of `ca_apply`

```rust
    if ctx.repair {
        return Err("the CA files are missing; Repair never makes a new CA (enrolled agents trust \
                    the old one): restore /etc/openvibes/pki and /var/lib/openvibes-ingest/\
                    intermediate.key from a backup, or uninstall with Remove everything and set up again"
            .into());
    }
```

and replace `certificates_check` with

```rust
const TLS_NAMES: &str = "/etc/openvibes/tls/setup-names";
const RENEW_DAYS: i64 = 14;

pub fn certificates_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let names = ctx.plan.names();
    let wanted = format!("{}\n", names.join("\n"));
    let present = chosen(ctx).all(|tls| ctx.exists(tls.cert) && ctx.exists(tls.key));
    if !present || ctx.read(TLS_NAMES).ok().as_deref() != Some(wanted.as_str()) {
        return Ok(StepState::Todo);
    }
    for tls in chosen(ctx) {
        let pem = ctx.read(tls.cert)?;
        let expires = platform_pki::not_after(&pem).map_err(|error| format!("{}: {error:?}", tls.cert))?;
        if expires - chrono::Utc::now() < chrono::Duration::days(RENEW_DAYS) {
            return Ok(StepState::Failed(format!(
                "{} expires on {}: renew it (docs/components/packaging.md, \"Renewing the server certificate\")",
                tls.cert,
                expires.format("%Y-%m-%d")
            )));
        }
    }
    Ok(StepState::Done(format!("server certificates for {}", names.join(", "))))
}
```

and in `certificates_apply`, before `remove_stage(ctx)?`: `ctx.put(TLS_NAMES, format!("{}\n", names.join("\n")).as_bytes(), None, 0o644)?;`. In `run_step` (mod.rs) a `Failed` check must not be applied over:

```rust
    match check(ctx, step) {
        state @ (StepState::Done(_) | StepState::Skipped(_) | StepState::Failed(_)) => state,
        _ => apply(ctx, step),
    }
```

(A check that could not run already returned `Failed` before, and `apply` would have failed the same way; now an expiring certificate is reported instead of re-issued. Watch the PR 4 step tests while doing this: any whose check errors on an unanswered fake call now stops at the check, so give that call an answer in the test.)

- [ ] **Step 5: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::`
Expected: PASS.

- [ ] **Step 6: Commit.**

```bash
git add crates/openvibes-admin/src/setup
git commit -m "admin: Setup repair mode, certificate names and expiry, run lock

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Database backup

**Files:**
- Create: `crates/openvibes-admin/src/setup/backup.rs`
- Modify: `crates/openvibes-admin/src/setup/{mod.rs,system.rs,pki.rs}`

**Interfaces — Produces:** `pub fn dump<R: Runner>(ctx: &Ctx<R>, out: &Path) -> Result<String, String>`; `Ctx::write_new(&self, abs: &str, from: &mut dyn std::io::Read) -> Result<String, String>` (create-only, 0600, owner the operator through the handle; returns a note when the owner could not be set). `pki::keep_root_key` uses `write_new`.

- [ ] **Step 1: Failing tests** at the end of `backup.rs` (file with only the tests and `//! Database backup.`; add `mod backup;` to `mod.rs`):

```rust
#[cfg(test)]
mod tests {
    use crate::setup::fake::{Fake, plan};
    use crate::setup::plan::Component::*;

    const PG: [&str; 4] = ["/usr/sbin/runuser", "-u", "postgres", "--"];

    fn postgres(fake: &Fake) {
        fake.effect(&[&PG[..], &["/usr/bin/pg_dump"]].concat(), |root| {
            std::fs::write(root.join("var/tmp/openvibes-backup/openvibes.dump"), "PGDMP data").unwrap();
        });
        fake.answer(&[&PG[..], &["/usr/bin/pg_dumpall"]].concat(), 0, "CREATE ROLE \"openvibes-admin\";\n");
        fake.answer(&[&PG[..], &["/usr/bin/pg_restore", "--list"]].concat(), 0, "; Archive created\n");
    }

    #[test]
    fn a_backup_is_dumped_checked_and_handed_over() {
        let fake = Fake::new("backup");
        postgres(&fake);
        std::fs::create_dir_all(fake.root.join("home/alice")).unwrap();
        let plan = plan(&[Ingest]);
        let note = super::dump(&fake.ctx(&plan), std::path::Path::new("/home/alice/b.dump")).unwrap();
        assert!(note.contains("/home/alice/b.dump"), "{note}");
        assert_eq!(fake.text("/home/alice/b.dump"), "PGDMP data");
        assert!(fake.text("/home/alice/b.dump.roles.sql").contains("CREATE ROLE"));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(fake.root.join("home/alice/b.dump")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!fake.root.join("var/tmp/openvibes-backup").exists(), "staging removed");
        let dumpall = fake.call(&[&PG[..], &["/usr/bin/pg_dumpall"]].concat());
        assert!(dumpall.contains(&"--no-role-passwords".to_owned()), "{dumpall:?}");
    }

    #[test]
    fn an_existing_backup_file_is_not_overwritten() {
        let fake = Fake::new("backup-exists");
        postgres(&fake);
        fake.file("/home/alice/b.dump", "last month");
        let plan = plan(&[Ingest]);
        let error = super::dump(&fake.ctx(&plan), std::path::Path::new("/home/alice/b.dump")).unwrap_err();
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(fake.text("/home/alice/b.dump"), "last month");
        assert!(!fake.called(&[&PG[..], &["/usr/bin/pg_dump"]].concat()));
    }

    #[test]
    fn an_unreadable_dump_is_not_handed_over() {
        let fake = Fake::new("backup-bad");
        fake.effect(&[&PG[..], &["/usr/bin/pg_dump"]].concat(), |root| {
            std::fs::write(root.join("var/tmp/openvibes-backup/openvibes.dump"), "").unwrap();
        });
        fake.answer(&[&PG[..], &["/usr/bin/pg_dumpall"]].concat(), 0, "");
        fake.answer(&[&PG[..], &["/usr/bin/pg_restore"]].concat(), 1, "");
        std::fs::create_dir_all(fake.root.join("home/alice")).unwrap();
        let plan = plan(&[Ingest]);
        assert!(super::dump(&fake.ctx(&plan), std::path::Path::new("/home/alice/b.dump")).is_err());
        assert!(!fake.root.join("home/alice/b.dump").exists());
    }
}
```

- [ ] **Step 2: Run, expect a compile failure.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::backup`

- [ ] **Step 3: Implement.** `system.rs`, in `impl Ctx`:

```rust
    /// Creates `abs` (never over an existing file), 0600, filled from
    /// `from`; owned by the operator through the handle when there is one.
    /// A note when the owner could not be changed (e.g. a vfat stick).
    pub fn write_new(&self, abs: &str, from: &mut dyn std::io::Read) -> Result<String, String> {
        let fail = |error: std::io::Error| format!("{abs}: {error}");
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(self.path(abs)).map_err(fail)?;
        std::io::copy(from, &mut file).and_then(|_| file.sync_all()).map_err(fail)?;
        let owner = self.plan.operator.as_deref().map(|user| {
            self.ids(Some((user, user))).and_then(|(uid, gid)| {
                std::os::unix::fs::fchown(&file, Some(uid), Some(gid)).map_err(|error| format!("{abs}: {error}"))
            })
        });
        Ok(match owner {
            Some(Err(error)) => format!(" (still owned by root: {error})"),
            _ => String::new(),
        })
    }
```

`pki.rs` `keep_root_key`: replace its open, write and fchown code with

```rust
    let mut key = fs::File::open(ctx.path(&format!("{ROOT_DIR}/root.key"))).map_err(|error| format!("root key: {error}"))?;
    let note = ctx.write_new(&shown, &mut key)?;
    Ok(format!("root key saved to {shown}: keep it offline{note}"))
```

(the "already exists" check in `quick` stays; `write_new`'s `create_new` is the second guard).

`backup.rs` above the tests:

```rust
//! The database backup Update and Remove everything offer first (§6.5,
//! §6.5a): `pg_dump` into a directory only postgres can write, checked with
//! `pg_restore --list`, then handed to the user as a new 0600 file, with the
//! roles next to it. Nothing is ever written over an existing file.

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use platform_host::runner::Runner;

use super::Ctx;

const WORK: &str = "/var/tmp/openvibes-backup";
const DUMP: &str = "/var/tmp/openvibes-backup/openvibes.dump";

pub fn dump<R: Runner>(ctx: &Ctx<R>, out: &Path) -> Result<String, String> {
    let shown = out.display().to_string();
    let roles_file = format!("{shown}.roles.sql");
    for file in [&shown, &roles_file] {
        if ctx.exists(file) {
            return Err(format!("{file} already exists; choose another backup file"));
        }
    }
    let work = ctx.path(WORK);
    if work.exists() {
        fs::remove_dir_all(&work).map_err(|error| format!("{WORK}: {error}"))?;
    }
    fs::create_dir_all(&work).map_err(|error| format!("{WORK}: {error}"))?;
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).map_err(|error| format!("{WORK}: {error}"))?;
    ctx.chown(WORK, Some(("postgres", "postgres")))?;
    let result = (|| {
        ctx.as_postgres(&["/usr/bin/pg_dump", "--format=custom", "--file", DUMP, "openvibes"])?;
        let roles = ctx.as_postgres(&["/usr/bin/pg_dumpall", "--roles-only", "--no-role-passwords"])?;
        ctx.as_postgres(&["/usr/bin/pg_restore", "--list", DUMP])?;
        let size = fs::metadata(ctx.path(DUMP)).map_err(|error| format!("{DUMP}: {error}"))?.len();
        if size == 0 {
            return Err("the database dump is empty".to_owned());
        }
        let mut dump = fs::File::open(ctx.path(DUMP)).map_err(|error| format!("{DUMP}: {error}"))?;
        let note = ctx.write_new(&shown, &mut dump)?;
        ctx.write_new(&roles_file, &mut roles.as_bytes())?;
        Ok(format!("backup saved to {shown} ({size} bytes) and {roles_file}{note}"))
    })();
    let _ = fs::remove_dir_all(&work);
    result
}
```

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::`
Expected: PASS (the root key tests too).

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin/src/setup
git commit -m "admin: Setup database backup (pg_dump, roles, never over a file)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Update steps

**Files:**
- Create: `crates/openvibes-admin/src/setup/update.rs`
- Modify: `crates/openvibes-admin/src/setup/{mod.rs,run.rs,base.rs}`

**Interfaces — Consumes:** `backup::dump`, `base::install`-style local file lookup (`base::local_rpm` made `pub(super)`), `run::ready` (made `pub(super)`).
**Produces:**

```rust
#[derive(clap::Args, Clone, Debug, Default)]
pub struct UpdateArgs { #[arg(long)] pub backup: Option<PathBuf>, #[arg(long)] pub repo_dir: Option<PathBuf> }
impl UpdateArgs { pub fn check(&self) -> Result<(), String>; }   // absolute paths
pub fn run<R: Runner>(ctx: &Ctx<R>, step: UpdateStep, args: &UpdateArgs) -> StepState;
```

- [ ] **Step 1: Failing tests** at the end of `update.rs` (file with a doc line and the tests; `pub mod update;` in `mod.rs`):

```rust
#[cfg(test)]
mod tests {
    use platform_host::{StepState, UpdateStep};

    use super::{UpdateArgs, run};
    use crate::setup::{fake::{Fake, plan}, plan::Component::*};

    const ADMIN: [&str; 5] = ["/usr/sbin/runuser", "-u", "openvibes-admin", "--", "/usr/bin/openvibes-admin"];

    #[test]
    fn without_a_backup_path_the_backup_is_skipped() {
        let fake = Fake::new("update-no-backup");
        let plan = plan(&[Ingest]);
        assert!(matches!(run(&fake.ctx(&plan), UpdateStep::Backup, &UpdateArgs::default()), StepState::Skipped(_)));
    }

    #[test]
    fn update_stops_nothing_when_the_backup_fails() {
        let fake = Fake::new("update-backup-exists");
        fake.file("/home/alice/b.dump", "old");
        let plan = plan(&[Ingest]);
        let args = UpdateArgs { backup: Some("/home/alice/b.dump".into()), repo_dir: None };
        let state = run(&fake.ctx(&plan), UpdateStep::Backup, &args);
        assert!(matches!(state, StepState::Failed(_)), "{state:?}");
        assert!(!fake.called(&["/usr/bin/systemctl"]));
    }

    #[test]
    fn only_previously_active_units_are_started() {
        let fake = Fake::new("update-stop-start");
        fake.answer(&["/usr/bin/systemctl", "is-active", "--quiet", "openvibes-ingest.service"], 0, "");
        fake.answer(&["/usr/bin/systemctl", "is-active", "--quiet", "openvibes-agent.service"], 0, "");
        fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
        fake.answer(&["/usr/bin/systemctl", "stop"], 0, "");
        fake.answer(&["/usr/bin/systemctl", "start"], 0, "");
        let plan = plan(&[Ingest, Distribution, Agent]);
        let ctx = fake.ctx(&plan);
        assert!(matches!(run(&ctx, UpdateStep::Stop, &UpdateArgs::default()), StepState::Done(_)));
        assert_eq!(
            fake.call(&["/usr/bin/systemctl", "stop"]),
            ["/usr/bin/systemctl", "stop", "openvibes-ingest.service", "openvibes-agent.service"]
        );
        assert!(matches!(run(&ctx, UpdateStep::Start, &UpdateArgs::default()), StepState::Done(_)));
        assert_eq!(
            fake.call(&["/usr/bin/systemctl", "start"]),
            ["/usr/bin/systemctl", "start", "openvibes-ingest.service", "openvibes-agent.service"],
            "distribution was stopped before and stays stopped"
        );
        assert!(!fake.root.join("run/openvibes-admin/update-active").exists());
    }

    #[test]
    fn exactly_the_installed_packages_are_upgraded() {
        let fake = Fake::new("update-upgrade");
        fake.answer(
            &["/usr/bin/rpm", "-qa"],
            0,
            "openvibes-ingest\nopenvibes-admin\nopenvibes-agent\nopenvibes-ingest-debuginfo\n",
        );
        fake.answer(&["/usr/bin/dnf", "upgrade"], 0, "");
        let plan = plan(&[Ingest, Agent]);
        assert!(matches!(run(&fake.ctx(&plan), UpdateStep::Upgrade, &UpdateArgs::default()), StepState::Done(_)));
        assert_eq!(
            fake.call(&["/usr/bin/dnf"]),
            ["/usr/bin/dnf", "upgrade", "-y", "openvibes-admin", "openvibes-agent", "openvibes-ingest"]
        );
    }

    #[test]
    fn a_local_folder_upgrades_from_its_files() {
        let fake = Fake::new("update-local");
        fake.answer(&["/usr/bin/rpm", "-qa"], 0, "openvibes-ingest\nopenvibes-admin\n");
        fake.answer(&["/usr/bin/dnf", "upgrade"], 0, "");
        fake.file("/srv/new/openvibes-ingest-0.2.0-1.fc44.x86_64.rpm", "");
        fake.file("/srv/new/openvibes-admin-0.2.0-1.fc44.x86_64.rpm", "");
        let mut plan = plan(&[Ingest]);
        plan.allow_unsigned_local = true;
        let args = UpdateArgs { backup: None, repo_dir: Some("/srv/new".into()) };
        assert!(matches!(run(&fake.ctx(&plan), UpdateStep::Upgrade, &args), StepState::Done(_)));
        assert_eq!(
            fake.call(&["/usr/bin/dnf"]),
            ["/usr/bin/dnf", "upgrade", "-y", "--setopt=localpkg_gpgcheck=0",
             "/srv/new/openvibes-admin-0.2.0-1.fc44.x86_64.rpm", "/srv/new/openvibes-ingest-0.2.0-1.fc44.x86_64.rpm"]
        );
    }

    #[test]
    fn migrate_runs_migrate_and_maintenance() {
        let fake = Fake::new("update-migrate");
        fake.answer(&[&ADMIN[..], &["migrate"]].concat(), 0, "schema version 25\n");
        fake.answer(&[&ADMIN[..], &["maintenance"]].concat(), 0, "created 0 partitions\n");
        let plan = plan(&[Ingest]);
        let state = run(&fake.ctx(&plan), UpdateStep::Migrate, &UpdateArgs::default());
        assert_eq!(state, StepState::Done("schema version 25; created 0 partitions".into()));
    }
}
```

- [ ] **Step 2: Run, expect a compile failure.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::update`

- [ ] **Step 3: Implement.** `base.rs`: make `local_rpm` `pub(super)`. `run.rs`: make `ready` `pub(super)`. `update.rs` above the tests:

```rust
//! Update (admin TUI spec §6.5a): backup offered, the active OpenVIBES
//! units stopped (and remembered), exactly the installed OpenVIBES packages
//! upgraded, the database migrated, the remembered units started again.

use std::path::PathBuf;

use platform_host::{StepState, Unit, UpdateStep, runner::{Program::{Dnf, Rpm, Systemctl}, Runner}};

use super::{Ctx, backup, base::local_rpm, run::ready};

const ACTIVE: &str = "/run/openvibes-admin/update-active";
const AGENT: &str = "openvibes-agent.service";

#[derive(clap::Args, Clone, Debug, Default)]
pub struct UpdateArgs {
    /// Write a database backup here first (a new file).
    #[arg(long)]
    pub backup: Option<PathBuf>,
    /// Upgrade from this folder of package files (test builds).
    #[arg(long)]
    pub repo_dir: Option<PathBuf>,
}

impl UpdateArgs {
    pub fn check(&self) -> Result<(), String> {
        for path in [&self.backup, &self.repo_dir].into_iter().flatten() {
            if !path.is_absolute() {
                return Err(format!("{} is not an absolute path", path.display()));
            }
        }
        Ok(())
    }
}

fn units() -> Vec<&'static str> {
    Unit::ALL.iter().map(|unit| unit.name()).chain([AGENT]).collect()
}

fn stop<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let active: Vec<&str> = units()
        .into_iter()
        .filter(|unit| ctx.succeeds(Systemctl, &["is-active", "--quiet", unit]))
        .collect();
    ctx.put(ACTIVE, format!("{}\n", active.join("\n")).as_bytes(), None, 0o600)?;
    if !active.is_empty() {
        let mut args = vec!["stop"];
        args.extend(&active);
        ctx.ok(Systemctl, &args)?;
    }
    Ok(StepState::Done(format!("stopped: {}", active.join(" "))))
}

fn upgrade<R: Runner>(ctx: &Ctx<R>, args: &UpdateArgs) -> Result<StepState, String> {
    let installed = ctx.ok(Rpm, &["-qa", "--qf", "%{NAME}\n", "openvibes-*"])?;
    let mut names: Vec<&str> = installed
        .lines()
        .filter(|name| !name.ends_with("-debuginfo") && !name.ends_with("-debugsource"))
        .collect();
    names.sort_unstable();
    let mut argv = vec!["upgrade".to_owned(), "-y".to_owned()];
    match args.repo_dir.as_ref().or(ctx.plan.repo_dir.as_ref()) {
        None => argv.extend(names.iter().map(|name| (*name).to_owned())),
        Some(dir) => {
            let check = if ctx.plan.allow_unsigned_local { "0" } else { "1" };
            argv.push(format!("--setopt=localpkg_gpgcheck={check}"));
            // A package the folder does not have stays as it is.
            argv.extend(names.iter().filter_map(|name| local_rpm(ctx, dir, name).ok()));
        }
    }
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    ctx.ok(Dnf, &argv)?;
    Ok(StepState::Done(format!("upgraded where newer: {}", names.join(" "))))
}

fn migrate<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let migrated = ctx.as_admin(&["migrate"])?;
    let maintained = ctx.as_admin(&["maintenance"])?;
    Ok(StepState::Done(format!("{}; {}", migrated.trim(), maintained.trim())))
}

fn start<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let text = ctx.read(ACTIVE).map_err(|_| "no record of the stopped services: run the Stop step first".to_owned())?;
    let active: Vec<&str> = text.lines().filter(|line| units().contains(line)).collect();
    if !active.is_empty() {
        let mut args = vec!["start"];
        args.extend(&active);
        ctx.ok(Systemctl, &args)?;
    }
    let _ = std::fs::remove_file(ctx.path(ACTIVE));
    Ok(StepState::Done(format!("started again: {}", active.join(" "))))
}

fn wait_ready<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let running: Vec<Unit> = Unit::ALL
        .into_iter()
        .filter(|unit| ctx.succeeds(Systemctl, &["is-active", "--quiet", unit.name()]))
        .collect();
    for unit in &running {
        let mut attempts = 0;
        while !ready(ctx, *unit) {
            attempts += 1;
            if attempts == 30 {
                return Err(format!("{} is not ready after 30 seconds; see journalctl -u {}", unit.name(), unit.name()));
            }
            ctx.pause();
        }
    }
    let names: Vec<&str> = running.iter().map(|unit| unit.name()).collect();
    Ok(StepState::Done(format!("ready: {}", names.join(" "))))
}

pub fn run<R: Runner>(ctx: &Ctx<R>, step: UpdateStep, args: &UpdateArgs) -> StepState {
    let result = match step {
        UpdateStep::Backup => match &args.backup {
            None => Ok(StepState::Skipped("no backup chosen".into())),
            Some(path) => backup::dump(ctx, path).map(StepState::Done),
        },
        UpdateStep::Stop => stop(ctx),
        UpdateStep::Upgrade => upgrade(ctx, args),
        UpdateStep::Migrate => migrate(ctx),
        UpdateStep::Start => start(ctx),
        UpdateStep::Ready => wait_ready(ctx),
    };
    result.unwrap_or_else(StepState::Failed)
}
```

The upgrade test's `rpm -qa` answer lists names only because the step asks for `%{NAME}\n`.

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin/src/setup
git commit -m "admin: Setup update steps (stop, upgrade, migrate, start again)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Remove steps (keep data, or remove everything)

**Files:**
- Create: `crates/openvibes-admin/src/setup/remove.rs`
- Modify: `crates/openvibes-admin/src/setup/{mod.rs,run.rs}`

**Interfaces — Consumes:** `backup::dump`; `run::ports_for` (new, below).
**Produces:**

```rust
#[derive(clap::Args, Clone, Debug, Default)]
pub struct RemoveArgs { #[arg(long, value_delimiter = ',', value_enum)] pub components: Vec<Component>,
                        #[arg(long)] pub backup: Option<PathBuf>, #[arg(long)] pub confirm: Option<String> }
impl RemoveArgs { pub fn check(&self) -> Result<(), String>; }
pub fn run<R: Runner>(ctx: &Ctx<R>, step: RemoveStep, args: &RemoveArgs) -> StepState;
```

- [ ] **Step 1: Failing tests** at the end of `remove.rs` (`pub mod remove;` in `mod.rs`):

```rust
#[cfg(test)]
mod tests {
    use platform_host::{RemoveStep, StepState};

    use super::{RemoveArgs, run};
    use crate::setup::{fake::{Fake, plan}, plan::Component::{self, *}};

    const PG: [&str; 4] = ["/usr/sbin/runuser", "-u", "postgres", "--"];

    fn args(components: &[Component], confirm: Option<&str>) -> RemoveArgs {
        RemoveArgs { components: components.to_vec(), backup: None, confirm: confirm.map(str::to_owned) }
    }

    #[test]
    fn removing_a_component_stops_it_closes_its_port_and_removes_its_packages() {
        let fake = Fake::new("remove-distribution");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-distribution"], 0, "");
        fake.answer(&["/usr/bin/systemctl", "disable", "--now"], 0, "");
        fake.answer(&["/usr/bin/firewall-cmd", "--state"], 0, "running\n");
        fake.answer(&["/usr/bin/firewall-cmd", "--permanent", "--query-port", "18424/tcp"], 0, "yes\n");
        fake.answer(&["/usr/bin/firewall-cmd", "--permanent", "--remove-port"], 0, "success\n");
        fake.answer(&["/usr/bin/firewall-cmd", "--reload"], 0, "success\n");
        fake.answer(&["/usr/bin/dnf", "remove"], 0, "");
        let plan = plan(&[Ingest, Distribution]);
        let ctx = fake.ctx(&plan);
        let args = args(&[Distribution], None);
        for step in RemoveStep::ALL {
            let state = run(&ctx, step, &args);
            assert!(state.finished(), "{step:?}: {state:?}");
        }
        assert_eq!(fake.call(&["/usr/bin/systemctl", "disable"]), ["/usr/bin/systemctl", "disable", "--now", "openvibes-distribution.service"]);
        assert_eq!(fake.call(&["/usr/bin/firewall-cmd", "--permanent", "--remove-port"])[3], "18424/tcp");
        assert_eq!(fake.call(&["/usr/bin/dnf"]), ["/usr/bin/dnf", "remove", "-y", "openvibes-distribution"]);
        assert!(!fake.called(&PG), "keep data: the database is not touched");
    }

    #[test]
    fn the_admin_package_is_left_for_last() {
        let fake = Fake::new("remove-admin");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet"], 0, "");
        fake.answer(&["/usr/bin/dnf", "remove"], 0, "");
        let plan = plan(&[Ingest, Agent]);
        let state = run(&fake.ctx(&plan), RemoveStep::Packages, &args(&[Ingest, Agent], None));
        assert_eq!(fake.call(&["/usr/bin/dnf"]), ["/usr/bin/dnf", "remove", "-y", "openvibes-ingest", "openvibes-agent"]);
        assert!(state.detail().contains("sudo dnf remove openvibes-admin"), "{state:?}");
    }

    #[test]
    fn purge_needs_the_hostname_and_the_whole_platform() {
        let fake = Fake::new("purge-refused");
        fake.file("/etc/openvibes/setup.toml", "kept");
        let plan = plan(&[Ingest, Vulns]);
        let ctx = fake.ctx(&plan);
        assert!(matches!(run(&ctx, RemoveStep::Purge, &args(&[Ingest, Vulns], None)), StepState::Skipped(_)));
        let wrong = run(&ctx, RemoveStep::Purge, &args(&[Ingest, Vulns], Some("other.example.com")));
        assert!(wrong.detail().contains("does not match"), "{wrong:?}");
        let partial = run(&ctx, RemoveStep::Purge, &args(&[Vulns], Some("platform.example.com")));
        assert!(partial.detail().contains("whole platform"), "{partial:?}");
        assert!(fake.root.join("etc/openvibes/setup.toml").exists());
        assert!(!fake.called(&PG));
    }

    #[test]
    fn purge_drops_the_database_roles_files_and_accounts() {
        let fake = Fake::new("purge");
        fake.file("/etc/openvibes/setup.toml", "x");
        fake.file("/var/lib/openvibes-ingest/intermediate.key", "x");
        fake.file("/etc/openvibes-agent/agent.toml", "x");
        fake.answer(
            &[&PG[..], &["/usr/bin/psql"]].concat(),
            0,
            "openvibes-admin\nopenvibes-ingest\nopenvibes-console\n",
        );
        fake.answer(&[&PG[..], &["/usr/bin/dropdb"]].concat(), 0, "");
        fake.answer(&[&PG[..], &["/usr/bin/dropuser"]].concat(), 0, "");
        fake.answer(&["/usr/sbin/userdel"], 0, "");
        fake.answer(&["/usr/sbin/groupdel"], 0, "");
        let plan = plan(&[Ingest, Console]);
        let state = run(&fake.ctx(&plan), RemoveStep::Purge, &args(&[Ingest, Console], Some("platform.example.com")));
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(fake.called(&[&PG[..], &["/usr/bin/dropdb", "--if-exists", "openvibes"]].concat()));
        let dropped: Vec<String> = fake.calls.borrow().iter()
            .filter(|c| c.get(4).is_some_and(|p| p == "/usr/bin/dropuser")).map(|c| c[6].clone()).collect();
        assert_eq!(dropped, ["openvibes-admin", "openvibes-ingest", "openvibes-console"]);
        for gone in ["etc/openvibes", "var/lib/openvibes-ingest", "etc/openvibes-agent"] {
            assert!(!fake.root.join(gone).exists(), "{gone}");
        }
        assert!(fake.called(&["/usr/sbin/userdel", "openvibes-ingest"]));
        assert!(fake.called(&["/usr/sbin/groupdel", "openvibes-operators"]));
        assert!(state.detail().contains("PostgreSQL itself stays"), "{state:?}");
    }
}
```

The fake's `/etc/passwd` and `/etc/group` (from `Fake::new`) list the accounts, so `userdel`/`groupdel` are called for those present.

- [ ] **Step 2: Run, expect a compile failure.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::remove`

- [ ] **Step 3: Implement.** `run.rs`: split `ports` so removal can ask for any set of components:

```rust
/// The firewall ports of `components`.
pub(super) fn ports_for<R: Runner>(ctx: &Ctx<R>, components: &[Component]) -> Result<Vec<String>, String> {
    let mut ports = Vec::new();
    if components.contains(&Component::Ingest) {
        ports.push("18423/tcp".to_owned());
    }
    if components.contains(&Component::Distribution) {
        ports.push("18424/tcp".into());
    }
    if components.contains(&Component::Console) {
        ports.extend(console_port(ctx)?);
    }
    Ok(ports)
}

fn ports<R: Runner>(ctx: &Ctx<R>) -> Result<Vec<String>, String> {
    ports_for(ctx, &ctx.plan.components)
}
```

`remove.rs` above the tests:

```rust
//! Removing components (keep data) and Remove everything (admin TUI spec
//! §6.5). `openvibes-admin` itself is never removed here: the TUI is
//! running; the last line says how to remove it.

use std::{fs, path::PathBuf};

use platform_host::{RemoveStep, StepState, runner::{Program::{Dnf, FirewallCmd, Groupdel, Rpm, Systemctl, Userdel}, Runner}};

use super::{Ctx, backup, plan::{Component, check_name}, run::ports_for};

#[derive(clap::Args, Clone, Debug, Default)]
pub struct RemoveArgs {
    /// The components to remove.
    #[arg(long, value_delimiter = ',', value_enum)]
    pub components: Vec<Component>,
    /// Write a database backup here first (a new file).
    #[arg(long)]
    pub backup: Option<PathBuf>,
    /// This host's name, typed to confirm Remove everything.
    #[arg(long)]
    pub confirm: Option<String>,
}

impl RemoveArgs {
    pub fn check(&self) -> Result<(), String> {
        if self.components.is_empty() {
            return Err("--components is required".into());
        }
        if let Some(path) = &self.backup
            && !path.is_absolute()
        {
            return Err(format!("{} is not an absolute path", path.display()));
        }
        if let Some(name) = &self.confirm {
            check_name(name)?;
        }
        Ok(())
    }
}

/// Data directories Remove everything deletes (fixed; never from input).
const DATA: [&str; 9] = [
    "/etc/openvibes",
    "/etc/openvibes-agent",
    "/var/lib/openvibes-admin",
    "/var/lib/openvibes-ingest",
    "/var/lib/openvibes-distribution",
    "/var/lib/openvibes-vulns",
    "/var/lib/openvibes-console",
    "/var/lib/openvibes-llm",
    "/var/lib/openvibes-agent",
];
/// Service accounts (user and group of the same name) it deletes.
const ACCOUNTS: [&str; 7] = [
    "openvibes-ingest",
    "openvibes-distribution",
    "openvibes-vulns",
    "openvibes-console",
    "openvibes-llm",
    "openvibes_agent",
    "openvibes-admin",
];

fn installed<R: Runner>(ctx: &Ctx<R>, package: &str) -> bool {
    ctx.succeeds(Rpm, &["-q", "--quiet", package])
}

fn packages<R: Runner>(ctx: &Ctx<R>, args: &RemoveArgs) -> Vec<&'static str> {
    args.components
        .iter()
        .flat_map(|c| c.packages())
        .copied()
        .filter(|package| *package != "openvibes-admin" && installed(ctx, package))
        .collect()
}

fn stop<R: Runner>(ctx: &Ctx<R>, args: &RemoveArgs) -> Result<StepState, String> {
    let mut units: Vec<&str> = Vec::new();
    for component in &args.components {
        if component.packages().iter().any(|package| installed(ctx, package)) {
            units.extend(component.units().iter().map(|unit| unit.name()));
            if *component == Component::Agent {
                units.push("openvibes-agent.service");
            }
            if *component == Component::Assistant {
                units.push("openvibes-llm.service");
            }
        }
    }
    if units.is_empty() {
        return Ok(StepState::Skipped("nothing installed to stop".into()));
    }
    let mut argv = vec!["disable", "--now"];
    argv.extend(&units);
    ctx.ok(Systemctl, &argv)?;
    Ok(StepState::Done(format!("stopped and disabled: {}", units.join(" "))))
}

fn firewall<R: Runner>(ctx: &Ctx<R>, args: &RemoveArgs) -> Result<StepState, String> {
    if !ctx.succeeds(FirewallCmd, &["--state"]) {
        return Ok(StepState::Skipped("firewalld is not running".into()));
    }
    // The console's port is read from its config, which may be gone already.
    let ports = ports_for(ctx, &args.components).unwrap_or_default();
    let open: Vec<&String> = ports
        .iter()
        .filter(|port| ctx.succeeds(FirewallCmd, &["--permanent", "--query-port", port]))
        .collect();
    for port in &open {
        ctx.ok(FirewallCmd, &["--permanent", "--remove-port", port])?;
    }
    ctx.ok(FirewallCmd, &["--reload"])?;
    let closed: Vec<&str> = open.iter().map(|port| port.as_str()).collect();
    Ok(StepState::Done(format!("closed: {}", closed.join(" "))))
}

fn remove_packages<R: Runner>(ctx: &Ctx<R>, args: &RemoveArgs) -> Result<StepState, String> {
    let packages = packages(ctx, args);
    if !packages.is_empty() {
        let mut argv = vec!["remove", "-y"];
        argv.extend(&packages);
        ctx.ok(Dnf, &argv)?;
    }
    let mut text = format!("removed: {}", packages.join(" "));
    if args.components.contains(&Component::Ingest) {
        text.push_str("; last, remove the administration tool itself: sudo dnf remove openvibes-admin");
    }
    Ok(StepState::Done(text))
}

fn purge<R: Runner>(ctx: &Ctx<R>, args: &RemoveArgs) -> Result<StepState, String> {
    let Some(confirm) = &args.confirm else {
        return Ok(StepState::Skipped("data kept".into()));
    };
    if *confirm != ctx.plan.hostname {
        return Err(format!("the typed name does not match this host's name ({}); nothing removed", ctx.plan.hostname));
    }
    if !ctx.plan.components.iter().all(|c| args.components.contains(c)) {
        return Err("Remove everything applies to the whole platform: list every component".into());
    }
    let roles = ctx.as_postgres(&["/usr/bin/psql", "-Atqc", "SELECT rolname FROM pg_roles WHERE rolname LIKE 'openvibes-%' ORDER BY oid"])?;
    ctx.as_postgres(&["/usr/bin/dropdb", "--if-exists", "openvibes"])?;
    for role in roles.lines().map(str::trim).filter(|r| {
        r.starts_with("openvibes-") && r.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
    }) {
        ctx.as_postgres(&["/usr/bin/dropuser", "--if-exists", role])?;
    }
    for dir in DATA {
        let path = ctx.path(dir);
        if path.exists() {
            fs::remove_dir_all(&path).map_err(|error| format!("{dir}: {error}"))?;
        }
    }
    let passwd = ctx.read("/etc/passwd")?;
    for account in ACCOUNTS {
        if passwd.lines().any(|line| line.starts_with(&format!("{account}:"))) {
            ctx.ok(Userdel, &[account])?;
        }
    }
    let groups = ctx.read("/etc/group")?;
    for group in ACCOUNTS.iter().chain(&["openvibes-operators"]) {
        if groups.lines().any(|line| line.starts_with(&format!("{group}:"))) {
            // userdel already removed a user's own group on most hosts.
            let _ = ctx.ok(Groupdel, &[group]);
        }
    }
    Ok(StepState::Done(
        "database, roles, configuration, data and service accounts removed; PostgreSQL itself stays installed".into(),
    ))
}

pub fn run<R: Runner>(ctx: &Ctx<R>, step: RemoveStep, args: &RemoveArgs) -> StepState {
    let result = match step {
        RemoveStep::Backup => match &args.backup {
            None => Ok(StepState::Skipped("no backup chosen".into())),
            Some(path) => backup::dump(ctx, path).map(StepState::Done),
        },
        RemoveStep::Stop => stop(ctx, args),
        RemoveStep::Firewall => firewall(ctx, args),
        RemoveStep::Packages => remove_packages(ctx, args),
        RemoveStep::Purge => purge(ctx, args),
    };
    result.unwrap_or_else(StepState::Failed)
}
```

In the purge test, the fake's `userdel` answers every account and `groupdel` every group; the test only checks the calls named.

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin setup::`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin/src/setup
git commit -m "admin: Setup remove steps (keep data, or remove everything)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Helper verbs, `setup --repair|--update|--uninstall`, the lock

**Files:**
- Modify: `crates/openvibes-admin/src/{helper.rs,main.rs,setup/mod.rs}`, `crates/openvibes-admin/tests/helper.rs`, `docs/components/openvibes-admin.md`

**Interfaces — Produces:** helper verbs `setup-step STEP [--repair]`, `update-step STEP [UpdateArgs]`, `remove-step STEP [RemoveArgs]`; refusal reasons passed through (`verb()` returns `Result<Verb, String>`); `setup::{step(step, repair), update(step, &UpdateArgs), remove(step, &RemoveArgs), repair_all(), update_all(&UpdateArgs), uninstall_all(everything, confirm, backup)}`.

- [ ] **Step 1: Failing tests** in `tests/helper.rs`:

```rust
#[test]
fn maintenance_verbs_check_their_arguments_before_the_root_check() {
    for (args, reason) in [
        (vec!["update-step", "everything"], "not an update step"),
        (vec!["update-step", "backup", "--backup", "relative.dump"], "absolute"),
        (vec!["remove-step", "purge"], "--components is required"),
        (vec!["remove-step", "purge", "--components", "ingest", "--confirm", "Bad Name"], "lowercase DNS name"),
        (vec!["setup-plan", "--components", "ingest", "--hostname", "platform.example.com", "--allow-unsigned-local"], "needs --repo-dir"),
    ] {
        let out = helper(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("not allowed") && stderr.contains(reason), "{args:?}: {stderr}");
    }
    for args in [vec!["setup-step", "ca", "--repair"], vec!["update-step", "stop"], vec!["remove-step", "stop", "--components", "vulns"]] {
        let out = helper(&args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
    }
}

#[test]
fn setup_actions_need_root_and_exactly_one_action() {
    let run = |args: &[&str]| Command::new(env!("CARGO_BIN_EXE_openvibes-admin")).args(args).output().unwrap();
    for args in [["setup", "--repair"].as_slice(), &["setup", "--update"], &["setup", "--uninstall", "--keep-data"]] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("must run as root"), "{args:?}");
    }
    let out = run(&["setup", "--repair", "--update"]);
    assert_eq!(out.status.code(), Some(2));
    let out = run(&["setup", "--uninstall"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--keep-data or --everything"));
    let out = run(&["setup", "--uninstall", "--everything"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--confirm"));
}
```

- [ ] **Step 2: Run, expect FAIL.**

Run: `cargo test -p openvibes-admin --test helper`

- [ ] **Step 3: Implement.** `helper.rs`:
- `HelperCommand::SetupStep` gains `/// Repair: never makes a new CA. #[arg(long)] repair: bool`; add

```rust
    /// Runs one Update step.
    UpdateStep {
        /// backup, stop, upgrade, migrate, start, ready.
        step: String,
        #[command(flatten)]
        args: crate::setup::update::UpdateArgs,
    },
    /// Runs one step of removing components or uninstalling.
    RemoveStep {
        /// backup, stop, firewall, packages, purge.
        step: String,
        #[command(flatten)]
        args: crate::setup::remove::RemoveArgs,
    },
```

- `Verb`: `SetupStep(Step, bool)`, `UpdateStep(UpdateStep, crate::setup::update::UpdateArgs)`, `RemoveStep(RemoveStep, crate::setup::remove::RemoveArgs)`.
- `verb()` returns `Result<Verb, String>`; each `.ok_or("…")?` becomes `.ok_or_else(|| "…".to_owned())?`; `SetupPlan` maps `Err(reason) => return Err(format!("invalid Setup arguments: {reason}"))`; new arms:

```rust
        HelperCommand::SetupStep { step, repair } => {
            Verb::SetupStep(Step::parse(step).ok_or_else(|| "not a Setup step".to_owned())?, *repair)
        }
        HelperCommand::UpdateStep { step, args } => {
            args.check()?;
            Verb::UpdateStep(UpdateStep::parse(step).ok_or_else(|| "not an update step".to_owned())?, args.clone())
        }
        HelperCommand::RemoveStep { step, args } => {
            args.check()?;
            Verb::RemoveStep(RemoveStep::parse(step).ok_or_else(|| "not a remove step".to_owned())?, args.clone())
        }
```

- `run()`: `Err(reason) => return refuse(&reason)`; dispatch `Verb::SetupStep(step, repair) => crate::setup::step(step, repair)`, `Verb::UpdateStep(step, args) => crate::setup::update(step, &args)`, `Verb::RemoveStep(step, args) => crate::setup::remove(step, &args)`; `Verb::SetupPlan` takes the lock first (`let _lock = match crate::setup::system::lock(Path::new("/")) { Ok(l) => l, Err(e) => return failed(&e) };`).

`setup/mod.rs` (`pub mod system;` so the helper can lock; `pub mod update; pub mod remove;`):

```rust
/// Loads the plan and holds the run lock; prints the error otherwise.
fn begin() -> Result<(std::fs::File, Plan), ExitCode> {
    let lock = system::lock(Path::new("/")).map_err(|error| {
        eprintln!("openvibes-admin: {error}");
        ExitCode::FAILURE
    })?;
    let plan = Plan::load(Path::new("/")).map_err(|error| {
        eprintln!("openvibes-admin: {error}");
        ExitCode::FAILURE
    })?;
    Ok((lock, plan))
}

/// `helper setup-step STEP [--repair]`.
pub fn step(step: Step, repair: bool) -> ExitCode {
    let (_lock, plan) = match begin() { Ok(v) => v, Err(code) => return code };
    println!("{}", run_step(&host_ctx(&plan, repair), step).line());
    ExitCode::SUCCESS
}

/// `helper update-step STEP …`.
pub fn update(step: UpdateStep, args: &update::UpdateArgs) -> ExitCode {
    let (_lock, plan) = match begin() { Ok(v) => v, Err(code) => return code };
    println!("{}", update::run(&host_ctx(&plan, false), step, args).line());
    ExitCode::SUCCESS
}

/// `helper remove-step STEP …`.
pub fn remove(step: RemoveStep, args: &remove::RemoveArgs) -> ExitCode {
    let (_lock, plan) = match begin() { Ok(v) => v, Err(code) => return code };
    println!("{}", remove::run(&host_ctx(&plan, false), step, args).line());
    ExitCode::SUCCESS
}

fn root_or_exit() -> Result<(), ExitCode> {
    if crate::helper::effective_uid().as_deref() == Some("0") {
        Ok(())
    } else {
        eprintln!("openvibes-admin: setup must run as root");
        Err(ExitCode::from(1))
    }
}

/// Prints one line per step; exit 0 when all finished, 3 waiting, 1 failed.
fn report(results: impl Iterator<Item = (&'static str, StepState)>) -> ExitCode {
    for (title, state) in results {
        println!("{title}: {} {}", state.label(), state.detail());
        if !state.finished() {
            return ExitCode::from(if matches!(state, StepState::Waiting(_)) { 3 } else { 1 });
        }
    }
    ExitCode::SUCCESS
}

/// `setup --repair`.
pub fn repair_all() -> ExitCode {
    if let Err(code) = root_or_exit() { return code; }
    let (_lock, plan) = match begin() { Ok(v) => v, Err(code) => return code };
    let ctx = host_ctx(&plan, true);
    report(Step::ALL.into_iter().map(|step| (step.title(), run_step(&ctx, step))))
}

/// `setup --update [--backup PATH] [--repo-dir DIR]`.
pub fn update_all(args: &update::UpdateArgs) -> ExitCode {
    if let Err(error) = args.check() {
        eprintln!("openvibes-admin: {error}");
        return ExitCode::from(2);
    }
    if let Err(code) = root_or_exit() { return code; }
    let (_lock, plan) = match begin() { Ok(v) => v, Err(code) => return code };
    let ctx = host_ctx(&plan, false);
    report(UpdateStep::ALL.into_iter().map(|step| (step.title(), update::run(&ctx, step, args))))
}

/// `setup --uninstall --keep-data|--everything [--confirm HOST] [--backup PATH]`.
pub fn uninstall_all(everything: bool, confirm: Option<String>, backup: Option<std::path::PathBuf>) -> ExitCode {
    if let Err(code) = root_or_exit() { return code; }
    let (_lock, plan) = match begin() { Ok(v) => v, Err(code) => return code };
    let args = remove::RemoveArgs {
        components: plan.components.clone(),
        backup,
        confirm: if everything { confirm } else { None },
    };
    if let Err(error) = args.check() {
        eprintln!("openvibes-admin: {error}");
        return ExitCode::from(2);
    }
    let ctx = host_ctx(&plan, false);
    report(RemoveStep::ALL.into_iter().map(|step| (step.title(), remove::run(&ctx, step, &args))))
}
```

`quick` also takes the lock (after its root check: `let _lock = match system::lock(Path::new("/")) { … }`). Note `report` stops at the first unfinished step because the iterator is lazy.

`main.rs`: replace the `Setup` variant with

```rust
    /// Set up, repair, update or uninstall the platform on this host without
    /// screens (as root). Without an action, run openvibes-admin with no
    /// arguments for the Setup screen.
    #[command(group(clap::ArgGroup::new("action").args(["quick", "repair", "update", "uninstall"]).required(true)))]
    Setup {
        /// Install and set up (needs --components and --hostname).
        #[arg(long)]
        quick: bool,
        /// Check every step and fix what failed (never a new CA).
        #[arg(long)]
        repair: bool,
        /// Upgrade the OpenVIBES packages (the local agent too).
        #[arg(long)]
        update: bool,
        /// Remove the platform: with --keep-data or --everything.
        #[arg(long)]
        uninstall: bool,
        /// With --uninstall: keep the database, CA and configuration.
        #[arg(long, conflicts_with = "everything")]
        keep_data: bool,
        /// With --uninstall: also delete the database, CA, configuration and accounts.
        #[arg(long)]
        everything: bool,
        /// With --everything: this host's name, to confirm.
        #[arg(long)]
        confirm: Option<String>,
        /// With --update or --uninstall: write a database backup here first.
        #[arg(long)]
        backup: Option<PathBuf>,
        /// With --update: upgrade from this folder of package files.
        #[arg(long)]
        update_repo_dir: Option<PathBuf>,
        #[command(flatten)]
        plan: setup::plan::PlanArgs,
    },
```

and in `main` replace the Setup branch with

```rust
    if let Command::Setup { quick, repair, update, uninstall, keep_data, everything, confirm, backup, update_repo_dir, plan } = command {
        return match (*quick, *repair, *update, *uninstall) {
            (true, ..) => setup::quick(plan),
            (_, true, ..) => setup::repair_all(),
            (_, _, true, _) => setup::update_all(&setup::update::UpdateArgs {
                backup: backup.clone(),
                repo_dir: update_repo_dir.clone(),
            }),
            _ if !keep_data && !everything => {
                eprintln!("openvibes-admin: --uninstall needs --keep-data or --everything");
                ExitCode::from(2)
            }
            _ if *everything && confirm.is_none() => {
                eprintln!("openvibes-admin: --everything needs --confirm HOSTNAME (this host's name)");
                ExitCode::from(2)
            }
            _ => setup::uninstall_all(*everything, confirm.clone(), backup.clone()),
        };
    }
```

(`--update-repo-dir` rather than `--repo-dir`, which `PlanArgs` already defines.) The uninstall argument checks come before the root check, as the test expects: move the two `_ if` arms above the root check by checking them here, which the `match` already does before `uninstall_all` runs.

`docs/components/openvibes-admin.md` "Setup command": add `--repair`, `--update [--backup PATH] [--update-repo-dir DIR]`, `--uninstall --keep-data|--everything --confirm HOSTNAME [--backup PATH]`, the helper verbs `setup-step … --repair`, `update-step`, `remove-step`, the lock, the backup files.

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --test helper && cargo test -p openvibes-admin --bin openvibes-admin setup:: && cargo clippy -p openvibes-admin --all-targets -- -D warnings`
Expected: PASS, no warnings.

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin docs/components/openvibes-admin.md
git commit -m "admin: helper update/remove/repair verbs; setup --repair|--update|--uninstall

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: TUI jobs: repair and change components

**Files:**
- Create: `crates/openvibes-admin/src/tui/jobs.rs`
- Modify: `crates/openvibes-admin/src/tui/{mod.rs,setup.rs,setup_view.rs,setup_tests.rs}`

**Interfaces — Produces:**

```rust
// jobs.rs
pub enum Job { Install, Repair, Update, Remove }
impl Job { pub fn titles(self) -> Vec<&'static str>; pub fn steps(self) -> usize; pub fn verb(self, index: usize, args: &[String]) -> Privileged<'_>; }
// setup.rs: Setup gains job: Job, job_args: Vec<String>, then_remove: Option<Vec<String>>,
//           previous: Option<BTreeSet<Component>>, home: Option<String>; states becomes Vec<Option<StepState>>;
//           After gains Job(Job); Status keys: c check, r repair, m change components (u, x in Task 9)
```

- [ ] **Step 1: Failing tests** in `setup_tests.rs`. Give `SetupHost` a `plan: String` field (default `""`, set in `app()`), return it from `setup_plan` (`Err` when empty), and add:

```rust
const PLAN: &str = "components = [\"ingest\", \"console\", \"distribution\", \"vulns\", \"rules\", \"agent\"]\nhostname = \"platform.example.com\"\nsans = []\nca = \"quick\"\noperator = \"alice\"\n";

fn set_up(answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    let mut app = app(true, answers);
    app.host.plan = PLAN.into();
    app
}

#[test]
fn a_set_up_host_offers_the_maintenance_actions() {
    let mut app = set_up(vec![]);
    app.key(Key::Tab);
    app.key(Key::Tab); // Services → Configuration → Setup
    let text = screen(&app);
    for want in ["c check", "r repair", "u update", "m change components", "x uninstall"] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn repair_runs_every_step_in_repair_mode() {
    let mut app = set_up(vec![]);
    app.tab = Tab::Setup;
    app.key(Key::Char('r'));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.setup_tick();
    assert_eq!(app.host.calls.borrow()[0].0, "setup-step packages --repair");
}

#[test]
fn changing_components_installs_then_removes_the_unticked_ones() {
    let mut app = set_up(vec![]);
    app.tab = Tab::Setup;
    app.key(Key::Char('m'));
    assert_eq!(app.setup.phase, Phase::Form);
    assert_eq!(app.setup.hostname, "platform.example.com");
    while app.setup.row != 3 {
        app.key(Key::Down); // vulns
    }
    app.key(Key::Char(' '));
    start(&mut app, "pw");
    for _ in 0..Step::ALL.len() {
        app.setup_tick();
    }
    app.setup_tick();
    let calls = app.host.calls.borrow();
    assert!(calls[0].0.starts_with("setup-plan --components ingest,console,distribution,rules,agent"), "{}", calls[0].0);
    assert_eq!(calls.last().unwrap().0, "remove-step backup --components vulns");
}
```

- [ ] **Step 2: Run, expect FAIL.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin tui::setup_tests`

- [ ] **Step 3: Implement.** `tui/jobs.rs`:

```rust
//! What the Setup tab runs step by step through the helper: install and
//! repair (§6.3–6.4), update (§6.5a), remove (§6.5).

use platform_host::{Privileged, RemoveStep, Step, UpdateStep};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Job {
    Install,
    Repair,
    Update,
    Remove,
}

impl Job {
    pub fn titles(self) -> Vec<&'static str> {
        match self {
            Job::Install | Job::Repair => Step::ALL.iter().map(|s| s.title()).collect(),
            Job::Update => UpdateStep::ALL.iter().map(|s| s.title()).collect(),
            Job::Remove => RemoveStep::ALL.iter().map(|s| s.title()).collect(),
        }
    }

    pub fn steps(self) -> usize {
        self.titles().len()
    }

    /// The helper verb for step `index`, with the job's arguments.
    pub fn verb(self, index: usize, args: &[String]) -> Privileged<'_> {
        match self {
            Job::Install => Privileged::SetupStep(Step::ALL[index]),
            Job::Repair => Privileged::Repair(Step::ALL[index]),
            Job::Update => Privileged::Update(UpdateStep::ALL[index], args),
            Job::Remove => Privileged::Remove(RemoveStep::ALL[index], args),
        }
    }
}
```

`tui/setup.rs`:
- `Setup` gains `pub job: Job` (`Job::Install`), `pub job_args: Vec<String>`, `pub then_remove: Option<Vec<String>>`, `pub previous: Option<BTreeSet<Component>>`, `pub home: Option<String>` (kept from `new`); `states: Vec<Option<StepState>>` (initially `vec![None; Step::ALL.len()]`).
- `After` gains `Job(Job)`.
- `Phase::Finished | Phase::Status` keys:

```rust
            Phase::Finished | Phase::Status => match key {
                Key::Char('c') => self.ask_password(After::Status),
                Key::Char('r') => {
                    self.setup.job_args.clear();
                    self.ask_password(After::Job(Job::Repair));
                }
                Key::Char('m') => self.change_components(),
                Key::Tab => self.leave_setup(),
                Key::Char('q') => self.quit = true,
                _ => {}
            },
```

with

```rust
    /// Back to the form, filled from `setup.toml`; what is unticked is
    /// removed (keep data) after the install run.
    fn change_components(&mut self) {
        let plan = match self.host.setup_plan().map_err(|e| e.to_string()).and_then(|text| {
            toml::from_str::<crate::setup::plan::Plan>(&text).map_err(|e| e.to_string())
        }) {
            Ok(plan) => plan,
            Err(error) => {
                self.message = Some(error);
                return;
            }
        };
        self.setup.components = plan.components.iter().copied().collect();
        self.setup.previous = Some(self.setup.components.clone());
        self.setup.hostname = plan.hostname.clone();
        self.setup.sans = plan.sans.join(", ");
        self.setup.ca = plan.ca;
        self.setup.root_key_out.clear(); // the CA exists; no new root key
        self.setup.row = 0;
        self.setup.phase = Phase::Form;
    }

    fn start_job(&mut self, job: Job, secret: Secret) {
        self.setup.job = job;
        self.setup.states = vec![None; job.steps()];
        self.setup.password = Some(secret);
        self.setup.phase = Phase::Running(0);
    }
```

- In `password_key`: `After::Job(job) => self.start_job(job, secret)`; `After::Plan`'s `Ok` arm becomes

```rust
                    Ok(_) => {
                        self.setup.prompt.failures = 0;
                        self.setup.job_args.clear();
                        if let Some(previous) = self.setup.previous.take() {
                            let removed: Vec<&str> = previous
                                .difference(&self.setup.components)
                                .map(|c| c.name())
                                .collect();
                            if !removed.is_empty() {
                                self.setup.then_remove = Some(vec!["--components".into(), removed.join(",")]);
                            }
                        }
                        self.start_job(Job::Install, secret);
                    }
```

- `After::Status`'s `Ok` arm: `self.setup.job = Job::Install; self.setup.states = vec![None; Step::ALL.len()];` before filling.
- `Cancelled` and `wrong_password` fall back for `After::Job(_)` to `Phase::Status`.
- `setup_tick`:

```rust
        let args = self.setup.job_args.clone();
        let verb = self.setup.job.verb(next, &args);
        let state = match self.host.privileged(verb, password) {
```

and the end of the job:

```rust
        } else if next + 1 == self.setup.job.steps() {
            if let Some(args) = self.setup.then_remove.take() {
                // Components unticked in the form: removed, data kept.
                self.setup.job = Job::Remove;
                self.setup.job_args = args;
                self.setup.states = vec![None; Job::Remove.steps()];
                Phase::Running(0)
            } else {
                self.setup.password = None;
                Phase::Finished
            }
        } else {
```

`tui/setup_view.rs`: the checklist uses `app.setup.job.titles()` and `app.setup.states` (by index) instead of `Step::ALL`; `finished()` shows the Install selection (CA, Console, Operators, Ready) for `Job::Install` and every step's `title: detail` for the other jobs; `DONE_KEYS` becomes `"c check  r repair  u update  m change components  x uninstall  Tab  q"`.

`tui/mod.rs`: `mod jobs;`.

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin tui`
Expected: PASS (all earlier Setup tab tests too).

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin/src/tui
git commit -m "admin TUI: Setup jobs; repair and change components

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: TUI Update and Uninstall screens

**Files:**
- Create: `crates/openvibes-admin/src/tui/{maintain.rs,maintain_view.rs}`
- Modify: `crates/openvibes-admin/src/tui/{mod.rs,setup.rs,setup_view.rs,setup_tests.rs}`

**Interfaces — Produces:** `Phase::Update`, `Phase::Uninstall`; `Setup` gains `backup: String`, `confirm: String`, `everything: bool`, `packages: Vec<PackageUpdate>`, `row2: usize` (the row on these screens); keys `u` and `x` on a set-up host.

- [ ] **Step 1: Failing tests** in `setup_tests.rs` (`SetupHost` gains `packages: Vec<PackageUpdate>` returned by `packages()`):

```rust
#[test]
fn update_lists_the_packages_then_runs_the_update_job() {
    let mut app = set_up(vec![]);
    app.host.packages = vec![
        PackageUpdate { name: "openvibes-agent".into(), installed: "0.1.0-1.fc44".into(), available: None },
        PackageUpdate { name: "openvibes-ingest".into(), installed: "0.1.0-1.fc44".into(), available: Some("0.2.0-1.fc44".into()) },
    ];
    app.setup.home = Some("/home/alice".into());
    app.tab = Tab::Setup;
    app.key(Key::Char('u'));
    let text = screen(&app);
    assert!(text.contains("openvibes-ingest") && text.contains("0.2.0-1.fc44"), "{text}");
    assert!(text.contains("up to date"), "{text}");
    app.key(Key::Down);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.setup_tick();
    assert_eq!(
        app.host.calls.borrow()[0].0,
        "update-step backup --backup /home/alice/openvibes-before-update.dump"
    );
}

#[test]
fn remove_everything_needs_this_hosts_name() {
    let mut answers: Vec<Result<String, HostError>> = Vec::new();
    for _ in 0..5 {
        answers.push(Ok("done\tok\n".into()));
    }
    let mut app = set_up(answers);
    app.setup.home = Some("/home/alice".into());
    app.tab = Tab::Setup;
    app.key(Key::Char('x'));
    app.key(Key::Char(' ')); // Remove everything
    while app.setup.row2 != 3 {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    assert!(app.message.clone().unwrap_or_default().contains("platform.example.com"));
    assert_eq!(app.setup.phase, Phase::Uninstall);
    app.key(Key::Up); // confirm field
    app.key(Key::Enter);
    type_text(&mut app, "platform.example.com");
    app.key(Key::Enter);
    app.key(Key::Down);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    for _ in 0..5 {
        app.setup_tick();
    }
    assert_eq!(
        app.host.calls.borrow()[0].0,
        "remove-step backup --components ingest,console,distribution,vulns,rules,agent --backup /home/alice/openvibes-backup.dump --confirm platform.example.com"
    );
    assert_eq!(app.setup.phase, Phase::Finished);
    assert!(screen(&app).contains("sudo dnf remove openvibes-admin"));
}

#[test]
fn keep_data_uninstall_sends_no_confirmation() {
    let mut app = set_up(vec![]);
    app.tab = Tab::Setup;
    app.key(Key::Char('x'));
    while app.setup.row2 != 3 {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.setup_tick();
    assert_eq!(
        app.host.calls.borrow()[0].0,
        "remove-step backup --components ingest,console,distribution,vulns,rules,agent"
    );
}
```

- [ ] **Step 2: Run, expect FAIL.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin tui::setup_tests`

- [ ] **Step 3: Implement.** `Phase` gains `Update` and `Uninstall`. `Setup` gains `backup`, `confirm`, `everything`, `packages`, `row2` (defaults empty/false/0). In `setup_key`: `Phase::Update => self.update_key(key)`, `Phase::Uninstall => self.uninstall_key(key)`, and in `Finished | Status`: `Key::Char('u') => self.open_update()`, `Key::Char('x') => self.open_uninstall()`. `Cancelled`/`wrong_password` for `After::Job(Job::Update | Job::Remove)` fall back to `Phase::Status`.

`tui/maintain.rs`:

```rust
//! The Update (§6.5a) and Uninstall (§6.5) screens of the Setup tab: what
//! to do and the backup, then the job runs like any other.

use platform_host::Host;

use super::{app::{App, Key}, jobs::Job, setup::{After, Phase}};
use crate::setup::plan::Plan;

pub const UPDATE_START_ROW: usize = 1;
pub const UNINSTALL_START_ROW: usize = 3;

impl<H: Host> App<H> {
    pub(super) fn open_update(&mut self) {
        self.setup.packages = self.host.packages().unwrap_or_else(|error| {
            self.message = Some(error.to_string());
            Vec::new()
        });
        let home = self.setup.home.clone().unwrap_or_default();
        self.setup.backup = format!("{home}/openvibes-before-update.dump");
        self.setup.row2 = 0;
        self.setup.editing = false;
        self.setup.phase = Phase::Update;
    }

    pub(super) fn open_uninstall(&mut self) {
        let home = self.setup.home.clone().unwrap_or_default();
        self.setup.backup = format!("{home}/openvibes-backup.dump");
        self.setup.confirm.clear();
        self.setup.everything = false;
        self.setup.row2 = 0;
        self.setup.editing = false;
        self.setup.phase = Phase::Uninstall;
    }

    /// The text field under the cursor on these screens.
    fn maintain_field(&mut self) -> Option<&mut String> {
        match (self.setup.phase, self.setup.row2) {
            (Phase::Update, 0) => Some(&mut self.setup.backup),
            (Phase::Uninstall, 1) if self.setup.everything => Some(&mut self.setup.backup),
            (Phase::Uninstall, 2) if self.setup.everything => Some(&mut self.setup.confirm),
            _ => None,
        }
    }

    /// Typing into a field; true when the key was used.
    fn edit(&mut self, key: Key) -> bool {
        if !self.setup.editing {
            return false;
        }
        let Some(field) = self.maintain_field() else {
            self.setup.editing = false;
            return false;
        };
        match key {
            Key::Char(c) if field.len() < 512 => field.push(c),
            Key::Backspace => {
                field.pop();
            }
            Key::Enter | Key::Esc => self.setup.editing = false,
            _ => {}
        }
        true
    }

    fn backup_args(&self) -> Vec<String> {
        let path = self.setup.backup.trim();
        if path.is_empty() { Vec::new() } else { vec!["--backup".into(), path.into()] }
    }

    pub(super) fn update_key(&mut self, key: Key) {
        if self.edit(key) {
            return;
        }
        match key {
            Key::Char('j') | Key::Down if self.setup.row2 < UPDATE_START_ROW => self.setup.row2 += 1,
            Key::Char('k') | Key::Up => self.setup.row2 = self.setup.row2.saturating_sub(1),
            Key::Enter if self.setup.row2 == UPDATE_START_ROW => {
                self.setup.job_args = self.backup_args();
                self.setup.prompt = Default::default();
                self.setup.phase = Phase::Password(After::Job(Job::Update));
            }
            Key::Enter => self.setup.editing = self.maintain_field().is_some(),
            Key::Esc => self.setup.phase = Phase::Status,
            _ => {}
        }
    }

    pub(super) fn uninstall_key(&mut self, key: Key) {
        if self.edit(key) {
            return;
        }
        match key {
            Key::Char('j') | Key::Down if self.setup.row2 < UNINSTALL_START_ROW => self.setup.row2 += 1,
            Key::Char('k') | Key::Up => self.setup.row2 = self.setup.row2.saturating_sub(1),
            Key::Char(' ') if self.setup.row2 == 0 => self.setup.everything = !self.setup.everything,
            Key::Enter if self.setup.row2 == UNINSTALL_START_ROW => self.start_uninstall(),
            Key::Enter => self.setup.editing = self.maintain_field().is_some(),
            Key::Esc => self.setup.phase = Phase::Status,
            _ => {}
        }
    }

    fn start_uninstall(&mut self) {
        let plan = match self.host.setup_plan().map_err(|e| e.to_string()).and_then(|text| {
            toml::from_str::<Plan>(&text).map_err(|e| e.to_string())
        }) {
            Ok(plan) => plan,
            Err(error) => {
                self.message = Some(error);
                return;
            }
        };
        let components: Vec<&str> = plan.components.iter().map(|c| c.name()).collect();
        let mut args = vec!["--components".to_owned(), components.join(",")];
        if self.setup.everything {
            if self.setup.confirm.trim() != plan.hostname {
                self.message = Some(format!("type this host's name ({}) to confirm Remove everything", plan.hostname));
                return;
            }
            args.extend(self.backup_args());
            args.extend(["--confirm".into(), plan.hostname.clone()]);
        }
        self.message = None;
        self.setup.job_args = args;
        self.setup.prompt = Default::default();
        self.setup.phase = Phase::Password(After::Job(Job::Remove));
    }
}
```

`tui/maintain_view.rs`:

```rust
//! Draws the Update and Uninstall screens.

use platform_host::Host;
use ratatui::{style::{Modifier, Style}, text::Line};

use super::{app::App, maintain::{UNINSTALL_START_ROW, UPDATE_START_ROW}, setup::Phase};

fn row(selected: bool, text: String) -> Line<'static> {
    if selected { Line::styled(text, Style::new().add_modifier(Modifier::REVERSED)) } else { Line::raw(text) }
}

pub fn update_lines<H: Host>(app: &App<H>) -> Vec<Line<'static>> {
    let setup = &app.setup;
    let mut lines: Vec<Line> = setup
        .packages
        .iter()
        .map(|p| {
            Line::raw(format!(
                "{:<26}{:<16}{}",
                p.name,
                p.installed,
                p.available.as_deref().map_or_else(|| "up to date".to_owned(), |v| format!("→ {v}"))
            ))
        })
        .collect();
    lines.push(Line::raw(""));
    let cursor = if setup.editing && setup.row2 == 0 { "_" } else { "" };
    lines.push(row(setup.row2 == 0, format!("Backup first (empty: none):  {}{cursor}", setup.backup)));
    lines.push(row(setup.row2 == UPDATE_START_ROW, "[ Update ]  services stop, packages upgrade, database migrates, services start".into()));
    lines
}

pub fn uninstall_lines<H: Host>(app: &App<H>) -> Vec<Line<'static>> {
    let setup = &app.setup;
    let mode = if setup.everything {
        "Remove everything: database, CA, configuration and accounts too"
    } else {
        "Keep data: remove the software, keep database, CA and configuration"
    };
    let cursor = |r: usize| if setup.editing && setup.row2 == r { "_" } else { "" };
    let mut lines = vec![row(setup.row2 == 0, format!("( space )  {mode}"))];
    if setup.everything {
        lines.push(row(setup.row2 == 1, format!("Backup first (empty: none):  {}{}", setup.backup, cursor(1))));
        lines.push(row(setup.row2 == 2, format!("Type this host's name to confirm:  {}{}", setup.confirm, cursor(2))));
    } else {
        lines.push(Line::raw(""));
        lines.push(Line::raw(""));
    }
    lines.push(row(setup.row2 == UNINSTALL_START_ROW, "[ Uninstall ]".into()));
    lines.push(Line::raw("PostgreSQL itself stays installed. openvibes-admin is removed last, by you."));
    lines
}

pub fn keys(phase: Phase) -> &'static str {
    match phase {
        Phase::Uninstall => "j/k move  space keep/everything  Enter edit/start  Esc back",
        _ => "j/k move  Enter edit/start  Esc back",
    }
}
```

`setup_view.rs`: `Phase::Update => (maintain_view::update_lines(app), maintain_view::keys(Phase::Update))`, `Phase::Uninstall => (maintain_view::uninstall_lines(app), maintain_view::keys(Phase::Uninstall))`; `finished()` for `Job::Remove` also pushes `"Last step: sudo dnf remove openvibes-admin"`. `tui/mod.rs`: `mod maintain; mod maintain_view;`.

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin tui && cargo clippy -p openvibes-admin --all-targets -- -D warnings`
Expected: PASS, no warnings.

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin/src/tui
git commit -m "admin TUI: Update and Uninstall screens

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Life cycle and update end to end; CI; docs

**Files:**
- Create: `scripts/setup-lifecycle-e2e.sh`
- Modify: `scripts/build-rpm.sh`, `.github/workflows/ci.yml`, `docs/components/{openvibes-admin.md,packaging.md}`

- [ ] **Step 1: Lower-version builds.** `scripts/build-rpm.sh`: `version=${OV_VERSION:-$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)}` and `topdir=${OV_RPM_TOPDIR:-$PWD/target/rpm}` used in `--define "_topdir $topdir"` and the final `ls "$topdir"/RPMS/*/openvibes-*.rpm`; document both in the header comment.

- [ ] **Step 2: The script** `scripts/setup-lifecycle-e2e.sh`:

```bash
#!/usr/bin/env bash
# Setup's whole life cycle under systemd (admin TUI spec §12), in podman
# fedora:44 with systemd as PID 1, from built RPMs:
# install (with the agent on the host) → repair after breaking things →
# uninstall keeping data → install again (same CA, same agent) → update to
# newer packages → remove everything (nothing left).
# Usage: scripts/setup-lifecycle-e2e.sh OLD_DIR NEW_DIR
#   OLD_DIR  lower-version openvibes-{ingest,distribution,vulns,admin}-*.rpm
#            and one openvibes-agent RPM
#   NEW_DIR  the same packages at the current version
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PODMAN=${PODMAN:-podman}
C=ov-setup-lifecycle
IMAGE=ov-e2e:44
W=$ROOT/target/setup-lifecycle
[[ $# == 2 ]] || { echo "usage: $0 OLD_DIR NEW_DIR" >&2; exit 2; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
in_c() { "$PODMAN" exec "$C" bash -c "$1"; }
wait_for() {
    local desc=$1 seconds=$2 i
    for ((i = 0; i < seconds; i++)); do
        if in_c "$3" >/dev/null 2>&1; then ok "$desc"; return 0; fi
        sleep 1
    done
    fail "$desc (after ${seconds}s)"
}
cleanup() {
    local status=$?
    if ((status != 0)); then
        for unit in openvibes-ingest openvibes-distribution openvibes-vulns openvibes-agent; do
            echo "--- $unit"
            "$PODMAN" exec "$C" journalctl -u "$unit" --no-pager -n 15 2>/dev/null || true
        done
    fi
    "$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT

rm -rf "$W"; mkdir -p "$W/old" "$W/new"
for d in old new; do
    src=$1; [[ $d == new ]] && src=$2
    cp "$src"/openvibes-{ingest,distribution,vulns,admin,agent}-[0-9]*.rpm "$W/$d/"
done
printf 'FROM registry.fedoraproject.org/fedora:44
RUN dnf -q -y install systemd postgresql-server procps-ng util-linux curl polkit sudo && dnf clean all
' | "$PODMAN" build -q -t "$IMAGE" -f - "$W" >/dev/null
"$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
"$PODMAN" run -d --systemd=always --privileged --name "$C" -v "$W:/test:Z" "$IMAGE" /sbin/init >/dev/null
wait_for "systemd is up" 30 'systemctl is-system-running | grep -qE "running|degraded"'

QUICK='openvibes-admin setup --quick --components ingest,distribution,vulns,agent --hostname localhost \
       --san 127.0.0.1 --repo-dir /test/old --allow-unsigned-local'
agent_id() { in_c 'runuser -u openvibes-admin -- openvibes-admin agent list' | awk '$2 == "active" {print $1; exit}'; }
fingerprint() { in_c 'sha256sum /etc/openvibes/pki/root.crt' | cut -d' ' -f1; }

# 1. Install from the lower version, with the agent on this host.
in_c 'dnf -q -y install /test/old/openvibes-admin-*.rpm' >/dev/null 2>&1 || fail "install openvibes-admin"
in_c "$QUICK" > "$W/install.out" 2>&1 || { cat "$W/install.out"; fail "setup --quick"; }
AGENT=$(agent_id); [[ -n "$AGENT" ]] || fail "the local agent is not active"
ROOT_FP=$(fingerprint)
ok "installed with the local agent ($AGENT)"

# 2. Repair: a stopped service and a removed package come back; the CA is not touched.
in_c 'systemctl stop openvibes-distribution && rpm -e --nodeps openvibes-vulns' || fail "break things"
in_c 'openvibes-admin setup --repair' > "$W/repair.out" 2>&1 || { cat "$W/repair.out"; fail "setup --repair"; }
in_c 'systemctl is-active --quiet openvibes-distribution && rpm -q --quiet openvibes-vulns' || fail "repair did not restore"
[[ "$(fingerprint)" == "$ROOT_FP" ]] || fail "repair changed the CA"
ok "repair restored the stopped service and the removed package"

# 3. Uninstall keeping data, then install again: same CA, same agent.
in_c 'openvibes-admin setup --uninstall --keep-data' > "$W/keep.out" 2>&1 || { cat "$W/keep.out"; fail "uninstall --keep-data"; }
in_c '! rpm -q --quiet openvibes-ingest && test -e /etc/openvibes/pki/root.crt' || fail "keep-data removed data or kept packages"
in_c "$QUICK" > "$W/reinstall.out" 2>&1 || { cat "$W/reinstall.out"; fail "reinstall"; }
[[ "$(fingerprint)" == "$ROOT_FP" ]] || fail "reinstall made a new CA"
wait_for "the same agent reports again" 60 "runuser -u openvibes-admin -- openvibes-admin agent list | grep -q '^$AGENT  active'"
ok "uninstall keeping data and reinstall keep the CA and the agent's enrollment"

# 4. Update to the newer packages, with a backup first.
in_c 'openvibes-admin setup --update --update-repo-dir /test/new --backup /root/before-update.dump' > "$W/update.out" 2>&1 ||
    { cat "$W/update.out"; fail "setup --update"; }
NEW=$(in_c "rpm -qp --qf '%{VERSION}' /test/new/openvibes-ingest-*.rpm")
[[ "$(in_c "rpm -q --qf '%{VERSION}' openvibes-ingest")" == "$NEW" ]] || fail "ingest not upgraded to $NEW"
in_c 'test -s /root/before-update.dump && test -s /root/before-update.dump.roles.sql' || fail "no backup"
in_c 'runuser -u openvibes-admin -- openvibes-admin status' >/dev/null || fail "schema not current after update"
wait_for "the agent reports after the update" 60 "runuser -u openvibes-admin -- openvibes-admin agent list | grep -q '^$AGENT  active'"
ok "update upgraded the packages, migrated, and the agent keeps reporting"

# 5. Remove everything, then the admin tool itself: nothing is left.
in_c 'openvibes-admin setup --uninstall --everything --confirm localhost' > "$W/purge.out" 2>&1 ||
    { cat "$W/purge.out"; fail "uninstall --everything"; }
in_c 'dnf -q -y remove openvibes-admin' >/dev/null 2>&1 || fail "remove openvibes-admin"
[[ -z "$(in_c "rpm -qa 'openvibes-*'")" ]] || fail "packages left"
in_c '! ls -d /etc/openvibes /etc/openvibes-agent /var/lib/openvibes-* 2>/dev/null' || fail "files left"
in_c '! getent passwd openvibes-ingest openvibes-admin openvibes_agent && ! getent group openvibes-operators' || fail "accounts left"
[[ -z "$(in_c "runuser -u postgres -- psql -Atqc \"SELECT 1 FROM pg_database WHERE datname = 'openvibes'\"")" ]] || fail "database left"
[[ -z "$(in_c "runuser -u postgres -- psql -Atqc \"SELECT 1 FROM pg_roles WHERE rolname LIKE 'openvibes-%'\"")" ]] || fail "roles left"
ok "remove everything left no packages, files, accounts, database or roles"
echo "setup-lifecycle-e2e: all checks passed"
```

- [ ] **Step 3: CI.** In `.github/workflows/ci.yml`'s `fedora` job, before "Build RPMs", add

```yaml
      - name: Build lower-version RPMs for the update test
        env:
          CARGO_NET_OFFLINE: "true"
          OV_LLM: "0"
          OV_VERSION: "0.0.9"
          OV_RPM_TOPDIR: ${{ github.workspace }}/target/rpm-old
        run: |
          bash scripts/build-rpm.sh
          mkdir -p dist/old
          cp target/rpm-old/RPMS/x86_64/openvibes-*.rpm dist/old/
```

and after the systemd e2e job add

```yaml
  setup-lifecycle:
    name: Setup life cycle under systemd (install, repair, update, uninstall)
    needs: fedora
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - name: Checkout repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Download RPMs
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: rpms
          path: dist
      - name: Life cycle
        run: |
          cp dist/openvibes-agent-*.rpm dist/old/
          bash scripts/setup-lifecycle-e2e.sh dist/old dist
```

(`dist/old` holds the lower-version platform RPMs; the agent RPM is the same in both. The systemd e2e's `cp "$1"/openvibes-…-*.rpm` reads only `dist`'s top level, so `dist/old` does not disturb it.)

- [ ] **Step 4: Docs.** `docs/components/openvibes-admin.md`: the Setup tab's `r`, `u`, `m`, `x` and the Update and Uninstall screens; `packaging.md`: "Updating" points to Setup's Update, "Removing" to Setup's Uninstall, and the new script under "How to test".

- [ ] **Step 5: Run the gate.** `testing.md` §2 from this worktree; then on this Fedora host build the RPMs twice (`OV_VERSION=0.0.9 OV_RPM_TOPDIR=$PWD/target/rpm-old bash scripts/build-rpm.sh` and `bash scripts/build-rpm.sh`), add the pinned agent RPM to both folders, and run `bash scripts/setup-lifecycle-e2e.sh OLD NEW` and `bash scripts/systemd-e2e.sh NEW SIGN_BIN`.

Expected: all green; `setup-lifecycle-e2e: all checks passed`, `systemd-e2e: all checks passed`.

- [ ] **Step 6: Commit.**

```bash
git add scripts .github/workflows/ci.yml docs/components
git commit -m "e2e: Setup life cycle (repair, keep-data reinstall, update, remove everything)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## After the tasks

- Open the PR ("Admin TUI PR 5: Setup repair, update, uninstall"), based on `tui-setup-spec` until #43 merges, with the Validation section listing what ran; the new CI job is not a required check until the user adds it.
- Deferred from #43 and still open: `is_set_up` ignoring a manual install's database, secret copies in TUI strings and buffers, an extra root recorded on a quick-CA retry after a successful import, agent readiness not tied to this host.
