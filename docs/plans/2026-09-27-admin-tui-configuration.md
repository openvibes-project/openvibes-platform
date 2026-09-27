# Admin TUI PR 2: Configuration screen — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (native) or superpowers:subagent-driven-development. Steps use checkboxes.

**Goal:** An operator edits `/etc/openvibes/{ingest,distribution,vulns,console,admin}.toml` from the TUI's Configuration screen: typed fields, checked by each service's own configuration type after every change, saved through a root helper that checks again, keeps owner, group, mode and a `.bak`, then offers a restart.

**Architecture:** `platform-host` gains `Service` (the closed list of config files), `Unit::Console`, `Host::read_config`/`write_config` and `Runner::run_with_input`; `Native` runs `sudo -n openvibes-admin helper config-read|config-write SERVICE` (content on stdin). `openvibes-admin` gains `configs.rs` (validation by the service types), `fields.rs` (the editable fields per service), `config_file.rs` (root-side read and atomic replace), the two helper verbs, and in `src/tui/` a `form.rs` document model (`toml_edit`, so comments survive), the screen state `configuration.rs` and its view `config_view.rs`. Tabs switch between Services and Configuration.

**Tech Stack:** Rust (ratatui 0.30, clap, toml 1.1, new `toml_edit` 0.25.12), sudoers, polkit, bash e2e.

**Spec:** `docs/specs/2026-09-27-admin-tui-design.md` (§3 helper and sudoers, §4 `Host`, §5 Configuration, §7 audit, §11 failure behaviour, §12 testing, §13 PR 2).

## Global Constraints

- Config files: exactly `/etc/openvibes/ingest.toml`, `distribution.toml`, `vulns.toml`, `console.toml`, `admin.toml`. `Service` is an enum; no path is ever taken from input. `llm.conf` is an environment file, not TOML, and is out of scope.
- Validation is the service's own: `toml::from_str::<T>` into the service's config type (all `deny_unknown_fields`) plus its `validate()`, done by the TUI after every change and again by the helper as root before writing. Files over 64 KiB are refused (as `platform_config::load` does).
- Only the fields listed for a service can be set or cleared; clearing a field removes the key (the service default applies). There is no free-text editor.
- The helper checks its arguments before the root check, refuses non-root, and writes: temp file in `/etc/openvibes` (0600, `create_new`), owner and group of the original, its mode, fsync, copy of the old file to `NAME.toml.bak`, rename, directory fsync. A symlink or missing file is refused. A failed write leaves the old file.
- Sudoers gains exactly `helper config-read *` and `helper config-write *` for `%openvibes-operators`; polkit and `Unit` gain `openvibes-console.service`.
- Every config save is written to the journal (`logger -t openvibes-admin`, user, uid, `config-write SERVICE ok|failed`). File contents are never logged.
- Keyboard only, 80×24, state as text. New dependency: `toml_edit = "0.25.12"` (default features `parse`, `display`; shares `toml_parser`, `toml_writer`, `toml_datetime` with `toml` 1.1) in `openvibes-admin`; `cargo audit` stays clean.
- `std::process::Command` only in `SystemRunner` and the helper's `logs` (clippy `disallowed_types`).
- Files under 500 lines; component docs updated in the same task; commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Gate: `testing.md` §2 in this worktree, plus §3 (Fedora job) because packaging (sudoers, polkit) and `scripts/systemd-e2e.sh` change.

## Review Focus

- Packaged files are full of comments and aligned trailing comments: saving one field must change only that line (Task 3 `set_keeps_comments_and_layout`; Task 5 save test checks an untouched commented line).
- A file edited by hand while the form is open: the save must not overwrite it silently (Task 5 `a_file_changed_on_disk_is_not_overwritten`).
- A file that is not valid TOML, or missing because the package is not installed: explained, nothing editable, nothing written (Task 5 `unreadable_and_broken_files_are_explained`; Task 4 `a_symlink_or_missing_file_is_refused`).
- Typed text with quotes, backslashes or non-ASCII: stored as a correctly escaped TOML string (Task 3 `typed_text_is_escaped`).
- Oversized or non-UTF-8 stdin to `helper config-write`, or a service name like `../../etc/shadow`: refused before anything is written (Task 4 tests).

---

### Task 1: `platform-host`: services, config read/write, console unit

**Files:**
- Create: `crates/platform-host/src/service.rs`
- Modify: `crates/platform-host/src/{lib.rs,unit.rs,runner.rs,native.rs}`, `crates/platform-host/tests/native.rs`, `packaging/rpm/openvibes-operators.polkit.rules`, `docs/components/platform-host.md`

**Interfaces — Produces:**

```rust
// service.rs
pub const CONFIG_DIR: &str = "/etc/openvibes";
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Service { Ingest, Distribution, Vulns, Console, Admin }
impl Service {
    pub const ALL: [Service; 5];               // in that order
    pub fn name(self) -> &'static str;          // "ingest", "distribution", "vulns", "console", "admin"
    pub fn file_name(self) -> &'static str;     // "ingest.toml", …
    pub fn path(self) -> String;                // "/etc/openvibes/ingest.toml", …
    pub fn unit(self) -> Option<Unit>;          // Admin → None
    pub fn parse(name: &str) -> Option<Service>; // exact name() only
}
// unit.rs: Unit::Console ("openvibes-console.service", label "console",
// ready "http://127.0.0.1:18482/ready"); ALL = [Ingest, Distribution, Vulns, Console, Llm, Maintenance]
// runner.rs
pub trait Runner {
    fn run(&self, program: Program, args: &[&str]) -> std::io::Result<Output>;
    fn run_with_input(&self, program: Program, args: &[&str], input: &[u8]) -> std::io::Result<Output>;
}
// lib.rs: pub use service::{Service, CONFIG_DIR}; Host gains
fn read_config(&self, service: Service) -> Result<String, HostError>;
fn write_config(&self, service: Service, toml: &str) -> Result<(), HostError>;
```

- [ ] **Step 1: Failing tests.** In `tests/native.rs`, give `FakeRunner` an `inputs: RefCell<Vec<String>>` (initialised in `fake`) and implement:

```rust
    fn run_with_input(&self, program: Program, args: &[&str], input: &[u8]) -> std::io::Result<Output> {
        self.inputs.borrow_mut().push(String::from_utf8_lossy(input).into_owned());
        self.run(program, args)
    }
```

Import `Service` and add:

```rust
#[test]
fn config_is_read_and_written_through_the_helper() {
    let host = fake(vec![
        (
            vec!["/usr/bin/sudo", "-n", "/usr/bin/openvibes-admin", "helper", "config-read", "ingest"],
            out(0, "listen = \"0.0.0.0:18423\"\n", ""),
        ),
        (
            vec!["/usr/bin/sudo", "-n", "/usr/bin/openvibes-admin", "helper", "config-write", "ingest"],
            out(0, "", ""),
        ),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    assert_eq!(host.read_config(Service::Ingest).unwrap(), "listen = \"0.0.0.0:18423\"\n");
    host.write_config(Service::Ingest, "listen = \"0.0.0.0:443\"\n").unwrap();
    assert_eq!(*host.runner.inputs.borrow(), ["listen = \"0.0.0.0:443\"\n"]);
    let calls = host.runner.calls.borrow();
    let journal = calls.iter().find(|call| call[0] == "/usr/bin/logger").unwrap();
    assert_eq!(journal[1..3], ["-t", "openvibes-admin"]);
    assert!(journal[3].ends_with(" config-write ingest ok"), "{journal:?}");
}

#[test]
fn config_refusals_are_reported() {
    let host = fake(vec![
        (
            vec!["/usr/bin/sudo", "-n", "/usr/bin/openvibes-admin", "helper", "config-read"],
            out(1, "", "sudo: a password is required\n"),
        ),
        (
            vec!["/usr/bin/sudo", "-n", "/usr/bin/openvibes-admin", "helper", "config-write"],
            out(1, "", "openvibes-admin helper: not saved: invalid ingest configuration\n"),
        ),
        (vec!["/usr/bin/logger"], out(0, "", "")),
    ]);
    assert_eq!(host.read_config(Service::Vulns), Err(HostError::NotOperator));
    assert_eq!(
        host.write_config(Service::Ingest, "x = 1\n"),
        Err(HostError::Failed(
            "openvibes-admin helper: not saved: invalid ingest configuration".into()
        ))
    );
    let calls = host.runner.calls.borrow();
    assert!(
        calls.iter().any(|call| call[0] == "/usr/bin/logger" && call[3].ends_with(" config-write ingest failed")),
        "{calls:?}"
    );
}

#[test]
fn services_and_their_files_are_a_closed_list() {
    for service in Service::ALL {
        assert_eq!(Service::parse(service.name()), Some(service));
        assert_eq!(service.path(), format!("/etc/openvibes/{}.toml", service.name()));
    }
    for bad in ["", "ingest.toml", "../ingest", "llm", "Ingest", "/etc/openvibes/ingest.toml"] {
        assert_eq!(Service::parse(bad), None, "{bad}");
    }
    assert_eq!(Service::Console.unit(), Some(Unit::Console));
    assert_eq!(Service::Admin.unit(), None);
    assert_eq!(Unit::parse("openvibes-console.service"), Some(Unit::Console));
}

#[test]
fn the_polkit_rule_lists_exactly_the_units() {
    let rule = include_str!("../../../packaging/rpm/openvibes-operators.polkit.rules");
    for unit in Unit::ALL {
        assert!(rule.contains(&format!("\"{}\"", unit.name())), "{} missing", unit.name());
    }
    let listed = rule.matches(".service\"").count() + rule.matches(".timer\"").count();
    assert_eq!(listed, Unit::ALL.len());
}
```

- [ ] **Step 2: Run, expect a compile failure** (`Service`, `Unit::Console`, `run_with_input`, `read_config` do not exist).

Run: `cargo test -p platform-host --test native`
Expected: FAIL to compile.

- [ ] **Step 3: Implement.** `src/service.rs`:

```rust
//! The configuration files the administration TUI may edit (admin TUI spec
//! §5). An enum, so no other path can be expressed.

use crate::Unit;

/// Where every OpenVIBES service configuration lives.
pub const CONFIG_DIR: &str = "/etc/openvibes";

/// One service whose `/etc/openvibes/NAME.toml` the TUI edits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Service {
    /// `ingest.toml`.
    Ingest,
    /// `distribution.toml`.
    Distribution,
    /// `vulns.toml`.
    Vulns,
    /// `console.toml` (with the assistant's `[assistant]` section).
    Console,
    /// `admin.toml`, the admin CLI's own.
    Admin,
}

impl Service {
    /// Every service, in display order.
    pub const ALL: [Service; 5] = [
        Service::Ingest,
        Service::Distribution,
        Service::Vulns,
        Service::Console,
        Service::Admin,
    ];

    /// The short name the helper takes.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Service::Ingest => "ingest",
            Service::Distribution => "distribution",
            Service::Vulns => "vulns",
            Service::Console => "console",
            Service::Admin => "admin",
        }
    }

    /// The file name in [`CONFIG_DIR`].
    #[must_use]
    pub fn file_name(self) -> &'static str {
        match self {
            Service::Ingest => "ingest.toml",
            Service::Distribution => "distribution.toml",
            Service::Vulns => "vulns.toml",
            Service::Console => "console.toml",
            Service::Admin => "admin.toml",
        }
    }

    /// The absolute path.
    #[must_use]
    pub fn path(self) -> String {
        format!("{CONFIG_DIR}/{}", self.file_name())
    }

    /// The unit to restart after a save; the admin CLI has none.
    #[must_use]
    pub fn unit(self) -> Option<Unit> {
        match self {
            Service::Ingest => Some(Unit::Ingest),
            Service::Distribution => Some(Unit::Distribution),
            Service::Vulns => Some(Unit::Vulns),
            Service::Console => Some(Unit::Console),
            Service::Admin => None,
        }
    }

    /// The service with exactly this name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Service> {
        Service::ALL.into_iter().find(|service| service.name() == name)
    }
}
```

`unit.rs`: add the `Console` variant (doc `openvibes-console.service`), place it after `Vulns` in `ALL` (now `[Unit; 6]`), and arms `"openvibes-console.service"`, `"console"`, `Some("http://127.0.0.1:18482/ready")`.

`lib.rs`: `pub mod service;` and `pub use service::{CONFIG_DIR, Service};`; add to `Host`:

```rust
    /// The service's configuration file, as text.
    fn read_config(&self, service: Service) -> Result<String, HostError>;
    /// Replaces the service's configuration file with `toml` (checked again
    /// by the helper; the old file is kept as `NAME.toml.bak`).
    fn write_config(&self, service: Service, toml: &str) -> Result<(), HostError>;
```

`runner.rs`: add `run_with_input` to the trait (doc: "Runs `program` with `args` and `input` on stdin, and waits for it."), extract `fn output(output: std::process::Output) -> Output` from `run`, and implement:

```rust
    // As `run`, with stdin piped: the second of the two process starts here.
    #[allow(clippy::disallowed_types)]
    fn run_with_input(&self, program: Program, args: &[&str], input: &[u8]) -> std::io::Result<Output> {
        use std::io::Write;
        let mut child = std::process::Command::new(program.path())
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        // ponytail: stdin is written before output is read; fine because the
        // helper reads all of stdin (at most 64 KiB) before writing anything.
        let written = child
            .stdin
            .take()
            .map_or(Ok(()), |mut stdin| stdin.write_all(input));
        let result = child.wait_with_output()?;
        // A child that refused before reading (sudo) closes the pipe; its own
        // error text is the useful one.
        if result.status.success() {
            written?;
        }
        Ok(output(result))
    }
```

`native.rs`: import `Service`; replace the ponytail note on `ready` with "packaged default ports: the configs are readable only through the root helper, and a sudo call per refresh would flood the auth log"; add

```rust
    /// `sudo -n openvibes-admin helper ARGS…`, stdin from `input`.
    fn helper(&self, args: &[&str], input: Option<&[u8]>) -> Result<crate::runner::Output, HostError> {
        let mut argv = vec!["-n", ADMIN, "helper"];
        argv.extend_from_slice(args);
        let out = match input {
            Some(input) => self.runner.run_with_input(Sudo, &argv, input),
            None => self.runner.run(Sudo, &argv),
        }
        .map_err(|error| HostError::Io(format!("{}: {error}", Sudo.path())))?;
        if out.status == 0 {
            Ok(out)
        } else if out.stderr.contains("password is required")
            || out.stderr.contains("is not allowed to execute")
        {
            Err(HostError::NotOperator)
        } else {
            Err(HostError::Failed(printable(&out.stderr)))
        }
    }

    /// A journal entry for an operator action (spec §7).
    // ponytail: a journal write that fails is not reported; the action's own
    // outcome is what the operator needs to see.
    fn journal(&self, what: &str) {
        let entry = format!("{} {what}", who());
        let _ = self.run(Logger, &["-t", "openvibes-admin", &entry]);
    }
```

`service_action` uses `self.journal(&format!("{} {} {outcome}", action.verb(), unit.name()))`; `logs` becomes `Ok(self.helper(&["logs", unit.name(), &count], None)?.stdout.lines().map(printable).collect())`; and in `impl Host`:

```rust
    fn read_config(&self, service: Service) -> Result<String, HostError> {
        self.helper(&["config-read", service.name()], None).map(|out| out.stdout)
    }

    fn write_config(&self, service: Service, toml: &str) -> Result<(), HostError> {
        let result = self.helper(&["config-write", service.name()], Some(toml.as_bytes()));
        let outcome = if result.is_ok() { "ok" } else { "failed" };
        self.journal(&format!("config-write {} {outcome}", service.name()));
        result.map(drop)
    }
```

Polkit rule: add `"openvibes-console.service"` to `units`.

- [ ] **Step 4: Run.**

Run: `cargo test -p platform-host`
Expected: PASS (the new tests and every existing one).

- [ ] **Step 5: Docs.** `docs/components/platform-host.md`: `Unit` lists `openvibes-console.service`; new bullet `Service` (the five files, `parse` exact names only); `Host` lists `read_config`/`write_config`; `Native` bullet "config: `sudo -n /usr/bin/openvibes-admin helper config-read SERVICE` and `config-write SERVICE` with the file on stdin, journalled as `config-write SERVICE ok|failed`"; `Runner` gains `run_with_input`; readiness adds console 18482 `/ready`.

- [ ] **Step 6: Commit.**

```bash
git add crates/platform-host packaging/rpm/openvibes-operators.polkit.rules docs/components/platform-host.md
git commit -m "platform-host: config files through the helper, console unit" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `openvibes-admin`: validation by the service types, and the field lists

**Files:**
- Create: `crates/openvibes-admin/src/configs.rs`, `crates/openvibes-admin/src/fields.rs`
- Modify: `crates/openvibes-admin/Cargo.toml`, `crates/openvibes-admin/src/main.rs` (move `AdminConfig`, add modules), `Cargo.lock`

**Interfaces — Produces:**

```rust
// configs.rs
pub const MAX_BYTES: usize = 64 * 1024;
#[derive(Deserialize)] #[serde(deny_unknown_fields)]
pub struct AdminConfig { pub database_url: String }
pub fn validate(service: Service, text: &str) -> Result<(), String>;
// fields.rs
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind { Text, Integer, Bool, Choice(&'static [&'static str]), TextList, IntegerList }
#[derive(Clone, Copy, Debug)]
pub struct Field { pub key: &'static str, pub kind: Kind, pub help: &'static str }
pub fn fields(service: Service) -> &'static [Field];
```

- [ ] **Step 1: Failing tests** at the end of `configs.rs` (create the file with only `use` lines and this module first):

```rust
#[cfg(test)]
pub(crate) mod tests {
    use platform_host::Service;

    use super::validate;

    pub(crate) fn packaged(service: Service) -> &'static str {
        match service {
            Service::Ingest => include_str!("../../../packaging/rpm/ingest.toml"),
            Service::Distribution => include_str!("../../../packaging/rpm/distribution.toml"),
            Service::Vulns => include_str!("../../../packaging/rpm/vulns.toml"),
            Service::Console => include_str!("../../../packaging/rpm/console.toml"),
            Service::Admin => include_str!("../../../packaging/rpm/admin.toml"),
        }
    }

    #[test]
    fn packaged_files_are_valid() {
        for service in Service::ALL {
            assert_eq!(validate(service, packaged(service)), Ok(()), "{}", service.name());
        }
    }

    #[test]
    fn unknown_keys_and_oversize_files_are_refused() {
        let error = validate(Service::Admin, "database_url = \"x\"\nextra = 1\n").unwrap_err();
        assert!(error.contains("unknown field"), "{error}");
        let big = format!("database_url = \"{}\"\n", "x".repeat(64 * 1024));
        assert_eq!(validate(Service::Admin, &big), Err("the file would exceed 64 KiB".into()));
    }

    #[test]
    fn range_errors_come_from_the_service() {
        let text = packaged(Service::Vulns).replace("check_interval_minutes = 60", "check_interval_minutes = 5");
        assert_eq!(validate(Service::Vulns, &text), Err("check_interval_minutes must be 15 to 1440".into()));
        let text = format!("{}max_inventory_in_flight = 200\n", packaged(Service::Ingest));
        assert_eq!(validate(Service::Ingest, &text), Err("invalid ingest configuration".into()));
    }
}
```

- [ ] **Step 2: Run, expect a compile failure** (`validate` missing).

Run: `cargo test -p openvibes-admin --bin openvibes-admin configs`
Expected: FAIL to compile.

- [ ] **Step 3: Implement.** `Cargo.toml` `[dependencies]`: `openvibes-ingest = { path = "../openvibes-ingest" }`, `openvibes-distribution = { path = "../openvibes-distribution" }`, `toml.workspace = true`, `toml_edit = "0.25.12"`. `configs.rs`:

```rust
//! The configuration files the Configuration screen edits (admin TUI spec
//! §5), checked by each service's own configuration type, so the TUI and
//! the root helper accept exactly what the service will start with.

use platform_host::Service;
use serde::{Deserialize, de::DeserializeOwned};

/// Largest configuration file, as `platform_config::load` reads it.
pub const MAX_BYTES: usize = 64 * 1024;

/// `/etc/openvibes/admin.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// PostgreSQL connection for the `openvibes-admin` role.
    pub database_url: String,
}

fn parse<T: DeserializeOwned>(text: &str) -> Result<T, String> {
    // `message()`: the reason only, without the file excerpt.
    toml::from_str(text).map_err(|error: toml::de::Error| error.message().to_owned())
}

/// Parses `text` as `service`'s configuration and runs the service's checks.
pub fn validate(service: Service, text: &str) -> Result<(), String> {
    if text.len() > MAX_BYTES {
        return Err("the file would exceed 64 KiB".into());
    }
    match service {
        Service::Ingest => parse::<openvibes_ingest::IngestConfig>(text)?
            .validate()
            .map_err(|error| error.to_string()),
        Service::Distribution => parse::<openvibes_distribution::DistributionConfig>(text)?
            .validate()
            .map_err(|error| error.to_string()),
        Service::Vulns => parse::<openvibes_vulns::config::VulnsConfig>(text)?.validate(),
        Service::Console => parse::<openvibes_console::ConsoleConfig>(text)?
            .validate()
            .map_err(|error| error.to_string()),
        Service::Admin => parse::<AdminConfig>(text).map(drop),
    }
}
```

`main.rs`: delete the private `AdminConfig`; add `mod configs; mod fields;`; the loader becomes `let config: configs::AdminConfig = match platform_config::load(&cli.config) {`.

`fields.rs` (every key below is a field of the named type; help texts carry the ranges, because some services report only "invalid … configuration"):

```rust
//! The fields the Configuration screen may change, per service (admin TUI
//! spec §5). A key not listed here cannot be added from the TUI; a listed
//! key the type does not know fails `every_listed_field_is_known_to_its_service_type`.

use platform_host::Service;

/// How a field is typed in and stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// A TOML string.
    Text,
    /// A whole number.
    Integer,
    /// `true` or `false`.
    Bool,
    /// One of these strings.
    Choice(&'static [&'static str]),
    /// Comma-separated strings, stored as an array.
    TextList,
    /// Comma-separated whole numbers, stored as an array.
    IntegerList,
}

/// One editable key; dotted keys live in tables (`assistant.backend.url`).
#[derive(Clone, Copy, Debug)]
pub struct Field {
    pub key: &'static str,
    pub kind: Kind,
    pub help: &'static str,
}

const fn field(key: &'static str, kind: Kind, help: &'static str) -> Field {
    Field { key, kind, help }
}

use Kind::{Bool, Choice, Integer, IntegerList, Text, TextList};

const INGEST: &[Field] = &[
    field("listen", Text, "Agent-facing TLS listener, e.g. 0.0.0.0:18423."),
    field("health_listen", Text, "Loopback health listener (/health, /ready), e.g. 127.0.0.1:18480."),
    field("server_certificate_file", Text, "Server certificate chain, leaf first (absolute path)."),
    field("server_key_file", Text, "Server private key (absolute path)."),
    field("client_ca_file", Text, "CA that issued accepted agent certificates (absolute path)."),
    field("issuing_certificate_file", Text, "Intermediate that signs agent certificates (absolute path)."),
    field("issuing_key_file", Text, "Its private key, 0600 for openvibes-ingest only (absolute path)."),
    field("database_url", Text, "PostgreSQL connection for the openvibes-ingest role."),
    field("client_certificate_days", Integer, "Agent certificate lifetime, 1 to 365 days (default 30)."),
    field("max_in_flight", Integer, "Requests served at once; above this, 503 (default 4096)."),
    field("inventory_request_timeout_seconds", Integer, "Deadline for a whole inventory upload, 1 to 900 s (default 180)."),
    field("max_inventory_in_flight", Integer, "Inventory uploads handled at once, 1 to 128 (default 4)."),
    field("finding_retention_days", Integer, "Findings older than this are not stored, 1 to 36500 days (default 90); match maintenance --retention-days."),
    field("request_timeout_seconds", Integer, "Deadline for the handshake, headers and each request, 1 to 300 s (default 10)."),
    field("max_connections", Integer, "Open agent connections at once, 1 to 65536 (default 1024)."),
    field("database_pool_size", Integer, "Database connections, 1 to 1024 (default 16)."),
];

const DISTRIBUTION: &[Field] = &[
    field("listen", Text, "Agent-facing TLS listener, e.g. 0.0.0.0:18424."),
    field("health_listen", Text, "Loopback health listener (/health, /ready), e.g. 127.0.0.1:18481."),
    field("server_certificate_file", Text, "Server certificate chain, leaf first (absolute path)."),
    field("server_key_file", Text, "Server private key (absolute path)."),
    field("client_ca_file", Text, "CA that issued accepted agent certificates (absolute path)."),
    field("database_url", Text, "PostgreSQL connection for the openvibes-distribution role."),
    field("max_in_flight", Integer, "Requests served at once; above this, 503 (default 4096)."),
    field("request_timeout_seconds", Integer, "Deadline for the handshake, headers and each request, 1 to 300 s (default 10)."),
    field("max_connections", Integer, "Open agent connections at once, 1 to 65536 (default 1024)."),
    field("database_pool_size", Integer, "Database connections, 1 to 1024 (default 16)."),
];

const VULNS: &[Field] = &[
    field("database_url", Text, "PostgreSQL connection for the openvibes-vulns role."),
    field("health_listen", Text, "Loopback health listener (default 127.0.0.1:18483)."),
    field("check_interval_minutes", Integer, "Minutes between feed checks, 15 to 1440 (default 60); downloads only on change."),
    field("metalink_url", Text, "Fedora mirror list (HTTPS) with {release} and {arch}; a local mirror when offline."),
    field("arch", Text, "Repository architecture fetched (default x86_64)."),
    field("proxy_url", Text, "Outbound proxy, e.g. http://proxy.example:3128; empty for none."),
    field("max_download_bytes", Integer, "Largest feed download, 1 to 1073741824 bytes (default 67108864)."),
    field("kev_url", Text, "CISA KEV catalog (HTTPS); empty turns it off."),
    field("epss_url", Text, "FIRST EPSS scores (HTTPS); empty turns it off."),
    field("nvd_url", Text, "NVD CVE API 2.0 (HTTPS); empty turns it off."),
    field("nvd_api_key_file", Text, "File holding an NVD API key, mode 0600 (absolute path); empty for none."),
    field("euvd_url", Text, "ENISA EUVD search API (HTTPS); empty turns it off."),
    field("osv_url", Text, "OSV.dev bucket (HTTPS) for Debian, Ubuntu, Rocky, Alma; empty turns it off."),
    field("osv_dir", Text, "Where OSV downloads are unpacked (absolute path; default /var/lib/openvibes-vulns)."),
    field("osv_max_download_bytes", Integer, "Largest OSV download, 1 to 8589934592 bytes (default 2147483648)."),
];

const CONSOLE: &[Field] = &[
    field("development_listen", Text, "TCP listener for development, direct TLS or TCP proxy mode, e.g. 0.0.0.0:443."),
    field("health_listen", Text, "Loopback health listener, e.g. 127.0.0.1:18482."),
    field("transport_mode", Choice(&["development", "direct_tls", "reverse_proxy"]), "development (loopback), direct_tls (needs both TLS files), or reverse_proxy."),
    field("database_url", Text, "PostgreSQL connection for the openvibes-console role; needed for login."),
    field("public_origin", Text, "Canonical origin, e.g. https://console.example.org."),
    field("server_certificate_file", Text, "TLS certificate chain for direct_tls (absolute path)."),
    field("server_key_file", Text, "TLS private key for direct_tls (absolute path)."),
    field("trusted_proxy_addresses", TextList, "reverse_proxy: loopback addresses of the proxy, comma-separated."),
    field("unix_socket_file", Text, "reverse_proxy: Unix socket used instead of development_listen (absolute path)."),
    field("trusted_proxy_uids", IntegerList, "reverse_proxy: uids allowed on the Unix socket, comma-separated."),
    field("assistant.enabled", Bool, "The assistant chat panel: true or false (default false)."),
    field("assistant.profile", Choice(&["small", "medium", "large"]), "Prompt budget for the model's hardware (default small)."),
    field("assistant.lookup_mode", Choice(&["auto", "native", "json_schema", "prompted"]), "How the model asks for lookups (default auto)."),
    field("assistant.conversation_retention_days", Integer, "Days a conversation is kept, 1 to 3650 (default 30)."),
    field("assistant.max_lookups", Integer, "Lookups per question, 1 to 8 (default 4)."),
    field("assistant.questions_per_user_per_hour", Integer, "Questions one user may ask per hour, 1 to 1000 (default 30)."),
    field("assistant.concurrency", Integer, "Questions answered at once, 1 to 64."),
    field("assistant.backend.url", Text, "Model API base URL, e.g. http://127.0.0.1:18430/v1."),
    field("assistant.backend.model", Text, "Model name sent with each request (openvibes-llm: its alias)."),
    field("assistant.backend.api_key_file", Text, "File holding the API key, owner-only (absolute path)."),
    field("assistant.backend.ca_file", Text, "CAs trusted for the backend (absolute path)."),
    field("assistant.backend.client_certificate_file", Text, "Client certificate chain for mutual TLS (absolute path)."),
    field("assistant.backend.client_key_file", Text, "Client private key for mutual TLS (absolute path)."),
    field("assistant.backend.allow_remote", Bool, "Must be true for a backend not on loopback."),
    field("assistant.backend.data_location", Choice(&["own-network", "external"]), "Where a remote backend runs; required for one."),
    field("assistant.backend.pseudonymize", Bool, "Replace hostnames, agent IDs and addresses before sending."),
    field("assistant.backend.proxy_url", Text, "Outbound proxy for a remote backend."),
    field("assistant.backend.deadline_seconds", Integer, "Seconds one request may take, 2 to 600."),
];

const ADMIN: &[Field] = &[field(
    "database_url",
    Text,
    "PostgreSQL connection for the openvibes-admin role (owns the schema).",
)];

/// The editable fields of `service`, in display order.
#[must_use]
pub fn fields(service: Service) -> &'static [Field] {
    match service {
        Service::Ingest => INGEST,
        Service::Distribution => DISTRIBUTION,
        Service::Vulns => VULNS,
        Service::Console => CONSOLE,
        Service::Admin => ADMIN,
    }
}
```

(Place the `use Kind::…` line at the top with the other `use` lines; `cargo fmt` will wrap long `field(…)` calls.)

- [ ] **Step 4: Run.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin configs`
Expected: PASS 3/3. If `packaged_files_are_valid` fails for a service, print the error and fix the test's understanding, not the packaged file, unless the packaged file is truly invalid (then say so in the PR).

- [ ] **Step 5: Commit.**

```bash
git add Cargo.lock crates/openvibes-admin
git commit -m "openvibes-admin: check configs with each service's own type" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: the form: a config document edited field by field

**Files:**
- Create: `crates/openvibes-admin/src/tui/form.rs`
- Modify: `crates/openvibes-admin/src/tui/mod.rs` (`pub mod form;`)

**Interfaces — Consumes:** `configs::validate`, `fields::{fields, Field, Kind}` (Task 2). **Produces:**

```rust
#[derive(Debug, Eq, PartialEq)]
pub struct Change { pub key: &'static str, pub before: Option<String>, pub after: Option<String> }
pub struct Form { pub service: Service, pub original: String, pub validity: Result<(), String>, /* private: read, doc */ }
impl Form {
    pub fn parse(service: Service, text: &str) -> Result<Form, String>; // Err only when not TOML: "not valid TOML: …"
    pub fn fields(&self) -> &'static [Field];
    pub fn get(&self, key: &str) -> Option<String>;   // None = absent (default)
    pub fn set(&mut self, field: Field, input: &str) -> Result<(), String>; // empty input removes the key
    pub fn undo(&mut self, key: &str);
    pub fn changes(&self) -> Vec<Change>;
    pub fn text(&self) -> String;
}
```

- [ ] **Step 1: Failing tests** (bottom of `form.rs`, with the file holding only its `use` lines):

```rust
#[cfg(test)]
mod tests {
    use platform_host::Service;

    use super::Form;
    use crate::{
        configs::tests::packaged,
        fields::{Field, Kind, fields},
    };

    fn field(service: Service, key: &str) -> Field {
        *fields(service).iter().find(|field| field.key == key).unwrap()
    }

    #[test]
    fn packaged_files_open_valid_and_unchanged() {
        for service in Service::ALL {
            let form = Form::parse(service, packaged(service)).unwrap();
            assert_eq!(form.validity, Ok(()), "{}", service.name());
            assert_eq!(form.text(), packaged(service));
            assert!(form.changes().is_empty());
        }
    }

    #[test]
    fn set_keeps_comments_and_layout() {
        let text = "# the port\nlisten = \"0.0.0.0:18423\" # agents\nmax_in_flight = 4096\n";
        let mut form = Form::parse(Service::Distribution, text).unwrap();
        form.set(field(Service::Distribution, "listen"), "0.0.0.0:443").unwrap();
        assert_eq!(
            form.text(),
            "# the port\nlisten = \"0.0.0.0:443\" # agents\nmax_in_flight = 4096\n"
        );
    }

    #[test]
    fn a_nested_field_creates_its_table_and_clearing_removes_it() {
        let base = packaged(Service::Console);
        let mut form = Form::parse(Service::Console, base).unwrap();
        form.set(field(Service::Console, "assistant.backend.url"), "http://127.0.0.1:18430/v1").unwrap();
        assert!(form.text().contains("[assistant.backend]\nurl = \"http://127.0.0.1:18430/v1\""), "{}", form.text());
        assert!(!form.text().contains("[assistant]\n"), "no empty parent header");
        form.set(field(Service::Console, "assistant.backend.url"), "").unwrap();
        assert_eq!(form.text(), base);
    }

    #[test]
    fn kinds_are_checked() {
        let mut form = Form::parse(Service::Console, packaged(Service::Console)).unwrap();
        let err = |form: &mut Form, key, input| form.set(field(Service::Console, key), input).unwrap_err();
        assert!(err(&mut form, "assistant.max_lookups", "four").contains("not a whole number"));
        assert_eq!(err(&mut form, "assistant.enabled", "yes"), "true or false");
        assert_eq!(err(&mut form, "assistant.profile", "huge"), "one of: small, medium, large");
        assert!(err(&mut form, "trusted_proxy_uids", "1, x").contains("not a whole number"));
        form.set(field(Service::Console, "trusted_proxy_addresses"), "127.0.0.1, ::1").unwrap();
        assert_eq!(form.get("trusted_proxy_addresses").as_deref(), Some("127.0.0.1, ::1"));
        form.set(field(Service::Console, "assistant.enabled"), "true").unwrap();
        assert_eq!(form.get("assistant.enabled").as_deref(), Some("true"));
    }

    #[test]
    fn changes_undo_and_validity() {
        let mut form = Form::parse(Service::Admin, "database_url = 1\n").unwrap();
        assert!(form.validity.is_err(), "an invalid file still opens");
        form.set(field(Service::Admin, "database_url"), "postgresql:///x").unwrap();
        assert_eq!(form.validity, Ok(()));
        assert_eq!(form.changes().len(), 1);
        assert_eq!(form.changes()[0].before.as_deref(), Some("1"));
        assert_eq!(form.changes()[0].after.as_deref(), Some("postgresql:///x"));
        form.undo("database_url");
        assert!(form.changes().is_empty());
        assert_eq!(form.text(), "database_url = 1\n");
        assert!(Form::parse(Service::Admin, "database_url = \n").unwrap_err().starts_with("not valid TOML"));
    }

    #[test]
    fn typed_text_is_escaped() {
        let mut form = Form::parse(Service::Admin, packaged(Service::Admin)).unwrap();
        let value = r#"postgresql:///a "quoted" \ value ✓"#;
        form.set(field(Service::Admin, "database_url"), value).unwrap();
        assert_eq!(form.validity, Ok(()));
        let reparsed = Form::parse(Service::Admin, &form.text()).unwrap();
        assert_eq!(reparsed.get("database_url").as_deref(), Some(value));
    }

    #[test]
    fn every_listed_field_is_known_to_its_service_type() {
        for service in Service::ALL {
            for field in fields(service) {
                let mut form = Form::parse(service, packaged(service)).unwrap();
                let value = match field.kind {
                    Kind::Text => "/x",
                    Kind::Integer | Kind::IntegerList => "1",
                    Kind::Bool => "true",
                    Kind::Choice(choices) => choices[0],
                    Kind::TextList => "::1",
                };
                form.set(*field, value).unwrap();
                if let Err(error) = &form.validity {
                    assert!(!error.contains("unknown field"), "{}: {}: {error}", service.name(), field.key);
                }
            }
        }
    }
}
```

- [ ] **Step 2: Run, expect a compile failure.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin form`
Expected: FAIL to compile (`Form` missing).

- [ ] **Step 3: Implement** `form.rs` above the tests:

```rust
//! A service's configuration file as a form (admin TUI spec §5). The file is
//! kept as a `toml_edit` document, so comments and layout survive a save;
//! only the service's listed fields change, and every change is checked by
//! the service's own configuration type.

use platform_host::Service;
use toml_edit::{DocumentMut, Item, Table, TableLike, Value};

use crate::{
    configs,
    fields::{self, Field, Kind},
};

/// A field whose value differs from the file as read.
#[derive(Debug, Eq, PartialEq)]
pub struct Change {
    pub key: &'static str,
    /// In the file; `None` when absent (the service default).
    pub before: Option<String>,
    /// In the form.
    pub after: Option<String>,
}

pub struct Form {
    pub service: Service,
    /// The file as read, byte for byte (to notice edits made meanwhile).
    pub original: String,
    /// The service type's verdict on the current text.
    pub validity: Result<(), String>,
    read: DocumentMut,
    doc: DocumentMut,
}

impl Form {
    /// Fails only when the text is not TOML; an invalid configuration still
    /// opens, with `validity` saying why.
    pub fn parse(service: Service, text: &str) -> Result<Form, String> {
        let doc: DocumentMut = text
            .parse()
            .map_err(|error: toml_edit::TomlError| format!("not valid TOML: {}", error.message()))?;
        Ok(Form {
            service,
            original: text.to_owned(),
            validity: configs::validate(service, text),
            read: doc.clone(),
            doc,
        })
    }

    pub fn fields(&self) -> &'static [Field] {
        fields::fields(self.service)
    }

    /// The value as it is typed; `None` when the key is absent.
    pub fn get(&self, key: &str) -> Option<String> {
        lookup(&self.doc, key).map(show)
    }

    /// Sets a field from typed text; empty text removes the key.
    pub fn set(&mut self, field: Field, input: &str) -> Result<(), String> {
        let input = input.trim();
        let value = if input.is_empty() { None } else { Some(parse(field.kind, input)?) };
        put(&mut self.doc, field.key, value);
        self.recheck();
        Ok(())
    }

    /// Puts a field back as the file had it.
    pub fn undo(&mut self, key: &str) {
        let value = lookup(&self.read, key).cloned();
        put(&mut self.doc, key, value);
        self.recheck();
    }

    pub fn changes(&self) -> Vec<Change> {
        self.fields()
            .iter()
            .filter_map(|field| {
                let before = lookup(&self.read, field.key).map(show);
                let after = self.get(field.key);
                (before != after).then_some(Change { key: field.key, before, after })
            })
            .collect()
    }

    pub fn text(&self) -> String {
        self.doc.to_string()
    }

    fn recheck(&mut self) {
        self.validity = configs::validate(self.service, &self.text());
    }
}

/// `a.b.c` → (`["a", "b"]`, `"c"`).
fn split(key: &str) -> (Vec<&str>, &str) {
    let mut parts: Vec<&str> = key.split('.').collect();
    let last = parts.pop().unwrap_or(key);
    (parts, last)
}

fn lookup<'a>(doc: &'a DocumentMut, key: &str) -> Option<&'a Value> {
    let (parents, last) = split(key);
    let mut table: &dyn TableLike = doc.as_table();
    for part in parents {
        table = table.get(part)?.as_table_like()?;
    }
    table.get(last)?.as_value()
}

fn table_at<'a>(doc: &'a mut DocumentMut, path: &[&str]) -> Option<&'a mut dyn TableLike> {
    let mut table: &mut dyn TableLike = doc.as_table_mut();
    for part in path {
        table = table.get_mut(part)?.as_table_like_mut()?;
    }
    Some(table)
}

/// Shown and typed the same way: strings bare, lists comma-separated.
fn show(value: &Value) -> String {
    match value {
        Value::String(text) => text.value().clone(),
        Value::Array(items) => items.iter().map(show).collect::<Vec<_>>().join(", "),
        other => {
            let mut other = other.clone();
            other.decor_mut().clear();
            other.to_string()
        }
    }
}

fn parse(kind: Kind, input: &str) -> Result<Value, String> {
    let int = |text: &str| {
        text.parse::<i64>()
            .map_err(|_| format!("{text:?} is not a whole number"))
    };
    let items = || input.split(',').map(str::trim).filter(|item| !item.is_empty());
    Ok(match kind {
        Kind::Text => input.into(),
        Kind::Integer => int(input)?.into(),
        Kind::Bool => match input {
            "true" => true.into(),
            "false" => false.into(),
            _ => return Err("true or false".into()),
        },
        Kind::Choice(choices) if choices.contains(&input) => input.into(),
        Kind::Choice(choices) => return Err(format!("one of: {}", choices.join(", "))),
        Kind::TextList => Value::Array(items().collect()),
        Kind::IntegerList => Value::Array(
            items()
                .map(int)
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .collect(),
        ),
    })
}

/// Sets `key` (keeping the old value's trailing comment), creating its
/// tables; `None` removes it and any table it leaves empty.
fn put(doc: &mut DocumentMut, key: &str, value: Option<Value>) {
    let (parents, last) = split(key);
    let Some(mut value) = value else {
        for depth in (0..=parents.len()).rev() {
            let Some(table) = table_at(doc, &parents[..depth]) else {
                return;
            };
            if depth == parents.len() {
                table.remove(last);
            } else if table
                .get(parents[depth])
                .and_then(Item::as_table_like)
                .is_some_and(TableLike::is_empty)
            {
                table.remove(parents[depth]);
            } else {
                return;
            }
        }
        return;
    };
    let mut table: &mut dyn TableLike = doc.as_table_mut();
    for part in &parents {
        let item = table.entry(part).or_insert_with(|| {
            // Implicit: no `[assistant]` header just to hold `[assistant.backend]`.
            let mut new = Table::new();
            new.set_implicit(true);
            Item::Table(new)
        });
        let Some(next) = item.as_table_like_mut() else {
            return;
        };
        table = next;
    }
    match table.get_mut(last) {
        Some(Item::Value(old)) => {
            *value.decor_mut() = old.decor().clone();
            *old = value;
        }
        Some(other) => *other = Item::Value(value),
        None => {
            table.insert(last, Item::Value(value));
        }
    }
}
```

If `Entry::or_insert_with` is not in toml_edit 0.25, use `.or_insert(item)` with the same table built before the call (Ruling in the ledger).

- [ ] **Step 4: Run.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin form`
Expected: PASS 7/7.

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin/src
git commit -m "Admin TUI: config forms that keep comments and check each change" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: helper `config-read` and `config-write`, sudoers, e2e

**Files:**
- Create: `crates/openvibes-admin/src/config_file.rs`
- Modify: `crates/openvibes-admin/src/{helper.rs,main.rs}`, `crates/openvibes-admin/tests/helper.rs`, `packaging/rpm/openvibes-operators.sudoers`, `scripts/systemd-e2e.sh`

**Interfaces — Consumes:** `configs::{validate, MAX_BYTES}` (Task 2), `platform_host::{Service, CONFIG_DIR}` (Task 1). **Produces:** `config_file::read(dir: &Path, service: Service) -> Result<String, String>`, `config_file::replace(dir: &Path, service: Service, text: &str) -> Result<(), String>`; CLI `openvibes-admin helper config-read SERVICE` (prints the file) and `helper config-write SERVICE` (file on stdin; exit 0, or 1 with `openvibes-admin helper: not saved: REASON`).

- [ ] **Step 1: Failing tests.** In `config_file.rs` (only `use` lines above):

```rust
#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
    };

    use platform_host::Service;

    use super::{read, replace};

    const OLD: &str = "# kept\ndatabase_url = \"postgresql:///old\"\n";
    const NEW: &str = "# kept\ndatabase_url = \"postgresql:///new\"\n";

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ov-config-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn admin_file(dir: &PathBuf) -> PathBuf {
        let path = dir.join("admin.toml");
        fs::write(&path, OLD).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        path
    }

    #[test]
    fn replaces_atomically_keeping_owner_mode_and_backup() {
        let dir = dir("replace");
        let path = admin_file(&dir);
        let before = fs::metadata(&path).unwrap();
        replace(&dir, Service::Admin, NEW).unwrap();
        let after = fs::metadata(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), NEW);
        assert_eq!(after.mode() & 0o7777, 0o640);
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_eq!(fs::read_to_string(dir.join("admin.toml.bak")).unwrap(), OLD);
        assert!(!dir.join(".admin.toml.new").exists());
        assert_eq!(read(&dir, Service::Admin).unwrap(), NEW);
    }

    #[test]
    fn an_invalid_file_is_refused_and_the_old_one_kept() {
        let dir = dir("invalid");
        let path = admin_file(&dir);
        assert!(replace(&dir, Service::Admin, "database_url = 1\n").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), OLD);
        assert!(!dir.join("admin.toml.bak").exists());
    }

    #[test]
    fn a_symlink_or_missing_file_is_refused() {
        let dir = dir("links");
        assert!(read(&dir, Service::Admin).unwrap_err().contains("not installed"));
        assert!(replace(&dir, Service::Admin, NEW).unwrap_err().contains("not installed"));
        let target = dir.join("elsewhere.toml");
        fs::write(&target, OLD).unwrap();
        std::os::unix::fs::symlink(&target, dir.join("admin.toml")).unwrap();
        assert!(read(&dir, Service::Admin).unwrap_err().contains("not a regular file"));
        assert!(replace(&dir, Service::Admin, NEW).unwrap_err().contains("not a regular file"));
        assert_eq!(fs::read_to_string(&target).unwrap(), OLD);
    }

    #[test]
    fn a_leftover_temp_file_does_not_block_a_save() {
        let dir = dir("leftover");
        admin_file(&dir);
        fs::write(dir.join(".admin.toml.new"), "junk").unwrap();
        replace(&dir, Service::Admin, NEW).unwrap();
        assert_eq!(read(&dir, Service::Admin).unwrap(), NEW);
    }
}
```

In `tests/helper.rs` add:

```rust
#[test]
fn config_verbs_refuse_other_services_before_anything_else() {
    for args in [
        ["config-read", "llm"],
        ["config-read", "../../etc/shadow"],
        ["config-write", "ingest.toml"],
        ["config-write", ""],
    ] {
        let out = helper(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("not allowed"), "{args:?}");
    }
}

#[test]
fn config_verbs_need_root() {
    for verb in ["config-read", "config-write"] {
        let out = helper(&[verb, "ingest"]);
        assert_eq!(out.status.code(), Some(1), "{verb}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("helper must run as root"));
    }
}
```

- [ ] **Step 2: Run, expect failures.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin config_file; cargo test -p openvibes-admin --test helper`
Expected: the first fails to compile; in the second the new tests fail (clap reports an unknown subcommand, exit 2 without "not allowed"; `config_verbs_need_root` gets 2, not 1).

- [ ] **Step 3: Implement.** `config_file.rs`:

```rust
//! `/etc/openvibes/NAME.toml` as the root helper reads and replaces it
//! (admin TUI spec §3): only regular files, checked by the service's type,
//! replaced atomically with the original owner, group and mode, the old
//! file kept as `NAME.toml.bak`.

use std::{
    fs::{self, Metadata, OpenOptions, Permissions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use platform_host::Service;

use crate::configs::{self, MAX_BYTES};

fn existing(path: &Path) -> Result<Metadata, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => format!("{}: not installed (no such file)", path.display()),
        _ => format!("{}: {error}", path.display()),
    })?;
    if metadata.is_file() {
        Ok(metadata)
    } else {
        Err(format!("{}: not a regular file", path.display()))
    }
}

/// The file's text.
pub fn read(dir: &Path, service: Service) -> Result<String, String> {
    let path = dir.join(service.file_name());
    if existing(&path)?.len() > MAX_BYTES as u64 {
        return Err(format!("{}: larger than 64 KiB", path.display()));
    }
    fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))
}

/// Replaces the file with `text` once the service's type accepts it.
pub fn replace(dir: &Path, service: Service, text: &str) -> Result<(), String> {
    let name = service.file_name();
    let path = dir.join(name);
    let metadata = existing(&path)?;
    configs::validate(service, text)?;
    let temp = dir.join(format!(".{name}.new"));
    // Left by an interrupted save; it is ours to replace.
    let _ = fs::remove_file(&temp);
    let result = write_temp(&temp, text, &metadata).and_then(|()| {
        fs::copy(&path, dir.join(format!("{name}.bak")))?;
        fs::rename(&temp, &path)?;
        fs::File::open(dir)?.sync_all()
    });
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(|error| format!("{}: {error}", path.display()))
}

/// Temp file, then owner and group, then mode (chown clears set-id bits).
fn write_temp(temp: &Path, text: &str, like: &Metadata) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp)?;
    file.write_all(text.as_bytes())?;
    std::os::unix::fs::fchown(&file, Some(like.uid()), Some(like.gid()))?;
    file.set_permissions(Permissions::from_mode(like.mode() & 0o7777))?;
    file.sync_all()
}
```

(If clippy flags `MAX_BYTES as u64`, use `u64::try_from(MAX_BYTES).unwrap_or(u64::MAX)`.)

`helper.rs`: add the verbs and check arguments before the root check:

```rust
    /// Prints a service's configuration file.
    ConfigRead {
        /// ingest, distribution, vulns, console or admin.
        service: String,
    },
    /// Replaces a service's configuration file with standard input, checked
    /// as the service checks it; keeps owner, group, mode and a .bak copy.
    ConfigWrite {
        /// ingest, distribution, vulns, console or admin.
        service: String,
    },
```

```rust
/// A verb whose arguments passed the allow-lists.
enum Verb {
    Logs(Unit, u16),
    ConfigRead(Service),
    ConfigWrite(Service),
}

fn verb(command: &HelperCommand) -> Result<Verb, &'static str> {
    let service = |name: &str| Service::parse(name).ok_or("not an OpenVIBES service");
    Ok(match command {
        HelperCommand::Logs { unit, lines } => {
            let unit = Unit::parse(unit).ok_or("not an OpenVIBES unit")?;
            match lines.parse::<u16>() {
                Ok(n @ 1..=500) => Verb::Logs(unit, n),
                _ => return Err("lines must be 1 to 500"),
            }
        }
        HelperCommand::ConfigRead { service: name } => Verb::ConfigRead(service(name)?),
        HelperCommand::ConfigWrite { service: name } => Verb::ConfigWrite(service(name)?),
    })
}

pub fn run(command: &HelperCommand) -> ExitCode {
    let verb = match verb(command) {
        Ok(verb) => verb,
        Err(reason) => return refuse(reason),
    };
    if effective_uid().as_deref() != Some("0") {
        eprintln!("openvibes-admin: helper must run as root (through sudo)");
        return ExitCode::from(1);
    }
    let dir = Path::new(CONFIG_DIR);
    match verb {
        Verb::Logs(unit, lines) => logs(unit, lines),
        Verb::ConfigRead(service) => match config_file::read(dir, service) {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => failed(&error),
        },
        Verb::ConfigWrite(service) => {
            match stdin_text().and_then(|text| config_file::replace(dir, service, &text)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => failed(&format!("not saved: {error}")),
            }
        }
    }
}

fn failed(error: &str) -> ExitCode {
    eprintln!("openvibes-admin helper: {error}");
    ExitCode::FAILURE
}

/// Standard input: at most 64 KiB of UTF-8.
fn stdin_text() -> Result<String, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("reading standard input: {error}"))?;
    if bytes.len() > MAX_BYTES {
        return Err("the file would exceed 64 KiB".into());
    }
    String::from_utf8(bytes).map_err(|_| "not UTF-8".to_owned())
}
```

Imports: `std::{io::Read, path::Path, process::ExitCode}`, `platform_host::{CONFIG_DIR, Service, Unit}`, `crate::{config_file, configs::MAX_BYTES}`. Update the module doc ("verbs `logs`, `config-read`, `config-write`"). `main.rs`: `mod config_file;`.

Sudoers (append):

```
%openvibes-operators ALL=(root) NOPASSWD: /usr/bin/openvibes-admin helper config-read *
%openvibes-operators ALL=(root) NOPASSWD: /usr/bin/openvibes-admin helper config-write *
```

`scripts/systemd-e2e.sh` §7c: replace the `helper config-write ingest` denial with:

```bash
allowed alice '/usr/bin/openvibes-admin helper config-read vulns' ||
    fail "operators may not read configs through the helper"
allowed alice '/usr/bin/openvibes-admin helper config-write vulns' ||
    fail "operators may not save configs through the helper"
allowed bob '/usr/bin/openvibes-admin helper config-write vulns' &&
    fail "a non-operator may save configs"
allowed alice '/usr/bin/openvibes-admin helper enable openvibes-llm.service' &&
    fail "operators may run helper verbs beyond logs and configs"
```

and before its `ok` line:

```bash
# A config save through the helper, as root as sudo runs it: checked by the
# service's type, owner, group and mode kept, the old file kept as .bak; an
# invalid file is refused and changes nothing.
in_c 'openvibes-admin helper config-read vulns | sed "s/^check_interval_minutes = 60 /check_interval_minutes = 30 /" |
      openvibes-admin helper config-write vulns' || fail "config-write through the helper"
[[ $(in_c 'stat -c "%U:%G %a" /etc/openvibes/vulns.toml') == "root:openvibes-vulns 640" ]] ||
    fail "config-write kept owner, group and mode"
in_c 'grep -q "^check_interval_minutes = 30 " /etc/openvibes/vulns.toml && test -f /etc/openvibes/vulns.toml.bak' ||
    fail "config-write content and backup"
in_c 'sed "s/^check_interval_minutes = 30 /check_interval_minutes = 5 /" /etc/openvibes/vulns.toml |
      openvibes-admin helper config-write vulns' >/dev/null 2>&1 && fail "config-write accepted an invalid file"
in_c 'grep -q "^check_interval_minutes = 30 " /etc/openvibes/vulns.toml' || fail "a refused write changed the file"
in_c 'runuser -u alice -- systemctl --no-ask-password restart openvibes-vulns.service' ||
    fail "restart after a config save"
wait_for "vulns ready with the saved config" 30 'curl -fsS http://127.0.0.1:18483/ready'
```

Update the §7c `ok` text to "…; sudo lets them read logs, read and save configs, and use the admin CLI; others cannot".

- [ ] **Step 4: Run.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin config_file && cargo test -p openvibes-admin --test helper`
Expected: PASS (4 and 5 tests).

- [ ] **Step 5: Commit.**

```bash
git add crates/openvibes-admin packaging/rpm/openvibes-operators.sudoers scripts/systemd-e2e.sh
git commit -m "Admin helper: config-read and config-write for operators" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: the Configuration screen and tabs

**Files:**
- Create: `crates/openvibes-admin/src/tui/configuration.rs` (state and keys), `crates/openvibes-admin/src/tui/config_view.rs` (render)
- Modify: `crates/openvibes-admin/src/tui/{app.rs,mod.rs,services.rs,tests.rs}`, `docs/components/openvibes-admin.md`, `docs/specs/2026-09-27-admin-tui-design.md`

**Interfaces — Consumes:** `Host::{read_config, write_config}`, `Service`, `Unit::Console` (Task 1); `Form`, `Change` (Task 3). **Produces:**

```rust
// app.rs
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Key { Char(char), Up, Down, Left, Right, Enter, Esc, Backspace, Tab }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tab { Services, Configuration }
// App gains: pub tab: Tab, pub config: Configuration; App::key(&mut self, key: Key)
// configuration.rs
pub enum Prompt { Save, Discard(Then), Restart(Unit) }     // Clone, Copy, Debug, Eq, PartialEq
pub enum Then { Service(usize), Services, Quit }            // same derives
#[derive(Default)] pub struct Configuration { pub service: usize, pub form: Option<Form>, pub selected: usize, pub editing: Option<String>, pub prompt: Option<Prompt> }
impl<H: Host> App<H> { pub fn load_config(&mut self); pub(super) fn config_key(&mut self, key: Key); }
// config_view.rs
pub fn draw<H: Host>(frame: &mut Frame, area: Rect, app: &App<H>);
// services.rs: pub fn draw<H: Host>(frame: &mut Frame, area: Rect, app: &App<H>) (title and size check move to mod.rs)
```

- [ ] **Step 1: Move the existing tests to `Key`.** Run `sed -i "s/app\.key('\(.\)')/app.key(Key::Char('\1'))/g" crates/openvibes-admin/src/tui/tests.rs` and import `super::app::{Key, Tab}`, `super::configuration::Prompt`, `platform_host::Service`. Extend `FakeHost`:

```rust
struct FakeHost {
    actions: RefCell<Vec<(Unit, ServiceAction)>>,
    log_reads: RefCell<usize>,
    writes: RefCell<Vec<(Service, String)>>,
    /// What a read returns instead, as if edited by hand meanwhile.
    hand_edit: RefCell<Option<String>>,
    refuse: bool,
}
```

(initialise the new fields in `app`), and in `impl Host for FakeHost`:

```rust
    fn read_config(&self, service: Service) -> Result<String, HostError> {
        if let Some(text) = self.hand_edit.borrow().clone() {
            return Ok(text);
        }
        if let Some((_, text)) = self.writes.borrow().iter().rev().find(|(s, _)| *s == service) {
            return Ok(text.clone());
        }
        match service {
            Service::Ingest => Ok(include_str!("../../../../packaging/rpm/ingest.toml").into()),
            Service::Distribution => Ok(include_str!("../../../../packaging/rpm/distribution.toml").into()),
            Service::Vulns => Ok(include_str!("../../../../packaging/rpm/vulns.toml").into()),
            Service::Console => Err(HostError::Failed(
                "openvibes-admin helper: /etc/openvibes/console.toml: not installed (no such file)".into(),
            )),
            Service::Admin => Ok("database_url = \n".into()),
        }
    }
    fn write_config(&self, service: Service, toml: &str) -> Result<(), HostError> {
        if self.refuse {
            return Err(HostError::NotOperator);
        }
        self.writes.borrow_mut().push((service, toml.into()));
        Ok(())
    }
```

- [ ] **Step 2: Failing tests** (append):

```rust
fn configuration(refuse: bool) -> App<FakeHost> {
    let mut app = app(refuse);
    app.key(Key::Tab);
    app
}

fn type_text(app: &mut App<FakeHost>, text: &str) {
    for c in text.chars() {
        app.key(Key::Char(c));
    }
}

/// Selects `key`, opens it, replaces its value with `value`, presses Enter.
fn set(app: &mut App<FakeHost>, key: &str, value: &str) {
    app.config.selected = 0;
    while app.config.form.as_ref().unwrap().fields()[app.config.selected].key != key {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    for _ in 0..app.config.editing.as_ref().unwrap().chars().count() {
        app.key(Key::Backspace);
    }
    type_text(app, value);
    app.key(Key::Enter);
}

fn message(app: &App<FakeHost>) -> String {
    app.message.clone().unwrap_or_default()
}

#[test]
fn configuration_renders_the_ingest_form_at_80x24() {
    let app = configuration(false);
    let text = screen(&app, 80, 24);
    for want in [
        "[Configuration]",
        "[ingest]",
        "/etc/openvibes/ingest.toml",
        "0.0.0.0:18423",
        "max_inventory_in_flight",
        "(default)",
        "w save",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    assert!(text.lines().any(|line| line.trim() == "valid"), "{text}");
}

#[test]
fn an_edit_is_checked_by_the_service_type() {
    let mut app = configuration(false);
    set(&mut app, "max_inventory_in_flight", "200");
    assert!(app.config.editing.is_none(), "a number is accepted as typed");
    let text = screen(&app, 80, 24);
    assert!(text.contains("invalid: invalid ingest configuration"), "{text}");
    assert!(text.contains("1 unsaved change"), "{text}");
    app.key(Key::Char('w'));
    assert_eq!(app.config.prompt, None);
    assert!(message(&app).starts_with("cannot save"), "{}", message(&app));
    assert!(app.host.writes.borrow().is_empty());
}

#[test]
fn a_value_of_the_wrong_kind_is_not_accepted() {
    let mut app = configuration(false);
    set(&mut app, "max_inventory_in_flight", "eight");
    assert!(app.config.editing.is_some(), "still editing");
    assert!(message(&app).contains("not a whole number"), "{}", message(&app));
    app.key(Key::Char('q'));
    assert!(!app.quit, "q is typed while editing");
    app.key(Key::Esc);
    assert!(app.config.editing.is_none());
    assert!(app.config.form.as_ref().unwrap().changes().is_empty());
}

#[test]
fn save_shows_the_changes_writes_and_offers_a_restart() {
    let mut app = configuration(false);
    set(&mut app, "max_inventory_in_flight", "8");
    app.key(Key::Char('w'));
    assert_eq!(app.config.prompt, Some(Prompt::Save));
    let text = screen(&app, 80, 24);
    assert!(text.contains("max_inventory_in_flight: (default) → 8"), "{text}");
    assert!(text.contains("Write /etc/openvibes/ingest.toml? y/n"), "{text}");
    app.key(Key::Char('y'));
    let writes = app.host.writes.borrow().clone();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].0, Service::Ingest);
    assert!(writes[0].1.contains("max_inventory_in_flight = 8"));
    assert!(
        writes[0].1.contains("max_in_flight = 4096                        # above this: 503"),
        "untouched lines keep their comments"
    );
    assert_eq!(app.config.prompt, Some(Prompt::Restart(Unit::Ingest)));
    assert!(screen(&app, 80, 24).contains("Saved. Restart openvibes-ingest.service now? y/n"));
    app.key(Key::Char('y'));
    assert_eq!(*app.host.actions.borrow(), [(Unit::Ingest, ServiceAction::Restart)]);
    assert!(app.config.form.as_ref().unwrap().changes().is_empty());
}

#[test]
fn leaving_with_unsaved_changes_asks_first() {
    let mut app = configuration(false);
    set(&mut app, "max_inventory_in_flight", "8");
    app.key(Key::Char('l'));
    assert!(matches!(app.config.prompt, Some(Prompt::Discard(_))));
    app.key(Key::Char('n'));
    assert_eq!(Service::ALL[app.config.service], Service::Ingest);
    assert_eq!(app.config.form.as_ref().unwrap().changes().len(), 1);
    app.key(Key::Char('l'));
    app.key(Key::Char('y'));
    assert_eq!(Service::ALL[app.config.service], Service::Distribution);
    assert!(app.config.form.as_ref().unwrap().changes().is_empty());
}

#[test]
fn unreadable_and_broken_files_are_explained() {
    let mut app = configuration(false);
    while Service::ALL[app.config.service] != Service::Console {
        app.key(Key::Char('l'));
    }
    assert!(app.config.form.is_none());
    assert!(message(&app).contains("not installed"), "{}", message(&app));
    app.key(Key::Enter);
    app.key(Key::Char('w'));
    assert!(app.config.editing.is_none() && app.config.prompt.is_none());
    app.key(Key::Char('l'));
    assert_eq!(Service::ALL[app.config.service], Service::Admin);
    assert!(app.config.form.is_none());
    assert!(message(&app).contains("not valid TOML"), "{}", message(&app));
}

#[test]
fn u_puts_the_file_value_back() {
    let mut app = configuration(false);
    set(&mut app, "max_in_flight", "10");
    app.key(Key::Char('u'));
    let form = app.config.form.as_ref().unwrap();
    assert!(form.changes().is_empty());
    assert_eq!(form.get("max_in_flight").as_deref(), Some("4096"));
}

#[test]
fn a_file_changed_on_disk_is_not_overwritten() {
    let mut app = configuration(false);
    set(&mut app, "max_inventory_in_flight", "8");
    app.host.hand_edit.replace(Some("listen = \"0.0.0.0:1\"\n".into()));
    app.key(Key::Char('w'));
    app.key(Key::Char('y'));
    assert!(app.host.writes.borrow().is_empty());
    assert!(message(&app).contains("changed on disk"), "{}", message(&app));
}

#[test]
fn a_refused_save_keeps_the_edits() {
    let mut app = configuration(true);
    set(&mut app, "max_inventory_in_flight", "8");
    app.key(Key::Char('w'));
    app.key(Key::Char('y'));
    assert!(message(&app).contains("openvibes-operators"), "{}", message(&app));
    assert_eq!(app.config.form.as_ref().unwrap().changes().len(), 1);
}

#[test]
fn tab_switches_screens() {
    let mut app = configuration(false);
    assert_eq!(app.tab, Tab::Configuration);
    app.key(Key::Tab);
    assert_eq!(app.tab, Tab::Services);
    assert!(screen(&app, 80, 24).contains("[Services]"));
}
```

- [ ] **Step 3: Run, expect a compile failure.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin tui`
Expected: FAIL to compile (`Key`, `Tab`, `Prompt`, `read_config` on `FakeHost`'s trait…).

- [ ] **Step 4: Implement.**

`app.rs`: add `Key` and `Tab` (docs: "A key press, as the event loop maps it" / "The screen shown"), fields `pub tab: Tab` (`Tab::Services`) and `pub config: Configuration` (`Configuration::default()`), and:

```rust
    /// One key, handled by the screen shown.
    pub fn key(&mut self, key: Key) {
        match self.tab {
            Tab::Services => self.services_key(key),
            Tab::Configuration => self.config_key(key),
        }
    }

    /// j/k (arrows) move, s/t/r ask to start/stop/restart, y answers, R
    /// refreshes, Tab opens Configuration, q quits.
    fn services_key(&mut self, key: Key) {
        if let Some((unit, action)) = self.confirm.take() {
            if key == Key::Char('y') {
                // (the existing body)
            }
            return;
        }
        match key {
            Key::Char('j') | Key::Down if self.selected + 1 < self.services.len() => { /* existing */ }
            Key::Char('k') | Key::Up if self.selected > 0 => { /* existing */ }
            Key::Char('s') => self.ask(ServiceAction::Start),
            Key::Char('t') => self.ask(ServiceAction::Stop),
            Key::Char('r') => self.ask(ServiceAction::Restart),
            Key::Char('R') => { /* existing */ }
            Key::Tab => {
                self.tab = Tab::Configuration;
                self.message = None;
                self.load_config();
            }
            Key::Char('q') => self.quit = true,
            _ => {}
        }
    }
```

`configuration.rs`:

```rust
//! The Configuration screen's state and keys (admin TUI spec §5): one form
//! per service, checked by the service's own type after every change; save
//! shows the changes, refuses a file changed on disk meanwhile, writes
//! through the root helper, then offers a restart.

use platform_host::{Host, Service, ServiceAction, Unit};

use super::{
    app::{App, Key, Tab},
    form::Form,
};

/// The longest value typed into a field.
const MAX_INPUT: usize = 4096;

/// What `y` confirms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Prompt {
    /// Write the file; the changes are shown.
    Save,
    /// Throw the unsaved changes away, then go on.
    Discard(Then),
    /// Restart the service whose file was just saved.
    Restart(Unit),
}

/// Where the operator goes once nothing is left unsaved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Then {
    /// Open this service's file (index into `Service::ALL`); the same index reloads.
    Service(usize),
    /// Back to the Services screen.
    Services,
    Quit,
}

#[derive(Default)]
pub struct Configuration {
    /// Index into `Service::ALL`.
    pub service: usize,
    /// The file as a form; `None` when it could not be read or is not TOML.
    pub form: Option<Form>,
    pub selected: usize,
    /// The value being typed.
    pub editing: Option<String>,
    pub prompt: Option<Prompt>,
}

impl<H: Host> App<H> {
    /// Reads the selected service's file into a fresh form.
    pub fn load_config(&mut self) {
        let service = Service::ALL[self.config.service];
        self.config.selected = 0;
        self.config.editing = None;
        self.config.prompt = None;
        self.config.form = match self.host.read_config(service) {
            Ok(text) => match Form::parse(service, &text) {
                Ok(form) => Some(form),
                Err(error) => {
                    self.message = Some(format!("{}: {error}; fix it by hand", service.path()));
                    None
                }
            },
            Err(error) => {
                self.message = Some(error.to_string());
                None
            }
        };
    }

    fn dirty(&self) -> bool {
        self.config.form.as_ref().is_some_and(|form| !form.changes().is_empty())
    }

    /// h/l service, j/k field, Enter edit, u undo, w save, R reload, Tab
    /// Services, q quit; while editing, keys type the value.
    pub(super) fn config_key(&mut self, key: Key) {
        if let Some(prompt) = self.config.prompt.take() {
            return self.answer(prompt, key == Key::Char('y'));
        }
        if self.config.editing.is_some() {
            return self.edit_key(key);
        }
        let count = Service::ALL.len();
        let fields = self.config.form.as_ref().map_or(0, |form| form.fields().len());
        match key {
            Key::Char('j') | Key::Down if self.config.selected + 1 < fields => self.config.selected += 1,
            Key::Char('k') | Key::Up => self.config.selected = self.config.selected.saturating_sub(1),
            Key::Char('l') | Key::Right => self.leave(Then::Service((self.config.service + 1) % count)),
            Key::Char('h') | Key::Left => self.leave(Then::Service((self.config.service + count - 1) % count)),
            Key::Char('R') => self.leave(Then::Service(self.config.service)),
            Key::Tab => self.leave(Then::Services),
            Key::Char('q') => self.leave(Then::Quit),
            Key::Enter => {
                if let Some(form) = &self.config.form {
                    let field = form.fields()[self.config.selected];
                    self.config.editing = Some(form.get(field.key).unwrap_or_default());
                    self.message = None;
                }
            }
            Key::Char('u') => {
                if let Some(form) = &mut self.config.form {
                    let key = form.fields()[self.config.selected].key;
                    form.undo(key);
                }
            }
            Key::Char('w') => self.ask_save(),
            _ => {}
        }
    }

    fn edit_key(&mut self, key: Key) {
        let Some(buffer) = self.config.editing.as_mut() else {
            return;
        };
        match key {
            Key::Char(c) if !c.is_control() && buffer.chars().count() < MAX_INPUT => buffer.push(c),
            Key::Backspace => {
                buffer.pop();
            }
            Key::Esc => {
                self.config.editing = None;
                self.message = None;
            }
            Key::Enter => {
                let input = buffer.clone();
                let Some(form) = self.config.form.as_mut() else {
                    return;
                };
                let field = form.fields()[self.config.selected];
                match form.set(field, &input) {
                    Ok(()) => {
                        self.config.editing = None;
                        self.message = None;
                    }
                    Err(error) => self.message = Some(format!("not accepted: {error}")),
                }
            }
            _ => {}
        }
    }

    fn leave(&mut self, then: Then) {
        if self.dirty() {
            self.config.prompt = Some(Prompt::Discard(then));
        } else {
            self.go(then);
        }
    }

    fn go(&mut self, then: Then) {
        match then {
            Then::Service(index) => {
                self.config.service = index;
                self.message = None;
                self.load_config();
            }
            Then::Services => {
                self.tab = Tab::Services;
                self.message = None;
                self.refresh();
            }
            Then::Quit => self.quit = true,
        }
    }

    fn ask_save(&mut self) {
        let Some(form) = &self.config.form else {
            return;
        };
        if form.changes().is_empty() {
            self.message = Some("nothing to save".into());
        } else if let Err(error) = &form.validity {
            self.message = Some(format!("cannot save: {error}"));
        } else {
            self.config.prompt = Some(Prompt::Save);
            self.message = None;
        }
    }

    fn answer(&mut self, prompt: Prompt, yes: bool) {
        match (prompt, yes) {
            (Prompt::Save, true) => self.save(),
            (Prompt::Discard(then), true) => self.go(then),
            (Prompt::Restart(unit), true) => {
                self.message = Some(match self.host.service_action(unit, ServiceAction::Restart) {
                    Ok(()) => format!("restart requested for {}", unit.name()),
                    Err(error) => error.to_string(),
                });
            }
            _ => {}
        }
    }

    fn save(&mut self) {
        let Some(form) = &self.config.form else {
            return;
        };
        let (service, text) = (form.service, form.text());
        // Someone may have edited the file by hand since it was opened.
        match self.host.read_config(service) {
            Ok(current) if current == form.original => {}
            Ok(_) => {
                self.message = Some(format!(
                    "{} changed on disk since it was opened; R reloads it (your edits are dropped)",
                    service.path()
                ));
                return;
            }
            Err(error) => {
                self.message = Some(error.to_string());
                return;
            }
        }
        match self.host.write_config(service, &text) {
            Ok(()) => {
                // The file is now exactly this text; no second read.
                self.config.form = Form::parse(service, &text).ok();
                self.message = Some(format!("saved {}", service.path()));
                self.config.prompt = service.unit().map(Prompt::Restart);
            }
            Err(error) => self.message = Some(error.to_string()),
        }
    }
}
```

`config_view.rs`:

```rust
//! The Configuration screen. Changed fields are marked `*`, absent ones
//! read `(default)`; the check result and prompts are text.

use platform_host::{Host, Service};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Paragraph, Row, Table, TableState, Wrap},
};

use super::{app::App, configuration::Prompt};

const KEYS: &str = "Tab screens  h/l file  j/k field  Enter edit  u undo  w save  R reload  q quit";
const EDIT_KEYS: &str = "type the value  Enter set  Esc cancel  (empty: the service default)";

fn shown(value: Option<&String>) -> &str {
    value.map_or("(default)", String::as_str)
}

pub fn draw<H: Host>(frame: &mut Frame, area: Rect, app: &App<H>) {
    let config = &app.config;
    let service = Service::ALL[config.service];
    let [bar, body, help, check, status, keys] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);
    let names: Vec<String> = Service::ALL
        .iter()
        .map(|s| if *s == service { format!("[{}]", s.name()) } else { s.name().to_owned() })
        .collect();
    frame.render_widget(Paragraph::new(format!("file: {}", names.join("  "))), bar);
    let block = Block::new().borders(Borders::ALL).title(format!(" {} ", service.path()));
    let prompt = config.prompt;
    let line = match (prompt, &config.form) {
        (Some(Prompt::Save), _) => format!("Write {}? y/n", service.path()),
        (Some(Prompt::Discard(_)), _) => "Discard the unsaved changes? y/n".to_owned(),
        (Some(Prompt::Restart(unit)), _) => format!("Saved. Restart {} now? y/n", unit.name()),
        (None, _) => app.message.clone().unwrap_or_default(),
    };
    frame.render_widget(Paragraph::new(line), status);
    frame.render_widget(
        Paragraph::new(if config.editing.is_some() { EDIT_KEYS } else { KEYS }),
        keys,
    );
    let Some(form) = &config.form else {
        frame.render_widget(Paragraph::new("Nothing to edit: the file could not be read.").block(block), body);
        return;
    };
    let changes = form.changes();
    if prompt == Some(Prompt::Save) {
        let lines: Vec<String> = changes
            .iter()
            .map(|c| format!("{}: {} → {}", c.key, shown(c.before.as_ref()), shown(c.after.as_ref())))
            .collect();
        frame.render_widget(Paragraph::new(lines.join("\n")).block(block.title(" changes ")), body);
        return;
    }
    let width = form.fields().iter().map(|f| f.key.len()).max().unwrap_or(10);
    let rows = form.fields().iter().enumerate().map(|(index, field)| {
        let marker = if changes.iter().any(|c| c.key == field.key) { "*" } else { " " };
        let value = match (&config.editing, index == config.selected) {
            (Some(buffer), true) => format!("{buffer}_"),
            _ => shown(form.get(field.key).as_ref()).to_owned(),
        };
        Row::new([marker.to_owned(), field.key.to_owned(), value])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Length(u16::try_from(width).unwrap_or(40)),
            Constraint::Min(10),
        ],
    )
    .block(block)
    .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    let mut state = TableState::default().with_selected(Some(config.selected));
    frame.render_stateful_widget(table, body, &mut state);
    let field = form.fields()[config.selected];
    frame.render_widget(Paragraph::new(field.help).wrap(Wrap { trim: true }), help);
    let mut verdict = match &form.validity {
        Ok(()) => "valid".to_owned(),
        Err(error) => format!("invalid: {error}"),
    };
    if !changes.is_empty() {
        verdict.push_str(&format!(" · {} unsaved change(s)", changes.len()));
    }
    frame.render_widget(Paragraph::new(verdict), check);
}
```

Note `valid` must appear alone on its line when nothing changed (the render test checks it); "1 unsaved change(s)" contains "1 unsaved change".

`services.rs`: rename `render` to `pub fn draw<H: Host>(frame: &mut Frame, area: Rect, app: &App<H>)`, drop the size check and the title (layout becomes `[table, logs, status, keys]` over `area`), move `MIN_WIDTH`/`MIN_HEIGHT` to `mod.rs`, and change `KEYS` to `"Tab screens  j/k select  s start  t stop  r restart  R refresh  q quit"`.

`mod.rs`: `mod configuration; mod config_view; pub mod form;` and

```rust
/// The smallest terminal the screens are laid out for (spec §5).
pub const MIN_WIDTH: u16 = 80;
pub const MIN_HEIGHT: u16 = 24;

pub fn render<H: Host>(frame: &mut Frame, app: &App<H>) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        let text = format!(
            "openvibes-admin needs at least {MIN_WIDTH}×{MIN_HEIGHT} (now {}×{}); enlarge the window",
            area.width, area.height
        );
        frame.render_widget(Paragraph::new(text), area);
        return;
    }
    let [title, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    let tabs = match app.tab {
        Tab::Services => "[Services]  Configuration",
        Tab::Configuration => "Services  [Configuration]",
    };
    frame.render_widget(
        Paragraph::new(format!("OpenVIBES administration   {tabs}"))
            .style(Style::new().add_modifier(Modifier::BOLD)),
        title,
    );
    match app.tab {
        Tab::Services => services::draw(frame, body, app),
        Tab::Configuration => config_view::draw(frame, body, app),
    }
}
```

In `run`, map keys to `Key` and refresh only on Services:

```rust
                    let key = match key.code {
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.quit = true;
                            continue;
                        }
                        KeyCode::Char(c) => Key::Char(c),
                        KeyCode::Up => Key::Up,
                        KeyCode::Down => Key::Down,
                        KeyCode::Left => Key::Left,
                        KeyCode::Right => Key::Right,
                        KeyCode::Enter => Key::Enter,
                        KeyCode::Esc => Key::Esc,
                        KeyCode::Backspace => Key::Backspace,
                        KeyCode::Tab | KeyCode::BackTab => Key::Tab,
                        _ => continue,
                    };
                    app.key(key);
```

(restructure the `if let … && …` into a `let`-`else` or `match` so `continue` applies to the loop) and `if app.tab == Tab::Services && app.confirm.is_none() && refreshed.elapsed() >= REFRESH`.

- [ ] **Step 5: Run.**

Run: `cargo test -p openvibes-admin --bin openvibes-admin tui`
Expected: PASS: the 7 earlier screen tests and the 10 new ones. Then `cargo run -p openvibes-admin` in a real terminal as a sanity look (read fails without the RPM; the screen must say so, not crash).

- [ ] **Step 6: Docs.** `docs/components/openvibes-admin.md` "Administration TUI": add **Configuration** (files, keys `h/l`, `j/k`, `Enter`, `u`, `w`, `R`, `Tab`, `q`; empty value = service default; checked by the service type after every change; save shows `key: before → after`, refuses a file changed on disk, writes through `helper config-write`, keeps `.bak`, offers a restart; journal entry `config-write SERVICE ok|failed`); Services lists `console`; helper paragraph lists `config-read SERVICE` and `config-write SERVICE` (stdin, 64 KiB, checked again as root). Spec: §5 Configuration add "The fields each form offers are listed per service in `openvibes-admin/src/fields.rs`, each checked against the service type by a test; `llm.conf` (an environment file) is not edited here."; §3 table "Config save" row reads `helper config-read SERVICE`, `helper config-write SERVICE`; §5 Services list the console unit as present.

- [ ] **Step 7: Commit.**

```bash
git add crates/openvibes-admin docs
git commit -m "Admin TUI: Configuration screen" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: gate and pull request

- [ ] **Step 1:** Rebase on `origin/main`; run `testing.md` §2 in order in this worktree (`eval "$(scripts/test-db.sh)"`, `build-console.sh`, fmt, `check-names.sh`, clippy, doc, `cargo test --locked --workspace --all-features`, `cargo audit --deny warnings`). Expected: all green.
- [ ] **Step 2:** `bash scripts/test-rename-account.sh` is not needed (no rename change). Run the Fedora job (`testing.md` §3) or `bash scripts/systemd-e2e.sh` locally; if it cannot run here, say so in the PR body and watch the CI job.
- [ ] **Step 3:** Push `admin-tui-configuration`, open the PR ("Admin TUI PR 2: Configuration screen"), Validation section listing the commands run and results, ending with the Claude Code line; watch `gh pr checks --watch`. Merge only with the user's approval.
