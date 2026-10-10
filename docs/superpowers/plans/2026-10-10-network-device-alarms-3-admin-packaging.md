# Network Device Alarms, Part 3: Admin, Setup, Packaging, Docs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Devices can be added from the admin CLI. Setup enables `openvibes-netlog` like every other service and warns when UDP 514 is closed. The RPM ships the service, and every component is documented.

**Architecture:** A `device` subcommand group in `openvibes-admin`. It does database work only, as the `openvibes-admin` account; netlog picks up changes within 30 s, so nothing needs root. `Unit::Netlog` joins the Ingest component's units, so Setup's Services and Readiness steps handle it. The Readiness step adds a heads-up when firewalld runs and 514/udp isn't open. OpenVIBES never opens that port itself (spec §6). Netlog ships inside the `openvibes-ingest` RPM, with its own unit, account and config.

**Tech Stack:** clap (derive), platform-host `Unit`, the RPM spec, systemd.

**Spec:** `docs/specs/2026-10-10-network-device-alarms-design.md` (platform #266). Needs Parts 1 and 2.

## Global Constraints

- **No command for end users** (project rule): the CLI is for the lab and tests. The console's Devices screen comes later, with mockups.
- `openvibes-admin device add --name NAME --address IP [--kind unifi]`, `device list`, `device remove ID`. Every command is audited like the others.
- Unit: `openvibes-netlog.service`, account `openvibes-netlog`, config `/etc/openvibes/netlog.toml` (0640 root:openvibes-netlog), health `127.0.0.1:18484`.
- Port 514 needs `AmbientCapabilities=CAP_NET_BIND_SERVICE` and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`. The rest of the hardening matches `openvibes-ingest.service`.
- Heads-up text, word for word: `heads-up: UDP 514 is not open in firewalld, so network devices cannot reach openvibes-netlog; open it the way this host manages its firewall (docs/quick-setup.md, Ports)`.
- The 514/udp port is documented next to the other platform ports in `docs/quick-setup.md`.

## Review Focus

1. **`device add` with an IPv6 address or `::ffff:192.168.1.1`.** Stored as given; netlog canonicalises senders, so a mapped address must be stored canonical too. Test in Task 9.
2. **The TUI service list.** `Unit::ALL` grows to 8; the TUI tests that count units or rows must be updated, not deleted. Task 10, Step 4.
3. **An upgrade from 0.2.8.** `%systemd_post` must not leave netlog stopped after `dnf upgrade` on a host already set up. Setup's Repair/Update enables it. Checked in the lab, Task 12.
4. **netlog without CAP_NET_BIND_SERVICE** (a distribution with `ip_unprivileged_port_start` = 1024 and a unit override). It must fail with "cannot bind 0.0.0.0:514: Permission denied", not exit silently. Covered by `main.rs` (Part 2) and checked in Task 11.
5. **firewalld missing or stopped.** No heads-up and no error, as the Firewall step behaves. Test in Task 10.

---

### Task 9: `openvibes-admin device`

**Files:**
- Create: `crates/openvibes-admin/src/device.rs`
- Modify: `crates/openvibes-admin/src/main.rs`:
  - `mod device;`
  - a `Device { #[command(subcommand)] command: device::DeviceCommand }` variant in `enum Command` (:53)
  - `Self::Device { command } => command.name()` in `Command::name()` (:207-224)
  - a dispatch arm next to `Command::Token` (:383)
  - `| Command::Device { .. }` in the `unreachable!` list (:533-546)
- Test: `crates/openvibes-admin/tests/device.rs`. If admin has no DB integration tests, put the parse tests in `device.rs` and leave the DB paths to Part 1's store tests.

**Interfaces:**
- Consumes: `platform_store::devices::{add, list, remove, heads_up, Device}`.
- Produces: `pub enum DeviceCommand { Add { name: String, address: IpAddr, kind: String }, List, Remove { id: i64 } }`, `impl DeviceCommand { pub fn name(&self) -> &'static str }`, `pub async fn run(command: &DeviceCommand, client: &platform_store::Client, actor: &str) -> (Result<String, String>, Option<String>)`, `pub fn render(devices: &[Device], now: DateTime<Utc>) -> String`.

- [ ] **Step 1: Write the failing tests** (bottom of `device.rs`)

```rust
#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: DeviceCommand,
    }

    #[test]
    fn add_parses_and_canonicalises_a_mapped_address() {
        let cli = Cli::try_parse_from(["x", "add", "--name", "UCG Max", "--address", "::ffff:192.168.1.1"]).unwrap();
        let DeviceCommand::Add { address, kind, .. } = cli.command else { panic!() };
        assert_eq!((address.to_string().as_str(), kind.as_str()), ("192.168.1.1", "unifi"));
        assert!(Cli::try_parse_from(["x", "add", "--name", "r", "--address", "nope"]).is_err());
    }

    #[test]
    fn list_shows_counters_and_the_heads_up() {
        let now = Utc::now();
        let device = Device {
            id: 3,
            name: "UCG Max".into(),
            kind: "unifi".into(),
            address: "192.168.1.1".parse().unwrap(),
            created_at: now - Duration::minutes(30),
            last_seen: None,
            received: 0,
            alarms: 0,
            not_cef: 0,
            unparsed: 0,
            dropped_other: 0,
            mismatch: 0,
            dropped_classes: serde_json::json!({}),
        };
        let out = render(&[device], now);
        assert!(out.contains("3  UCG Max  192.168.1.1  unifi  never"), "{out}");
        assert!(out.contains(platform_store::devices::NO_EVENTS), "{out}");
        assert_eq!(render(&[], now), "no devices\n");
    }
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin device`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `device.rs`**

```rust
//! `openvibes-admin device …`: routers and firewalls that send events to
//! openvibes-netlog (spec 2026-10-10-network-device-alarms §6). Database
//! work only; netlog reloads devices every 30 seconds.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use clap::Subcommand;
use platform_store::devices::{self, Device};

fn parse_address(s: &str) -> Result<IpAddr, String> {
    s.parse::<IpAddr>()
        .map(|ip| ip.to_canonical())
        .map_err(|_| format!("{s} is not an IP address"))
}

#[derive(Subcommand)]
pub enum DeviceCommand {
    /// Add a device; it is accepted within 30 seconds.
    Add {
        /// Shown in the console (1 to 64 characters).
        #[arg(long)]
        name: String,
        /// The address its syslog comes from.
        #[arg(long, value_parser = parse_address)]
        address: IpAddr,
        /// Device kind.
        #[arg(long, default_value = "unifi")]
        kind: String,
    },
    /// List devices with their counters.
    List,
    /// Remove a device by id; its alarms stay.
    Remove {
        /// Device id from `device list`.
        id: i64,
    },
}

impl DeviceCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Add { .. } => "device add",
            Self::List => "device list",
            Self::Remove { .. } => "device remove",
        }
    }
}

pub async fn run(
    command: &DeviceCommand,
    client: &platform_store::Client,
    actor: &str,
) -> (Result<String, String>, Option<String>) {
    let now = Utc::now();
    match command {
        DeviceCommand::Add { name, address, kind } => match devices::add(client, name, kind, *address, actor, now).await {
            Ok(Ok(id)) => (
                Ok(format!(
                    "device {id} added: {name} ({address}); point its SIEM server at this host, \
                     UDP port 514\n"
                )),
                Some(id.to_string()),
            ),
            Ok(Err(error)) => (Err(error), None),
            Err(error) => (Err(error.to_string()), None),
        },
        DeviceCommand::List => match devices::list(client).await {
            Ok(list) => (Ok(render(&list, now)), None),
            Err(error) => (Err(error.to_string()), None),
        },
        DeviceCommand::Remove { id } => match devices::remove(client, *id, actor, now).await {
            Ok(true) => (Ok(format!("device {id} removed\n")), Some(id.to_string())),
            Ok(false) => (Err(format!("no device {id}")), None),
            Err(error) => (Err(error.to_string()), None),
        },
    }
}

/// One line per device, then its heads-up if any.
#[must_use]
pub fn render(list: &[Device], now: DateTime<Utc>) -> String {
    if list.is_empty() {
        return "no devices\n".into();
    }
    let mut out = String::new();
    for d in list {
        let seen = d.last_seen.map_or_else(|| "never".to_owned(), |t| t.format("%Y-%m-%d %H:%M UTC").to_string());
        out.push_str(&format!(
            "{}  {}  {}  {}  {}  received {} alarms {} not-cef {} unparsed {} other {} mismatch {}\n",
            d.id, d.name, d.address, d.kind, seen, d.received, d.alarms, d.not_cef, d.unparsed, d.dropped_other, d.mismatch
        ));
        if let Some(note) = devices::heads_up(d, now) {
            out.push_str(&format!("    {note}\n"));
        }
    }
    out
}
```

Dispatch arm in `main.rs`:

```rust
        Command::Device { command } => match require_current_schema(&client).await {
            Ok(()) => device::run(command, &client, &actor).await,
            Err(error) => (Err(error), None),
        },
```

- [ ] **Step 4: Run the tests and a manual check**

Run: `cargo test -p openvibes-admin && cargo clippy -p openvibes-admin --all-targets -- -D warnings`
Expected: PASS.

Manual check against the test database:

```bash
eval "$(scripts/test-db.sh)"
cargo run -q -p openvibes-admin -- migrate   # if it needs a config, use an admin.toml with database_url = $OPENVIBES_TEST_DATABASE_URL
```

If the admin binary can't run against the test cluster without its packaged config, skip this check. The store tests already cover the database paths, and the lab covers the rest (Task 12).

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-admin/src/device.rs crates/openvibes-admin/src/main.rs
git commit -m "Admin: device add, list, remove"
```

---

### Task 10: Setup enables netlog and warns about UDP 514

**Files:**
- Modify: `crates/platform-host/src/unit.rs`:
  - a `Netlog` variant
  - `ALL: [Unit; 8]`, with `Unit::Netlog` after `Unit::Vulns`
  - `name` → `"openvibes-netlog.service"`, `label` → `"netlog"`, `ready_url` → `Some("http://127.0.0.1:18484/ready")`
- Modify: `crates/openvibes-admin/src/setup/plan.rs:96`: `Component::Ingest => &[Unit::Ingest, Unit::Maintenance, Unit::Netlog],`
- Modify: `crates/openvibes-admin/src/setup/run.rs` (`ready_apply`, the last `Ok(StepState::Done(format!(` at :259)
- Modify: `crates/platform-host/src/service.rs:70` and any other `match` the compiler flags as non-exhaustive
- Modify: `packaging/rpm/openvibes-operators.polkit.rules:11` (add `"openvibes-netlog.service"` to the list)
- Test: `crates/openvibes-admin/src/setup/run_tests.rs`

**Interfaces:**
- Produces: `Unit::Netlog`, and `pub(super) fn netlog_port_note<R: Runner>(ctx: &Ctx<R>) -> Option<String>` in `run.rs`.

- [ ] **Step 1: Write the failing test** (append to `run_tests.rs`)

```rust
#[test]
fn readiness_warns_when_udp_514_is_closed_and_firewalld_runs() {
    let fake = Fake::new("netlog-port");
    fake.answer(&["/usr/bin/firewall-cmd", "--permanent", "--query-port", "514/udp"], 1, "no\n");
    let note = super::run::netlog_port_note(&fake.ctx(&plan(&[Ingest])));
    assert!(note.as_deref().is_some_and(|n| n.contains("UDP 514 is not open")), "{note:?}");

    let fake = Fake::new("netlog-port-open");
    fake.answer(&["/usr/bin/firewall-cmd", "--permanent", "--query-port", "514/udp"], 0, "yes\n");
    assert_eq!(super::run::netlog_port_note(&fake.ctx(&plan(&[Ingest]))), None);

    let fake = Fake::new("netlog-no-firewalld");
    fake.answer(&["/usr/bin/firewall-cmd", "--state"], 252, "not running\n");
    assert_eq!(super::run::netlog_port_note(&fake.ctx(&plan(&[Ingest]))), None);

    // Not planned (no Ingest component): nothing to say.
    let fake = Fake::new("netlog-not-planned");
    fake.answer(&["/usr/bin/firewall-cmd", "--permanent", "--query-port", "514/udp"], 1, "no\n");
    assert_eq!(super::run::netlog_port_note(&fake.ctx(&plan(&[Console]))), None);
}
```

If `Console` isn't in scope in `run_tests.rs`, import it the way `Ingest` is imported at the top of that file. `Fake` answers unmatched calls with status 0 (see `fake.rs:43-66`), so `--state` defaults to "running".

- [ ] **Step 2: Run it to make sure it fails**

Run: `cargo test -p openvibes-admin readiness_warns`
Expected: FAIL, `cannot find function netlog_port_note`.

- [ ] **Step 3: Implement**

Add `Unit::Netlog` as listed under Files. In `run.rs`, add:

```rust
/// Spec §6: OpenVIBES does not open 514/udp (how ports are opened differs
/// per installation); when firewalld runs and it is closed, say so.
// ponytail: checks the default 514; a moved `listen` in netlog.toml is the
// admin's own change and is not re-read here.
pub(super) fn netlog_port_note<R: Runner>(ctx: &Ctx<R>) -> Option<String> {
    let planned = units(ctx).contains(&Unit::Netlog);
    if !planned || !ctx.succeeds(FirewallCmd, &["--state"]) {
        return None;
    }
    if ctx.succeeds(FirewallCmd, &["--permanent", "--query-port", "514/udp"]) {
        return None;
    }
    Some(
        "heads-up: UDP 514 is not open in firewalld, so network devices cannot reach \
         openvibes-netlog; open it the way this host manages its firewall \
         (docs/quick-setup.md, Ports)"
            .into(),
    )
}
```

In `ready_apply`, after `let closed = firewall;`, append the note to `closed`. That way both Done texts (repair and first install) carry it:

```rust
    let mut closed = firewall;
    if let Some(note) = netlog_port_note(ctx) {
        closed.push_str("; ");
        closed.push_str(&note);
    }
```

(Replace the existing `let closed = firewall;` line.)

- [ ] **Step 4: Run all admin and host tests; fix unit counts**

Run: `cargo test -p platform-host -p openvibes-admin`
Expected: PASS after updating every test that lists or counts units. `tui/tests.rs` and `setup/run_tests.rs` assert names like `"enabled and started: openvibes-ingest.service openvibes-maintenance.timer"`; add `openvibes-netlog.service` where Ingest is planned. Update these expected strings; don't loosen the assertions.

- [ ] **Step 5: Commit**

```bash
git add crates/platform-host crates/openvibes-admin packaging/rpm/openvibes-operators.polkit.rules
git commit -m "Setup: enable openvibes-netlog with ingest; heads-up when UDP 514 is closed"
```

---

### Task 11: Packaging

**Files:**
- Create: `packaging/rpm/openvibes-netlog.service`, `packaging/rpm/openvibes-netlog.sysusers`, `packaging/rpm/netlog.toml`
- Modify: `packaging/rpm/openvibes-platform.spec`. Use the ingest lines as the reference: `install` near :161/:179/:184, the scriptlets near :228-236, `%files -n openvibes-ingest` at :355-366.
- Modify: `scripts/build-rpm.sh:12` (add `-p openvibes-netlog`), `scripts/check-rpm.sh` (the checks below)

- [ ] **Step 1: Write the files**

`packaging/rpm/openvibes-netlog.service`:

```ini
[Unit]
Description=OpenVIBES network device events (UniFi IPS/IDS over syslog)
Documentation=https://github.com/openvibes-project/openvibes-platform/blob/main/docs/components/openvibes-netlog.md
After=network-online.target postgresql.service openvibes-migrate.service
Wants=network-online.target openvibes-migrate.service

[Service]
Type=exec
User=openvibes-netlog
Group=openvibes-netlog
ExecStart=/usr/bin/openvibes-netlog --config /etc/openvibes/netlog.toml
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGINT
Restart=on-failure
RestartSec=5s
UMask=0077
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
MemoryMax=64M

[Install]
WantedBy=multi-user.target
```

`bind(2)` isn't in `@privileged`; the capability alone allows port 514. Task 12's lab run confirms it. If bind fails with EPERM there, drop `~@privileged` for this unit only and say so in the component page.

`packaging/rpm/openvibes-netlog.sysusers`:

```
u openvibes-netlog - "OpenVIBES network device events" - -
```

`packaging/rpm/netlog.toml`:

```toml
# openvibes-netlog: UniFi IPS/IDS events (CEF over UDP syslog) become
# alarms; see docs/components/openvibes-netlog.md. Devices are added in the
# console (or `openvibes-admin device add`); open UDP 514 in this host's
# firewall yourself.
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes-netlog"
listen = "0.0.0.0:514"                     # the router's SIEM server port
health_listen = "127.0.0.1:18484"          # /health, /ready; loopback only
batch_seconds = 5                          # 1 to 60
collapse_minutes = 10                      # 1 to 1440; quiet window per signature and source
max_collapse_keys = 2000                   # 1 to 100000; also bounds alarms kept while the database is down
```

- [ ] **Step 2: Add to the spec file** (inside the `openvibes-ingest` subpackage)

`%install`:

```
install -D -m 0755 $S/target/release/openvibes-netlog %{buildroot}%{_bindir}/openvibes-netlog
install -D -m 0644 $S/packaging/rpm/openvibes-netlog.service %{buildroot}%{_unitdir}/openvibes-netlog.service
install -D -m 0644 $S/packaging/rpm/openvibes-netlog.sysusers %{buildroot}%{_sysusersdir}/openvibes-netlog.conf
install -D -m 0640 $S/packaging/rpm/netlog.toml %{buildroot}%{_sysconfdir}/openvibes/netlog.toml
```

Scriptlets: add `openvibes-netlog.service` next to `openvibes-ingest.service` in `%systemd_post`, `%systemd_preun` and `%systemd_postun_with_restart` of `openvibes-ingest`. It's a new account, so no `%rename_pre`. Make sure the sysusers file is applied in `%pre` the way ingest's is (look at what `%rename_pre ingest` expands to and copy only its sysusers part, `%sysusers_create_compat` or `systemd-sysusers`, for netlog).

`%files -n openvibes-ingest`:

```
%{_bindir}/openvibes-netlog
%{_unitdir}/openvibes-netlog.service
%{_sysusersdir}/openvibes-netlog.conf
%config(noreplace) %attr(0640, root, openvibes-netlog) %{_sysconfdir}/openvibes/netlog.toml
```

Add a `%changelog` line: `- openvibes-netlog: UniFi IPS/IDS events as alarms (spec 2026-10-10)`.

- [ ] **Step 3: Extend `scripts/check-rpm.sh`** (installed-package section, after the vulns lines)

```bash
getent passwd openvibes-netlog >/dev/null || fail "no user openvibes-netlog"
expect_stat /etc/openvibes/netlog.toml 640 root:openvibes-netlog
rpm -qc openvibes-ingest | grep -qx /etc/openvibes/netlog.toml || fail "netlog.toml not %config"
systemd-analyze verify /usr/lib/systemd/system/openvibes-netlog.service || fail "netlog unit verification"
grep -q '^KillSignal=SIGINT' /usr/lib/systemd/system/openvibes-netlog.service || fail "netlog unit lacks KillSignal=SIGINT"
grep -qx 'AmbientCapabilities=CAP_NET_BIND_SERVICE' /usr/lib/systemd/system/openvibes-netlog.service || fail "netlog cannot bind 514"
grep -q '^After=.*openvibes-migrate.service' /usr/lib/systemd/system/openvibes-netlog.service || fail "netlog starts before migrate"
out=$(/usr/bin/openvibes-netlog --config /nonexistent 2>&1) && fail "netlog started without config"
[[ "$out" == *"invalid netlog configuration"* ]] || fail "netlog error: $out"
```

The `.toml cn` count check (`grep -c '\.toml cn'` == 4) counts per package. Netlog's config is in the ingest package, so the count becomes 5. Update that number.

- [ ] **Step 4: Build and check the RPM locally**

Run: `scripts/build-rpm.sh && scripts/check-rpm.sh` (whatever `testing.md` gives as the RPM gate; the Fedora container job runs the installed checks).
Expected: `check-rpm (built): ok` locally; the installed-package section passes in CI's Fedora job.

- [ ] **Step 5: Commit**

```bash
git add packaging/rpm scripts/build-rpm.sh scripts/check-rpm.sh
git commit -m "Packaging: openvibes-netlog in the ingest RPM (unit, account, config)"
```

---

### Task 12: Docs and lab measurement

**Files:**
- Create: `docs/components/openvibes-netlog.md`
- Modify: `docs/components/README.md`. Add a row after `openvibes-vulns`: `` | `openvibes-netlog` | service (UDP 514, health 18484) | UniFi IPS/IDS events from registered devices become alarms (spec 2026-10-10) | [openvibes-netlog.md](openvibes-netlog.md) | ``. Also correct the `platform-store` row's schema number to 46.
- Modify: `docs/components/platform-store.md` (a "Network devices (schema 46)" section: `devices`, the new `alarms` columns and CHECK, suppression scopes `device`/`signature`, the `openvibes-netlog` grants, `devices::heads_up`)
- Modify: `docs/components/openvibes-admin.md` (`device add/list/remove`; the readiness heads-up)
- Modify: `docs/quick-setup.md` (a **Ports** list: 443 or 8443+ console, 18423 ingest, 18424 distribution, **514/udp netlog (open it yourself; Setup warns when firewalld has it closed)**; router setup: UniFi Network → Settings → Control Plane → Integrations → Activity Logging → SIEM Server, this host, port 514, at least "Security Detections")
- Modify: `docs/sizing.md` or wherever service footprints are listed (`grep -rln "RSS" docs`): netlog's measured figures from Step 2

- [ ] **Step 1: Write `docs/components/openvibes-netlog.md`**

Cover, in the style of `openvibes-vulns.md`:

- **Purpose:** spec link, not a SIEM.
- **Run:** binary, config path, SIGINT drain, SIGHUP reload.
- **Configuration:** the table of the six keys, with defaults and ranges from `netlog.toml`.
- **Interfaces:** UDP in, Postgres out, health 18484.
- **Data flow:** the seven steps from spec §2.
- **What becomes an alarm:** spec §3 table.
- **Router settings changes:** the table from Part 2.
- **Failure behaviour:** database down → collapse map; flood → counters; unknown senders → logged per flush.
- **Security notes:** spec §7.
- **How to test:** unit, integration (`scripts/test-db.sh`), lab replay.

- [ ] **Step 2: Lab measurement** (`openvibes-lab`, private repo; see its `AGENTS.md` for the VM commands)

Install the built RPM on a lab VM, add a device with that VM's replay host address, then:

```bash
# idle
systemctl show -p MemoryCurrent openvibes-netlog; ps -o rss=,cputime= -C openvibes-netlog
# replay: the real fixture at ~10,000 packets/s for 60 s from the replay host
timeout 60 sh -c 'while :; do cat ucgmax-ips-blacksun.cef; done' | pv -qL 10m | socat -u - UDP-SENDTO:VM:514
ps -o rss=,cputime= -C openvibes-netlog
openvibes-admin device list
```

Record idle and flood RSS and CPU in the sizing doc and the component page. The target is under 10 MB RSS and near-zero idle CPU. If it misses, say by how much and why; don't move the target silently.

- [ ] **Step 3: Run the local gate** from `../testing.md` (fmt, clippy, the whole workspace's tests, docs with `-D warnings`, the OpenAPI check if the console changed).
Expected: green, except known local WebKit gaps noted in `status.md`.

- [ ] **Step 4: Commit**

```bash
git add docs
git commit -m "Docs: openvibes-netlog component, ports, store and admin pages, sizing"
```
