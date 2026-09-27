# Administration TUI — design

Status: approved by the user in conversation, 2026-09-27; written spec
awaiting review. Implements the "local administration TUI" decided on
2026-09-23 (workspace `decisions.md`): the web console never controls host
services or edits host configuration; this TUI does.

## 1. Decisions (the user, 2026-09-27)

- **`openvibes-admin` with no arguments opens the TUI.** Subcommands keep
  working unchanged for scripts. The TUI covers what the web console does
  not: setup, services, configuration, database, health, and the
  operating system.
- **Setup and keep it running.** A guided first-run setup, then day-to-day
  host administration. Fleet work (tokens, agents, rules, vulnerabilities)
  stays in the CLI and the web console.
- **CA: both modes, quick by default.** Quick creates the root on this host,
  signs the intermediate, shows and writes the root key once for offline
  keeping, then deletes it from the host. Careful keeps today's offline
  root: the wizard writes the request, waits while it is signed elsewhere,
  then imports the result.
- **No sudo to open it; as little root as possible.** The TUI runs as the
  invoking user. Day-to-day work needs no password; the few actions that
  need root ask for the user's password inside the TUI.
- **Deployment-agnostic.** Native (RPM, systemd) is built now; rootless
  pods/Docker, Kubernetes and a virtual appliance come later, and SSH must
  land straight in the TUI where the deployment allows.
- **The operating system is managed from the TUI** (needed on the
  appliance): updates, reboot and power off, hostname, network, time.
- **Shell access, two options:** a read-only shell, and a normal shell
  behind a warning that it is unsupported because changes might break the
  application.

Out of scope: building the appliance image, container images, Kubernetes
manifests (their own sub-projects); fleet screens; remote access (the TUI
never listens on the network).

## 2. Account names (the user, 2026-09-27)

Service accounts use hyphens, matching the package and command names:
`openvibes-admin`, `openvibes-ingest`, `openvibes-distribution`,
`openvibes-vulns`, `openvibes-llm`, and later `openvibes-console`
(replacing `openvibes_admin`, `openvibes_ingest`, …). Each OS user and group
keeps the same name as its PostgreSQL role, so peer login still needs no
configuration (PM4). Human operators are the separate group
`openvibes-operators`, which cannot be mistaken for the `openvibes-admin`
service account.

- **Database:** new databases create the hyphenated roles directly: the
  role statements in the earlier migrations are edited (applied migrations
  never re-run and carry no checksum; a rename migration would instead
  recreate old roles in every further database of a cluster, as the tests
  create). Existing installs are renamed once by the RPM as `postgres`
  (`ALTER ROLE openvibes_admin RENAME TO "openvibes-admin"`, …); ownership
  and grants move with the rename. SQL quotes the names.
- **OS:** the RPM `%pre` renames existing users and groups (`usermod -l`,
  `groupmod -n`, stopping the unit first) and `%post` rewrites `user=` in
  the kept configs, on upgrade; and the sysusers files create
  the new names on fresh installs; unit files, file ownership, sudoers and
  docs use the new names.
- **Upgrade order:** the OS rename, config rewrite and role rename happen in
  the same upgrade, so the admin CLI never loses its database login. A
  remote database gets the printed `ALTER ROLE` statements. The upgrade is
  tested in the systemd container from the previous release's RPMs.
- **Console:** PR #29 (Codex) must name its role `openvibes-console`.

## 3. Users and privileges (native)

An **operator** is a member of the group `openvibes-operators`, created by
the `openvibes-admin` RPM (sysusers). Setup adds the invoking user to it
once (a root step). Membership grants exactly these, with no password:

| Need | How | Scope |
|---|---|---|
| Service lifecycle | polkit rule (`/usr/share/polkit-1/rules.d/50-openvibes-operators.rules`) for `org.freedesktop.systemd1.manage-units`: start, stop, restart | only units named in the allow-list (§5) |
| Database work | sudoers drop-in: run `/usr/bin/openvibes-admin` as `openvibes-admin` | the existing CLI, its peer login, schema checks and audit log, unchanged |
| Config save, service logs | sudoers drop-in: run `/usr/bin/openvibes-admin helper config-write SERVICE` and `helper logs UNIT` as root | fixed verbs; arguments checked against the allow-lists; content read from stdin and validated again as root |

Enabling and disabling a unit at boot are privileged steps: systemd's
`manage-unit-files` polkit action does not name the unit, so a rule could
not limit it to OpenVIBES units.

Everything else that needs root is a **privileged step**: the TUI shows
what it will do, asks for the user's password in the TUI, and runs
`sudo -S -k -p '' /usr/bin/openvibes-admin helper <verb> [args]` with the
password on stdin (never on the command line, never stored). The user must
be allowed to use sudo (wheel on Fedora; the appliance's admin user is).
Privileged steps: setup steps (§6), certificate installation and renewal,
OS actions (§8).

`openvibes-admin helper` is a hidden subcommand with a closed set of verbs.
It refuses to run unless real or effective uid is 0, takes no paths or unit
names except from the allow-lists, and never runs a shell. Each verb is its
own function; there is no generic "run command" verb.

Why a helper rather than group-writable files: service configs are
`0640 root:<service group>` so each service can read only its own, and a
file has one group. Replacing a file atomically as an operator would also
change its owner. The helper writes a temp file in `/etc/openvibes`, sets
the original owner, group and mode, keeps `NAME.toml.bak`, and renames.

## 4. Architecture

- **`crates/platform-host`** (new, no terminal code): the backend. A
  `Host` trait with the operations the screens need; `Native` implements it
  for systemd, and a fake implements it for tests. Later backends (§10)
  implement the same trait.
- **`crates/openvibes-admin`**: `main` opens the TUI when no subcommand is
  given; `src/tui/` holds the screens (ratatui + crossterm, new
  dependencies); `src/helper.rs` the root verbs; `src/setup.rs` the
  non-interactive `setup` command. Screens call `Host`, never
  `std::process` directly.
- **Commands** are run through one `Runner` (fixed program path plus
  argument vector, never a shell string), so tests assert the exact
  commands and the allow-lists are enforced in one place.

```rust
pub trait Host {
    fn services(&self) -> Result<Vec<ServiceStatus>, HostError>;
    fn service_action(&self, unit: Unit, action: ServiceAction) -> Result<(), HostError>;
    fn logs(&self, unit: Unit, lines: u16) -> Result<Vec<String>, HostError>;
    fn read_config(&self, service: Service) -> Result<String, HostError>;
    fn write_config(&self, service: Service, toml: &str) -> Result<(), HostError>;
    fn admin(&self, args: &[&str]) -> Result<Output, HostError>; // openvibes-admin as openvibes_admin
    fn privileged(&self, step: Step, password: &Secret) -> Result<Output, HostError>;
}
```

`Unit`, `Service` and `Step` are enums, so an unknown unit or step cannot
be expressed.

## 5. Screens

Keyboard only; works at 80×24 over SSH; readable without colour (state is
also written as text); no mouse needed. Tabs: Setup · Services ·
Configuration · Database · Health · System. `?` shows keys; every
destructive action asks for confirmation.

- **Services.** For each installed allow-listed unit (`openvibes-ingest`,
  `-distribution`, `-vulns`, `-llm`, `-maintenance.timer`, later
  `-console`): enabled, active, readiness (`/ready` where the unit has
  one), last error line. Actions: start, stop, restart (enable and disable
  at boot are privileged steps, PR 4).
  The last 50 journal lines of the selected unit.
- **Configuration.** One form per service, built from that service's own
  config type (`openvibes-ingest`, `-distribution`, `-vulns`, admin,
  assistant), so the TUI validates exactly as the service does. Unknown
  fields cannot be added; there is no free-text file editor. Save shows a
  diff, writes through `helper config-write`, then offers to restart the
  service.
- **Database.** Schema version and whether it is current; migrate;
  run maintenance now; partitions (oldest, newest, count); database size.
- **Health.** Readiness of each service; days until each certificate
  expires (ingest and distribution server certificates, intermediate);
  feed errors (`feeds status`); disk use of `/var/lib/pgsql` and
  `/var/lib/openvibes-*`. Problems are listed first.
- **Setup** (§6) and **System** (§8).

## 6. Setup

Opens first on a host that is not set up. A checklist; each step checks its
own state first (so re-running is safe and resumes), shows the exact
commands it runs, and marks root steps with a lock.

1. PostgreSQL installed, initialised, running (root).
2. Operator group membership for the current user (root, once).
3. Database and `openvibes-admin` role (root, as `postgres`).
4. Schema migrated, partitions created (operator).
5. CA — quick or careful:
   - quick: root created in `/run` (tmpfs), intermediate signed, root key
     shown once and written to a path the user chooses (e.g. a USB stick),
     then deleted; only the root certificate stays;
   - careful: intermediate request written, the wizard waits with the
     exact offline commands shown, then imports the signed certificate.
6. Server certificates for ingest and, if installed, distribution, with
   the hostname and addresses to put in them (root: key install).
7. Services enabled and started (operator).
8. Firewall ports 18423 and, with distribution, 18424 (root).
9. Readiness checks.
10. First enrollment token, and the agent configuration snippet to paste on
    endpoints (platform URL, CA certificate, token).

`openvibes-admin setup --quick --hostname NAME [--san ADDR]...
[--root-key-out PATH]` runs the same steps without screens, as root, for
scripts and the systemd end-to-end test.

## 7. Audit

Every action (service action, config save, privileged step, shell opened)
is written to the system journal with `SYSLOG_IDENTIFIER=openvibes-admin`,
the operator's user name and uid, and the outcome. When the database is
reachable it is also recorded in `audit_log` through the existing CLI
(`openvibes-admin audit note ACTION TARGET RESULT`, a hidden subcommand run
as `openvibes-admin`). Passwords and key material are never logged.

## 8. System (operating system)

All privileged steps (password prompt), shown on every deployment where the
backend supports them:

- **Updates:** check (`dnf check-update`, no root) and apply
  (`dnf upgrade --refresh`), with the output streamed; OpenVIBES packages
  and the OS together. A reboot is offered when the kernel or core
  libraries changed.
- **Power:** reboot, power off (confirmation naming the host).
- **Hostname:** show and set (`hostnamectl`).
- **Network:** show interfaces, addresses, gateway, DNS; set an interface
  to DHCP or a static address (`nmcli`), with a revert if the new setting
  loses the SSH session within 60 seconds (the TUI asks to confirm on the
  new address).
- **Time:** time zone and NTP state (`timedatectl`); set the zone, enable
  NTP.
- **Shell** (§9).

## 9. Shell

Two options, both returning to the TUI on exit:

- **Read-only shell:** `/bin/bash` inside bubblewrap (`bwrap`) with the whole
  filesystem bound read-only, a private `/tmp`, no new privileges, so
  `sudo` does not work and nothing on disk can change. For looking at
  logs, processes, network state and files.
- **Normal shell:** after a warning screen: "This shell is unsupported.
  Changes made here can break OpenVIBES and are not covered by upgrades or
  support." The user types `yes`. Opening it is audited (§7), and the TUI
  shows "a normal shell was used on this host" on Health until dismissed.

Both run as the operator, never as root. On a native install the operator
already has a shell; the options matter most on the appliance, whose admin
user logs in straight into the TUI.

## 10. Other deployments (later)

The screens stay; a new `Host` implementation provides:

| Deployment | Services | Config | Privileged steps | SSH lands in |
|---|---|---|---|---|
| Native (now) | systemd units | `/etc/openvibes/*.toml` via helper | sudo + helper | `openvibes-admin` typed by the operator |
| Rootless pods / Docker | user units (quadlet) or containers | files on volumes | none needed; System limited to what the user owns | an admin container, or the user's login |
| Kubernetes | Deployments via the API | ConfigMaps | none; System hidden | `kubectl exec` into an admin pod |
| Virtual appliance | as native | as native | as native; admin user in wheel | login shell of `admin` is `openvibes-admin` |

`Host` reports which features it supports; screens hide what it does not.

## 11. Failure behaviour

- A failed action shows the command's error text (control characters
  escaped) and changes nothing else; a failed config write leaves the old
  file in place.
- Wrong password: the step is refused and nothing runs; three failures
  close the prompt.
- Database unreachable: Database and Health show it; Services, Setup and
  System still work.
- Terminal too small (under 80×24): a message asks for a larger window.
- The TUI never leaves the terminal in raw mode: panics and signals
  restore it.

## 12. Testing

- `platform-host`: `Native` against a fake `Runner` asserting exact argument
  vectors, allow-list refusals, config write order (temp, owner, mode,
  `.bak`, rename).
- `helper`: refuses non-root, unknown verbs and arguments outside the
  allow-lists.
- Screens: ratatui `TestBackend` snapshots for each screen at 80×24.
- End to end (systemd container): `setup --quick` on a clean container,
  then services ready, an agent enrolls with the printed snippet, a config
  save through the helper, a restart through polkit as an operator, and the
  read-only shell refusing a write.

## 13. Delivery

One PR each, in order:

0. Account rename (§2): migration, RPM upgrade scripts, units, docs,
   upgrade test.
1. `platform-host` + Services screen + `openvibes-admin` opening the TUI;
   RPM: `openvibes-operators` group, polkit rule (start, stop, restart),
   sudoers drop-in, helper `logs`.
2. Configuration screen + helper `config-write`.
3. Database and Health screens + `audit note`.
4. Setup (screen and `setup` command) + privileged steps with the password
   prompt (including enable and disable); e2e uses `setup --quick`.
5. System screen + shell options.

Each PR updates `docs/components/` (new page `platform-host.md`; admin page
for the TUI) and merges with the user's approval.
