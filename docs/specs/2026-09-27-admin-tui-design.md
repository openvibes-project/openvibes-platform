# Administration TUI — design

Status: approved by the user in conversation, 2026-09-27; written spec
awaiting review. Implements the "local administration TUI" decided on
2026-09-23 (workspace `decisions.md`): the web console never controls host
services or edits host configuration; this TUI does.

Amended 2026-09-27 (the user, in conversation): Setup also installs,
repairs and uninstalls the platform (§6), so the quick-setup guide is "run
the install script, follow the TUI" (workspace `decisions.md`, "Easy
setup").

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
- **Install, repair and uninstall from the TUI.** The install script adds
  the signed OpenVIBES package repository and installs only
  `openvibes-admin`; Setup installs the chosen components, the baseline
  rules and, optionally, the agent on this host. Repair re-checks and fixes
  every step (it is also the reinstall). Update upgrades the OpenVIBES
  packages (the local agent too), stopping the services and migrating the
  database in between. Uninstall either keeps the data
  or removes everything (typed hostname, backup offered first).
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
| Config read and save, service logs | sudoers drop-in: run `/usr/bin/openvibes-admin helper config-read SERVICE`, `helper config-write SERVICE` and `helper logs UNIT` as root | fixed verbs; arguments checked against the allow-lists; content read from stdin and validated again as root |

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

Exception for Setup: a Setup run (install, repair, change components,
uninstall) asks for the password once when it starts, keeps it for that
run only (zeroed on drop with `zeroize`; not `mlock`ed, because
`openvibes-admin` forbids unsafe code), and wipes it when the run ends or
fails. Every other screen asks per step. The operator group added in step
3 takes effect only at the next login, so during Setup every step,
including the ones an operator could run, goes through the helper as root
(database commands as `runuser -u openvibes-admin`). Setup's helper verbs,
each its own function:

| Verb | Does |
|---|---|
| `setup-plan --components LIST --hostname NAME [--san ADDR]... [--ca quick\|careful] [--root-key-out PATH] [--repo-dir DIR] [--allow-unsigned-local]` | checks the arguments (components from an enum, hostname and addresses as DNS names or IPs) and writes `/etc/openvibes/setup.toml` |
| `setup-status` | prints each step's state (done, to do, waiting, failed with a reason) |
| `setup-step STEP` | runs one step (§6.3) for the components in `setup.toml`; packages come from each component's fixed package names, and signature checks stay on (`--nogpgcheck` is never passed; local package files are checked with `localpkg_gpgcheck=1` unless `--allow-unsigned-local` was given) |
| `unit-enable UNIT` / `unit-disable UNIT` | enable or disable an allow-listed unit at boot (Services screen) |
| `purge` | remove-everything uninstall (§6.5, PR 5); refuses unless the typed hostname is passed and matches |
| `update-step STEP` | one step of Update (§6.5a, PR 5): `backup PATH`, `stop`, `upgrade`, `migrate`, `start`; `stop` records the active units in `/run/openvibes-admin/update-active` for `start` |

These verbs run only with the user's password (their own sudo rights, no
sudoers entry), so, unlike the password-free verbs, `setup-plan` may take
paths.

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
    fn is_set_up(&self) -> bool;                      // /etc/openvibes/setup.toml exists
    fn privileged(&self, verb: Privileged<'_>, password: &Secret) -> Result<String, HostError>;
}
// Privileged: SetupPlan(args), SetupStatus, SetupStep(Step), UnitEnable(Unit), UnitDisable(Unit)
```

`Unit`, `Service` and `Step` are enums, so an unknown unit or step cannot
be expressed. The root side of Setup (the step checks and actions) lives in
`openvibes-admin/src/setup/` and runs commands through the same `Runner`.

## 5. Screens

Keyboard only; works at 80×24 over SSH; readable without colour (state is
also written as text); no mouse needed. Tabs: Setup · Services ·
Configuration · Database · Health · System. `?` shows keys; every
destructive action asks for confirmation.

- **Services.** For each installed allow-listed unit (`openvibes-ingest`,
  `-distribution`, `-vulns`, `-console`, `-llm`, `-maintenance.timer`): enabled, active, readiness (`/ready` where the unit has
  one), last error line. Actions: start, stop, restart (enable and disable
  at boot are privileged steps, PR 4).
  The last 50 journal lines of the selected unit.
- **Configuration.** One form per service, built from that service's own
  config type (`openvibes-ingest`, `-distribution`, `-vulns`, admin,
  assistant), so the TUI validates exactly as the service does. Unknown
  fields cannot be added; there is no free-text file editor. Save shows a
  diff, writes through `helper config-write`, then offers to restart the
  service. The fields each form offers are listed per service in
  `openvibes-admin/src/fields.rs`, each checked against the service type by
  a test; the files are read through `helper config-read` (they are
  readable only by root and the service's group). `llm.conf` (an
  environment file) is not edited here.
- **Database.** Schema version and whether it is current; migrate;
  run maintenance now; partitions (oldest, newest, count); database size.
- **Health.** Readiness of each service; days until each certificate
  expires (ingest and distribution server certificates, intermediate);
  feed errors (`feeds status`); disk use of `/var/lib/pgsql` and
  `/var/lib/openvibes-*`. Problems are listed first.
- **Setup** (§6) and **System** (§8).

## 6. Setup

### 6.1 Starting point

The install script (its own sub-project: signed dnf repository on GitHub
Pages, published by CI from release tags) adds the repository, installs
`openvibes-admin` and opens the TUI as the invoking user (`SUDO_USER` when
the script ran under sudo). `curl … | sh -s -- --agent …` installs only the
agent on an endpoint. Setup installs from whatever dnf repository is
configured and does not know where it lives. Before the published
repository exists, `setup --repo-dir DIR` adds a temporary local repository
of locally built packages; unsigned packages there are refused unless
`--allow-unsigned-local` is given, shown in red.

### 6.2 State

What is installed is read from the system (`rpm -q`) and each step's own
check; there is no state file that could drift. The chosen components are
kept in `/etc/openvibes/setup.toml`, so Repair knows what complete means.
A host without `setup.toml` and without an `openvibes` database is "not set
up", and the TUI opens on Setup.

### 6.3 Install

**Components** (checkboxes): ingest and console (always in the TUI;
`--components` must name ingest and may leave out the console, which the
systemd end-to-end test installs separately for its upgrade check),
distribution, vulns, assistant (off by default: heavy), baseline rules (on
with distribution), agent on this host (on by default).

**Checklist.** Each step checks its own state first (so re-running is safe
and resumes), shows the exact commands it runs, and marks root steps with
a lock. A failed step stops the run and shows the failing command and its
last output lines; Retry continues from that step.

1. Platform packages of the chosen components installed (root; the rules
   and agent packages are installed by their own steps).
2. PostgreSQL installed, initialised, running (root).
3. Operator group membership for the current user (root, once).
4. Database and `openvibes-admin` role (root, as `postgres`).
5. Schema migrated, partitions created (operator).
6. CA — quick or careful:
   - quick: root created in `/run` (tmpfs), intermediate signed, root key
     shown once and written to a path the user chooses (e.g. a USB stick),
     then deleted; only the root certificate stays;
   - careful: intermediate request written, the wizard waits with the
     exact offline commands shown, then imports the signed certificate.
7. Server certificates for ingest and, if chosen, distribution, with the
   hostname and addresses to put in them, shown and editable (root: key
   install).
8. Console TLS and the first admin account (the console RPM's existing
   setup, `packaging.md` "Console RPM setup"): a server certificate from
   the intermediate (browsers trust it once the root certificate is
   imported), `public_origin` set to `https://HOSTNAME`, and the account
   `admin` with a generated password shown once on the last screen
   (`--admin-password-file` sets it for scripts).
9. Services enabled and started (root: enable).
10. Firewall ports 18423 and, with distribution, 18424, and the console's
    port (root).
11. Baseline rules: install `openvibes-rules-baseline`, trust the project
    rules key and publish the bundle it installs under
    `/usr/share/openvibes/rules/` (`baseline.json`, and `baseline.key`:
    one line `RULE_SET ISSUER_KEY_ID PUBLIC_KEY`) with `rules trust add`
    and `rules publish`. Skipped while the package is not available.
12. Agent on this host: install `openvibes-agent`, write its config
    (platform at `https://localhost`, the root certificate, a single-use
    token, the baseline rule set and its key), start it, and wait up to
    60 seconds for it to show as active.
13. Readiness checks, and an endpoint enrollment token (24 hours, 10
    uses). The last screen shows the console address, the admin login,
    the endpoint command (`curl -fsSL https://openvibes-project.github.io/install.sh
    | sudo sh -s -- --agent --platform HOSTNAME --token TOKEN --ca-sha256
    FINGERPRINT`, releases spec §5; `openvibes-admin agent command`
    prints it again with a new token) and the root certificate's path and
    SHA-256 fingerprint.

### 6.4 Repair, change components

On a set-up host, Setup shows the checklist with each step ok or failed,
and three actions:

- **Repair:** runs every step's check and fixes only failing steps:
  missing package reinstalled, stopped service started, missing firewall
  port opened, schema migrated, a newer installed baseline bundle
  republished. The CA, certificates and database contents are never
  replaced silently: a missing CA key or an expiring certificate is
  reported with its action (Renew certificate), not regenerated.
- **Change components:** ticking a component runs its install steps;
  unticking one runs its uninstall part (keep data, below).
- **Uninstall** (§6.5).

### 6.5 Uninstall

Two choices on one screen:

- **Keep data:** stop and disable the services, close the firewall ports,
  remove the packages (and the agent, if Setup installed it). The
  database, CA, certificates and `/etc/openvibes` stay; a later install
  finds them and continues with the same platform, so enrolled agents keep
  working.
- **Remove everything:** the above, then drop the `openvibes` database and
  its roles, delete `/etc/openvibes`, `/var/lib/openvibes-*`, the CA and
  certificates, and the service accounts and groups (`purge`). PostgreSQL
  itself stays installed (other software may use it; the screen says so).
  First "Export a database backup?" (default yes: `pg_dump` to a chosen
  path, checked to be non-empty and readable), then the full list of what
  will be deleted, then the hostname typed to confirm.

The TUI cannot remove its own package while running: both choices end by
showing the one remaining command, `sudo dnf remove openvibes-admin`.

### 6.5a Update (the user, 2026-09-27)

Setup shows, for each installed OpenVIBES package (the agent included when
Setup installed it on this host), the installed version and any newer one
in the configured repository (`dnf list --upgrades 'openvibes-*'`, no
password). **Update** (password once per run, like the other Setup
actions) runs, stopping at the first step that fails:

1. Database backup offered first (default yes: `pg_dump` to a chosen path,
   checked to be non-empty and readable), as uninstall does.
2. Every OpenVIBES service and the maintenance timer stopped; which were
   active is remembered for step 5. No service can start against a
   half-migrated database.
3. `dnf upgrade` of exactly the installed OpenVIBES packages (the agent
   with them; signature checks on, as in §6.3). The RPMs' restart hooks
   are harmless here because the units are stopped.
4. `openvibes-admin migrate` (and `maintenance`).
5. The previously active services started again, the local agent
   restarted, then the readiness checks (step 13 of §6.3).

A failed step leaves the host as it is and shows the error, the backup's
path and the documented way back (`packaging.md` "Console update and
recovery": restore the backup, install the previous packages). There is no
automatic rollback: a half-applied rollback of a forward-only schema is
worse than a clear stop. Other hosts' agents are updated on those hosts
(`dnf upgrade openvibes-agent`); the platform accepts older agents.

### 6.6 Without screens

`openvibes-admin setup --quick --hostname NAME [--san ADDR]...
[--components LIST] [--root-key-out PATH] [--admin-password-file F]
[--repo-dir DIR]` runs the install steps as root, for scripts and the
systemd end-to-end test (replacing most of `scripts/systemd-e2e.sh`'s
manual steps). `setup --repair`, `setup --update [--backup PATH]`,
`setup --uninstall --keep-data` and
`setup --uninstall --everything --confirm HOSTNAME` do the same for the
other actions.

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
  (`dnf upgrade --refresh --exclude='openvibes-*'`), with the output
  streamed. OpenVIBES packages are left out: they are updated only through
  Setup's Update (§6.5a), which stops the services and migrates the
  database; otherwise an OS update could upgrade the platform without the
  migration and leave services refusing to start. A reboot is offered when
  the kernel or core libraries changed.
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
- Setup life cycle (systemd container, `--repo-dir` with the CI-built
  packages): install with the local agent, which reports baseline-rule
  findings; break things (stop a service, remove a package) and `--repair`
  restores them; uninstall with keep-data, reinstall, and the same CA and
  the agent's existing enrollment keep working; remove everything, then no
  OpenVIBES packages, files, users, groups or database remain.
- Update (same container): install from lower-version packages (built with
  a lower release, as the console upgrade check does), `setup --update` to
  the CI-built ones, then the schema is current, the previously active
  services are running and ready, and the local agent keeps reporting.

## 13. Delivery

One PR each, in order:

0. Account rename (§2): migration, RPM upgrade scripts, units, docs,
   upgrade test.
1. `platform-host` + Services screen + `openvibes-admin` opening the TUI;
   RPM: `openvibes-operators` group, polkit rule (start, stop, restart),
   sudoers drop-in, helper `logs`.
2. Configuration screen + helper `config-write`.
3. Database and Health screens + `audit note`.
4. Setup install (§6.1–6.3, 6.6: screen and `setup` command, `--repo-dir`)
   + privileged steps with the password prompt (including enable and
   disable) + Setup's helper verbs; e2e uses `setup --quick`.
5. Setup repair, change components, update and uninstall (§6.4–6.5a)
   + the life cycle and update e2e (§12).
6. System screen + shell options.

Outside this spec, each with its own spec: the baseline rules package and
`rules keygen|sign` (can go in parallel with 4–5; until it lands, step 11
is skipped when the package is absent); releases, the signed repository
and the install script (after 5); the quick-setup guide (last).

Each PR updates `docs/components/` (new page `platform-host.md`; admin page
for the TUI) and merges with the user's approval.
