# platform-host

## Purpose

What the administration TUI (`openvibes-admin` with no arguments) may do to
this host, behind one trait, so the screens never start processes
themselves and other deployments (pods, Kubernetes) can plug in later
(admin TUI spec §4). No terminal code.

## Interfaces

- `Unit`: the allow-list: `openvibes-ingest.service`,
  `openvibes-distribution.service`, `openvibes-vulns.service`,
  `openvibes-console.service`, `openvibes-llm.service`,
  `openvibes-maintenance.timer`. An enum; `Unit::parse` accepts only these
  exact names.
- `Service`: the configuration files the TUI edits,
  `/etc/openvibes/{ingest,distribution,vulns,console,admin}.toml`
  (`CONFIG_DIR`). An enum; `Service::parse` accepts only the exact short
  names, so no path ever comes from input.
- `Host`: `services()` (installed, enabled, active state, readiness, since),
  `service_action(unit, Start | Stop | Restart)`, `logs(unit, lines)`,
  `read_config(service)`; for the Database
  and Health screens `database(Status | Migrate | Maintenance |
  FeedsStatus)`, `certificates()` and `disk()`. These three have defaults
  (not supported, none, none) for hosts without a local database or files
  (spec §10). `listeners(port)` (Setup's console port row): the
  `ss -ltnpH` lines for that TCP port, by default none.
- `native::Native<R: Runner>`: the systemd implementation.
  - services: one `systemctl show --property=… UNITS…`, plus
    `openvibes-certificates.service`: when its last run failed, the
    certificate timer's `last_run_failed` is set (its own state stays as
    systemd reports it); readiness by
    `curl --silent --fail --max-time 1` on the default loopback endpoints
    (ingest 18480, distribution 18481, vulns 18483, console 18482 `/ready`,
    llm 18430 `/health`), only for active units;
  - actions: `systemctl --no-ask-password --no-block VERB UNIT` (queued, so
    the screen stays responsive; the next refresh shows the outcome), allowed for
    `openvibes-operators` by the RPM's polkit rule; each is written to the
    journal with `logger -t openvibes-admin` (user, uid, verb, unit,
    outcome);
  - logs: `sudo -n /usr/bin/openvibes-admin helper logs UNIT N` (the RPM's
    sudoers drop-in allows it to operators);
  - config: `sudo -n /usr/bin/openvibes-admin helper config-read SERVICE`
    (there is no write verb: service files are changed by Setup or by hand);
  - audit: every journalled action (service action,
    privileged verb) is also sent to `sudo -n -u openvibes-admin
    /usr/bin/openvibes-admin audit note ACTION TARGET OUTCOME`, best effort
    (no database or operator group yet during Setup);
  - database: `sudo -n -u openvibes-admin /usr/bin/openvibes-admin status |
    migrate | maintenance | feeds status` (the operators' sudoers entry);
    migrate and maintenance are journalled, the CLI writes their audit row;
  - certificates: reads `CERTIFICATES` (`/etc/openvibes/tls/ingest.crt`,
    `distribution.crt`, `/etc/openvibes/pki/intermediate.crt`, all 0644);
    missing files are left out; `root_and_chain()` reads `ROOT_CERT` and
    says whether `CHAIN` exists, or one of `REPLACE_STAGED` (the `.new`
    files a Replace cut short by a crash left; Repair ends that), for
    Health's lost-chain check (none by default);
  - disk: `df --output=file,size,pcent,avail -h` on `/var/lib/pgsql` and each
    existing `/var/lib/openvibes-*`.
  - listeners: `ss -ltnpH sport = :PORT`, as the user (so processes of
    other users are rarely named).
- `runner::Runner` / `SystemRunner`: every command is one of a closed set of
  `Program`s (`/usr/bin/systemctl`, `sudo`, `logger`, `curl`) with an
  argument vector, never a shell; `run_with_input` also writes stdin. `SystemRunner` is one of the two places this
  crate starts processes (the workspace's clippy rule forbids
  `std::process::Command` elsewhere); because `Program` is closed, the
  exception cannot be used to run anything else.
- `Host::shell` (Maintenance › Shell, spec §10.9; `src/shell.rs`, the
  other place): runs the operator's login shell on the inherited terminal
  (stdin, stdout and stderr not captured) and returns when it exits; the
  shell's own exit status is not an error, only a shell that cannot start
  is (`HostError::Io`). Under sudo (effective uid 0 with a `SUDO_USER`
  other than root) it is `/usr/sbin/runuser -l USER`, never root's shell:
  a malformed `SUDO_USER`, or one with no passwd entry, is an error
  ("cannot tell whose shell to open");
  otherwise the passwd entry's shell for the effective uid (`getent passwd
  -- UID`, then `/etc/passwd`; `/bin/sh` without one) with `-l`; root
  logged in directly gets root's own. `shell_argv(uid, sudo_user,
  passwd_shell)` is the pure choice and `operator_of` the journal's
  name (both tested in `tests/shell.rs`); the spawn is checked in the
  lab. The trait's default is `Err(HostError::Failed("this host has no
  shell"))`. The caller (the TUI) gives the terminal back before and takes
  it again after.

### Setup (admin TUI spec §3, §6)

- `Step`: the 13 Setup steps in order (`packages` … `ready`), with
  `name()` (the helper's argument), `title()` and `parse()`.
- `StepState`: `Done`, `Todo`, `Waiting`, `Skipped`, `Failed`, each with a
  one-line detail. The helper prints `STATE<TAB>DETAIL`
  (`line()`/`parse()`); control characters become spaces.
- `Secret`: the user's password for one Setup run, zeroed on drop
  (`zeroize`), `Debug` prints `Secret(..)`.
- `Privileged`: the password-gated helper verbs `setup-plan ARGS…`,
  `setup-status`, `setup-step STEP`, `unit-enable UNIT`, `unit-disable UNIT`,
  `admin-reset` (journalled as `admin-reset admin`, with no detail: its
  stdout holds the new console password), `shell-open` (journalled and
  audit-noted as `shell-open OPERATOR`, the operator being `SUDO_USER`
  only when the process is root and the name is well formed (`shell::valid_user`,
  shared with Setup's operator), else the real uid's passwd name; the helper does nothing else, so sudo's password check and
  the journal line are what it is for), `ca-request [--copy PATH]` and
  `ca-accept --cert PEM --root-cert PEM` (journalled and audit-noted
  as `ca-request /etc/openvibes/pki/request` and `ca-accept
  /etc/openvibes/pki/request`, without the copy path or PEM),
  `ca-replace [--root-key PATH]` (journalled and audit-noted as
  `ca-replace /etc/openvibes/pki/intermediate.crt`, without the key path),
  and `ca-import` (`Privileged::CaImport(&Secret)`: the certificates and
  key go on stdin, never in argv; journalled and audit-noted as
  `ca-import /run/openvibes-import`),
  `console-cert-set` (`Privileged::ConsoleCertSet(&Secret)`: the console's
  own certificate and key on stdin, as `ca-import`; journalled as
  `console-cert-set /etc/openvibes/tls/console-own.crt`) and
  `console-cert-reset` (`Privileged::ConsoleCertReset`, journalled as
  `console-cert-reset /etc/openvibes/tls/console-own.crt`).
  `Host::privileged` runs `sudo -S -k -p '' /usr/bin/openvibes-admin helper
  VERB…` with the password on stdin only (never in argv or the journal),
  followed by the verb's own input (`Privileged::stdin`: `ca-import`'s and
  `console-cert-set`'s bundle, after sudo's one password line; as root the helper is run
  directly with the bundle alone, or stdin closed when there is none;
  after a wrong password, `sudo -S` may read the bundle's next lines as
  further attempts, and those are always public certificate lines, since
  the certificates come before the key),
  journals `VERB ok|failed` (without `setup-plan`'s arguments), and returns
  the helper's stdout. sudo's refusals map to `WrongPassword` ("incorrect
  password") and `NotSudoer` (not in sudoers, or "is not allowed to
  execute", which a session started before joining wheel also gets). sudo's
  first-use lecture is removed from stderr first, so it never stands in for
  the error (#75).
- `UpdateStep` (`backup`, `stop`, `upgrade`, `migrate`, `start`, `ready`) and
  `RemoveStep` (`backup`, `stop`, `firewall`, `packages`, `purge`), with
  the verbs `Privileged::Update` (`update-step STEP [ARGS]`),
  `Privileged::Remove` (`remove-step STEP ARGS`) and `Privileged::Repair`
  (`setup-step STEP --repair`). The journal names the step only, never the
  arguments, and records the state a step ended in (`ok`, `failed`,
  `waiting`, `todo`), not just the exit status.
- `Host::is_set_up`: whether `/etc/openvibes/setup.toml` exists;
  `Host::setup_plan`: that file's text (world-readable, no secrets).
- `Host::packages`: installed `openvibes-*` packages (`rpm -qa`,
  debuginfo left out) with any newer version (`dnf -q list --upgrades`, as
  the user; offline, none are shown).
- `Host::user_home`: a person's home directory for the TUI under sudo
  (where the root key is saved). It runs `getent passwd -- USER`, so
  directory users (SSSD, FreeIPA, LDAP) are found too, and falls back to
  `/etc/passwd`.
- `Program` also covers `getent`, `dnf`, `rpm`, `runuser`, `postgresql-setup`,
  `usermod`, `firewall-cmd`, `userdel`, `groupdel`, `df`, `ss`, `journalctl`
  and `openvibes-admin`,
  which Setup's root side runs. `SystemRunner` runs every command with
  `LC_ALL=C`, because sudo's, dnf's and systemctl's messages are parsed.

## Configuration

None. Readiness uses the packaged default ports.

## Failure behaviour

- polkit or sudo refusing (not an operator) → `HostError::NotOperator`, whose
  message names the `openvibes-operators` group and how to join it.
- Any other failure → `HostError::Failed` with the command's error text,
  trimmed, control characters escaped.
- A unit whose package is not installed is reported as not installed; a
  unit that is not active is not probed for readiness.

## How to test

`cargo test -p platform-host`: the backend against a fake runner (exact
argument vectors, parsing of `systemctl show`, refusal mapping, the unit
and service allow-lists, config read and write through the helper, database commands as the admin
account, the audit note after each action, `df` parsing, and that
the RPM's polkit rule names exactly the units in `Unit::ALL`). The real rights are exercised by `scripts/systemd-e2e.sh`
(section "Operators").

## Operating system updates

`os_updates` parses what `dnf` prints: `check_update_packages` (one format for
`check-update` and `check-update --security`, wrapped dnf4 lines joined),
`restart_answer` (`needs-restarting -r`'s own words; anything else is no
answer), `short_kernel` and `os_release` (`PRETTY_NAME`, else `NAME
VERSION_ID`, else "Linux"). It keeps the last check as `OsUpdates` in
`OS_UPDATES_FILE` (`/etc/openvibes/os-updates`). `Host::os_info()` returns the
distribution, kernel, last check and whether the `openvibes-os-update` unit is
running (`Host::os_update_running()`, read when the page opens or refreshes, never per draw), or `None` without dnf. `APPLIANCE_FILE` (`/etc/openvibes/appliance`, an empty marker the appliance image adds) makes `Host::is_appliance()` true; `os-power-off` joins the `os-*` verbs. `network` (`src/network.rs`) parses NetworkManager's terse output into `NetInfo` (`Host::network_info()`), checks every network value (`change`, `cidr`, `host_name`, `dns_name`), probes a DNS server over UDP (`dns_answers`) and encodes the saved settings (`Snapshot`) for the appliance's Network verbs. The password-gated verbs are
`Privileged::OsCheck`, `OsUpdate` and `OsRestart` (`os-check`, `os-update`,
`os-restart`, journalled under their own names); `Program::SystemdRun` runs
the upgrade.
