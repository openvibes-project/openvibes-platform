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
  `read_config(service)`, `write_config(service, text)`.
- `native::Native<R: Runner>`: the systemd implementation.
  - services: one `systemctl show --property=… UNITS…`; readiness by
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
  - config: `sudo -n /usr/bin/openvibes-admin helper config-read SERVICE`,
    and `config-write SERVICE` with the file on stdin (the helper checks it
    again as root); each save is journalled as `config-write SERVICE
    ok|failed`, never with the file's content.
- `runner::Runner` / `SystemRunner`: every command is one of a closed set of
  `Program`s (`/usr/bin/systemctl`, `sudo`, `logger`, `curl`) with an
  argument vector, never a shell; `run_with_input` also writes stdin (the
  config save). `SystemRunner` is the one place this
  crate starts processes (the workspace's clippy rule forbids
  `std::process::Command` elsewhere); because `Program` is closed, the
  exception cannot be used to run anything else.

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
and service allow-lists, config read and write through the helper, and that
the RPM's polkit rule names exactly the units in `Unit::ALL`). The real rights are exercised by `scripts/systemd-e2e.sh`
(section "Operators").
