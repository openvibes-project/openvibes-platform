<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/openvibes-wordmark-dark.svg">
    <img src="docs/brand/openvibes-wordmark-light.svg" alt="OpenVIBES" width="560">
  </picture>
</p>

<h3 align="center">OpenVIBES Platform</h3>

<p align="center">
  Open Vulnerability Inspection &amp; Baseline Evaluation System: the server
  side that enrolls agents, hands them signed rules, stores what they find,
  and tells you which hosts to patch first.
</p>

---

> **AI disclosure:** OpenVIBES is built with the help of AI coding tools
> (Claude Code and Codex), and they will continue to be used. Every change
> still goes through a pull request and the full CI checks before it is
> merged. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the policy.

## What OpenVIBES is

OpenVIBES is a free, open-source, self-hosted security tool for homelabs,
small businesses and security enthusiasts, built to stay light as it grows
to many agents. A small, read-only agent on every host collects facts
(running processes, installed packages, listening ports and services,
hardening settings, operating system), evaluates signed rules against them,
raises threat alarms from program starts, and reports to the platform over
mutually authenticated TLS. The platform keeps agent identities, hands out
rules, matches every host's packages against security advisories, and
ranks what to fix in one web console.

Design principles, shared by every repository:

- **Secure by default.** Mutual TLS 1.3 everywhere, a built-in certificate
  authority, offline-signed rules, least-privilege services and database
  roles, strict size limits on every input, and no remediation: nothing in
  OpenVIBES changes the hosts it audits.
- **Self-hosted, no vendor cloud.** The platform fetches public feeds itself
  and sends no telemetry. Air-gapped hosts can run the agent without any
  network and export their results to a file.
- **Modular.** Each service is its own binary, system user, and database
  role. Services talk only through PostgreSQL and documented protocols.
- **The protocol is the contract.** Everything that crosses the agent–platform
  boundary is specified in `openvibes-protocol` first and tested against its
  shared fixtures on both sides.

## The repositories

| Repository | What it is |
|---|---|
| [openvibes-agent](https://github.com/openvibes-project/openvibes-agent) | The endpoint agent (Rust; Linux, Windows, macOS): collectors, signed-rule evaluation, a durable local queue, and the mTLS client. |
| **openvibes-platform** (this one) | The server side: ingest, rule distribution, vulnerability matching, the admin CLI, the built-in PKI, the web console with its AI assistant, and packaging. |
| [openvibes-protocol](https://github.com/openvibes-project/openvibes-protocol) | The single source of truth for everything exchanged between agent and platform: the spec, JSON Schemas, shared valid and invalid fixtures, and the paired plan. |
| [openvibes-rules](https://github.com/openvibes-project/openvibes-rules) | The project's signed rule sets (baseline, threat alarms, Linux hardening level 1), shipped as one RPM that Setup and upgrades publish. |

```
 openvibes-agent (every host)              openvibes-platform
   collect facts                             openvibes-ingest        :18423  enroll, renew, heartbeat,
   evaluate signed rules  --- mTLS 1.3 -->                                   findings, inventory
   queue and send         <-- mTLS 1.3 ---   openvibes-distribution  :18424  signed rule bundles
                                             openvibes-vulns                 feeds > match > enrich > rank
 routers, firewalls  --- syslog UDP --->     openvibes-netlog        :514    IPS/IDS events > alarms
                                             openvibes-admin (TUI, CLI), openvibes-console (:443)
                                                 all sharing one PostgreSQL database

 contracts, schemas, fixtures: openvibes-protocol (a submodule in both repositories)
```

## Capabilities today

### Agent lifecycle (`openvibes-ingest`, port 18423)

- **Enrollment:** single-use or multi-use tokens, with CSR checks. Agents
  then renew their certificates before they expire.
- **Revocation:** a structured "identity revoked" answer, so an agent knows
  to re-enroll instead of retrying forever.
- **Heartbeats:** each agent reports its host name, versions, enabled
  collectors (capabilities), and its own health; the platform rates each
  agent Healthy, Degraded, Offline, or Unknown with the reasons.
- **Compliance findings:** agents report a match when it starts, changes or
  ends, not on every scan. Each is accepted or refused on its own and
  stored exactly once; history is partitioned by day, with a current-state
  table per agent, rule set, and rule.
- **Threat alarms:** process starts that match the signed alarm rules
  arrive within seconds of the event, with the process tree. The platform
  records each host's alarm source (eBPF or kernel audit) and says when
  alarms are off and why.
- **Services:** each host's listening ports and the services and programs
  behind them, sent when they change.
- **Inventory:** package reports (operating system, packages, running
  kernel) arrive only when they change, as gzip-compressed change sets
  after the first full list, and are stored compactly.
- **Network device alarms** (`openvibes-netlog`, UDP 514): registered
  routers and firewalls (UniFi's SIEM export today) send their IPS/IDS
  events; the ones that matter become alarms with the same triage, cases
  and suppressions. It is not a SIEM: everything else is dropped and only
  counted. The receiver is built; the console screens to add a device
  come next.
- **Operations:** per-connection and per-request limits, structured logs,
  health and readiness endpoints, and a graceful drain on shutdown.
- **Scale:** horizontally scalable. Load-tested with the `openvibes-load`
  generator (see [`docs/sizing.md`](docs/sizing.md)).

### Rule distribution (`openvibes-distribution`, port 18424)

- Serves rule bundles exactly as they were signed offline. Each rule set
  has its own trusted Ed25519 keys, and the private keys never touch the
  platform.
- Agents poll for newer versions, and verify and refuse rollbacks
  themselves. A compromised platform therefore cannot make agents trust new
  rules.
- **Rule-set assignment:** the project's own sets (baseline, alarms,
  hardening) come with the agent package. Hardening sets are
  switched per host group in the console; a host the set is not assigned
  to gets `410`, and its open findings end.

### Vulnerability management (`openvibes-vulns`)

- **Fedora feed:** security advisories are fetched from Fedora's mirror
  network. Every file is checked against the SHA-256 chain that starts at
  the HTTPS mirror list. The service checks hourly and downloads only when
  the index changes.
- **More distributions via OSV.dev:** Debian, Ubuntu, Rocky Linux, and
  AlmaLinux. Debian and Ubuntu are matched by source package with dpkg
  version order. Vulnerabilities without a fix are shown and labelled as
  such.
- **Matching:** exact RPM version order (epoch, version, release, and
  architecture) against every host's inventory.
- **Lifecycle:** each host–advisory pair is a record that opens, is closed
  automatically when the host reports the fixed version, and reopens on a
  downgrade.
- **Kernels:** a separate "reboot needed" state for a fix that is installed
  but not yet running.
- **Enrichment:** CISA KEV (known exploited, ransomware use), FIRST EPSS,
  NVD, and ENISA EUVD, combined into one priority so open vulnerabilities
  sort by what to patch first.
- **Offline import:** feed and KEV files can be imported for air-gapped
  platforms, and every feed check is recorded so data freshness is visible.
- **Scale check:** 10,000 hosts at 244,000 open vulnerabilities; a list
  query takes 0.63 s.

### Administration (`openvibes-admin`)

- **TUI:** `openvibes-admin` opens host administration over SSH (keyboard
  only, 80×24), kept out of the web console by design. One frame with Home,
  Status (problems first, each with its fix), Service (start, stop, logs)
  and Help; Maintenance holds Database, Back up, Update (with a backup
  first, and recovery from a half-done update), Repair, Optional parts
  (agent, assistant), Ports and addresses, Certificates and Names, Console
  sign-in (reset the admin password), a logged Shell, and Uninstall. Members
  of `openvibes-operators` use it without root. `setup --quick` installs
  unattended.
- **Upgrades run themselves:** `dnf upgrade` backs up and migrates the
  database, upgrades the console with the platform, publishes a newer rules
  package's rule sets, and tunes the assistant if it has not been tuned, with no command.
- **Schema and data:** `migrate`, `status`, and daily `maintenance`
  (partitions and retention) from a systemd timer.
- **Built-in PKI (`ca`):** an offline root, an online intermediate, and
  server certificates.
- **Agents:** `token` (create, list, revoke) and `agent` (list, show,
  revoke).
- **Rules:** `rules trust add|list|remove` and `rules publish|list|show`
  for signed bundles.
- **Vulnerabilities:** `feeds status|import` and `vulns list|summary|show`.
- **File import:** `import PATH...` stores export files from agents
  without a platform (air-gapped hosts) as imported hosts: their findings,
  and their inventory matched for vulnerabilities like any other host.
- **Audit:** every command is recorded in an append-only audit log. The log
  records the real user who ran it, not a name the caller can choose.

### Packaging and verification

- **Fedora RPMs:** hardened systemd units, each with its own user, no
  capabilities, a read-only system, a system-call filter, and
  `no_new_privs`. A small SELinux policy module lets the assistant's socket
  activation work with SELinux enforcing.
- **Offline kit:** every release carries
  `openvibes-platform-<version>-offline-fedora44.tar`: all platform packages
  and their Fedora dependencies, PostgreSQL included, signed and
  checksummed, with an installer that never goes online.
- **CI on every change:** formatting, clippy with warnings as errors, docs,
  the RustSec audit, and unit and PostgreSQL tests.
- **Integration test:** a real agent runs against the installed binaries,
  through enrollment, delivery, restart, renewal, revocation, and
  re-enrollment.
- **End to end under systemd:** a scripted install of the platform and
  agent RPMs in which the agent enrolls, fetches its rules, reports
  findings and inventory, and gets vulnerabilities matched.

### Web console (`openvibes-console`, port 443)

- **Roles and people:** local accounts; custom roles built from 48
  permissions, each with a reach (all hosts, some host groups, or none).
  Service accounts get expiring tokens. OIDC, SAML and MFA come later.
- **Host groups and labels:** automatic groups per operating system and
  release, rule-based and manual groups, and free labels on hosts.
- **Settings:** one page for people, roles, host groups and the general
  settings; alarm suppressions can be set to need a second person's
  approval (off by default).
- **Compliance findings:** each finding is shown once however many
  endpoints report it, and its detail lists every endpoint. Analysts can
  triage and assign.
- **Threat alarms:** the alarm, why it fired and the process tree, with
  triage, suppressions, and cases to collect alarms, findings and notes
  into an investigation.
- **MITRE ATT&CK:** every shipped rule carries its techniques; a Coverage
  page shows them on a kill-chain view, and the rule editor has a
  technique picker.
- **Test triggers:** `openvibes-test` on a host raises a harmless test
  alarm or finding; the host page shows the last test.
- **Hosts:** a list with a shared filter bar and saved views, and a host
  page with software, advisories per package, ports and services, hardening
  and the last test; a host compare view. Add hosts from Enrollment
  (Install package or Copy CLI install).
- **Alarms:** a list and an alarm page with why the rule fired, the
  process tree, the commands seen beside it, and the rule's own
  explanation and what to check.
- **Hardening:** Linux level 1 rules (sshd, sysctls, file modes, mounts,
  services and more), switched on per host group.
- **Dashboards:** a built-in Overview with 30-day trends, plus your own grid
  dashboards (Graph, Trend, List and more), shareable with other users.
- **Operations:** agents (seen recently, offline, revoked), enrollment
  tokens, previews of signed bundles, and an exportable audit log.
- **Wording:** the console never claims more certainty than the data
  supports; it shows "latest observed matches", not "resolved".

### AI assistant (opt-in, in the console)

- **Questions in plain language:** "which hosts are exposed to
  CVE-…?", answered from fixed, read-only lookups that run with the
  asking user's own permissions and scope. Every answer cites the
  agents and findings it is based on.
- **Internet lookups (opt in):** OSV and Bodhi references and a SearXNG
  web search, each with its own risk level; off by default.
- **Model:** runs on a local model (Qwen3.5-4B) by default. The optional
  `openvibes-llm` package runs llama.cpp's `llama-server` from a pinned
  build: CPU or Vulkan GPU, loopback only, sandboxed. Setup downloads the
  model from its publisher, checked against a pinned SHA-256 (offline, it
  comes as a file beside the kit). The model starts on the first question
  and unloads when idle, and is tuned to the host's CPU.
- **Replaceable:** both the runtime and the model can be swapped. Any
  OpenAI-compatible server on your own network works.
- **Quality gate:** a question set, including prompt-injection cases,
  that a model must pass before the assistant is enabled.

## In progress

The latest release is **0.2.9**. Hardening per host group, roles and
people, host groups, settings with approval, the new Hosts and Alarms
pages and most of the TUI rework are on `main` but not released yet: they ship as **0.3.0** (the agent
too) once the work below is done.

- **Admin TUI rework:** the last sub-projects of the rework spec
  (`docs/specs/2026-10-10-tui-rework-design.md`), next the Install flow
  that replaces today's Setup form.
- **Console list and detail pages:** after Hosts and Alarms, the same
  rework for Vulnerabilities (next), Compliance, Cases, Software, Services
  and Ports; then dashboard sharing by role.
- **Network device alarms in the console:** add a gateway and see its
  alarms (the receiver is already in place).

## Planned

- **Hardening level 2** rules, and hardening for more systems.
- **Alpine** via OSV.dev.
- **Assistant options:** an external AI provider, opt-in only, with host
  names and addresses pseudonymised before anything leaves the platform.
- **Correlation** (`openvibes-correlation`) across findings and inventory.
- **Third-party inventory and CMDB sync** (`openvibes-cmdb`).
- **Platform on AlmaLinux and Rocky Linux.**
- **Offline agent install from the console:** per-distribution archives and
  updates through the platform.
- **Trust-root rotation:** rotate rule-signing keys and the platform CA
  without reinstalling agents.

## Runs on

- **Platform:** Fedora 44, x86_64, online or with no internet (the offline
  kit). 2 GB RAM and 1 vCPU served 500 simulated agents in the lab
  ([`docs/sizing.md`](docs/sizing.md)).
- **Agents:** Fedora 44, AlmaLinux and Rocky Linux 9+, Debian 12+, Ubuntu
  22.04+ and Arch, x86_64.

## Getting started

Install from the package repository: [`docs/quick-setup.md`](docs/quick-setup.md)
(one script, then Setup in the admin TUI). Without internet: the offline
kit from the [latest release](https://github.com/openvibes-project/openvibes-platform/releases/latest),
`tar xf openvibes-platform-<version>-offline-fedora44.tar && sudo ./openvibes-offline/install`.

Build from source and install on Fedora (details, including first-time CA and database
setup, in [`docs/components/packaging.md`](docs/components/packaging.md)):

```sh
git clone --recurse-submodules https://github.com/openvibes-project/openvibes-platform.git
cd openvibes-platform
scripts/build-rpm.sh                    # → target/rpm/RPMS/x86_64/openvibes-*.rpm
sudo dnf install target/rpm/RPMS/x86_64/openvibes-{ingest,distribution,vulns,admin}-*.rpm
```

Develop and test (Rust toolchain pinned in `rust-toolchain.toml`; the
database tests need PostgreSQL 17 or later):

```sh
eval "$(scripts/test-db.sh)"            # throwaway PostgreSQL under target/
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

## Documentation

- [`docs/components/`](docs/components/): one page per crate or service
  (interfaces, configuration, failure behaviour, and how to test).
- [`docs/specs/`](docs/specs/): architecture and design, approved before
  implementation.
- [`docs/plans/`](docs/plans/): implementation plans with progress.
- [`docs/sizing.md`](docs/sizing.md): measured and estimated requirements.
- [`docs/dependencies.md`](docs/dependencies.md): what the builds ship and
  what development needs, with versions and licences.
- [`docs/dev-setup.md`](docs/dev-setup.md): run the console interface locally
  with live reload.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`AGENTS.md`](AGENTS.md): how
  changes are made, including by AI coding agents.

Licensed under the [Apache License 2.0](LICENSE).
