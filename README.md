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

OpenVIBES is an open-source, self-hosted vulnerability and configuration
auditing system for fleets of **1,000 to 50,000 hosts**. A small, read-only
agent on every host collects facts (running processes, installed packages,
listening ports, operating system), evaluates signed audit rules against
them, and reports the results to the platform over mutually authenticated
TLS. The platform keeps agent identities, distributes rules, matches every
host's packages against security advisories, and ranks what to fix.

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

```
 openvibes-agent (every host)              openvibes-platform
   collect facts                             openvibes-ingest        :18423  enroll, renew, heartbeat,
   evaluate signed rules  --- mTLS 1.3 -->                                   findings, inventory
   queue and send         <-- mTLS 1.3 ---   openvibes-distribution  :18424  signed rule bundles
                                             openvibes-vulns                 feeds > match > enrich > rank
                                             openvibes-admin (CLI), openvibes-console (:443)
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
- **Findings:** accepted or refused one by one within a batch, and stored
  exactly once. History is partitioned by day, with a current-state table
  per agent, rule set, and rule.
- **Inventory:** package reports (operating system, packages, running
  kernel) arrive only when they change, as gzip-compressed change sets
  after the first full list, and are stored compactly.
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

- **TUI:** `openvibes-admin` with no subcommand opens host administration
  over SSH (keyboard only): Setup (install, repair, update, uninstall),
  configuration, and service lifecycle, kept out of the web console by
  design. `setup --quick` runs the same install unattended.
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
  `no_new_privs`.
- **CI on every change:** formatting, clippy with warnings as errors, docs,
  the RustSec audit, and unit and PostgreSQL tests.
- **Integration test:** a real agent runs against the installed binaries,
  through enrollment, delivery, restart, renewal, revocation, and
  re-enrollment.
- **End to end under systemd:** a scripted install of the platform and
  agent RPMs in which the agent enrolls, fetches its rules, reports
  findings and inventory, and gets vulnerabilities matched.

### Web console (`openvibes-console`, port 443)

- **Access:** local accounts first; OIDC, SAML, and MFA come later as
  adapters. Access is role-based and scoped by asset group, and service
  accounts get expiring tokens.
- **Findings:** each finding is shown once however many endpoints report
  it, and its detail lists every endpoint. Analysts can triage and assign.
- **Dashboards:** a built-in overview plus your own grid dashboards,
  shareable with other users.
- **Operations:** agents (seen recently, offline, revoked), enrollment
  tokens, previews of signed bundles, and an exportable audit log.
- **Wording:** the console never claims more certainty than the data
  supports; it shows "latest observed matches", not "resolved".

### AI assistant (opt-in, in the console)

- **Questions in plain language:** "which hosts are exposed to
  CVE-…?", answered from fixed, read-only lookups that run with the
  asking user's own permissions and scope. Every answer cites the
  agents and findings it is based on.
- **Model:** runs on a local model by default. The optional
  `openvibes-llm` package runs llama.cpp's `llama-server` from a pinned
  build: CPU or Vulkan GPU, loopback only, sandboxed, and a model file
  with a pinned SHA-256.
- **Replaceable:** both the runtime and the model can be swapped. Any
  OpenAI-compatible server on your own network works.
- **Quality gate:** a question set, including prompt-injection cases,
  that a model must pass before the assistant is enabled.

## In progress

- **Admin TUI:** Database and Health screens.
- **Baseline rules package:** a signed starter rule set from the new
  `openvibes-rules` repository, which Setup trusts and publishes.

## Planned

- **Alpine** via OSV.dev.
- **Assistant options:** an external AI provider, opt-in only, with host
  names and addresses pseudonymised before anything leaves the platform.
- **Correlation** (`openvibes-correlation`) across findings and inventory.
- **Third-party inventory and CMDB sync** (`openvibes-cmdb`).
- **Fewer repeat findings:** a protocol change so agents report when a
  match starts and ends, instead of on every scan.
- **Trust-root rotation:** rotate rule-signing keys and the platform CA
  without reinstalling agents.

## Getting started

Install from the package repository: [`docs/quick-setup.md`](docs/quick-setup.md)
(one script, then Setup in the admin TUI).

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
- [`docs/dev-setup.md`](docs/dev-setup.md): run the console interface locally
  with live reload.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`AGENTS.md`](AGENTS.md): how
  changes are made, including by AI coding agents.

Licensed under the [MIT License](LICENSE).
