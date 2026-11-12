# What the platform does

The platform in detail, service by service, as of release 0.3.0. The
[README](../README.md) is the short version.

## Agent lifecycle (`openvibes-ingest`, port 18423)

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
  generator (see [`docs/sizing.md`](sizing.md)).

## Rule distribution (`openvibes-distribution`, port 18424)

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

## Vulnerability management (`openvibes-vulns`)

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

## Administration (`openvibes-admin`)

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

## Packaging and verification

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

## Web console (`openvibes-console`, port 443)

- **Roles and people:** local accounts; custom roles built from 48
  permissions, each with a reach (all hosts, some host groups, or none).
  Service accounts get expiring tokens. Single sign-on through SAML;
  OIDC and MFA come later.
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

## AI assistant (opt-in, in the console)

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

## Next

Work in progress and the next releases are on the
[project board](https://github.com/orgs/openvibes-project/projects/1). Planned:

- **Offline agent install from the console** (0.3.1): the platform holds the
  agent packages, so hosts with no internet can be enrolled and updated.
- **Hardening level 2** rules, and hardening for more systems.
- **Alpine** via OSV.dev.
- **Assistant options:** an external AI provider, opt-in only, with host
  names and addresses pseudonymised before anything leaves the platform.
- **Correlation** (`openvibes-correlation`) across findings and inventory.
- **Third-party inventory and CMDB sync** (`openvibes-cmdb`).
- **Platform on AlmaLinux and Rocky Linux.**
- **Trust-root rotation:** rotate rule-signing keys and the platform CA
  without reinstalling agents.

