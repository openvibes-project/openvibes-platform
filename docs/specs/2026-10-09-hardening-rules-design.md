# Hardening rules (baseline stage 2)

Decisions (user, 2026-10-09): stage 2 of the wider baseline checks how hosts
are configured, per operating system, with **our own scanner**: the agent
collects facts and our signed CEL rules judge them. No external scanner
(OpenSCAP, CIS-CAT) runs on hosts. Facts are **curated and typed**: the
protocol names each one, and the agent reads them itself without running
programs. The first sets cover **Level 1 and Level 2** checks for Linux
servers.

## 1. Sources and licences

- **ComplianceAsCode** (`ComplianceAsCode/content`, BSD-3-Clause) is the
  reference: its rule descriptions, check logic (OVAL) and remediation tell
  us what to collect and how to judge it. Rules we derive from it name it
  in `openvibes-rules/NOTICE` (BSD attribution).
- **CIS Benchmarks** text is CIS's own, not BSD. ComplianceAsCode's CIS
  profiles state that they "include Center for Internet Security® …
  CIS Benchmarks™ content". We do not copy CIS titles, wording, numbering
  or profile lists into our MIT rules, and we do not claim CIS compliance.
  We say "Level 1 / Level 2 (server)" in our own words.
- **Public references** we may cite: DISA STIG IDs and NIST SP 800-53
  controls (US government, public domain), which ComplianceAsCode also
  lists per rule.

## 2. Rule sets, quiet by default

| Set | Contents | Default |
|---|---|---|
| `hardening-linux-l1` | Checks a typical server should pass with no service impact: SSH, kernel network sysctls, permissions of key system files, password and login policy, unneeded services, core dumps | Published by Setup; on for every Linux agent |
| `hardening-linux-l2` | Stricter, possibly disruptive checks: auditd rules and settings, separate mounts and their options, kernel module blacklists, AppArmor/SELinux enforcing, tighter limits | Shipped and trusted, **off** until an admin turns it on (per asset group) |

- One set per OS family, as decided for the baseline: an agent loads only
  its own family's sets (enrollment writes them into `agent.toml`).
  Distribution differences (Fedora/RHEL vs Debian/Ubuntu paths, package
  names, PAM layout) are handled inside the rules through the `os.id`
  fact, not by more sets.
- Each rule carries ATT&CK pairs (P18) and severity: info/low for most
  hygiene items, medium/high only where the setting is directly
  exploitable (for example SSH root login with passwords).
- Ids: `harden.<area>.<setting>`, e.g. `harden.ssh.permit_root_login`.

## 3. Facts (protocol P19)

All facts are read by the agent with std file APIs (no `Command`, no
shells), bounded like every collector, and refreshed each scan. A fact the
agent could not read is **unavailable**, never "false": a rule over it
evaluates to `Unavailable` and raises no finding (existing behaviour).

| Fact (key shape) | Source | Type |
|---|---|---|
| `os.id`, `os.version_id` | `/etc/os-release` (already read for inventory) | string |
| `sshd.<keyword>` | `/etc/ssh/sshd_config` and its `Include`s, lowercase keyword, **first value wins** as sshd does; `Match` blocks counted in `sshd.match_blocks`, not merged | string |
| `sysctl.<name>` | `/proc/sys/...` for a fixed list of names (net.ipv4.*, kernel.*, fs.*) | string |
| `file.mode.<path>`, `file.owner.<path>` | `stat` of a fixed list of paths (`/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/ssh/sshd_config`, crontab files, `/boot/grub2/grub.cfg`, …) | octal string, `uid:gid` |
| `mount.options.<mountpoint>` | `/proc/self/mountinfo` for `/tmp`, `/var`, `/var/tmp`, `/var/log`, `/home`, `/dev/shm` | string list |
| `service.enabled`, `service.active` | systemd unit symlinks under `/etc/systemd/system/*.wants` and the running cgroup tree (as the services collector already does) | string list |
| `login_defs.<key>` | `/etc/login.defs` | string |
| `pam.pwquality.<key>`, `pam.faillock.<key>` | `/etc/security/pwquality.conf(.d)`, `faillock.conf` | string |
| `kernel.modules.loaded`, `modprobe.disabled` | `/proc/modules`; `install <m> /bin/false|true` and `blacklist` lines in `/etc/modprobe.d` | string list |
| `audit.rules.keys`, `auditd.<key>` (L2) | `/etc/audit/rules.d/*.rules`, `/etc/audit/auditd.conf` | string list, string |
| `lsm.selinux`, `lsm.apparmor` (L2) | `/sys/fs/selinux/enforce`, `/sys/module/apparmor/parameters/enabled` | string |

- The exact list, key syntax, value encoding and limits go into the
  protocol (P19) with fixtures; this table is the shape.
- The agent's fact allowlist grows; the rules repository gets a **new
  checker pin and allowlist for the hardening sets** at the first agent
  release that collects these facts (AGENTS.md: the baseline's pin stays
  at the oldest agent).

## 4. Privilege: root-only files

Some sources are readable only by root: `/etc/ssh/sshd_config` is `0600` on
Fedora/RHEL, `/etc/audit/*` and `/etc/security/faillock.conf` often too.
The agent runs unprivileged and must stay so.

**Rule (user, 2026-10-09): nobody ever types a command.** It works after
install, or it is a switch in the console. So no opt-in drop-in and no
host-side step.

Chosen: **a small root helper that the agent package installs and
enables** (`openvibes-agent-facts.service`, plus a timer):

- It reads only the fixed list of root-only sources from §3, parses them
  with the same code as the agent (a second binary from the same crates),
  and writes one bounded JSON file,
  `/run/openvibes-agent/root-facts.json`, mode `0640 root:openvibes_agent`.
  The agent reads it as one more collector and checks size, age and shape;
  a missing, stale or malformed file makes those facts unavailable.
- It takes **no input**: no network, no rules, no arguments, no config. The
  network-facing agent, which evaluates rules from the platform, never
  gains a capability.
- Locked down by systemd: `User=root` with
  `CapabilityBoundingSet=CAP_DAC_READ_SEARCH` only, `NoNewPrivileges=yes`,
  `PrivateNetwork=yes`, `ProtectSystem=strict` with
  `ReadWritePaths=/run/openvibes-agent`, `ProtectHome=yes`, no devices,
  `SystemCallFilter=@system-service`, `MemoryMax` and `RuntimeMaxSec`
  small.
- It runs at boot and then on the scan interval (timer), so facts are as
  fresh as a scan. `check-rpm.sh` and the systemd test check the unit's
  sandbox like the agent's.

**Port owners use the same helper (user, 2026-10-09).** Naming the program
behind a listening port (protocol P15 `owners`) today needs the opt-in
`owners.conf` drop-in, which gives the agent `CAP_DAC_READ_SEARCH` and
`CAP_SYS_PTRACE` and has to be installed by hand. That breaks the
no-commands rule, so the drop-in is retired:

- The helper also maps listening socket inodes (from `/proc/net/*`) to the
  owning process by reading `/proc/<pid>/fd` links, and writes
  `owners: [{protocol, address, port, exe, unit}]` into the same file;
  executable paths only, never command lines or environments. For this it
  also needs `CAP_SYS_PTRACE` in its bounding set (reading other users'
  fd links), still with no input and no network.
- The agent merges these owners into its P15 report and marks `owners`
  `complete` when the file is fresh, `partial` otherwise (as today without
  the drop-in). No protocol change.
- `owners.conf` and its docs are removed from the agent packages; an
  existing drop-in is left in place but no longer needed (the release
  note says it can go; the console never asks for it).
- Port owners ship first: the helper with only this collector is useful on
  its own and proves the unit, the sandbox and the file hand-off before
  the hardening facts arrive.

Rejected: an opt-in `CAP_DAC_READ_SEARCH` drop-in on the agent (a manual
step, and a capability on the network-facing process); package-set ACLs on
the files (changes the host's security settings).

**Console switches, not commands:** hardening L1 and L2 are turned on or off
per asset group on the console's rule-set pages; the platform writes the
choice into the agent configuration it serves. The host page shows
"Hardening: L1 on · L2 off" and, if the helper is missing or failing,
"Hardening facts unavailable" with the cause (as for alarms).

## 5. Rules repository

- `hardening/linux-l1/rules.json`, `hardening/linux-l2/rules.json`, each
  with cases (match / no_match / unavailable per rule, and per OS family
  where the rule branches on `os.id`), signed with the same offline key
  as their own rule sets, shipped in the `openvibes-rules-baseline` RPM.
- `NOTICE` with the ComplianceAsCode BSD attribution; no CIS text.
- First release: about 40 L1 rules (the highest-value checks), then L2.
  Growth by rule set versions, like the baseline.

## 6. Platform

- Setup and Update trust and publish both sets; L2 is published but not
  assigned.
- Enrollment and the agent configuration name the OS family's sets
  (L1 on by default; L2 when the host's asset group has it on), switched
  in the console only.
- Console: hardening results are compliance findings (existing pages),
  grouped by set; the Coverage page includes them; the host page shows
  "Hardening: L1 · L2 off" and the read-access hint when facts are
  unavailable for lack of privilege.

## 7. Order of work

1. Protocol P19: facts, encodings, limits, fixtures.
2. Agent, first: the root-facts helper with the port-owners collector,
   its unit and timer in every agent package, `owners.conf` removed
   (independent of the hardening rules; can ship in the next agent
   release).
3. Agent, then: collectors (sshd parser with includes, sysctl, stat list,
   mountinfo, login.defs, pwquality/faillock, modules, audit, LSM), the
   in the helper or the agent as §3 says, docs.
4. Rules: L1 set and cases, new checker pin; then L2.
5. Platform: Setup/Update publishing, per-group L1/L2 switches that reach
   agents without host-side steps, host page.

## 8. Out of scope

Windows and macOS hardening (their own sets and facts later); fixing
settings (the agent stays read-only); claiming CIS certification;
importing OpenSCAP/CIS-CAT results.
