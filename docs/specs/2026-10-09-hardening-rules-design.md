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

## 4. Privilege: root-only files (decision needed)

Some sources are readable only by root: `/etc/ssh/sshd_config` is `0600` on
Fedora/RHEL, `/etc/audit/*` and `/etc/security/faillock.conf` often too.
The agent runs unprivileged. Options:

- **A (recommended): an opt-in drop-in**, as for port owners (decision
  2026-10-01): a documented `hardening.conf` drop-in that grants only
  `CAP_DAC_READ_SEARCH`. Without it, those facts are unavailable and the
  host page says "Hardening checks need read access: install the
  drop-in" with the command. Everything else (sysctls, file modes via
  `stat`, mounts, services, login.defs on most systems) works without it.
- B: the package grants the agent's group read access to the few files
  (ACLs set at install). Changes host security settings; against "never
  mutate audited host state".
- C: a tiny root helper that reads the fixed list and hands facts to the
  agent. A second privileged component to maintain and secure.

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
  (L1 always; L2 when the host's asset group has it on).
- Console: hardening results are compliance findings (existing pages),
  grouped by set; the Coverage page includes them; the host page shows
  "Hardening: L1 · L2 off" and the read-access hint when facts are
  unavailable for lack of privilege.

## 7. Order of work

1. Protocol P19: facts, encodings, limits, fixtures.
2. Agent: collectors (sshd parser with includes, sysctl, stat list,
   mountinfo, login.defs, pwquality/faillock, modules, audit, LSM), the
   opt-in drop-in if option A, docs.
3. Rules: L1 set and cases, new checker pin; then L2.
4. Platform: Setup/Update publishing, per-group L2 assignment, host page.

## 8. Out of scope

Windows and macOS hardening (their own sets and facts later); fixing
settings (the agent stays read-only); claiming CIS certification;
importing OpenSCAP/CIS-CAT results.
