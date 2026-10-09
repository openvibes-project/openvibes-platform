# Agent packages, offline install and updates through the console

Date: 2026-10-09. Design session with the user (install experience, Part D
of `docs/superpowers/plans/2026-10-08-install-experience.md`). Spans
openvibes-agent, openvibes-platform, openvibes-protocol and the website.

## 1. Goal

Every agent install and update goes through the console, whatever the
network looks like. Five modes, all required (user):

1. **Air-gapped, upload:** an admin uploads a release to the platform; hosts
   install and update from it.
2. **Air-gapped, fetch from the console:** hosts install or update from the
   platform (one-line command, or their package manager).
3. **Air-gapped, one click:** an operator clicks "Update" in the console and
   the agent on that host is updated.
4. **Air-gapped, existing tooling:** the console makes an install package
   that Ansible, MECM or similar push out.
5. **Internet:** the console fetches the latest release from the internet
   and distributes it to the agents.

Success: a Debian, Ubuntu, Fedora, AlmaLinux/Rocky or Arch host with no
internet access gets the agent, enrolls, and is later updated, in each of
the five modes, without anyone copying files by hand beyond mode 1's upload
and mode 4's push.

## 2. Decisions (user, 2026-10-09)

- The platform may have internet or not: **support both** (fetch releases
  itself, or accept an uploaded release bundle).
- The per-platform **settings file is TOML**.
- **.deb and Arch packages are built with native tools** (`debian/` with
  `dpkg-buildpackage`, a `PKGBUILD` with `makepkg`); the RPM keeps its spec.
- One-click updates use a **small root updater** next to the unprivileged
  agent, off by default.
- The **distribution service** serves the package repositories (no new
  port).
- **No anonymous downloads** (user): agents roaming on the internet need the
  distribution port reachable from the internet, so the repositories must
  not serve anyone who asks. Enrolled hosts use their client certificate;
  a new host uses its enrollment token, once.
- Earlier (`decisions.md`, 2026-10-08): one installer script, one settings
  file per platform, one native signed package per distribution; the
  console offers one archive per distribution; the one-line command fetches
  the same pieces from the platform.

## 3. Overview

| Part | Repository | Delivers | Modes |
|---|---|---|---|
| A. Packages per distribution | agent, website | RPM, .deb, Arch package per release; `install.sh --agent` on every supported system | groundwork |
| B. Agent-package store | platform, protocol | releases fetched or uploaded, verified, approved, served as repositories | 1, 2, 5 |
| C. Installer, settings, archive | agent, platform | `openvibes-agent-install`, `openvibes-settings.toml`, per-distribution archives, platform-local one-line command | 1, 2, 4 |
| D. One-click update | agent, platform, protocol | approve in the console, root updater installs | 3 |

Built in that order; each part is useful on its own. Each gets its own
implementation plan.

## 4. Part A: packages per distribution

**Contents**, the same as today's RPM in every format: the binary, the
hardened systemd unit (eBPF capabilities), the `sysusers` file for
`openvibes_agent`, `agent.toml` as configuration (`conffiles` on Debian,
`backup=()` on Arch: upgrades keep host edits), the audit-rule template,
`audit-setup`, `audit-fallback`, licence and docs.

**One binary for all.** The agent built on Fedora 44 needs glibc 2.34 and
only `libc`, `libm`, `libgcc_s` (checked 2026-10-09). Every supported
system has glibc 2.34 or newer (Debian 12: 2.36, Ubuntu 22.04: 2.35,
EL 9: 2.34), so all three packages carry the same release binary. A CI
check fails the build if the binary ever needs a glibc above 2.34.

**Install scripts.** All three formats call the same `audit-setup`:

| Moment | RPM (today) | Debian | Arch |
|---|---|---|---|
| After install or upgrade: eBPF or audit fallback | `%posttrans`: `audit-setup apply` | `postinst configure` | `post_install`, `post_upgrade` |
| Agent user | sysusers | `dh_installsysusers` | sysusers hook |
| Service | installed, not started | `dh_installsystemd --no-enable --no-start` | installed, not started |
| Erase: give back the host's audit rules | `%preun`: `audit-setup remove` | `prerm remove` | `pre_remove` |

auditd is usually absent on Debian and Ubuntu; eBPF hosts do not need it,
and on a fallback host `audit-setup` already says how to load the rules.

**Signing.** RPM: signed inside, as today. Arch: a detached `.sig` per
package. Debian: unsigned packages by convention; trust comes from the
signed repository `Release` file. All with the OpenVIBES release key
(`710A D8AF B7AF E6E8 64C0 CDC4 E134 BAF3 7786 DA36`).

**Release assets.** The three packages, their signatures, `SHA256SUMS`,
the installer (Part C), and the release bundle (Part B):
`openvibes-agent-<version>-bundle.tar`.

**Website.** The package repository grows from one `dnf` repository to
`dnf`, `apt` and `pacman`, same key. `install.sh --agent` detects the
system (`/etc/os-release`), adds the matching repository and key, and
installs with `dnf`, `apt` or `pacman`; once Part C exists it hands over to
`openvibes-agent-install` (one copy of the install logic). The lab's
`guest/agent-generic.sh` stand-in is deleted; the lab installs real packages
everywhere.

**Supported:** Debian 12+, Ubuntu 22.04+, Fedora (current releases),
AlmaLinux and Rocky 9+, Arch. x86_64 only.

**Testing.** CI builds the .deb in a Debian 12 container and the Arch
package in an Arch container, runs `lintian` and `namcap`, and installs,
upgrades and erases each under systemd in its own container (the checks the
RPM test already makes). Before the release, the lab runs `lab alarms` on
Debian, Ubuntu and Arch from the real packages.

## 5. Part B: the agent-package store

**Getting releases.**
- *Online (mode 5):* the console's "Check for updates" (and an optional
  daily check, off by default) fetches the latest agent release from
  GitHub: the release bundle.
- *Offline (modes 1–4):* an admin uploads the release bundle in the console.

The **release bundle** is one tar per agent release: the three packages,
their signatures, `SHA256SUMS`, a detached signature of `SHA256SUMS`, and
the installer. The platform accepts a bundle only if the `SHA256SUMS`
signature verifies against the OpenVIBES release key the platform ships
with, every file matches its sum, and the version is well formed. Anything
else is rejected whole, with the reason shown.

**Storing.** Packages on the platform's disk
(`/var/lib/openvibes/agent-packages/<version>/`, a few MB per version); the
database records the versions held, when and how each arrived, and which is
**approved** (globally, and per group for Part D). The last 5 versions are
kept, the approved ones never removed; older ones are deleted.

**Serving.** The distribution service serves, for the approved version,
signed repository metadata built by the platform:
- `dnf`: `repodata/` (`repomd.xml` signed);
- `apt`: `dists/openvibes/` with a signed `InRelease`;
- `pacman`: `openvibes.db` with its `.sig`.

The metadata is signed with a **platform repository key** the platform
generates at setup (the platform cannot hold the release key). Hosts trust
two things: the release key for the packages themselves (RPM, Arch) and the
platform repository key for the metadata (all three; for .deb it is the
only signature). The installer installs both.

**Access.** Never anonymous:
- *Enrolled hosts:* their agent client certificate (the identity that
  already fetches rule bundles). `dnf` (`sslclientcert`/`sslclientkey`) and
  `apt` (`Acquire::https::<host>::SslCert`/`SslKey`) support it natively;
  for `pacman` the installer sets `XferCommand` to `curl` with the
  certificate. A revoked host gets 403.
- *A new host, first install only:* HTTP Basic with the enrollment token as
  password, accepted only for the installer and the package files, and only
  while the token is valid (the same lifetime and use count enrollment
  checks).
- Anything else: 401.

**Console page "Agent packages".** Versions held (verified, source, date),
the approved version, how many hosts run each version, "Check for updates",
"Upload release bundle", "Approve for all hosts / for a group". When the
platform is reachable from the internet, the page names the port agents
need and that it is authenticated.

**Protocol.** The repository paths, their authentication, and the
release-bundle layout are written in `openvibes-protocol` first.

## 6. Part C: installer, settings file, archive

**`openvibes-agent-install`**, POSIX sh, in the agent repository, released
with the agent and part of the release bundle.

1. Reads `openvibes-settings.toml` (fixed-shape parser: known keys only,
   anything else is an error).
2. Detects the system; installs or upgrades the agent from the archive's
   package, or from the platform's repository (token authentication).
3. Writes `agent.toml`, `platform-ca.crt`, the token file (0600), and the
   repository configuration with both keys.
4. Starts the agent, waits up to 60 s for "enrolled", then switches the
   repository configuration to the agent's client certificate and deletes
   the token file.
5. With `--auto-update` (or `auto_update = true` in the settings), enables
   the updater (Part D).

For automation: non-interactive, idempotent (a second run upgrades if a
newer package is there, otherwise changes nothing), leaves an existing
configuration alone unless `--reconfigure`. Exit codes: 0 done or already
current, 2 bad usage or settings, 3 enrolled with another platform, 4
package install failed, 5 not enrolled within 60 s, 6 unsupported system.

**`openvibes-settings.toml`**, made by the console per platform:

```toml
platform_url      = "https://platform.example.com"
ingest_port       = 18423
distribution_port = 18424
enrollment_token  = "…"      # secret
auto_update       = false
root_ca = """
-----BEGIN CERTIFICATE-----
…
-----END CERTIFICATE-----"""
repo_key = """…"""           # the platform repository key (public)

[[rule_sets]]                # baseline and baseline-alarms, with trusted keys
```

The installer checks `root_ca` the way `install.sh` does today (exactly one
certificate, canonicalised).

**Archive** `openvibes-agent-<distribution>-<version>.tar`, one per package
format (`rpm`, `deb`, `arch`), downloaded from the console (Enrollment →
Add a host → Download for offline install):

```
openvibes-agent-install
openvibes-settings.toml    (secret: holds the token)
packages/<the signed package for that format>
SHA256SUMS
```

Mode 1: copy, unpack, `sudo ./openvibes-agent-install`. Mode 4: Ansible or
MECM copy and run the same archive; the console shows a ready-to-paste
Ansible task. The installer checks `SHA256SUMS`; `rpm` and `pacman` verify
the package signatures too. The token in an archive follows the console's
token rules (lifetime, uses).

**One-line command (mode 2)**, copied by the console's "Copy CLI install".
Nothing comes from the internet; the platform serves the installer with
the settings built in, and the command pins its hash:

```sh
curl -fsSk -u enroll:<token> https://platform:18424/v1/agent/install -o /tmp/ova && echo "<sha256>  /tmp/ova" | sha256sum -c - && sudo sh /tmp/ova
```

`-k` is safe here because the hash check, not TLS, authenticates the file.
The website's `install.sh --agent` stays for internet hosts.

## 7. Part D: one-click update

1. An operator approves version X for a host, a group, or all hosts.
2. The heartbeat reply (protocol change, made in `openvibes-protocol`
   first) gains `agent_update: {version}` for hosts whose approved version
   differs from what they run.
3. The agent writes only that version string to
   `/var/lib/openvibes-agent/update-request`. It installs nothing.
4. A systemd path unit starts `openvibes-agent-updater` (one-shot, root,
   otherwise sandboxed). It accepts only a strictly formed version, refuses
   one older than the installed version unless the request is marked as an
   approved downgrade, installs exactly `openvibes-agent` at that version
   from the platform's repository with signature checking, and writes the
   outcome (version, ok or error) to `/var/lib/openvibes-agent-updater/result`
   (root-written, agent-readable).
5. The upgrade restarts the agent; its next health report carries the
   outcome; the console shows per host: updated, failed (reason), waiting.

**Safety.** Off by default; enabled only with root on the host
(`--auto-update` or the settings file). A compromised platform can choose
among genuinely signed OpenVIBES versions, nothing else; downgrades need an
explicit approval the console marks as such. The agent's privileges and
sandbox do not change.

Hosts without the updater still get the approved version through their own
package updates; the console shows "auto-update off" and the command to
turn it on.

## 8. Testing (all parts)

- Agent: package builds and container install/upgrade/erase per format;
  installer unit tests (settings parser, refusals, exit codes, idempotence);
  updater unit tests (version validation, the exact command per package
  manager, downgrade floor).
- Protocol: fixtures for the repository authentication, the release bundle
  layout, and the heartbeat `agent_update` field.
- Platform: bundle verification (good bundle, bad signature, mismatched
  sum, malformed version); repository metadata per format checked by the
  real `dnf`, `apt` and `pacman` in containers; access (certificate, token
  once, anonymous 401, revoked 403).
- End to end, per format in containers: archive install, mode 2 install,
  approve then update (Part D).
- Lab before release: offline install on Debian, Ubuntu, Fedora, AlmaLinux
  and Arch with the VMs' internet cut off.

## 9. Out of scope

Windows and macOS agents; ARM; Debian 11 and older, Ubuntu 20.04 and older,
EL 8; the platform itself on other distributions (separate roadmap item);
staged or percentage rollouts beyond host/group approval; delta updates.
