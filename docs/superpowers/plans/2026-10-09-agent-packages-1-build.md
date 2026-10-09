# Agent packages per distribution — Part A.1: build the .deb and Arch packages (agent repo, Tasks 1–3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every agent release ships a signed RPM, .deb and Arch package of the same binary, the website serves them as dnf, apt and pacman repositories, `install.sh --agent` installs on every supported system, and the lab installs real packages everywhere.

**Architecture:** The agent binary is built once (Fedora 44, as today). `.deb` and Arch packages wrap that binary with native tools in their own containers, and share the RPM's files and the `audit-setup` script. CI tests each format under systemd in containers of the supported systems. The website's publish job adds a flat apt repository and a pacman repository beside the dnf one, all signed with the OpenVIBES key. `install.sh` picks the package manager from `/etc/os-release`.

**Tech Stack:** bash/POSIX sh, rpmbuild, debhelper 13 / dpkg-buildpackage / lintian (Debian 12), makepkg / namcap (Arch), podman with systemd, GitHub Actions, gpg, createrepo_c, dpkg-scanpackages and repo-add (Fedora's `dpkg-dev` and `pacman` packages).

**Spec:** `openvibes-platform` `docs/specs/2026-10-09-offline-install-and-updates-design.md` §4 (Part A). Parts B–D have their own plans later.

## The three plan files

Part A is split by repository so each file stays under 500 lines: `2026-10-09-agent-packages-1-build.md`, `2026-10-09-agent-packages-2-test-release.md`, `2026-10-09-agent-packages-3-website-lab.md`. Task numbers run across all three. Global Constraints and Review Focus below are the same in each.

## Repositories and order

| Tasks | Repository | Branch | PR |
|---|---|---|---|
| 1–5 | openvibes-agent | `agent-packages` | one PR |
| 6–7 | openvibes-project.github.io | `agent-repos` | one PR, merged after the agent PR |
| 8 | openvibes-lab | `real-packages` | one PR, merged after an agent release with .deb/Arch is on the website |
| 9 | none (release check) | — | — |

Every repository: identity `itismelime` / `26064407+itismelime@users.noreply.github.com`; commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; run the workspace `testing.md` gate before each PR; the user merges.

## Global Constraints

- Supported: Debian 12+, Ubuntu 22.04+, Fedora 44, AlmaLinux and Rocky 9+, Arch. x86_64 only.
- One binary for all three formats; it must not need a glibc symbol version above **2.34**.
- Package contents identical across formats: `/usr/bin/openvibes-agent`; the unit `openvibes-agent.service`; sysusers `openvibes-agent.conf` (user `openvibes_agent`); `/etc/openvibes-agent/` 0750 root:openvibes_agent; `/etc/openvibes-agent/agent.toml` 0640 root:openvibes_agent, a configuration file kept across upgrades; `/usr/share/openvibes-agent/openvibes-agent.rules` 0644; `/usr/libexec/openvibes-agent/audit-setup` and `audit-fallback` 0755; `owners.conf` as documentation; the licence.
- After install or upgrade: `audit-setup apply`. Before erase: `audit-setup remove`. Scriptlets never fail the transaction (`|| :`).
- The service is installed, not enabled, not started; an upgrade restarts it only if it was running.
- Version scheme: release `X.Y.Z-1`; CI builds `X.Y.Z-1.1.ci<run>` (RPM, .deb) and `pkgrel=1.<run>` (Arch): above the published package, below the next version.
- Signing key: `710A D8AF B7AF E6E8 64C0 CDC4 E134 BAF3 7786 DA36` (rsa4096). RPM signed inside; Arch detached `.sig`; .deb unsigned, the apt repository's `InRelease` signed.
- Shared packaging files stay in `packaging/rpm/` (moving them would touch the spec, the checks and the platform's template detection for no gain).
- The platform itself stays Fedora 44 only.

## Review Focus

1. **Ubuntu 22.04's systemd (249) and the hardened unit.** A directive 249 does not know is silently ignored there, weakening the sandbox. Task 4's check runs `systemd-analyze verify` on each image and fails on "Unknown key"; if it fails on 22.04, stop and ask the user (raise the floor to 24.04, or accept and document).
2. **`audit-setup` under mawk** (Debian/Ubuntu default awk) — so far it only ran under gawk. Task 4 runs a fallback/remove round trip with `--root` on every image.
3. **An edited `agent.toml` across an upgrade** on .deb and Arch (conffile / `backup=`). Task 4 edits it before the upgrade and checks the edit is still there after.
4. **The Fedora 44 RPM on AlmaLinux 9** (rpm 4.16, older dnf): installs, its signature verifies against the OpenVIBES key. Task 4 runs the RPM on `almalinux:9`.
5. **A mixed PEM answer from a fake platform** (`TRUSTED CERTIFICATE` block next to the real CA): `install.sh` today checks one block and installs the whole file. Task 7 ports the lab's `canonical_ca` and tests it.

---

## Task 1: glibc floor check and a shared audit-fallback file (agent)

**Files:**
- Create: `scripts/check-glibc.sh`, `scripts/test-check-glibc.sh`, `packaging/rpm/audit-fallback`
- Modify: `packaging/rpm/openvibes-agent.spec` (install `audit-fallback` from the file instead of `printf`)

**Interfaces:**
- Produces: `scripts/check-glibc.sh BINARY MAX` (exit 0 if the highest `GLIBC_x.y` the binary needs is ≤ MAX, else 1 with `check-glibc: BINARY needs glibc N, above MAX`); `packaging/rpm/audit-fallback` (used by Tasks 2 and 3).

- [ ] **Step 1: Branch**

```bash
cd ~/Projects/OpenVIBES/openvibes-agent && git switch main && git pull --ff-only && git switch -c agent-packages
```

- [ ] **Step 2: Write the failing test** `scripts/test-check-glibc.sh`

```bash
#!/usr/bin/env bash
# Tests scripts/check-glibc.sh against this machine's bash: it needs some
# glibc 2.x, so a floor of 2.0 must fail and 99.0 must pass.
set -euo pipefail
cd "$(dirname "$0")/.."
bin=$(command -v bash)
bash scripts/check-glibc.sh "$bin" 99.0 >/dev/null || { echo "FAIL: 99.0 refused"; exit 1; }
if out=$(bash scripts/check-glibc.sh "$bin" 2.0 2>&1); then echo "FAIL: 2.0 accepted"; exit 1; fi
grep -q 'above 2.0' <<<"$out" || { echo "FAIL: message: $out"; exit 1; }
if bash scripts/check-glibc.sh /nonexistent 2.34 2>/dev/null; then echo "FAIL: missing file accepted"; exit 1; fi
echo "test-check-glibc: ok"
```

- [ ] **Step 3: Run it** — `bash scripts/test-check-glibc.sh`. Expected: fails (`scripts/check-glibc.sh: No such file`).

- [ ] **Step 4: Implement** `scripts/check-glibc.sh`

```bash
#!/usr/bin/env bash
# Fails if BINARY needs a glibc symbol version above MAX: the one agent
# binary goes into the RPM, .deb and Arch packages, and the oldest system
# supported (EL 9) has glibc 2.34 (offline install spec §4).
# Usage: scripts/check-glibc.sh BINARY MAX
set -euo pipefail
[[ $# == 2 && -f $1 ]] || { echo "usage: $0 BINARY MAX" >&2; exit 2; }
need=$(objdump -T "$1" | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sed 's/^GLIBC_//' | sort -Vu | tail -1)
[[ -n $need ]] || { echo "check-glibc: $1 needs no versioned glibc symbol" >&2; exit 1; }
if [[ $(printf '%s\n%s\n' "$need" "$2" | sort -V | tail -1) != "$2" ]]; then
    echo "check-glibc: $1 needs glibc $need, above $2" >&2; exit 1
fi
echo "check-glibc: $1 needs glibc $need (max $2)"
```

- [ ] **Step 5: Run it** — `bash scripts/test-check-glibc.sh`. Expected: `test-check-glibc: ok`.

- [ ] **Step 6: `audit-fallback` as a file.** Create `packaging/rpm/audit-fallback` (mode 0755) with exactly what the spec's `printf` writes today:

```sh
#!/bin/sh
# Sets up the kernel-audit fallback for threat alarms (see audit-setup).
exec /usr/libexec/openvibes-agent/audit-setup fallback "$@"
```

In `openvibes-agent.spec` replace the `printf … > …/audit-fallback` and `chmod` lines with:

```
install -D -m 0755 $S/packaging/rpm/audit-fallback %{buildroot}%{_libexecdir}/openvibes-agent/audit-fallback
```

- [ ] **Step 7: Verify the RPM is unchanged in content** — `bash scripts/build-rpm.sh && rpm2cpio target/rpm/RPMS/x86_64/openvibes-agent-*.rpm | cpio -i --to-stdout ./usr/libexec/openvibes-agent/audit-fallback`. Expected: the three lines above. Then `bash scripts/check-glibc.sh target/release/openvibes-agent 2.34`. Expected: `needs glibc 2.34 (max 2.34)`.

- [ ] **Step 8: Commit** — `git add scripts/check-glibc.sh scripts/test-check-glibc.sh packaging/rpm/audit-fallback packaging/rpm/openvibes-agent.spec && git commit -m "packaging: glibc 2.34 floor check; audit-fallback as a file"` (with the trailer).

## Task 2: the .deb (agent)

**Files:**
- Create: `packaging/debian/{control,rules,copyright,openvibes-agent.install,openvibes-agent.postinst,openvibes-agent.prerm,openvibes-agent.lintian-overrides,source/format}`, `scripts/build-deb.sh`

**Interfaces:**
- Consumes: `packaging/rpm/audit-fallback` (Task 1).
- Produces: `scripts/build-deb.sh BINARY [VERSION]` → prints the path `target/deb/openvibes-agent_<VERSION>-<OV_RELEASE>_amd64.deb`; env `OV_RELEASE` (default `1`). Runs on Debian 12 with `debhelper dpkg-dev lintian`.

- [ ] **Step 1: `packaging/debian/control`**

```
Source: openvibes-agent
Section: admin
Priority: optional
Maintainer: OpenVIBES <26064407+itismelime@users.noreply.github.com>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2
Homepage: https://github.com/openvibes-project/openvibes-agent
Rules-Requires-Root: no

Package: openvibes-agent
Architecture: amd64
Depends: ${misc:Depends}, libc6 (>= 2.34), libgcc-s1, coreutils, diffutils, gawk | mawk, grep, systemd
Description: OpenVIBES endpoint agent
 Collects host facts, evaluates signed rules, and delivers findings to the
 OpenVIBES platform over mTLS. Runs as the unprivileged openvibes_agent user.
```

`packaging/debian/source/format`: `3.0 (native)`.

- [ ] **Step 2: `packaging/debian/rules`** (mode 0755). The binary is prebuilt and identical to the RPM's, so build, test, strip and dwz are no-ops.

```make
#!/usr/bin/make -f
%:
	dh $@

override_dh_auto_build override_dh_auto_test override_dh_auto_clean override_dh_strip override_dh_dwz:

override_dh_installsystemd:
	dh_installsystemd --no-enable --no-start --no-restart-after-upgrade

override_dh_fixperms:
	dh_fixperms
	chmod 0750 debian/openvibes-agent/etc/openvibes-agent
	chmod 0640 debian/openvibes-agent/etc/openvibes-agent/agent.toml
	chmod 0755 debian/openvibes-agent/usr/libexec/openvibes-agent/audit-setup debian/openvibes-agent/usr/libexec/openvibes-agent/audit-fallback
```

- [ ] **Step 3: `packaging/debian/openvibes-agent.install`** (paths in the staging tree `build-deb.sh` makes):

```
openvibes-agent usr/bin
files/openvibes-agent.conf usr/lib/sysusers.d
files/agent.toml etc/openvibes-agent
files/openvibes-agent.rules usr/share/openvibes-agent
files/audit-setup usr/libexec/openvibes-agent
files/audit-fallback usr/libexec/openvibes-agent
files/owners.conf usr/share/doc/openvibes-agent
```

- [ ] **Step 4: maintainer scripts** (mode 0755).

`openvibes-agent.postinst`:

```sh
#!/bin/sh
# The agent user, its group on the configuration, then the audit fallback
# decision (the same audit-setup the RPM's %posttrans runs). On an upgrade
# ($2 set) a running agent is restarted; a stopped one stays stopped.
set -e
if [ "$1" = configure ]; then
    systemd-sysusers openvibes-agent.conf
    chown root:openvibes_agent /etc/openvibes-agent /etc/openvibes-agent/agent.toml
    /usr/libexec/openvibes-agent/audit-setup apply || :
    if [ -n "$2" ]; then systemctl try-restart openvibes-agent.service || :; fi
fi
#DEBHELPER#
```

`openvibes-agent.prerm`:

```sh
#!/bin/sh
# Package removal: give the host its audit rules back while audit-setup exists.
set -e
if [ "$1" = remove ]; then
    systemctl stop openvibes-agent.service 2>/dev/null || :
    /usr/libexec/openvibes-agent/audit-setup remove || :
fi
#DEBHELPER#
```

- [ ] **Step 5: `packaging/debian/copyright`** (machine-readable, MIT):

```
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: openvibes-agent
Source: https://github.com/openvibes-project/openvibes-agent

Files: *
Copyright: 2026 The OpenVIBES contributors
License: MIT
```

followed by a `License: MIT` paragraph holding the text of `LICENSE`, each line indented by one space and blank lines written as ` .`.

- [ ] **Step 6: `scripts/build-deb.sh`**

```bash
#!/usr/bin/env bash
# Builds target/deb/openvibes-agent_<version>-<release>_amd64.deb around a
# release binary, the same one the RPM carries (offline install spec §4).
# Usage: scripts/build-deb.sh BINARY [VERSION]; OV_RELEASE is the Debian
# revision (default 1; CI sets 1.1.ci<run>). Needs debhelper, dpkg-dev, lintian.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# -ge 1 && -f $1 ]] || { echo "usage: $0 BINARY [VERSION]" >&2; exit 2; }
bin=$(realpath "$1")
version=${2:-$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)}
release=${OV_RELEASE:-1}
W=target/deb/src
rm -rf target/deb; mkdir -p "$W/files"
cp -r packaging/debian "$W/debian"
cp packaging/rpm/openvibes-agent.service "$W/debian/openvibes-agent.service"
install -m 0755 "$bin" "$W/openvibes-agent"
cp packaging/rpm/{agent.toml,openvibes-agent.rules,audit-setup,audit-fallback,owners.conf} "$W/files/"
cp packaging/rpm/openvibes-agent.sysusers "$W/files/openvibes-agent.conf"
cat > "$W/debian/changelog" <<EOF
openvibes-agent ($version-$release) unstable; urgency=medium

  * Release $version.

 -- OpenVIBES <26064407+itismelime@users.noreply.github.com>  $(date -R)
EOF
(cd "$W" && dpkg-buildpackage -b -us -uc >&2)
deb=$(ls target/deb/openvibes-agent_"$version-$release"_amd64.deb)
lintian --fail-on error --suppress-tags-from-file packaging/debian/openvibes-agent.lintian-overrides "$deb" >&2
echo "$deb"
```

`packaging/debian/openvibes-agent.lintian-overrides` starts empty except for a comment line; add a tag only with a one-line reason after reading lintian's output in Step 7 (expected candidates: `no-manual-page`, `unstripped-binary-or-object` because the binary is deliberately the RPM's).

- [ ] **Step 7: Build in Debian 12**

```bash
cargo build --release --locked -p openvibes-agent
podman run --rm -v "$PWD:/src:z" -w /src debian:12 bash -c \
  'apt-get update -q && apt-get install -y -q debhelper dpkg-dev lintian >/dev/null && bash scripts/build-deb.sh target/release/openvibes-agent'
```

Expected: last line `target/deb/openvibes-agent_<version>-1_amd64.deb`, lintian exit 0. Then `dpkg-deb -c target/deb/*.deb` lists every path in Global Constraints with the modes given there, and `dpkg-deb -I` shows `etc/openvibes-agent/agent.toml` under conffiles (`dpkg-deb -e … && cat DEBIAN/conffiles`).

- [ ] **Step 8: Commit** — `git add packaging/debian scripts/build-deb.sh && git commit -m "packaging: Debian package of the release binary"`.

## Task 3: the Arch package (agent)

**Files:**
- Create: `packaging/arch/PKGBUILD`, `packaging/arch/openvibes-agent.install`, `scripts/build-arch.sh`

**Interfaces:**
- Consumes: `packaging/rpm/audit-fallback` (Task 1).
- Produces: `scripts/build-arch.sh BINARY [VERSION]` → prints `target/arch/openvibes-agent-<VERSION>-<PKGREL>-x86_64.pkg.tar.zst`; env `OV_PKGREL` (default `1`). Runs as root in `archlinux:base-devel` (it drops to a build user for makepkg).

- [ ] **Step 1: `packaging/arch/PKGBUILD`** (version and pkgrel from the build script's environment)

```bash
# Built by scripts/build-arch.sh around the release binary (the RPM's).
pkgname=openvibes-agent
pkgver=${OV_VERSION:?}
pkgrel=${OV_PKGREL:-1}
pkgdesc='OpenVIBES endpoint agent'
arch=(x86_64)
url='https://github.com/openvibes-project/openvibes-agent'
license=(MIT)
depends=(glibc gcc-libs systemd coreutils diffutils gawk grep)
backup=(etc/openvibes-agent/agent.toml)
install=openvibes-agent.install
options=(!strip !debug)
source=(openvibes-agent openvibes-agent.service openvibes-agent.sysusers agent.toml
        openvibes-agent.rules audit-setup audit-fallback owners.conf LICENSE)
sha256sums=(SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP)

package() {
    install -Dm0755 openvibes-agent "$pkgdir/usr/bin/openvibes-agent"
    install -Dm0644 openvibes-agent.service "$pkgdir/usr/lib/systemd/system/openvibes-agent.service"
    install -Dm0644 openvibes-agent.sysusers "$pkgdir/usr/lib/sysusers.d/openvibes-agent.conf"
    install -dm0750 "$pkgdir/etc/openvibes-agent"
    install -Dm0640 agent.toml "$pkgdir/etc/openvibes-agent/agent.toml"
    install -Dm0644 openvibes-agent.rules "$pkgdir/usr/share/openvibes-agent/openvibes-agent.rules"
    install -Dm0755 audit-setup "$pkgdir/usr/libexec/openvibes-agent/audit-setup"
    install -Dm0755 audit-fallback "$pkgdir/usr/libexec/openvibes-agent/audit-fallback"
    install -Dm0644 owners.conf "$pkgdir/usr/share/doc/openvibes-agent/owners.conf"
    install -Dm0644 LICENSE "$pkgdir/usr/share/licenses/openvibes-agent/LICENSE"
}
```

(`SKIP`: the sources are local files the build script just copied; the release binary's integrity is the release's SHA256SUMS.)

- [ ] **Step 2: `packaging/arch/openvibes-agent.install`**

```sh
# pacman runs these; the sysusers hook runs only after the transaction, so
# the user is created here first (its group owns the configuration).
post_install() {
    systemd-sysusers openvibes-agent.conf
    chown root:openvibes_agent /etc/openvibes-agent /etc/openvibes-agent/agent.toml
    /usr/libexec/openvibes-agent/audit-setup apply || :
}
post_upgrade() {
    post_install
    systemctl try-restart openvibes-agent.service || :
}
pre_remove() {
    systemctl disable --now openvibes-agent.service 2>/dev/null || :
    /usr/libexec/openvibes-agent/audit-setup remove || :
}
```

- [ ] **Step 3: `scripts/build-arch.sh`**

```bash
#!/usr/bin/env bash
# Builds target/arch/openvibes-agent-<version>-<pkgrel>-x86_64.pkg.tar.zst
# around a release binary, the same one the RPM carries (offline install
# spec §4). Usage (as root in archlinux:base-devel):
#   scripts/build-arch.sh BINARY [VERSION]; OV_PKGREL (default 1; CI 1.<run>).
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# -ge 1 && -f $1 ]] || { echo "usage: $0 BINARY [VERSION]" >&2; exit 2; }
version=${2:-$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)}
W=target/arch
rm -rf "$W"; mkdir -p "$W"
install -m 0755 "$1" "$W/openvibes-agent"
cp packaging/arch/PKGBUILD packaging/arch/openvibes-agent.install LICENSE "$W/"
cp packaging/rpm/{openvibes-agent.service,openvibes-agent.sysusers,agent.toml,openvibes-agent.rules,audit-setup,audit-fallback,owners.conf} "$W/"
id builder >/dev/null 2>&1 || useradd -m builder
chown -R builder "$W"
runuser -u builder -- env OV_VERSION="$version" OV_PKGREL="${OV_PKGREL:-1}" \
    bash -c "cd '$W' && makepkg --force --nodeps --noconfirm" >&2
pkg=$(ls "$W"/openvibes-agent-"$version"-*-x86_64.pkg.tar.zst)
namcap "$pkg" >&2
echo "$pkg"
```

- [ ] **Step 4: Build in Arch**

```bash
podman run --rm -v "$PWD:/src:z" -w /src archlinux:base-devel bash -c \
  'pacman -Syu --noconfirm --needed namcap >/dev/null && bash scripts/build-arch.sh target/release/openvibes-agent'
```

Expected: last line the package path. Read namcap's output: an `E:` line is a defect to fix; `W:` lines are recorded in the PR body with a reason. `bsdtar -tvf <pkg>` shows the Global Constraints paths and modes; `.BUILDINFO`/`.PKGINFO` show `backup = etc/openvibes-agent/agent.toml`.

- [ ] **Step 5: Commit** — `git add packaging/arch scripts/build-arch.sh && git commit -m "packaging: Arch package of the release binary"`.
