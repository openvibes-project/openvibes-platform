# Agent packages per distribution — Part A.2: install tests, CI and release (agent repo, Tasks 4–5)

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

## Task 4: install tests on every supported system (agent)

**Files:**
- Create: `scripts/check-package.sh`, `scripts/pkg-test.sh`
- Modify: `scripts/systemd-test.sh` (copy and run `check-package.sh` instead of `check-rpm.sh`)
- Delete: `scripts/check-rpm.sh` (folded into `check-package.sh`)

**Interfaces:**
- Consumes: packages from Tasks 2–3 and `scripts/build-rpm.sh`.
- Produces: `scripts/check-package.sh` (run as root inside an installed system; detects rpm/dpkg/pacman); `scripts/pkg-test.sh IMAGE DIR` where DIR holds the BASE and NEXT packages of the format IMAGE uses (`*.rpm`, `*.deb`, or `*.pkg.tar.zst`), BASE = workspace version, NEXT = next patch.

- [ ] **Step 1: `scripts/check-package.sh`** — `check-rpm.sh`'s checks, with the package-manager queries behind three helpers:

```bash
#!/usr/bin/env bash
# Static checks of an installed openvibes-agent package, any format (run as root).
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_stat() { # PATH MODE OWNER:GROUP
    [[ "$(stat -c '%a %U:%G' "$1")" == "$2 $3" ]] || fail "$1 is $(stat -c '%a %U:%G' "$1"), want $2 $3"
}
if command -v rpm >/dev/null && rpm -q openvibes-agent >/dev/null 2>&1; then
    pkg_files() { rpm -ql openvibes-agent; }
    is_conffile() { rpm -q --qf '[%{FILENAMES} %{FILEFLAGS:fflags}\n]' openvibes-agent | grep -qx "$1 cn"; }
elif command -v dpkg-query >/dev/null && dpkg-query -W openvibes-agent >/dev/null 2>&1; then
    pkg_files() { dpkg-query -L openvibes-agent; }
    is_conffile() { dpkg-query -W -f='${Conffiles}\n' openvibes-agent | awk '{print $1}' | grep -qx "$1"; }
else
    pkg_files() { pacman -Qlq openvibes-agent; }
    is_conffile() { pacman -Qii openvibes-agent | grep -qE "^(MODIFIED|UNMODIFIED|MISSING)[[:space:]]+$1\$"; }
fi
UNIT=$(systemctl show -P FragmentPath openvibes-agent)
[[ -n $UNIT ]] || fail "systemd does not know openvibes-agent.service"
getent passwd openvibes_agent >/dev/null || fail "no user openvibes_agent"
expect_stat /etc/openvibes-agent 750 root:openvibes_agent
expect_stat /etc/openvibes-agent/agent.toml 640 root:openvibes_agent
is_conffile /etc/openvibes-agent/agent.toml || fail "agent.toml is not a configuration file of the package"
expect_stat /usr/share/openvibes-agent/openvibes-agent.rules 644 root:root
expect_stat /usr/libexec/openvibes-agent/audit-setup 755 root:root
expect_stat /usr/libexec/openvibes-agent/audit-fallback 755 root:root
! pkg_files | grep -qx /etc/audit/rules.d/openvibes-agent.rules ||
    fail "the package must not own /etc/audit/rules.d/openvibes-agent.rules (eBPF hosts get no audit rule)"
# Fails on a directive this systemd does not know: it would be ignored, and the sandbox weaker.
out=$(systemd-analyze verify "$UNIT" 2>&1) || fail "unit verification: $out"
! grep -qi 'unknown key\|unknown lvalue' <<<"$out" || fail "this systemd ignores part of the unit: $out"
pkg_files | grep -qx /usr/share/doc/openvibes-agent/owners.conf || fail "owners.conf is not shipped"
[[ ! -e /etc/systemd/system/openvibes-agent.service.d/owners.conf ]] || fail "owners.conf is enabled"
! grep -q 'CAP_SYS_PTRACE\|CAP_DAC_READ_SEARCH' "$UNIT" || fail "the unit grants an owner capability"
for forbidden in ProtectProc=invisible ProcSubset=pid PrivateNetwork=yes PrivateUsers=yes ProtectHostname=yes; do
    ! grep -q "^$forbidden" "$UNIT" || fail "unit sets $forbidden"
done
# --offline exists from systemd 252; the unit is the same file everywhere,
# and the Fedora test enforces the score.
if exposure=$(systemd-analyze security --offline=true "$UNIT" 2>/dev/null | sed -n 's/.*exposure level for openvibes-agent.service: \([0-9.]*\).*/\1/p') && [[ -n $exposure ]]; then
    awk -v e="$exposure" 'BEGIN { exit !(e <= 2.5) }' || fail "exposure $exposure > 2.5"
    echo "exposure: $exposure"
else
    echo "exposure: not measured (systemd $(systemctl --version | awk 'NR==1{print $2}'))"
fi
[[ "$(systemctl is-enabled openvibes-agent 2>/dev/null || true)" == disabled ]] || fail "service not disabled after install"
status=0; /usr/bin/openvibes-agent >/dev/null 2>&1 || status=$?
((status == 2)) || fail "openvibes-agent without arguments exited $status, want 2 (usage)"
# audit-setup under this system's awk (mawk on Debian/Ubuntu): a fallback and its undo in a scratch root.
r=$(mktemp -d); mkdir -p "$r/etc/audit/rules.d"
/usr/libexec/openvibes-agent/audit-setup fallback --root "$r" >/dev/null
[[ -f $r/etc/audit/rules.d/openvibes-agent.rules ]] || fail "audit-setup fallback wrote no rule"
/usr/libexec/openvibes-agent/audit-setup remove --root "$r" >/dev/null
[[ ! -e $r/etc/audit/rules.d/openvibes-agent.rules ]] || fail "audit-setup remove left the rule"
rm -rf "$r"
[[ $(/usr/libexec/openvibes-agent/audit-setup decide) =~ ^(ebpf|fallback)$ ]] || fail "audit-setup decide"
echo "check-package: ok"
```

Before relying on the fallback round trip, read `audit-setup`'s `fallback`/`remove` code paths and confirm `--root DIR` with an empty `etc/audit/rules.d` is enough; if it needs `/etc/audit/rules.d/audit.rules` to exist under the root, create an empty one in the check.

- [ ] **Step 2: switch the Fedora test** — in `scripts/systemd-test.sh` replace `check-rpm.sh` with `check-package.sh` (the `cp` and the `bash /test/check-rpm.sh` call), `git rm scripts/check-rpm.sh`, and run `bash scripts/systemd-test.sh`. Expected: passes as before, printing `check-package: ok`.

- [ ] **Step 3: `scripts/pkg-test.sh`**

```bash
#!/usr/bin/env bash
# One package format on one system, under a real systemd (podman): install,
# static checks (check-package.sh), an edited agent.toml kept across an
# upgrade to NEXT, then erase. Usage: scripts/pkg-test.sh IMAGE DIR, DIR
# holding the BASE and NEXT packages of IMAGE's format.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ $# == 2 ]] || { echo "usage: $0 IMAGE DIR" >&2; exit 2; }
IMAGE=$1 DIR=$(realpath "$2")
PODMAN=${PODMAN:-podman}
C=ov-pkg-test
fail() { echo "FAIL ($IMAGE): $*" >&2; exit 1; }
ok() { echo "ok ($IMAGE): $*"; }
in_c() { "$PODMAN" exec "$C" bash -c "$1"; }
BASE=$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml")
NEXT=${BASE%.*}.$((${BASE##*.} + 1))
case $IMAGE in
    debian:*|ubuntu:*)
        prep='apt-get update -q && apt-get install -y -q systemd dbus procps >/dev/null'
        base=$(ls "$DIR"/openvibes-agent_"$BASE"-*_amd64.deb) next=$(ls "$DIR"/openvibes-agent_"$NEXT"-*_amd64.deb)
        install() { echo "apt-get install -y -q /pkgs/$(basename "$1")"; }
        version='dpkg-query -W -f="\${Version}" openvibes-agent'
        erase='apt-get remove -y -q openvibes-agent' gone='! dpkg-query -W -f="\${Status}" openvibes-agent 2>/dev/null | grep -q "^install ok installed"' ;;
    archlinux*)
        prep='pacman -Syu --noconfirm --needed procps-ng >/dev/null'
        base=$(ls "$DIR"/openvibes-agent-"$BASE"-*-x86_64.pkg.tar.zst) next=$(ls "$DIR"/openvibes-agent-"$NEXT"-*-x86_64.pkg.tar.zst)
        install() { echo "pacman -U --noconfirm /pkgs/$(basename "$1")"; }
        version="pacman -Q openvibes-agent | awk '{print \$2}'"
        erase='pacman -R --noconfirm openvibes-agent' gone='! pacman -Q openvibes-agent 2>/dev/null' ;;
    *almalinux*|*rockylinux*|*fedora*)
        prep='dnf -q -y install systemd procps-ng >/dev/null'
        base=$(ls "$DIR"/openvibes-agent-"$BASE"-*.x86_64.rpm) next=$(ls "$DIR"/openvibes-agent-"$NEXT"-*.x86_64.rpm)
        install() { echo "dnf -q -y install /pkgs/$(basename "$1")"; }
        version="rpm -q --qf '%{VERSION}-%{RELEASE}' openvibes-agent"
        erase='dnf -q -y remove openvibes-agent' gone='! rpm -q openvibes-agent' ;;
    *) fail "no package format for $IMAGE" ;;
esac
cleanup() { local s=$?; ((s == 0)) || "$PODMAN" exec "$C" journalctl --no-pager -n 40 2>/dev/null || true; "$PODMAN" rm -f "$C" >/dev/null 2>&1 || true; exit "$s"; }
trap cleanup EXIT
"$PODMAN" rm -f "$C" >/dev/null 2>&1 || true
"$PODMAN" run -d --systemd=always --privileged --name "$C" -v "$DIR:/pkgs:ro,z" -v "$ROOT/scripts:/scripts:ro,z" \
    "$IMAGE" bash -c "$prep && exec /usr/lib/systemd/systemd" >/dev/null
for _ in $(seq 120); do in_c 'systemctl is-system-running 2>/dev/null | grep -qE "running|degraded"' && break; sleep 1; done
in_c 'systemctl is-system-running 2>/dev/null | grep -qE "running|degraded"' || fail "systemd did not come up"
in_c "$(install "$base")" >/dev/null || fail "install $BASE"
in_c 'bash /scripts/check-package.sh' || fail "static checks"
ok "installed $BASE, static checks pass"
in_c 'echo "# kept across upgrades" >> /etc/openvibes-agent/agent.toml'
in_c "$(install "$next")" >/dev/null || fail "upgrade to $NEXT"
[[ $(in_c "$version") == "$NEXT"-* ]] || fail "not at $NEXT after the upgrade"
in_c 'grep -qx "# kept across upgrades" /etc/openvibes-agent/agent.toml' || fail "the upgrade lost an edit to agent.toml"
in_c 'bash /scripts/check-package.sh' >/dev/null || fail "static checks after the upgrade"
ok "upgraded to $NEXT, agent.toml edit kept"
in_c "$erase" >/dev/null || fail "erase"
in_c "$gone" || fail "still installed after erase"
in_c '[ ! -e /etc/audit/rules.d/openvibes-agent.rules ]' || fail "erase left the audit rule"
ok "erased"
```

CI packages are unsigned. `dnf install` of a local file does not check signatures by default (`localpkg_gpgcheck=0`), and `apt`/`pacman -U` of a local file do not either, so the test installs them as they are. The signature on EL 9 is checked once against the released package (Task 9).

- [ ] **Step 4: run each locally** (packages from Tasks 2–3 built at BASE and NEXT: `OV_RELEASE=1 build-deb.sh BIN` and `build-deb.sh BIN $NEXT`, the same for Arch and `OV_VERSION=$NEXT build-rpm.sh`; collect them into `target/pkgs/{deb,arch,rpm}`):

```bash
for i in debian:12 ubuntu:22.04; do bash scripts/pkg-test.sh $i target/pkgs/deb; done
bash scripts/pkg-test.sh archlinux:latest target/pkgs/arch
bash scripts/pkg-test.sh almalinux:9 target/pkgs/rpm
```

Expected: three `ok` lines per image. Run them one at a time (memory rule). If Ubuntu 22.04 fails on "this systemd ignores part of the unit", stop and ask the user (Review Focus 1).

- [ ] **Step 5: Commit** — `git add -A scripts && git commit -m "packaging: install, upgrade and erase tests for every supported system"`.

## Task 5: CI, release and docs (agent)

**Files:**
- Modify: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `docs/components/packaging.md`, `README.md` (install section, if it says Fedora only)

**Interfaces:**
- Consumes: `check-glibc.sh`, `build-deb.sh`, `build-arch.sh`, `pkg-test.sh`.
- Produces: CI artifacts `agent-rpms` (now also holds `openvibes-agent`, the binary), `agent-debs`, `agent-arch`; release assets `openvibes-agent-X.Y.Z-1.fc44.x86_64.rpm`, `openvibes-agent_X.Y.Z-1_amd64.deb`, `openvibes-agent-X.Y.Z-1-x86_64.pkg.tar.zst` and `.sig`, `SHA256SUMS` over all of them. The website (Task 6) and lab (Task 8) consume these names.

- [ ] **Step 1: CI.** In the `rpm` job, after the build step, add `bash scripts/test-check-glibc.sh` and `bash scripts/check-glibc.sh target/release/openvibes-agent 2.34`, and copy `target/release/openvibes-agent` into `dist/`. Add jobs (actions pinned to the same SHAs the file already uses):

```yaml
  deb:
    name: Debian package (debian:12)
    needs: rpm
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    container: debian:12
    steps:
      - name: Install build packages
        run: apt-get update -q && apt-get install -y -q git debhelper dpkg-dev lintian
      - name: Checkout repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Download the binary
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: agent-rpms
          path: rpms
      - name: Build BASE and NEXT
        env:
          OV_RELEASE: 1.1.ci${{ github.run_number }}
        run: |
          base=$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)
          mkdir dist
          cp "$(bash scripts/build-deb.sh rpms/openvibes-agent)" dist/
          cp "$(bash scripts/build-deb.sh rpms/openvibes-agent "${base%.*}.$((${base##*.} + 1))")" dist/
      - name: Upload
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: agent-debs
          path: dist/
          if-no-files-found: error

  arch:
    name: Arch package (archlinux:base-devel)
    needs: rpm
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    container: archlinux:base-devel
    steps:
      - name: Install build packages
        run: pacman -Syu --noconfirm --needed git namcap
      - name: Checkout repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Download the binary
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: agent-rpms
          path: rpms
      - name: Build BASE and NEXT
        env:
          OV_PKGREL: 1.${{ github.run_number }}
        run: |
          base=$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)
          mkdir dist
          cp "$(bash scripts/build-arch.sh rpms/openvibes-agent)" dist/
          cp "$(bash scripts/build-arch.sh rpms/openvibes-agent "${base%.*}.$((${base##*.} + 1))")" dist/
      - name: Upload
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: agent-arch
          path: dist/
          if-no-files-found: error

  packages:
    name: Install, upgrade, erase (${{ matrix.image }})
    needs: [rpm, deb, arch]
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    strategy:
      fail-fast: false
      matrix:
        include:
          - { image: "debian:12", artifact: agent-debs }
          - { image: "ubuntu:22.04", artifact: agent-debs }
          - { image: "archlinux:latest", artifact: agent-arch }
          - { image: "almalinux:9", artifact: agent-rpms }
    steps:
      - name: Checkout repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Download packages
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: ${{ matrix.artifact }}
          path: pkgs
      - name: Install, upgrade, erase
        run: bash scripts/pkg-test.sh "${{ matrix.image }}" pkgs
```

`build-arch.sh` runs `rm -rf target/arch` each call, so the BASE package is copied to `dist/` before the NEXT build (as written). The same holds for `build-deb.sh` and `target/deb`.

- [ ] **Step 2: Release.** Split `release.yml` into four jobs, keeping every existing step:
  - `build` (fedora:44, as today up to "Build the RPM"; adds the glibc check; uploads `dist/` with the unsigned RPM and the binary as artifact `release-rpm`);
  - `deb` (debian:12; `build-deb.sh` at the tag version, `OV_RELEASE=1`; artifact `release-deb`);
  - `arch` (archlinux:base-devel; `build-arch.sh`, `OV_PKGREL=1`; artifact `release-arch`);
  - `publish` (fedora:44, `needs: [build, deb, arch]`): downloads all three into `dist/`, deletes the bare binary from `dist/`, runs `sign-rpms.sh` as today, signs the Arch package, writes `SHA256SUMS`, publishes as today.

Arch signing, in `publish` after `sign-rpms.sh`:

```bash
export GNUPGHOME=$(mktemp -d)
printf '%s' "$RPM_SIGNING_KEY" | gpg --batch --quiet --import
printf '%s' "$RPM_SIGNING_PASSPHRASE" > "$GNUPGHOME/pass"
for p in dist/*.pkg.tar.zst; do
    gpg --batch --pinentry-mode loopback --passphrase-file "$GNUPGHOME/pass" --detach-sign --output "$p.sig" "$p"
    gpg --batch --verify "$p.sig" "$p"
done
rm -rf "$GNUPGHOME"
(cd dist && sha256sum *.rpm *.deb *.pkg.tar.zst *.sig > SHA256SUMS)
```

- [ ] **Step 3: Docs.** `docs/components/packaging.md`: a "Formats" section (the three packages, built from one binary, where each file comes from, the scripts per format and the table from spec §4), "How to test" (`pkg-test.sh` per image, `check-glibc.sh`), and the version scheme per format.

- [ ] **Step 4: Gate and PR.** Run the `testing.md` gate for the agent plus every Task 4 image locally, push `agent-packages`, open the PR (body: what ships, namcap/lintian warnings kept and why, AI disclosure, the Claude Code line). Expected CI: every job green, including the four `packages` matrix jobs.
