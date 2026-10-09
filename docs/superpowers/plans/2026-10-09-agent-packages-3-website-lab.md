# Agent packages per distribution — Part A.3: website repositories, install.sh and the lab (Tasks 6–9)

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

## Task 6: apt and pacman repositories on the website

**Files:**
- Modify: `scripts/collect.sh`, `scripts/build-repo.sh`, `tests/test-build-repo.sh`, `.github/workflows/publish.yml`, `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: Task 5's release asset names.
- Produces (site layout, used by Task 7): `deb/` — a flat apt repository: `*.deb`, `Packages`, `Packages.gz`, `Release`, `InRelease` (clear-signed); `arch/x86_64/` — `*.pkg.tar.zst` + `.sig`, `openvibes.db` and `openvibes.db.sig` (plain files, no symlinks); `rpm/fedora/44/x86_64/` unchanged. `collect.sh SITE` (the site root, no longer the rpm folder).

- [ ] **Step 1: Branch** — `cd ~/Projects/OpenVIBES/openvibes-project.github.io && git switch main && git pull --ff-only && git switch -c agent-repos`.

- [ ] **Step 2: Failing tests** in `tests/test-build-repo.sh`: build a minimal .deb (`dpkg-deb --build` of a tree with `DEBIAN/control`: `Package: one`, `Version: 1`, `Architecture: amd64`, `Maintainer: t`, `Description: t`) into `$T/site1/deb/`, and a minimal Arch package (`bsdtar -cf - .PKGINFO usr | zstd > one-1-1-x86_64.pkg.tar.zst` with a `.PKGINFO` holding `pkgname = one`, `pkgver = 1-1`, `arch = x86_64`) signed with the test key into `$T/site1/arch/x86_64/`. Then assert:

```bash
gpg --batch --verify "$T/site1/deb/InRelease" 2>/dev/null || { echo "FAIL: InRelease does not verify"; exit 1; }
grep -q '^Package: one$' "$T/site1/deb/Packages" || { echo "FAIL: deb not indexed"; exit 1; }
sha=$(sha256sum "$T/site1/deb/Packages" | cut -d' ' -f1)
grep -q " $sha .* Packages\$" "$T/site1/deb/Release" || { echo "FAIL: Release does not hash Packages"; exit 1; }
gpg --batch --verify "$T/site1/arch/x86_64/openvibes.db.sig" "$T/site1/arch/x86_64/openvibes.db" 2>/dev/null ||
    { echo "FAIL: openvibes.db.sig does not verify"; exit 1; }
[[ ! -L $T/site1/arch/x86_64/openvibes.db ]] || { echo "FAIL: openvibes.db is a symlink"; exit 1; }
```

and a refusal case: an Arch package without a `.sig` (or with a `.sig` from another key) stops the build, like an unsigned RPM. Run `bash tests/test-build-repo.sh`. Expected: FAIL (no InRelease).

- [ ] **Step 3: `build-repo.sh`** — after the RPM part, add:

```bash
# apt: a flat repository (deb URL ./), its Release hashed and clear-signed.
deb=$site/deb
if compgen -G "$deb/*.deb" >/dev/null; then
    (cd "$deb" && dpkg-scanpackages --multiversion . /dev/null > Packages 2>/dev/null && gzip -9kf Packages)
    {
        echo "Origin: OpenVIBES"; echo "Label: OpenVIBES"; echo "Architectures: amd64"
        echo "Date: $(LC_ALL=C date -Ru)"; echo "SHA256:"
        for f in Packages Packages.gz; do printf ' %s %s %s\n' "$(sha256sum "$deb/$f" | cut -d' ' -f1)" "$(stat -c %s "$deb/$f")" "$f"; done
    } > "$deb/Release"
    gpg --batch --yes --pinentry-mode loopback --passphrase-file "$T/pass" --clearsign --output "$deb/InRelease" "$deb/Release"
fi
# pacman: every package signed by PUBKEY, the database built and signed.
arch=$site/arch/x86_64
if compgen -G "$arch/*.pkg.tar.zst" >/dev/null; then
    gpg --batch --quiet --import "$pubkey"
    for p in "$arch"/*.pkg.tar.zst; do
        gpg --batch --verify "$p.sig" "$p" 2>/dev/null || { echo "build-repo: $p is not signed with the OpenVIBES key" >&2; exit 1; }
    done
    (cd "$arch" && rm -f openvibes.db* openvibes.files* && repo-add -q openvibes.db.tar.gz ./*.pkg.tar.zst)
    for f in openvibes.db openvibes.files; do cp --remove-destination "$arch/$f.tar.gz" "$arch/$f"; done
    gpg --batch --yes --pinentry-mode loopback --passphrase-file "$T/pass" --detach-sign --output "$arch/openvibes.db.sig" "$arch/openvibes.db"
fi
```

The import of `$pubkey` into the signing keyring is what makes `--verify` check against the OpenVIBES key only (the keyring holds nothing else). The `.deb` files have no signature of their own; they come from the agent's GitHub releases, the same trust the collect step already has, and the signed `InRelease` covers them from there on.

- [ ] **Step 4: `collect.sh SITE`** — per release, list assets and download only the kinds present (old releases have no .deb, and `gh release download -p` fails when nothing matches):

```bash
#!/usr/bin/env bash
# Downloads the packages of every published (non-draft) release of
# openvibes-platform, openvibes-agent and openvibes-rules into SITE's
# repositories: RPMs to rpm/fedora/44/x86_64, .debs to deb, Arch packages
# and their signatures to arch/x86_64. Needs GH_TOKEN.
set -euo pipefail
[[ $# == 1 ]] || { echo "usage: $0 SITE" >&2; exit 2; }
site=$1
declare -A dest=([rpm]=$site/rpm/fedora/44/x86_64 [deb]=$site/deb [arch]=$site/arch/x86_64)
mkdir -p "${dest[@]}"
for repo in openvibes-platform openvibes-agent openvibes-rules; do
    gh release list -R "openvibes-project/$repo" --limit 1000 --json tagName,isDraft \
        --jq '.[] | select(.isDraft | not) | .tagName' |
        while read -r tag; do
            gh release view "$tag" -R "openvibes-project/$repo" --json assets --jq '.assets[].name' |
                while read -r a; do
                    case $a in
                        *.rpm) d=${dest[rpm]} ;;
                        *.deb) d=${dest[deb]} ;;
                        *.pkg.tar.zst|*.pkg.tar.zst.sig) d=${dest[arch]} ;;
                        *) continue ;;
                    esac
                    [[ -f $d/$a ]] || gh release download "$tag" -R "openvibes-project/$repo" -p "$a" -D "$d"
                done
        done
done
echo "collect: $(find "$site" -name '*.rpm' | wc -l) RPMs, $(find "$site" -name '*.deb' | wc -l) debs, $(find "$site" -name '*.pkg.tar.zst' | wc -l) Arch packages"
```

In `publish.yml`: `dnf -q -y install git gh createrepo_c rpm gnupg2 dpkg-dev pacman bsdtar zstd` and `bash scripts/collect.sh site`. In `ci.yml` add the same packages to the ShellCheck job.

- [ ] **Step 5: Run** — `bash tests/test-build-repo.sh` (in a fedora:44 container with those packages if the host lacks them). Expected: `test-build-repo: all checks passed`. `shellcheck install.sh scripts/*.sh tests/*.sh` clean.

- [ ] **Step 6: Commit** — `git commit -am "Publish apt and pacman repositories beside the dnf one"`.

## Task 7: `install.sh --agent` on every supported system

**Files:**
- Modify: `install.sh`, `tests/install-e2e.sh`, `.github/workflows/ci.yml`, `packages.html`, `index.html` ("Runs on today" agents line; roadmap drops "Debian, Ubuntu and Arch agent packages")
- Create: `tests/test-install-ca.sh`

**Interfaces:**
- Consumes: Task 6's site layout.
- Produces: `install.sh --agent …` (flags unchanged) on Fedora 44, AlmaLinux/Rocky 9+, Debian 12+, Ubuntu 22.04+, Arch; platform mode Fedora 44 only. Hidden test entry `install.sh --canonical-ca IN OUT` (prints the SHA-256 of the DER).

- [ ] **Step 1: Failing CA test** — `tests/test-install-ca.sh`: the lab's `tests/test_agent_ca.sh` with `g=install.sh` and plain `fail` helpers (real certificate kept and its fingerprint printed; a `TRUSTED CERTIFICATE` block next to it never reaches the output; two certificates refused). Run it. Expected: FAIL (`--canonical-ca` unknown → usage).

- [ ] **Step 2: Port `canonical_ca`** from `openvibes-lab/guest/agent-generic.sh` (lines 10–26, the function and its comment) into `install.sh` after `say()`, add `if [ "${1:-}" = --canonical-ca ]; then [ $# = 3 ] || usage; canonical_ca "$2" "$3"; exit 0; fi` before the argument loop, and replace the fingerprint computation and the `install … ca.pem` with the canonical file:

```sh
ca=$(canonical_ca "$tmp/ca.pem" "$tmp/ca-trusted.pem") || exit 1
[ "$ca" = "$fp" ] || die "the platform's CA has fingerprint $ca, not the expected $fp"
curl -fsS --cacert "$tmp/ca-trusted.pem" --max-time 10 "$url/v1/ca" -o /dev/null ||
    die "the server at $url does not hold a certificate from that CA"
…
install -m 0644 "$tmp/ca-trusted.pem" "$AGENT_DIR/platform-ca.crt"
```

Run `tests/test-install-ca.sh`. Expected: ok lines. (`base64 -w` is GNU coreutils: on every supported system.)

- [ ] **Step 3: System detection.** Replace the Fedora-44-only check with:

```sh
# shellcheck source=/dev/null
os_id=$(. /etc/os-release && printf %s "$ID")
# shellcheck source=/dev/null
os_version=$(. /etc/os-release && printf %s "${VERSION_ID:-}")
major=${os_version%%.*}
case $os_id in
    fedora) [ "$os_version" = 44 ] && family=rpm ;;
    almalinux|rocky) [ "${major:-0}" -ge 9 ] 2>/dev/null && family=rpm ;;
    debian) [ "${major:-0}" -ge 12 ] 2>/dev/null && family=deb ;;
    ubuntu) [ "${major:-0}" -ge 22 ] 2>/dev/null && family=deb ;;
    arch) family=arch ;;
esac
[ "$(uname -m)" = x86_64 ] && [ -n "${family:-}" ] ||
    die "OpenVIBES agent packages are for Fedora 44, AlmaLinux and Rocky 9+, Debian 12+, Ubuntu 22.04+ and Arch on x86_64 (this is $os_id $os_version $(uname -m))"
[ "$mode" = agent ] || { [ "$os_id" = fedora ] && [ "$os_version" = 44 ]; } ||
    die "the OpenVIBES platform is for Fedora 44 on x86_64 (this is $os_id $os_version)"
```

- [ ] **Step 4: Repository per family.** Turn the repository block and `install_package` into `case $family`:
  - **rpm:** as today. On AlmaLinux/Rocky the `baseurl` is `$SITE/rpm/fedora/44/x86_64/` (the agent RPM is the same file for every rpm system; `$releasever` would be 9 or 10). Comment it with `# ponytail: EL reads the Fedora 44 folder; give the agent its own rpm folder if the RPMs ever differ.`
  - **deb:** `command -v gpg >/dev/null || { apt-get update -q >/dev/null && apt-get install -y -q gnupg >/dev/null; } || die "could not install gnupg"`; the fingerprint check as today; `install -D -m 0644 "$tmp/openvibes.gpg" /etc/apt/keyrings/openvibes.asc`; the list file `deb [signed-by=/etc/apt/keyrings/openvibes.asc] $SITE/deb ./` written to `/etc/apt/sources.list.d/openvibes.list` with the same "exists and differs → die" rule as `openvibes.repo`; `apt-get update -q -o Dir::Etc::sourcelist=sources.list.d/openvibes.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0`; `install_package` runs `DEBIAN_FRONTEND=noninteractive apt-get install -y "$1"`.
  - **arch:** fingerprint check as today; `pacman-key --add "$tmp/openvibes.gpg" && pacman-key --lsign-key "$KEY_FINGERPRINT"`; append to `/etc/pacman.conf` only when `^\[openvibes\]` is absent:

```sh
printf '\n[openvibes]\nSigLevel = Required DatabaseRequired\nServer = %s/arch/$arch\n' "$SITE" >> /etc/pacman.conf
```

    `install_package` runs `pacman -Sy --noconfirm --needed "$1"` (comment: `# ponytail: -Sy without -u; the agent needs only glibc, gcc-libs and systemd, already current on a maintained host.`).

  The `-a task,never` warning further down stays as it is: it only reads files and works on every system.

- [ ] **Step 5: End to end.** In `tests/install-e2e.sh`: the repository container builds `deb/` and `arch/x86_64/` too (with the CI `agent-debs` and `agent-arch` artifacts and the throwaway key, by running `scripts/build-repo.sh` itself rather than its own copy of the steps); step 2 enrolls agents in `debian:12`, `ubuntu:22.04`, `archlinux:latest` and `almalinux:9` containers with the platform's line, each checked to report `enrolled as` and fetch the baseline rule set (the existing `agent` checks); refusals: `debian` becomes `debian:11` ("are for Fedora 44, AlmaLinux…"), and platform mode on `debian:12` is refused ("the OpenVIBES platform is for Fedora 44"). In `ci.yml` the end-to-end job downloads `agent-debs` and `agent-arch` from the agent's latest main CI run beside `agent-rpms`. Run it locally one container set at a time. Expected: every `ok` line, no FAIL.

- [ ] **Step 6: Pages.** `packages.html`: per-system repository lines (dnf `.repo`, apt `sources.list.d` line with `signed-by`, pacman.conf block) and the key check. `index.html` "Runs on today": `Agents: Fedora 44, AlmaLinux and Rocky 9+, Debian 12+, Ubuntu 22.04+, Arch (x86_64)`; roadmap: drop the packages item. `bash tests/check-site.sh` ok.

- [ ] **Step 7: Gate and PR** — testing.md gate, ShellCheck, `test-build-repo.sh`, `test-install-ca.sh`, `install-e2e.sh`; PR "Agent packages for Debian, Ubuntu, AlmaLinux, Rocky and Arch" stating it must merge after the agent release that ships them (until then the new repositories are empty and only Fedora installs work).

## Task 8: the lab installs real packages everywhere

**Files:**
- Modify: `lib/install.sh` (`install_agent`, delete `agent_payload`), `lib/selftest.sh` (comment), `README.md`
- Delete: `guest/agent-generic.sh`, `tests/test_agent_args.sh`, `tests/test_agent_ca.sh` (the CA test now lives in the website, Task 7)
- Test: `tests/test_install_agent.sh` (new)

**Interfaces:**
- Consumes: the website's install line on every system (Task 7), release assets (Task 5).
- Produces: `install_agent NAME [SOURCE]` unchanged in signature; `/etc/openvibes-lab-installed` reads `agent <version>` on every system.

- [ ] **Step 1: Branch** — `cd ~/Projects/OpenVIBES/openvibes-lab && git switch main && git pull --ff-only && git switch -c real-packages`.

- [ ] **Step 2: Failing test** `tests/test_install_agent.sh`: with `lab_ssh`, `lab_scp`, `agent_line`, `wait_for` and `state_get` stubbed to record their arguments, check that
  - `install_agent debian repo` runs the install line on debian and copies nothing;
  - `install_agent debian dir:$D` (D holding `openvibes-agent_1.2.3-1.1.ci9_amd64.deb`, `openvibes-agent-1.2.3-1.1.ci9.fc44.x86_64.rpm`, `openvibes-agent-1.2.3-1.9-x86_64.pkg.tar.zst`) copies only the .deb, installs it with `apt-get install -y /tmp/<deb>`, then runs the install line;
  - the same for `arch` (`pacman -U --noconfirm`) and `alma` (`dnf -y install`);
  - `install_agent ubuntu dir:$D` with no .deb in D dies with `no .deb for ubuntu in`.

Run `bash tests/run.sh`. Expected: the new test FAILS.

- [ ] **Step 3: Implement** — replace the `else` branch of `install_agent` and delete `agent_payload`:

```bash
# pkg_kind NAME: the package format of a lab machine.
pkg_kind() { case $1 in debian|ubuntu) echo deb ;; arch) echo arch ;; *) echo rpm ;; esac; }

install_agent() { # NAME [SOURCE]
    local n=$1 src=${2:-$(state_get source)} line args dir pkg kind v
    src=${src:-repo}
    [[ $n != platform ]] || die "the platform machine gets its agent from Setup"
    if [[ $n == windows ]]; then install_windows_agent "$src"; return; fi
    line=$(agent_line) || die "could not get the install line from platform (is it installed?)"
    args=${line#*sudo sh -s -- }
    install_args_ok "$args" || die "unexpected install line from platform: $line"
    kind=$(pkg_kind "$n")
    dir=$(source_dir "$src") || exit 1
    if [[ -n $dir ]]; then
        # A package folder (--from, --version): that package first; the install line
        # then finds it installed and only configures and enrolls.
        case $kind in
            deb) pkg=$(find "$dir" -maxdepth 1 -name 'openvibes-agent_*_amd64.deb' | sort -V | tail -1) ;;
            arch) pkg=$(find "$dir" -maxdepth 1 -name 'openvibes-agent-[0-9]*-x86_64.pkg.tar.zst' | sort -V | tail -1) ;;
            rpm) pkg=$(find "$dir" -maxdepth 1 -name 'openvibes-agent-[0-9]*.x86_64.rpm' | sort -V | tail -1) ;;
        esac
        [[ -n $pkg ]] || die "no .$kind for $n in $dir"
        lab_scp "$pkg" "$n:/tmp/"
        case $kind in
            deb) lab_ssh "$n" "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y /tmp/$(basename "$pkg")" >&2 ;;
            arch) lab_ssh "$n" "sudo pacman -U --noconfirm /tmp/$(basename "$pkg")" >&2 ;;
            rpm) lab_ssh "$n" "sudo dnf -y install /tmp/$(basename "$pkg")" >&2 ;;
        esac || die "could not install $(basename "$pkg") on $n"
    fi
    log "installing the agent on $n with the real install line"
    lab_ssh "$n" "$line" >&2
    case $kind in
        deb) v=$(lab_ssh "$n" "dpkg-query -W -f='\${Version}' openvibes-agent") ;;
        arch) v=$(lab_ssh "$n" "pacman -Q openvibes-agent | cut -d' ' -f2") ;;
        rpm) v=$(lab_ssh "$n" "rpm -q --qf '%{VERSION}' openvibes-agent") ;;
    esac
    v=${v%%-*}
    safe_word "$v" || die "unexpected agent version on $n: $v"
    lab_ssh "$n" "echo 'agent $v' | sudo tee /etc/openvibes-lab-installed >/dev/null"
    wait_for "$n enrolls" 120 lab_ssh "$n" 'sudo journalctl -u openvibes-agent -o cat | grep -q "enrolled as"' ||
        die "the agent on $n did not enroll (lab ssh $n sudo journalctl -u openvibes-agent)"
}
```

A released package from `version:` sources is signed (RPM, Arch) and checked by the guest's own package manager once the install line has added the key; for a `dir:` .deb (a CI build) there is no signature, as with `--from` today (`setup_source_flags` already allows unsigned local packages only for `dir:`). Then `git rm guest/agent-generic.sh tests/test_agent_args.sh tests/test_agent_ca.sh`, drop the payload mention from `lib/selftest.sh`'s comment and the README ("the agent payload"), and `host_keyring`/`rpm_signed` if nothing else uses them (`grep -n` first).

- [ ] **Step 4: Run** — `bash tests/run.sh` all PASS; `shellcheck -x lab lib/*.sh guest/*.sh tests/*.sh` clean.

- [ ] **Step 5: Commit and PR** — after an agent release with the new formats is live on the website: in the `ovlab` tmux session (user attached), `sg libvirt -c './lab up'` with every Linux machine, each enrolls; then the PR, noting the run.

## Task 9: release check (no code)

After the agent PR merges and before the website PR merges:

- [ ] Download the merged main's `agent-debs`, `agent-arch` and `agent-rpms` CI artifacts into one folder; in the `ovlab` tmux session (user attached): `sg libvirt -c './lab alarms --from DIR'` (Task 8 merged by then, or on its branch). Expected: Debian, Ubuntu and Arch raise the exec alarm within seconds, as in `results/2026-10-08-alarms-ebpf.md`.
- [ ] Cut the agent release (`scripts/release.sh`); check the release has the five assets plus `SHA256SUMS` and that `rpm -K` of the RPM verifies on `almalinux:9` with the OpenVIBES key imported.
- [ ] Merge the website PR; after Publish, run the website's one-line agent install on a fresh Debian 12 and Arch lab machine (Task 8's `lab up`).
- [ ] `status.md`: Part A done; next plan Part B.
