#!/usr/bin/env bash
# The appliance's package source (#546, #558), shared by the ISO
# (build-appliance-iso.sh) and the update file (build-appliance-update.sh,
# #673): the kit, checked, and the kickstart's packages resolved with it
# into one repository. Run it as root in an almalinux:10 container with
# network access to AlmaLinux's mirrors.
# Usage: appliance-repo.sh KIT_TAR WORK [EXTRA_DIR]
#   writes WORK/kit (the kit, unpacked), WORK/repo (the repository) and
#   WORK/keys (the keys the appliance checks it with)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ $# == 2 || $# == 3 ]] || { echo "usage: $0 KIT_TAR WORK [EXTRA_DIR]" >&2; exit 2; }
kit_tar=$(realpath "$1") work=$(realpath "$2") extra_dir=${3:+$(realpath "$3")}
dnf -y install tar gnupg2 createrepo_c >/dev/null

# 1. The kit, unpacked and checked (signature, checksums) before it goes on
# the disk: Anaconda installs from it without running the kit's installer.
mkdir "$work/kit"
tar -C "$work/kit" -xf "$kit_tar"
"$work/kit/openvibes-offline/install" --check
[[ -d $work/kit/openvibes-offline/packages ]] || { echo "$kit_tar has no openvibes-offline/packages" >&2; exit 1; }

# 2. The package repository: one consistent, current set of
# everything the installed system gets (#546). The kit carries only the
# updates its own packages pulled in (a newer systemd, but not systemd-udev),
# and the minimal ISO's older companions then conflict with them: Anaconda
# stopped at "Error checking software selection". Dropping the updates instead
# would install a known-vulnerable OpenSSL, sudo and glibc on hosts that may
# never reach a mirror. So the kickstart's %packages are resolved into an
# empty root against AlmaLinux's current repositories and the kit, and the
# whole result is the repository: every update comes with its companions,
# and the appliance starts fully updated.
# (dnf names an environment @name in an installroot, not @^name; the CI kit
# has no model package, as below.)
pkgs=$(sed -n '/^%packages/,/^%end/p' "$ROOT/packaging/appliance/openvibes-appliance.ks" | grep -vE '^(%|#|$)' | sed 's/^@\^/@/')
[[ -z ${OPENVIBES_ISO_TEST:-} ]] || pkgs=$(grep -vx openvibes-llm-model <<<"$pkgs")
# Anaconda installs more than %packages: the bootloader, the storage tools
# and kdump for the disk and machine it finds. Their current versions go in
# too, or the minimal ISO's older ones clash again (dracut-network, #546).
# Setup's optional packages (#558): not installed by the kickstart, but on
# the disk, so Setup adds them with no network: openvibes-fetch (internet
# lookups) and the agent ("Agent on this host").
extra=()
mkdir "$work/extra"
for name in openvibes-fetch openvibes-agent; do
    found=$(find "${extra_dir:-/nonexistent}" -maxdepth 1 -name "$name-[0-9]*.x86_64.rpm" 2>/dev/null | sort -V | tail -n 1 || true)
    if [[ -n $found ]]; then
        cp "$found" "$work/extra/"
        pkgs="$pkgs
$name"
    else
        echo "no $name package in ${extra_dir:-EXTRA_DIR}: the ISO has none; Setup needs the internet for it"
    fi
done
if compgen -G "$work/extra/*.rpm" > /dev/null; then
    createrepo_c -q "$work/extra"
    extra=(--repofrompath="openvibes-extra,$work/extra" --setopt=openvibes-extra.gpgcheck=0)
fi
pkgs="$pkgs
kernel grub2-efi-x64 grub2-pc grub2-tools shim-x64 efibootmgr lvm2 xfsprogs dosfstools mdadm cryptsetup device-mapper-multipath kdump-utils kexec-tools makedumpfile dracut-network"
# shellcheck disable=SC2086  # one word per package or group
dnf -y -q --installroot="$work/root" --releasever=10 --setopt=reposdir=/etc/yum.repos.d \
    --repofrompath="openvibes-kit,$work/kit/openvibes-offline/packages" --setopt=openvibes-kit.gpgcheck=0 \
    "${extra[@]}" install --downloadonly --destdir="$work/repo" $pkgs
createrepo_c -q "$work/repo"
echo "installer repository: $(find "$work/repo" -name '*.rpm' | wc -l) packages"
# The keys the appliance's package source is checked with (#558): the
# kit's (CI signs with a throwaway one), the project's (the agent), PGDG's.
mkdir "$work/keys"
cp "$work/kit/openvibes-offline/openvibes.gpg" "$work/keys/RPM-GPG-KEY-openvibes-appliance"
cp "$ROOT/packaging/rpm/openvibes-packages.gpg" "$work/keys/RPM-GPG-KEY-openvibes-appliance-packages"
cp "$work/kit/openvibes-offline/pgdg.gpg" "$work/keys/RPM-GPG-KEY-openvibes-appliance-pgdg"
