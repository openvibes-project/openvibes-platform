#!/usr/bin/env bash
# Builds the appliance installer ISO: AlmaLinux 10's minimal ISO with the
# OpenVIBES kickstart and the AlmaLinux 10 offline kit added (mkksiso, from
# AlmaLinux's lorax). Run it as root in an almalinux:10 container started
# with --privileged, with network access to repo.almalinux.org.
# Usage: build-appliance-iso.sh KIT_TAR OUT_ISO
#   KIT_TAR  openvibes-platform-<v>-offline-el10.tar (signed)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ $# == 2 ]] || { echo "usage: $0 KIT_TAR OUT_ISO" >&2; exit 2; }
kit_tar=$(realpath "$1") out=$(realpath -m "$2")
[[ $(. /etc/os-release && echo "$ID:${VERSION_ID%%.*}") == almalinux:10 ]] || { echo "this is not an almalinux:10 container" >&2; exit 1; }

dnf -y install lorax xorriso syslinux isomd5sum gnupg2 curl tar >/dev/null
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# 1. AlmaLinux's minimal ISO, checked against the signed checksum list.
base=https://repo.almalinux.org/almalinux/10/isos/x86_64
iso=AlmaLinux-10-latest-x86_64-minimal.iso
curl -sSfo "$work/CHECKSUM" "$base/CHECKSUM"
export GNUPGHOME=$work/gnupg; mkdir -m 0700 "$GNUPGHOME"
gpg --batch --quiet --import /etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10
gpg --batch --verify "$work/CHECKSUM" 2>&1 | grep -q 'Good signature' || { echo "AlmaLinux's CHECKSUM is not signed by its key" >&2; exit 1; }
curl -sSfo "$work/$iso" "$base/$iso"
want=$(sed -n "s/^SHA256 ($iso) = //p" "$work/CHECKSUM")
[[ -n $want ]] || { echo "no checksum for $iso in AlmaLinux's CHECKSUM" >&2; exit 1; }
[[ $(sha256sum "$work/$iso" | cut -d ' ' -f1) == "$want" ]] || { echo "$iso does not match its checksum" >&2; exit 1; }

# 2. The kit: checked by its own installer logic later; here just unpacked.
mkdir "$work/kit"
tar -C "$work/kit" -xf "$kit_tar"
[[ -d $work/kit/openvibes-offline/packages ]] || { echo "$kit_tar has no openvibes-offline/packages" >&2; exit 1; }

# 3. The new ISO: the kickstart runs on its own and the kit sits on the disk.
mkksiso --ks "$ROOT/packaging/appliance/openvibes-appliance.ks" \
    --add "$work/kit/openvibes-offline" \
    "$work/$iso" "$out"
ls -l "$out"
