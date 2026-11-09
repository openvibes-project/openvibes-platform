#!/usr/bin/env bash
# Builds the appliance installer ISO: AlmaLinux 10's minimal ISO with the
# OpenVIBES kickstart and the AlmaLinux 10 offline kit added. xorriso does it
# directly (the ISO's EFI boot image is a hidden partition that lorax's
# mkksiso 40 cannot carry over: xorriso refuses its boot image #2). Run it as
# root in an almalinux:10 container, with network access to
# repo.almalinux.org.
# Usage: build-appliance-iso.sh KIT_TAR OUT_ISO
#   KIT_TAR  openvibes-platform-<v>-offline-el10.tar (signed)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ $# == 2 ]] || { echo "usage: $0 KIT_TAR OUT_ISO" >&2; exit 2; }
kit_tar=$(realpath "$1") out=$(realpath -m "$2")
[[ $(. /etc/os-release && echo "$ID:${VERSION_ID%%.*}") == almalinux:10 ]] || { echo "this is not an almalinux:10 container" >&2; exit 1; }

dnf -y install xorriso mtools isomd5sum gnupg2 curl tar >/dev/null
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

# 2. The kit, unpacked and checked (signature, checksums) before it goes on
# the disk: Anaconda installs from it without running the kit's installer.
mkdir "$work/kit"
tar -C "$work/kit" -xf "$kit_tar"
"$work/kit/openvibes-offline/install" --check
[[ -d $work/kit/openvibes-offline/packages ]] || { echo "$kit_tar has no openvibes-offline/packages" >&2; exit 1; }

# 3. The new ISO. The kickstart is found by its place on the disk; the
# kernel lines of both boot menus (and the copy inside the EFI boot image)
# name it.
label=$(xorriso -indev "$work/$iso" -pvd_info 2>&1 | sed -n "s/^Volume Id *: *//p")
[[ -n $label ]] || { echo "no volume id in $iso" >&2; exit 1; }
ksarg="inst.ks=hd:LABEL=$label:/openvibes-appliance.ks"
ks=$ROOT/packaging/appliance/openvibes-appliance.ks
# OPENVIBES_ISO_TEST=1 builds the CI test variant (never released): the same
# ISO, but the installer runs by itself on a serial console, from the
# kickstart plus test-install.ks (disk, user, power off, a boot check). The
# CI kit carries no model package, so that one is left out.
if [[ -n ${OPENVIBES_ISO_TEST:-} ]]; then
    ksarg="$ksarg inst.text console=ttyS0,115200n8"
    ks=$work/test.ks
    sed -e '/^reboot /d' -e '/^openvibes-llm-model$/d' "$ROOT/packaging/appliance/openvibes-appliance.ks" > "$ks"
    cat "$ROOT/packaging/appliance/test-install.ks" >> "$ks"
fi
mkdir "$work/boot"
xorriso -osirrox on -indev "$work/$iso" -extract /EFI/BOOT/grub.cfg "$work/boot/efi-grub.cfg" \
    -extract /boot/grub2/grub.cfg "$work/boot/grub.cfg" -extract_boot_images "$work/boot/images" >/dev/null 2>&1
ls -l "$work/boot/images"
efi=$(find "$work/boot/images" -type f -name '*uefi*' | head -n 1)
[[ -n $efi ]] || { echo "no EFI boot image found in $iso" >&2; exit 1; }
for f in efi-grub.cfg grub.cfg; do
    sed -i -E "/^[[:space:]]*linux(efi)?[[:space:]]/ s|\$| $ksarg|" "$work/boot/$f"
    grep -q "$ksarg" "$work/boot/$f" || { echo "no kernel line to extend in $f" >&2; exit 1; }
done
cp "$work/boot/efi-grub.cfg" "$work/boot/efi-image-grub.cfg"
chmod u+w "$efi"
mcopy -o -i "$efi" "$work/boot/efi-image-grub.cfg" ::EFI/BOOT/grub.cfg

# The original BIOS boot (El Torito image and GRUB2 boot sector) is replayed.
# Its UEFI entry points at a hidden partition xorriso cannot replay (a SORRY
# it reports, so exit values below FAILURE are tolerated); the edited EFI
# image is added again as an appended partition and a new UEFI entry.
xorriso -return_with FAILURE 32 -indev "$work/$iso" -outdev "$out" \
    -boot_image any replay \
    -boot_image any appended_part_as=gpt \
    -append_partition 2 C12A7328-F81F-11D2-BA4B-00A0C93EC93B "$efi" \
    -boot_image any next \
    -boot_image any efi_path=--interval:appended_partition_2:all:: \
    -boot_image any platform_id=0xef \
    -update "$work/boot/efi-grub.cfg" /EFI/BOOT/grub.cfg \
    -update "$work/boot/grub.cfg" /boot/grub2/grub.cfg \
    -map "$work/kit/openvibes-offline" openvibes-offline \
    -map "$ks" openvibes-appliance.ks \
    -commit
# Show the boot entries of the result: BIOS and UEFI must both be there.
report=$(xorriso -indev "$out" -report_el_torito plain 2>&1)
echo "$report" | grep -E "El Torito|Boot|efi" || true
for platform in BIOS UEFI; do
    echo "$report" | grep -q "El Torito boot img .*$platform" || { echo "the ISO has no $platform boot entry" >&2; exit 1; }
done
# The kit and the kickstart must really be in the result (a tolerated SORRY
# could hide a half-added kit).
xorriso -indev "$out" -find /openvibes-offline/packages/repodata -name repomd.xml 2>&1 | grep -q repomd.xml || { echo "the ISO has no kit repository" >&2; exit 1; }
xorriso -indev "$out" -find /openvibes-appliance.ks 2>&1 | grep -q openvibes-appliance.ks || { echo "the ISO has no kickstart" >&2; exit 1; }
implantisomd5 "$out" >/dev/null
ls -l "$out"
