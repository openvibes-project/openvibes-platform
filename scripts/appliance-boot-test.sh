#!/usr/bin/env bash
# Installs the appliance test ISO (build-appliance-iso.sh with
# OPENVIBES_ISO_TEST=1) into an empty disk in QEMU, then boots the installed
# system and waits for its boot check. One firmware per run, so both the BIOS
# and the UEFI boot of the ISO are tried.
# Usage: appliance-boot-test.sh TEST_ISO bios|uefi [LOG_DIR]
# Needs qemu-system-x86, qemu-utils, ovmf and /dev/kvm (the install takes
# minutes with KVM and hours without).
set -euo pipefail
[[ $# -ge 2 ]] || { echo "usage: $0 TEST_ISO bios|uefi [LOG_DIR]" >&2; exit 2; }
iso=$(realpath "$1") fw=$2 logs=$(realpath -m "${3:-.}")
mkdir -p "$logs"
[[ -w /dev/kvm ]] || { echo "no /dev/kvm: the install would take hours" >&2; exit 1; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
qemu-img create -q -f qcow2 "$work/disk.qcow2" 20G
args=(-enable-kvm -cpu host -smp 2 -m 6144 -display none -no-reboot
      -serial "file:$logs/$fw-STAGE_.log" -drive "file=$work/disk.qcow2,if=virtio")
case $fw in
    bios) ;;
    uefi)
        cp /usr/share/OVMF/OVMF_VARS_4M.fd "$work/vars.fd"
        args+=(-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd
               -drive "if=pflash,format=raw,file=$work/vars.fd") ;;
    *) echo "firmware must be bios or uefi" >&2; exit 2 ;;
esac
run() { # STAGE MINUTES [EXTRA QEMU ARGS]
    local stage=$1 minutes=$2; shift 2
    local log="$logs/$fw-$stage.log"
    local a=("${args[@]//STAGE_/$stage}")
    echo "== $fw: $stage (up to $minutes minutes)"
    timeout "${minutes}m" qemu-system-x86_64 "${a[@]}" "$@" || { echo "$stage: QEMU did not finish in time or failed" >&2; tail -n 40 "$log" >&2; return 1; }
}
run install 45 -cdrom "$iso" -boot d
run boot 10
log="$logs/$fw-boot.log"
grep -q OPENVIBES-BOOT-OK "$log" || { echo "the installed system did not pass its boot check" >&2; tail -n 40 "$log" >&2; exit 1; }
echo "== $fw: installed and booted"
