#!/usr/bin/env bash
# Builds the appliance update file (Decision #664, #673): the appliance's
# package source as the ISO carries it (scripts/appliance-repo.sh), with
# SHA256SUMS over every file. The appliance checks the signature against
# the key it was installed with, makes the repository its package source,
# and runs Update from it (#674); online and offline (#568) alike.
# Usage, as the offline kit is built:
#   build-appliance-update.sh KIT_TAR OUT_DIR [EXTRA_DIR]
#       in an almalinux:10 container: writes OUT_DIR/openvibes-appliance-update/
#       (repo/, VERSION, SHA256SUMS)
#   (the caller signs: OUT_DIR/openvibes-appliance-update/SHA256SUMS.asc, a
#   detached armoured signature by the OpenVIBES package key)
#   build-appliance-update.sh --pack OUT_DIR
#       writes OUT_DIR/openvibes-appliance-update-<VERSION>.tar
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BASE=openvibes-appliance-update

if [[ ${1:-} == --pack ]]; then
    [[ $# == 2 ]] || { echo "usage: $0 --pack OUT_DIR" >&2; exit 2; }
    tree=$2/$BASE
    [[ -s $tree/SHA256SUMS.asc ]] || { echo "$tree/SHA256SUMS.asc is missing: sign SHA256SUMS first" >&2; exit 1; }
    version=$(cat "$tree/VERSION")
    tar -C "$2" --owner=0 --group=0 --numeric-owner -cf "$2/$BASE-$version.tar" "$BASE"
    echo "$2/$BASE-$version.tar"
    exit 0
fi

[[ $# == 2 || $# == 3 ]] || { echo "usage: $0 KIT_TAR OUT_DIR [EXTRA_DIR]" >&2; exit 2; }
kit_tar=$(realpath "$1") out=$(realpath -m "$2") extra_dir=${3:+$(realpath "$3")}
[[ $(. /etc/os-release && echo "$ID:${VERSION_ID%%.*}") == almalinux:10 ]] || { echo "this is not an almalinux:10 container" >&2; exit 1; }
# The version is the kit's: openvibes-platform-<version>-offline-el10.tar.
version=$(basename "$kit_tar" | sed -n 's/^openvibes-platform-\(.*\)-offline-el10\.tar$/\1/p')
[[ $version =~ ^[0-9][0-9A-Za-z.~+_-]*$ ]] || { echo "$kit_tar is not named openvibes-platform-<version>-offline-el10.tar" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
bash "$ROOT/scripts/appliance-repo.sh" "$kit_tar" "$work" ${extra_dir:+"$extra_dir"}

tree=$out/$BASE
rm -rf "$tree"
mkdir -p "$tree"
cp -r "$work/repo" "$tree/repo"
printf '%s\n' "$version" > "$tree/VERSION"
# Every file, sorted; the signature (added by the caller) covers this list.
(cd "$tree" && find . -type f -print0 | sort -z | sed -z 's|^\./||' | xargs -0 sha256sum) > "$work/sums"
mv "$work/sums" "$tree/SHA256SUMS"
echo "update file tree: $tree ($(find "$tree/repo" -name '*.rpm' | wc -l) packages, version $version)"
