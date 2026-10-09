#!/usr/bin/env bash
# Builds an offline kit signed with a throwaway key, for the kit's tests (CI
# on pull requests, local runs). The RPMs are re-signed with that key, so the
# installer must be run with OPENVIBES_KEY_FINGERPRINT=$(cat OUT_DIR/fingerprint).
# Usage: offline-kit-test-kit.sh RPM_DIR OUT_DIR FEDORA
#   prints the tar's path. Needs podman (the build runs in fedora:FEDORA).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ $# == 3 ]] || { echo "usage: $0 RPM_DIR OUT_DIR FEDORA" >&2; exit 2; }
rpm_dir=$(realpath "$1") out=$(realpath -m "$2") fedora=$3
# Work in a temp directory: the containers mount it relabelled (SELinux),
# which must not touch the checkout.
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/src/scripts" "$work/src/packaging/llm" "$work/src/packaging/rpm" "$work/out/rpms"
cp -r "$ROOT/packaging/offline" "$work/src/packaging/"
cp "$ROOT/packaging/llm/model.pin" "$work/src/packaging/llm/"
cp "$ROOT/packaging/rpm/openvibes-packages.gpg" "$work/src/packaging/rpm/"
cp "$ROOT"/scripts/build-offline-kit.sh "$ROOT"/scripts/sign-rpms.sh "$work/src/scripts/"
cp "$rpm_dir"/openvibes-*.rpm "$work/out/rpms/"
rm -f "$work"/out/rpms/*-debuginfo-* "$work"/out/rpms/*-debugsource-* "$work"/out/rpms/openvibes-agent-*
img=registry.fedoraproject.org/fedora:$fedora

export GNUPGHOME=$work/gnupg; mkdir -m 0700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' --quick-generate-key 'OpenVIBES test kit <test@example.invalid>' rsa3072 sign never 2>/dev/null
fingerprint=$(gpg --with-colons --list-keys | awk -F: '$1=="fpr"{print $10; exit}')
gpg --armor --export "$fingerprint" > "$work/out/pub.gpg"
# rpmsign lives in a throwaway container, apart from the build's clean one.
gpg --armor --export-secret-keys "$fingerprint" > "$work/out/secret.asc"
podman run --rm -v "$work/src:/src:ro,Z" -v "$work/out:/out:z" "$img" bash -c '
    set -e; dnf -q -y install rpm-sign gnupg2 >/dev/null
    rpmsign --delsign /out/rpms/*.rpm >/dev/null 2>&1 || true
    RPM_SIGNING_KEY=$(cat /out/secret.asc) RPM_SIGNING_PASSPHRASE= \
        bash /src/scripts/sign-rpms.sh /out/rpms /out/pub.gpg' >&2
rm -f "$work/out/secret.asc"

podman run --rm -v "$work/src:/src:ro,Z" -v "$work/out:/out:z" \
    -e OPENVIBES_KIT_PUBKEY=/out/pub.gpg "$img" \
    bash /src/scripts/build-offline-kit.sh /out/rpms /out "$fedora" >&2
gpg --batch --quiet --detach-sign --armor -o "$work/out/openvibes-offline/SHA256SUMS.asc" "$work/out/openvibes-offline/SHA256SUMS"
bash "$ROOT/scripts/build-offline-kit.sh" --pack "$work/out" "$fedora" >&2
rm -rf "$out"; mkdir -p "$out"
mv "$work"/out/openvibes-platform-*.tar "$out/"
echo "$fingerprint" > "$out/fingerprint"
ls "$out"/openvibes-platform-*.tar
