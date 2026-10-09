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
rm -rf "$out"; mkdir -p "$out/rpms"
cp "$rpm_dir"/openvibes-*.rpm "$out/rpms/"
rm -f "$out"/rpms/*-debuginfo-* "$out"/rpms/*-debugsource-* "$out"/rpms/openvibes-agent-*

export GNUPGHOME=$out/gnupg; mkdir -m 0700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' --quick-generate-key 'OpenVIBES test kit <test@example.invalid>' rsa3072 sign never 2>/dev/null
fingerprint=$(gpg --with-colons --list-keys | awk -F: '$1=="fpr"{print $10; exit}')
echo "$fingerprint" > "$out/fingerprint"
gpg --armor --export "$fingerprint" > "$out/pub.gpg"
# rpmsign lives in a throwaway container, apart from the build's clean one.
gpg --armor --export-secret-keys "$fingerprint" > "$out/secret.asc"
podman run --rm -v "$ROOT:/src:ro,z" -v "$out:/out:z" "registry.fedoraproject.org/fedora:$fedora" bash -c '
    set -e; dnf -q -y install rpm-sign gnupg2 >/dev/null
    rpmsign --delsign /out/rpms/*.rpm >/dev/null 2>&1 || true
    RPM_SIGNING_KEY=$(cat /out/secret.asc) RPM_SIGNING_PASSPHRASE= \
        bash /src/scripts/sign-rpms.sh /out/rpms /out/pub.gpg' >&2
rm -f "$out/secret.asc"

podman run --rm -v "$ROOT:/src:ro,z" -v "$out/rpms:/rpms:ro,z" -v "$out:/out:z" \
    -e OPENVIBES_KIT_PUBKEY=/out/pub.gpg "registry.fedoraproject.org/fedora:$fedora" \
    bash /src/scripts/build-offline-kit.sh /rpms /out "$fedora" >&2
gpg --batch --quiet --detach-sign --armor -o "$out/openvibes-offline/SHA256SUMS.asc" "$out/openvibes-offline/SHA256SUMS"
bash "$ROOT/scripts/build-offline-kit.sh" --pack "$out" "$fedora"
