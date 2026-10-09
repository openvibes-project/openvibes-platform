#!/usr/bin/env bash
# Builds an offline kit signed with a throwaway key, for the kit's tests (CI
# on pull requests, local runs). The RPMs are re-signed with that key, so the
# installer must be run with OPENVIBES_KEY_FINGERPRINT=$(cat OUT_DIR/fingerprint).
# Usage: offline-kit-test-kit.sh RPM_DIR OUT_DIR FEDORA
#   OUT_DIR gets the kit's tar, `fingerprint`, `test-key.asc` (the throwaway
#   secret key: OPENVIBES_TEST_KEY=that file makes a second kit with the same
#   key, for the upgrade test) and bad-signature.tar: the same kit with one
#   RPM signed by a third key and SHA256SUMS signed again by the test key, so
#   --check passes and only gpgcheck can refuse the install.
#   Needs podman (the build runs in fedora:FEDORA); prints the tar's path.
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
if [[ -n ${OPENVIBES_TEST_KEY:-} ]]; then
    gpg --batch --quiet --import "$OPENVIBES_TEST_KEY" 2>/dev/null
else
    gpg --batch --quiet --passphrase '' --quick-generate-key 'OpenVIBES test kit <test@example.invalid>' rsa3072 sign never 2>/dev/null
fi
fingerprint=$(gpg --with-colons --list-keys | awk -F: '$1=="fpr"{print $10; exit}')
gpg --armor --export "$fingerprint" > "$work/out/pub.gpg"
gpg --armor --export-secret-keys "$fingerprint" > "$work/out/secret.asc"
cp "$work/out/secret.asc" "$work/test-key.asc"
# A third key, for the bad-signature kit.
third=$work/third; mkdir -m 0700 "$third"
GNUPGHOME=$third gpg --batch --quiet --passphrase '' --quick-generate-key 'Third key <third@example.invalid>' rsa3072 sign never 2>/dev/null
GNUPGHOME=$third gpg --armor --export-secret-keys > "$work/out/third.asc"
# rpmsign lives in a throwaway container, apart from the build's clean one.
podman run --rm -v "$work/src:/src:ro,Z" -v "$work/out:/out:z" "$img" bash -c '
    set -e; dnf -q -y install rpm-sign gnupg2 >/dev/null
    rpmsign --delsign /out/rpms/*.rpm >/dev/null 2>&1 || true
    RPM_SIGNING_KEY=$(cat /out/secret.asc) RPM_SIGNING_PASSPHRASE= \
        bash /src/scripts/sign-rpms.sh /out/rpms /out/pub.gpg' >&2
rm -f "$work/out/secret.asc"

podman run --rm -v "$work/src:/src:ro,Z" -v "$work/out:/out:z" \
    -e OPENVIBES_KIT_PUBKEY=/out/pub.gpg "$img" \
    bash /src/scripts/build-offline-kit.sh /out/rpms /out "$fedora" >&2
sign() { gpg --batch --quiet --detach-sign --armor -o "$1/SHA256SUMS.asc" "$1/SHA256SUMS"; }
sign "$work/out/openvibes-offline"
bash "$ROOT/scripts/build-offline-kit.sh" --pack "$work/out" "$fedora" >&2
tar_name=$(basename "$work"/out/openvibes-platform-*.tar)

# The bad-signature kit: a copy of the tree with openvibes-signer signed by the
# third key and the repository metadata and checksums redone.
mkdir "$work/bad"
cp -a "$work/out/openvibes-offline" "$work/bad/"
podman run --rm -v "$work/src:/src:ro,Z" -v "$work/bad:/bad:z" -v "$work/out/third.asc:/third.asc:ro,Z" "$img" bash -c '
    set -e; dnf -q -y install rpm-sign gnupg2 createrepo_c >/dev/null
    export GNUPGHOME=/tmp/g; mkdir -m 0700 "$GNUPGHOME"; gpg --batch --quiet --import /third.asc
    fpr=$(gpg --with-colons --list-secret-keys | awk -F: "\$1==\"fpr\"{print \$10; exit}")
    f=$(ls /bad/openvibes-offline/packages/openvibes-signer-[0-9]*.rpm)
    rpmsign --delsign "$f" >/dev/null 2>&1 || true
    : > /tmp/pass
    rpmsign --addsign --define "_gpg_name $fpr" \
        --define "_gpg_sign_cmd_extra_args --batch --pinentry-mode loopback --passphrase-file /tmp/pass" "$f" >/dev/null
    rm -rf /bad/openvibes-offline/packages/repodata; createrepo_c --quiet /bad/openvibes-offline/packages
    bash /src/scripts/build-offline-kit.sh --sums /bad/openvibes-offline' >&2
sign "$work/bad/openvibes-offline"
tar -C "$work/bad" --owner=0 --group=0 --numeric-owner --sort=name -cf "$work/bad-signature.tar" openvibes-offline

rm -rf "$out"; mkdir -p "$out"
mv "$work/out/$tar_name" "$work/bad-signature.tar" "$work/test-key.asc" "$out/"
echo "$fingerprint" > "$out/fingerprint"
ls "$out/$tar_name"
