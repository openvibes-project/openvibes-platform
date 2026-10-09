#!/usr/bin/env bash
# Builds the offline platform kit. Run it as root inside a clean fedora:N
# container (a minimal base image), with network access to Fedora's repositories and the
# repository checkout at ../ (mounted).
# Usage: build-offline-kit.sh RPM_DIR OUT_DIR FEDORA
#        build-offline-kit.sh --pack OUT_DIR FEDORA     (after signing)
#   RPM_DIR  the platform RPMs (admin console ingest distribution vulns signer
#            llm llm-model) and the openvibes-rules-*.rpm packages
#   OUT_DIR  receives openvibes-offline/ and
#            openvibes-platform-<v>-offline-fedora<N>.tar
# Signing is the caller's job: put SHA256SUMS.asc (a detached signature with
# the OpenVIBES key) into OUT_DIR/openvibes-offline/, then run --pack.
# Env: OPENVIBES_KIT_PUBKEY replaces packaging/rpm/openvibes-packages.gpg
# (tests, which sign with a throwaway key).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)

pack() { # OUT_DIR FEDORA: the tar of the tree
    local out=$1 fedora=$2 version
    version=$(sed -n 's/^KIT_VERSION=//p' "$out/openvibes-offline/install")
    tar -C "$out" --owner=0 --group=0 --numeric-owner --sort=name \
        -cf "$out/openvibes-platform-$version-offline-fedora$fedora.tar" openvibes-offline
    echo "$out/openvibes-platform-$version-offline-fedora$fedora.tar"
}
if [[ ${1:-} == --pack ]]; then
    [[ $# == 3 ]] || { echo "usage: $0 --pack OUT_DIR FEDORA" >&2; exit 2; }
    pack "$(realpath "$2")" "$3"
    exit
fi
[[ $# == 3 ]] || { echo "usage: $0 RPM_DIR OUT_DIR FEDORA" >&2; exit 2; }
rpm_dir=$(realpath "$1") out=$(realpath -m "$2") fedora=$3
[[ $fedora =~ ^[0-9]+$ ]] || { echo "FEDORA must be a number" >&2; exit 2; }
[[ $(. /etc/os-release && echo "$VERSION_ID") == "$fedora" ]] || { echo "this is not a fedora:$fedora container" >&2; exit 1; }


kit=$out/openvibes-offline
rm -rf "$kit"
mkdir -p "$kit/packages" "$kit/LICENSES"

# 1. The OpenVIBES packages, exactly these.
rpms=()
for name in admin console ingest distribution vulns signer llm llm-model; do
    f=$(ls "$rpm_dir"/openvibes-"$name"-[0-9]*.x86_64.rpm 2>/dev/null | tail -n 1 || true)
    [[ -n $f ]] || { echo "build-offline-kit: no openvibes-$name RPM in $rpm_dir" >&2; exit 1; }
    rpms+=("$f")
done
shopt -s nullglob
rules=("$rpm_dir"/openvibes-rules-*.rpm)
shopt -u nullglob
((${#rules[@]})) || { echo "build-offline-kit: no openvibes-rules-* RPM in $rpm_dir" >&2; exit 1; }
rpms+=("${rules[@]}")
cp "${rpms[@]}" "$kit/packages/"
version=$(rpm -qp --nosignature --qf '%{VERSION}' "$rpm_dir"/openvibes-admin-[0-9]*.x86_64.rpm)

# 2. Their dependency closure from Fedora (no weak dependencies). dnf cannot
# download from local files, so they form a repository first. --alldeps
# ignores what is installed.
dnf -y install createrepo_c >/dev/null
createrepo_c --quiet "$kit/packages"
# PostgreSQL is not a dependency of the packages: Setup installs it on demand,
# which an offline host could not do.
names=(postgresql-server)
for f in "${rpms[@]}"; do names+=("$(rpm -qp --nosignature --qf '%{NAME}' "$f")"); done
dnf -y --repofrompath=ovlocal,"$kit/packages" --setopt=ovlocal.gpgcheck=0 download --resolve --alldeps \
    --exclude='*.i686' --destdir "$kit/packages" --setopt=install_weak_deps=False "${names[@]}"
rm -rf "$kit/packages/repodata"

# 3. The whole closure stays, base-image packages included: a host on an
# older Fedora point release gets the newer libraries it needs from the kit.
for p in postgresql-server openvibes-admin; do
    ls "$kit"/packages/"$p"-[0-9]*.rpm >/dev/null || { echo "build-offline-kit: $p is not in the kit" >&2; exit 1; }
done

# 4. The repository, now with the closure.
createrepo_c --quiet "$kit/packages"

# 5. The installer, README, key, licences.
sed -e "s/@VERSION@/$version/g" -e "s/@FEDORA@/$fedora/g" "$ROOT/packaging/offline/install" > "$kit/install"
chmod 0755 "$kit/install"
fingerprint=$(sed -n 's/^KEY_FINGERPRINT=\([0-9A-F]*\)$/\1/p' "$ROOT/packaging/offline/install" | head -n 1)
# shellcheck source=../packaging/llm/model.pin
. "$ROOT/packaging/llm/model.pin"
sed -e "s/@VERSION@/$version/g" -e "s/@FEDORA@/$fedora/g" \
    -e "s|@MODEL_FILE@|$LLM_MODEL_FILE|g" -e "s|@MODEL_URL@|$LLM_MODEL_URL|g" \
    -e "s|@MODEL_SHA256@|$LLM_MODEL_SHA256|g" -e "s|@MODEL_LICENSE_URL@|$LLM_MODEL_LICENSE_URL|g" \
    -e "s|@KEY_FINGERPRINT@|$fingerprint|g" "$ROOT/packaging/offline/README.txt.in" > "$kit/README.txt"
cp "${OPENVIBES_KIT_PUBKEY:-$ROOT/packaging/rpm/openvibes-packages.gpg}" "$kit/openvibes.gpg"
{
    printf '%s\n' 'Fedora packages in this kit: name, licence, source RPM, where to get the sources.'
    for f in "$kit"/packages/*.rpm; do
        [[ $(rpm -qp --nosignature --qf '%{NAME}' "$f") == openvibes-* ]] && continue
        rpm -qp --nosignature --qf '%{NAME}\t%{LICENSE}\t%{SOURCERPM}\n' "$f" | awk -F'\t' '{
            src = $3; sub(/-[^-]*-[^-]*\.src\.rpm$/, "", src)
            printf "%s\t%s\t%s\thttps://src.fedoraproject.org/rpms/%s\n", $1, $2, $3, src }'
    done | sort
} > "$kit/LICENSES/fedora-packages.txt"

# 6. Every file, for the signature.
(cd "$kit" && find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.asc -print0 | sort -z |
    sed -z 's|^\./||' | xargs -0 sha256sum > SHA256SUMS)

pack "$out" "$fedora"
