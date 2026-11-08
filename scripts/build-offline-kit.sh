#!/usr/bin/env bash
# Builds the offline platform kit. Run it as root inside a clean fedora:N or
# almalinux:10 container (a minimal base image), with network access to the
# distribution's repositories and the repository checkout at ../ (mounted).
# Usage: build-offline-kit.sh RPM_DIR OUT_DIR TARGET
#        build-offline-kit.sh --pack OUT_DIR TARGET     (after signing)
#   TARGET   a Fedora release number (44) or el10 (AlmaLinux 10)
#        build-offline-kit.sh --sums TREE               (SHA256SUMS again)
#   RPM_DIR  the platform RPMs (admin console ingest distribution vulns signer
#            llm llm-model) and the openvibes-rules-*.rpm packages
#   OUT_DIR  receives openvibes-offline/ and
#            openvibes-platform-<v>-offline-fedora<N>.tar (or -offline-el10.tar)
# Signing is the caller's job: put SHA256SUMS.asc (a detached signature with
# the OpenVIBES key) into OUT_DIR/openvibes-offline/, then run --pack.
# Env: OPENVIBES_KIT_PUBKEY replaces packaging/rpm/openvibes-packages.gpg
# (tests, which sign with a throwaway key).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)

sums() { # TREE: SHA256SUMS over every file (the signature is the caller's)
    (cd "$1" && rm -f SHA256SUMS SHA256SUMS.asc && find . -type f -print0 | sort -z |
        sed -z 's|^\./||' | xargs -0 sha256sum > ../SHA256SUMS.new && mv ../SHA256SUMS.new SHA256SUMS)
}
label() { # TARGET: the name part of the tar (fedora44, el10)
    if [[ $1 =~ ^[0-9]+$ ]]; then echo "fedora$1"; else echo "$1"; fi
}
pack() { # OUT_DIR TARGET: the tar of the tree
    local out=$1 version name
    version=$(sed -n 's/^KIT_VERSION=//p' "$out/openvibes-offline/install")
    name=openvibes-platform-$version-offline-$(label "$2").tar
    tar -C "$out" --owner=0 --group=0 --numeric-owner --sort=name -cf "$out/$name" openvibes-offline
    echo "$out/$name"
}
if [[ ${1:-} == --sums ]]; then # TREE: redo SHA256SUMS (tests that alter a kit)
    [[ $# == 2 ]] || { echo "usage: $0 --sums TREE" >&2; exit 2; }
    sums "$(realpath "$2")"
    exit
fi
if [[ ${1:-} == --pack ]]; then
    [[ $# == 3 ]] || { echo "usage: $0 --pack OUT_DIR TARGET" >&2; exit 2; }
    pack "$(realpath "$2")" "$3"
    exit
fi
[[ $# == 3 ]] || { echo "usage: $0 RPM_DIR OUT_DIR TARGET" >&2; exit 2; }
rpm_dir=$(realpath "$1") out=$(realpath -m "$2") target=$3
if [[ $target =~ ^[0-9]+$ ]]; then
    [[ $(. /etc/os-release && echo "$VERSION_ID") == "$target" ]] || { echo "this is not a fedora:$target container" >&2; exit 1; }
    os_name="Fedora $target" sources_url=https://src.fedoraproject.org/rpms
    pg_server=postgresql-server
elif [[ $target == el10 ]]; then
    [[ $(. /etc/os-release && echo "$ID:${VERSION_ID%%.*}") == almalinux:10 ]] || { echo "this is not an almalinux:10 container" >&2; exit 1; }
    os_name="AlmaLinux 10" sources_url=https://git.almalinux.org/rpms
    # AlmaLinux 10 carries PostgreSQL 16; the migrations need 17, so the
    # PostgreSQL project's repository (PGDG) supplies it, as in Setup.
    dnf -y install dnf-plugins-core \
        https://download.postgresql.org/pub/repos/yum/reporpms/EL-10-x86_64/pgdg-redhat-repo-latest.noarch.rpm >/dev/null
    pg_server=postgresql17-server
else
    echo "TARGET must be a Fedora number or el10" >&2; exit 2
fi


kit=$out/openvibes-offline
rm -rf "$kit"
mkdir -p "$kit/packages" "$kit/LICENSES"

# 1. The OpenVIBES packages, exactly these.
rpms=()
admins=$(find "$rpm_dir" -maxdepth 1 -name 'openvibes-admin-[0-9]*.x86_64.rpm')
(($(grep -c . <<<"$admins") == 1)) || { echo "build-offline-kit: want exactly one openvibes-admin RPM in $rpm_dir, found: ${admins:-none}" >&2; exit 1; }
for name in admin console ingest distribution vulns signer llm llm-model; do
    f=$(find "$rpm_dir" -maxdepth 1 -name "openvibes-$name-[0-9]*.x86_64.rpm" | sort -V | tail -n 1)
    [[ -n $f ]] || { echo "build-offline-kit: no openvibes-$name RPM in $rpm_dir" >&2; exit 1; }
    rpms+=("$f")
done
shopt -s nullglob
rules=("$rpm_dir"/openvibes-rules-*.rpm)
shopt -u nullglob
((${#rules[@]})) || { echo "build-offline-kit: no openvibes-rules-* RPM in $rpm_dir" >&2; exit 1; }
rpms+=("${rules[@]}")
cp "${rpms[@]}" "$kit/packages/"
version=$(rpm -qp --nosignature --qf '%{VERSION}' "$admins")

# 2. Their dependency closure from the distribution (no weak dependencies). dnf cannot
# download from local files, so they form a repository first. --alldeps
# ignores what is installed.
dnf -y install createrepo_c >/dev/null
createrepo_c --quiet "$kit/packages"
# PostgreSQL is not a dependency of the packages: Setup installs it on demand,
# which an offline host could not do.
names=("$pg_server")
for f in "${rpms[@]}"; do names+=("$(rpm -qp --nosignature --qf '%{NAME}' "$f")"); done
# Downloaded apart, because dnf 4 (AlmaLinux) also "downloads" the local
# packages and fails copying a file onto itself.
dl=$kit/.download
dnf -y --repofrompath=ovlocal,"$kit/packages" --setopt=ovlocal.gpgcheck=0 download --resolve --alldeps \
    --exclude='*.i686' --destdir "$dl" --setopt=install_weak_deps=False "${names[@]}"
mv -n "$dl"/*.rpm "$kit/packages/"
rm -rf "$dl" "$kit/packages/repodata"

# 3. The whole closure stays, base-image packages included: a host on an
# older Fedora point release gets the newer libraries it needs from the kit.
for p in "$pg_server" openvibes-admin; do
    ls "$kit"/packages/"$p"-[0-9]*.rpm >/dev/null || { echo "build-offline-kit: $p is not in the kit" >&2; exit 1; }
done
# The migrations need PostgreSQL 17 or later.
pg=$(rpm -qp --nosignature --qf '%{VERSION}' "$(ls "$kit"/packages/"$pg_server"-[0-9]*.rpm | head -n 1)")
((${pg%%.*} >= 17)) || { echo "build-offline-kit: $os_name carries PostgreSQL $pg; 17 or later is needed" >&2; exit 1; }

# 4. The repository, now with the closure.
createrepo_c --quiet "$kit/packages"

# 5. The installer, README, key, licences.
sed -e "s/@VERSION@/$version/g" -e "s/@TARGET@/$target/g" "$ROOT/packaging/offline/install" > "$kit/install"
chmod 0755 "$kit/install"
fingerprint=$(sed -n 's/^KEY_FINGERPRINT=\([0-9A-F]*\)$/\1/p' "$ROOT/packaging/offline/install" | head -n 1)
# shellcheck source=../packaging/llm/model.pin
. "$ROOT/packaging/llm/model.pin"
sed -e "s/@VERSION@/$version/g" -e "s/@OS@/$os_name/g" -e "s/@LABEL@/$(label "$target")/g" -e "s|@SOURCES_URL@|$sources_url|g" \
    -e "s|@MODEL_FILE@|$LLM_MODEL_FILE|g" -e "s|@MODEL_URL@|$LLM_MODEL_URL|g" \
    -e "s|@MODEL_SHA256@|$LLM_MODEL_SHA256|g" -e "s|@MODEL_LICENSE_URL@|$LLM_MODEL_LICENSE_URL|g" \
    -e "s|@KEY_FINGERPRINT@|$fingerprint|g" "$ROOT/packaging/offline/README.txt.in" > "$kit/README.txt"
cp "${OPENVIBES_KIT_PUBKEY:-$ROOT/packaging/rpm/openvibes-packages.gpg}" "$kit/openvibes.gpg"
if [[ $target == el10 ]]; then # PGDG's key, covered by the signed checksums like the rest
    cp "$(rpm -ql pgdg-redhat-repo | grep -m1 'GPG-KEY')" "$kit/pgdg.gpg"
fi
{
    printf '%s\n' "$os_name packages in this kit: name, licence, source RPM, where to get the sources."
    for f in "$kit"/packages/*.rpm; do
        [[ $(rpm -qp --nosignature --qf '%{NAME}' "$f") == openvibes-* ]] && continue
        rpm -qp --nosignature --qf '%{NAME}\t%{LICENSE}\t%{SOURCERPM}\n' "$f" | awk -F'\t' -v url="$sources_url" '{
            src = $3; sub(/-[^-]*-[^-]*\.src\.rpm$/, "", src)
            printf "%s\t%s\t%s\t%s/%s\n", $1, $2, $3, url, src }'
    done | sort
} > "$kit/LICENSES/distribution-packages.txt"

sums "$kit"

pack "$out" "$target"
