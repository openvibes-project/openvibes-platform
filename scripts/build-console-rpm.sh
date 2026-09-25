#!/usr/bin/env bash
# Build the console RPM from an independently pinned, offline npm cache.
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -- "${script_dir}/.." && pwd -P)"

if [[ $# -ne 2 ]]; then
    printf 'usage: %s CACHE_ARCHIVE EXPECTED_SHA256\n' "$0" >&2
    exit 2
fi

readonly cache_archive="$(cd -- "$(dirname -- "$1")" && pwd -P)/$(basename -- "$1")"
readonly expected_sha256="$2"
if [[ ! "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'error: expected SHA-256 must be 64 lowercase hex characters\n' >&2
    exit 2
fi
if [[ ! -f "${cache_archive}" || -L "${cache_archive}" ]]; then
    printf 'error: cache archive must be a regular file\n' >&2
    exit 1
fi

readonly cache_name="$(basename -- "${cache_archive}")"
if [[ ! "${cache_name}" =~ ^openvibes-console-npm-cache-linux-x64-[0-9a-f]{64}\.tar\.gz$ ]]; then
    printf 'error: unexpected npm cache archive name/platform\n' >&2
    exit 1
fi

readonly version="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "${repository_root}/Cargo.toml" | head -n 1)"
mkdir -p -- "${repository_root}/target"
build_dir="$(mktemp -d "${repository_root}/target/console-rpm.XXXXXX")"
trap 'rm -rf -- "${build_dir}"' EXIT
readonly cache_dir="${build_dir}/npm-cache"

"${script_dir}/check-console-npm-cache.sh" \
    "${cache_archive}" "${cache_dir}" "${expected_sha256}"
cd -- "${repository_root}"
scripts/build-console.sh --offline-cache-dir "${cache_dir}"
env CARGO_NET_OFFLINE=true cargo build --release --locked -p openvibes-console --features embedded-ui

rpmbuild -bb packaging/rpm/openvibes-console.spec \
    --define "_topdir ${repository_root}/target/rpm-console" \
    --define "_sourcedir $(dirname -- "${cache_archive}")" \
    --define "console_repo_root ${repository_root}" \
    --define "console_npm_cache_name ${cache_name}" \
    --define "console_npm_cache_sha256 ${expected_sha256}" \
    --define "ov_version ${version}"

ls "${repository_root}"/target/rpm-console/RPMS/*/openvibes-console-*.rpm
