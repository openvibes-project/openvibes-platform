#!/usr/bin/env bash
# Build the checksummed npm cache artefact consumed by offline RPM builds.
set -euo pipefail

readonly required_node_version="22.23.1"
readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -- "${script_dir}/.." && pwd -P)"
readonly web_root="${repository_root}/crates/openvibes-console/web"
readonly output_dir="${1:-${repository_root}/target/console-npm-cache}"

if [[ $# -gt 1 ]]; then
    printf 'usage: %s [OUTPUT_DIR]\n' "$0" >&2
    exit 2
fi

for required_command in node npm tar gzip sha256sum; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        printf 'error: required command is unavailable: %s\n' "${required_command}" >&2
        exit 1
    fi
done

if [[ "$(node --version)" != "v${required_node_version}" ]]; then
    printf 'error: Node.js v%s is required\n' "${required_node_version}" >&2
    exit 1
fi

readonly lockfile="${web_root}/package-lock.json"
readonly lock_digest="$(sha256sum "${lockfile}" | cut -d' ' -f1)"
readonly platform="$(node --print 'process.platform + "-" + process.arch')"
readonly artifact_name="openvibes-console-npm-cache-${platform}-${lock_digest}.tar.gz"
readonly checksum_name="${artifact_name}.sha256"

mkdir -p -- "${output_dir}"
readonly resolved_output_dir="$(cd -- "${output_dir}" && pwd -P)"
if [[ -e "${resolved_output_dir}/${artifact_name}" || -e "${resolved_output_dir}/${checksum_name}" ]]; then
    printf 'error: cache artefact already exists for this lock file: %s\n' "${resolved_output_dir}/${artifact_name}" >&2
    exit 1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf -- "${work_dir}"' EXIT
cache_dir="${work_dir}/npm-cache"
mkdir -p -- "${cache_dir}"

cd -- "${web_root}"
npm ci --no-audit --no-fund --cache "${cache_dir}" >&2
npm cache verify --cache "${cache_dir}" >&2

printf '%s\n' "${lock_digest}" >"${cache_dir}/.lockfile-sha256"
printf '%s\n' "${platform}" >"${cache_dir}/.platform"
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner --format=posix \
    -C "${work_dir}" -cf "${work_dir}/cache.tar" \
    npm-cache/.lockfile-sha256 npm-cache/.platform npm-cache/_cacache
gzip -n --stdout "${work_dir}/cache.tar" >"${work_dir}/${artifact_name}"
(
    cd -- "${work_dir}"
    sha256sum "${artifact_name}" >"${checksum_name}"
)

install -m 0644 "${work_dir}/${artifact_name}" "${resolved_output_dir}/${artifact_name}"
install -m 0644 "${work_dir}/${checksum_name}" "${resolved_output_dir}/${checksum_name}"
printf '%s\n' "${resolved_output_dir}/${artifact_name}"
