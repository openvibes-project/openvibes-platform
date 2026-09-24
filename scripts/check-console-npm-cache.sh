#!/usr/bin/env bash
# Verify an npm cache artefact and prove a frontend install/build stays offline.
set -euo pipefail

readonly required_node_version="22.23.1"
readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -- "${script_dir}/.." && pwd -P)"
readonly web_root="${repository_root}/crates/openvibes-console/web"

if [[ $# -ne 1 ]]; then
    printf 'usage: %s CACHE.tar.gz\n' "$0" >&2
    exit 2
fi

for required_command in node npm tar sha256sum; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        printf 'error: required command is unavailable: %s\n' "${required_command}" >&2
        exit 1
    fi
done

if [[ "$(node --version)" != "v${required_node_version}" ]]; then
    printf 'error: Node.js v%s is required\n' "${required_node_version}" >&2
    exit 1
fi

readonly archive="$(cd -- "$(dirname -- "$1")" && pwd -P)/$(basename -- "$1")"
readonly checksum="${archive}.sha256"
if [[ ! -f "${archive}" || -L "${archive}" || ! -f "${checksum}" || -L "${checksum}" ]]; then
    printf 'error: cache artefact and checksum must be regular files\n' >&2
    exit 1
fi

recorded_digest=
recorded_name=
trailing=
if ! read -r recorded_digest recorded_name trailing <"${checksum}"; then
    printf 'error: cache artefact checksum is invalid\n' >&2
    exit 1
fi
readonly actual_digest="$(sha256sum "${archive}" | cut -d' ' -f1)"
if [[ ! "${recorded_digest}" =~ ^[0-9a-f]{64}$ \
    || "${recorded_name}" != "$(basename -- "${archive}")" \
    || -n "${trailing:-}" \
    || "$(wc -l <"${checksum}")" -ne 1 \
    || "${recorded_digest}" != "${actual_digest}" ]]; then
    printf 'error: cache artefact checksum is invalid\n' >&2
    exit 1
fi

while IFS= read -r entry; do
    case "/${entry}/" in
        *'/../'*|*'/./'*)
            printf 'error: unsafe cache archive entry: %s\n' "${entry}" >&2
            exit 1
            ;;
    esac
    case "${entry}" in
        npm-cache/.lockfile-sha256|npm-cache/.platform|npm-cache/_cacache|npm-cache/_cacache/*) ;;
        *)
            printf 'error: unexpected cache archive entry: %s\n' "${entry}" >&2
            exit 1
            ;;
    esac
done < <(tar -tzf "${archive}")

work_dir="$(mktemp -d)"
cleanup() {
    rm -rf -- "${work_dir}"
    mkdir -p -- "${web_root}/dist"
    printf '\n' >"${web_root}/dist/.gitkeep"
}
trap cleanup EXIT
tar -xzf "${archive}" -C "${work_dir}" --no-same-owner

readonly cache_dir="${work_dir}/npm-cache"
if [[ -n "$(find "${cache_dir}" -mindepth 1 ! -type f ! -type d -print -quit)" ]]; then
    printf 'error: cache artefact contains a non-regular path\n' >&2
    exit 1
fi

readonly expected_lock_digest="$(sha256sum "${web_root}/package-lock.json" | cut -d' ' -f1)"
readonly expected_platform="$(node --print 'process.platform + "-" + process.arch')"
if [[ "$(<"${cache_dir}/.lockfile-sha256")" != "${expected_lock_digest}" \
    || "$(<"${cache_dir}/.platform")" != "${expected_platform}" ]]; then
    printf 'error: cache artefact does not match this lock file and platform\n' >&2
    exit 1
fi

npm cache verify --cache "${cache_dir}"
cd -- "${web_root}"
npm ci --offline --no-audit --no-fund --cache "${cache_dir}"
npm run build
