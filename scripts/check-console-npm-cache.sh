#!/usr/bin/env bash
# Verify an npm cache artefact and prove a frontend install/build stays offline.
set -euo pipefail

readonly required_node_version="22.23.1"
readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -- "${script_dir}/.." && pwd -P)"
readonly web_root="${repository_root}/crates/openvibes-console/web"

if [[ $# -ne 1 && $# -ne 3 ]]; then
    printf 'usage: %s CACHE.tar.gz [EXTRACTED_CACHE_DIR EXPECTED_SHA256]\n' "$0" >&2
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
persisted_cache=
expected_sha256=
if [[ $# -eq 3 ]]; then
    expected_sha256="$3"
    if [[ ! "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
        printf 'error: expected SHA-256 must be 64 lowercase hex characters\n' >&2
        exit 2
    fi
    cache_parent="$(dirname -- "$2")"
    mkdir -p -- "${cache_parent}"
    persisted_cache="$(cd -- "${cache_parent}" && pwd -P)/$(basename -- "$2")"
    if [[ -e "${persisted_cache}" || -L "${persisted_cache}" ]]; then
        printf 'error: extracted cache destination already exists\n' >&2
        exit 1
    fi
fi
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
    || "${recorded_digest}" != "${actual_digest}" \
    || ( -n "${expected_sha256}" && "${recorded_digest}" != "${expected_sha256}" ) ]]; then
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
while IFS= read -r entry; do
    case "${entry:0:1}" in
        -|d) ;;
        *)
            printf 'error: cache archive contains a non-file path: %s\n' "${entry}" >&2
            exit 1
            ;;
    esac
done < <(tar -tvzf "${archive}")

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

# The install and build run without a network where the system allows an
# unprivileged network namespace, so "offline" is enforced rather than
# assumed (install scripts such as esbuild's postinstall run too). Some CI
# kernels forbid it; the check then relies on --offline alone and says so.
isolate=()
if unshare -rn true 2>/dev/null; then
    isolate=(unshare -rn)
else
    printf 'warning: no network namespace available; relying on npm --offline only\n' >&2
fi

cd -- "${web_root}"
"${isolate[@]}" npm ci --offline --no-audit --no-fund --cache "${cache_dir}"
# Build into a scratch directory: the real dist/ (and its build stamp, which
# embedded-ui builds need) is left untouched.
"${isolate[@]}" npm run build -- --outDir "${work_dir}/dist" --emptyOutDir

if [[ -n "${persisted_cache}" ]]; then
    cp -a -- "${cache_dir}" "${persisted_cache}"
    printf '%s\n' "${persisted_cache}"
fi
