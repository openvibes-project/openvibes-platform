#!/usr/bin/env bash
# Generate or verify the browser types derived from the Rust OpenAPI snapshot.
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -- "${script_dir}/.." && pwd -P)"
readonly web_root="${repository_root}/crates/openvibes-console/web"
readonly snapshot="${repository_root}/docs/api/console-v1.openapi.json"
readonly output="${web_root}/src/api/generated.ts"

if [[ ! -f "${snapshot}" ]]; then
    printf 'error: missing OpenAPI snapshot: %s\n' "${snapshot}" >&2
    exit 1
fi

generate() {
    local destination="$1"
    cd -- "${web_root}"
    npm exec -- openapi-typescript "${snapshot}" --output "${destination}"
}

case "${1:-}" in
    "")
        mkdir -p -- "$(dirname -- "${output}")"
        generate "${output}"
        ;;
    --check)
        if [[ ! -f "${output}" ]]; then
            printf 'error: missing generated client: %s\n' "${output}" >&2
            exit 1
        fi
        readonly candidate="$(mktemp)"
        trap 'rm -f -- "${candidate}"' EXIT
        generate "${candidate}"
        if ! cmp -s -- "${output}" "${candidate}"; then
            printf 'error: generated console client is stale; run npm run generate:api\n' >&2
            diff -u -- "${output}" "${candidate}" || true
            exit 1
        fi
        ;;
    *)
        printf 'usage: %s [--check]\n' "$0" >&2
        exit 2
        ;;
esac
