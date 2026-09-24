#!/usr/bin/env bash
# Run the real embedded console in Chromium, Firefox, and WebKit.
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -- "${script_dir}/.." && pwd -P)"
readonly web_root="${repository_root}/crates/openvibes-console/web"

for required_command in node npm cargo; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        printf 'error: required command is unavailable: %s\n' "${required_command}" >&2
        exit 1
    fi
done

cd -- "${repository_root}"
scripts/build-console.sh
cargo build --locked -p openvibes-console --features embedded-ui

cd -- "${web_root}"
npm run test:e2e -- "$@"
