#!/usr/bin/env bash
# Run the real console (embedded UI, production CSP, throwaway database) in
# Chromium, Firefox and WebKit. Needs OPENVIBES_TEST_DATABASE_URL.
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -- "${script_dir}/.." && pwd -P)"
readonly web_root="${repository_root}/crates/openvibes-console/web"
: "${OPENVIBES_TEST_DATABASE_URL:?set OPENVIBES_TEST_DATABASE_URL, for example eval \"\$(scripts/test-db.sh)\"}"

for required_command in node npm cargo psql; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        printf 'error: required command is unavailable: %s\n' "${required_command}" >&2
        exit 1
    fi
done

cd -- "${repository_root}"
scripts/build-console.sh
# The real console with the embedded UI, and the admin CLI that prepares its
# throwaway database (scripts/console-e2e-server.sh).
cargo build --locked -p openvibes-admin -p openvibes-console --features openvibes-console/embedded-ui

cd -- "${web_root}"
npm run test:e2e -- "$@"
