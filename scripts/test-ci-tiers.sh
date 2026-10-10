#!/usr/bin/env bash
# Cases for scripts/ci-tiers.sh: which CI tiers a pull request runs.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
check() { # expected "heavy kit light docs", event, labels, then changed files
    local want=$1 event=$2 labels=$3; shift 3
    local got
    got=$(printf '%s\n' "$@" | EVENT=$event LABELS=$labels bash scripts/ci-tiers.sh \
        | sed 's/^[a-z]*=//' | tr '\n' ' ' | sed 's/ $//')
    if [[ "$got" != "$want" ]]; then
        echo "FAIL: $* ($event, labels '$labels'): want '$want', got '$got'"
        fail=1
    fi
}
#      heavy kit   light docs
check "false false true true"   pull_request "" docs/quick-setup.md README.md
check "false false true false"  pull_request "" crates/openvibes-console/web/src/App.tsx docs/x.md
check "false false false false" pull_request "" docs/api/console-v1.openapi.json
check "true false false false"  pull_request "" crates/openvibes-netlog/src/cef.rs docs/x.md
check "true true false false"   pull_request "" packaging/rpm/openvibes-platform.spec
check "true true false false"   pull_request "full-ci" docs/x.md
check "true true false false"   push "" docs/x.md
check "true true false false"   schedule "" docs/x.md
check "true true false false"   pull_request "" scripts/ci-tiers.sh
[[ $fail == 0 ]] && echo "ci-tiers: ok"
exit $fail
