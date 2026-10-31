#!/usr/bin/env bash
# Cases for scripts/ci-tiers.sh: which CI tiers a pull request runs.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
check() { # expected "heavy kit docs", event, labels, then changed files
    local want=$1 event=$2 labels=$3; shift 3
    local got
    got=$(printf '%s\n' "$@" | EVENT=$event LABELS=$labels bash scripts/ci-tiers.sh \
        | sed 's/^[a-z]*=//' | tr '\n' ' ' | sed 's/ $//')
    if [[ "$got" != "$want" ]]; then
        echo "FAIL: $* ($event, labels '$labels'): want '$want', got '$got'"
        fail=1
    fi
}
#      heavy kit   docs
check "false false true"   pull_request "" docs/quick-setup.md README.md
check "false false false"  pull_request "" crates/openvibes-console/web/src/App.tsx docs/x.md
# web/public is compiled into Rust (router.rs), the built frontend checked by build.rs
check "false false false"  pull_request "" crates/openvibes-console/web/public/brand/openvibes-wordmark-light.svg
check "false false false" pull_request "" docs/api/console-v1.openapi.json
check "true false false"  pull_request "" crates/openvibes-netlog/src/cef.rs docs/x.md
check "true true false"   pull_request "" packaging/rpm/openvibes-platform.spec
check "true true false"   pull_request "full-ci" docs/x.md
check "true true true"   push "" docs/x.md
check "true true false"   schedule "" docs/x.md
check "true true false"   pull_request "" scripts/ci-tiers.sh
# Any *.md is docs, even in a code folder (folder READMEs); the tiers still hold with code beside it.
check "false false true"   pull_request "" crates/openvibes-console/src/cases/README.md docs/x.md .github/pull_request_template.md
check "true false false"   pull_request "" crates/openvibes-console/src/cases/README.md crates/openvibes-netlog/src/cef.rs
# A push to main skips only for docs; nothing listed or any code runs everything.
check "true true true"     push "" docs/x.md crates/openvibes-console/src/cases/README.md
check "true true false"    push "" crates/openvibes-netlog/src/cef.rs docs/x.md
check "true true false"    push "" docs/api/console-v1.openapi.json
check "true true false"    pull_request ""
check "true true false"    push ""
[[ $fail == 0 ]] && echo "ci-tiers: ok"
exit $fail
