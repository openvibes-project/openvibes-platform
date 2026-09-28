#!/bin/bash
# Old service account names (openvibes_NAME) may appear only where the
# upgrade rename needs them (admin TUI spec §2).
cd "$(dirname "$0")/.." || exit 2
hits=$(git grep -n -E 'openvibes_(admin|ingest|distribution|vulns|llm)\b' -- \
    ':!packaging/rpm/openvibes-platform.spec' ':!scripts/check-names.sh' \
    ':!scripts/test-rename-account.sh' \
    ':!docs/specs' ':!docs/plans' ':!docs/handover' ':!docs/components/packaging.md' |
    grep -v -E 'openvibes_(admin|ingest|distribution|vulns|llm)::|use openvibes_(llm|vulns|ingest|distribution)')
[[ -z $hits ]] || { echo "old account names:"; echo "$hits"; exit 1; }
echo "ok: no old account names"
