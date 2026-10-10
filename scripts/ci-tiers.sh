#!/usr/bin/env bash
# Which CI tiers run (the "Choose test tiers" job). Changed files on stdin;
# EVENT and LABELS from the workflow. Prints heavy=, kit=, light=, docs=.
#
# - heavy: RPMs and the end to end jobs, Firefox/WebKit, the release
#   latency test. Off only on a pull request whose every file is frontend
#   source or docs.
# - kit: the offline kit test, on a pull request only when the kit, its
#   scripts or the spec changed.
# - light: frontend source and docs only: the Rust job is skipped (the
#   console job builds and tests the frontend; nothing in Rust reads it).
# - docs: docs only: the console job is skipped too. docs/api/ is not docs:
#   the OpenAPI snapshot is compiled into a console test.
# Pushes to main, the nightly run, manual runs and the full-ci label run
# everything. Skipped jobs count as passing for required checks.
set -euo pipefail
heavy=true kit=true light=false docs=false
changed=$(cat)
if [[ ${EVENT:-} == pull_request && ",${LABELS:-}," != *,full-ci,* ]]; then
    grep -qE '^(packaging/offline/|packaging/llm/model\.pin$|scripts/[^/]*offline[^/]*$|scripts/sign-rpms\.sh$|packaging/rpm/openvibes-platform\.spec$|crates/openvibes-admin/src/(setup/assistant|model_fetch)\.rs$|\.github/workflows/ci\.yml$|scripts/(test-)?ci-tiers\.sh$)' <<<"$changed" || kit=false
    docs_re='^(docs/|[^/]+\.md$)'
    front_re='^crates/openvibes-console/web/(src|tests|e2e|public)/'
    # Every file docs or frontend (and none of it docs/api/).
    if ! grep -qvE "$docs_re|$front_re" <<<"$changed" && ! grep -q '^docs/api/' <<<"$changed"; then
        heavy=false light=true
        grep -qE "$front_re" <<<"$changed" || docs=true
    elif ! grep -qvE "$docs_re|$front_re" <<<"$changed"; then
        heavy=false # docs/api/ only: no RPM or end to end job reads it
    fi
fi
printf 'heavy=%s\nkit=%s\nlight=%s\ndocs=%s\n' "$heavy" "$kit" "$light" "$docs"
