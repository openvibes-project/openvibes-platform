#!/usr/bin/env bash
# Which CI tiers run (the "Choose test tiers" job). Changed files on stdin;
# EVENT and LABELS from the workflow. Prints heavy=, kit=, docs=.
#
# - heavy: RPMs and the end to end jobs, Firefox/WebKit, the release
#   latency test. Off only on a pull request whose every file is frontend
#   source or docs.
# - kit: the offline kit test, on a pull request only when the kit, its
#   scripts or the spec changed.
# - docs: docs only: the Rust and console jobs are skipped. docs/api/ is
#   not docs: the OpenAPI snapshot is compiled into a console test. The
#   frontend is not either: Rust compiles web/public in (router.rs) and
#   checks the built frontend (build.rs, embedded-ui), so a frontend
#   change runs Rust (security review, 2026-10-10).
# Any *.md counts as docs (folder READMEs, .github, planning). A push to main
# skips only for docs (the previous commit's diff on stdin; nothing on stdin
# runs everything). The nightly run, manual runs and the full-ci label run
# everything. Skipped jobs count as passing for required checks.
set -euo pipefail
heavy=true kit=true docs=false
docs_re='^docs/|\.md$'
changed=$(cat)
# No changed files listed (a failed diff): run everything.
if [[ ${EVENT:-} == pull_request && -n $changed && ",${LABELS:-}," != *,full-ci,* ]]; then
    grep -qE '^(packaging/offline/|packaging/llm/model\.pin$|scripts/[^/]*offline[^/]*$|scripts/sign-rpms\.sh$|packaging/rpm/openvibes-platform\.spec$|crates/openvibes-admin/src/(setup/assistant|model_fetch)\.rs$|\.github/workflows/ci\.yml$|scripts/(test-)?ci-tiers\.sh$)' <<<"$changed" || kit=false
    front_re='^crates/openvibes-console/web/(src|tests|e2e|public)/'
    # Every file docs or frontend (and none of it docs/api/).
    # Frontend source and docs: no RPM or end to end job reads them.
    grep -qvE "$docs_re|$front_re" <<<"$changed" || heavy=false
    if ! grep -qvE "$docs_re" <<<"$changed" && ! grep -q '^docs/api/' <<<"$changed"; then
        docs=true
    fi
fi
# A push to main: only the docs rule; an empty diff (no usable previous commit) runs everything.
if [[ ${EVENT:-} == push && -n $changed ]] && ! grep -qvE "$docs_re" <<<"$changed" && ! grep -q '^docs/api/' <<<"$changed"; then
    heavy=false kit=false docs=true
fi
printf 'heavy=%s\nkit=%s\ndocs=%s\n' "$heavy" "$kit" "$docs"
