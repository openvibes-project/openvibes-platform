#!/bin/sh
# Joins the bundled model's two package parts into the one GGUF file
# openvibes-llm loads, checks it against the pinned SHA-256, and removes the
# parts. Run by the openvibes-llm-model package's %posttrans; safe to repeat.
# The parts exist because a release asset may not exceed 2 GiB.
# OV_LLM_SHARE and OV_LLM_MODELS are overridden only by the CI test.
set -eu
share=${OV_LLM_SHARE:-/usr/share/openvibes-llm/model}
models=${OV_LLM_MODELS:-/var/lib/openvibes-llm/models}
# shellcheck disable=SC1091
. "$share/model.env"
target=$models/$LLM_MODEL_FILE
digest() { sha256sum "$1" | cut -d ' ' -f1; }
if [ -f "$target" ] && [ "$(digest "$target")" = "$LLM_MODEL_SHA256" ]; then
    rm -f "$share/$LLM_MODEL_FILE".part*
    exit 0
fi
for part in "$share/$LLM_MODEL_FILE".part*; do
    [ -f "$part" ] || { echo "openvibes-llm-model: model parts are missing" >&2; exit 1; }
done
tmp=$models/.$LLM_MODEL_FILE.joining
trap 'rm -f "$tmp"' EXIT
(umask 077; cat "$share/$LLM_MODEL_FILE".part* > "$tmp")
if [ "$(digest "$tmp")" != "$LLM_MODEL_SHA256" ]; then
    echo "openvibes-llm-model: joined model does not match its pinned SHA-256" >&2
    exit 1
fi
chmod 0444 "$tmp"
mv "$tmp" "$target"
rm -f "$share/$LLM_MODEL_FILE".part*
