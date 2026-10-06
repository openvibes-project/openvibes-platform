#!/usr/bin/env bash
# Downloads the bundled model and its licence into target/llm-model/ and
# checks the model's SHA-256 against packaging/llm/model.pin (an existing
# file is reused once it matches).
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=../packaging/llm/model.pin
. packaging/llm/model.pin
dir=target/llm-model
mkdir -p "$dir"
fetch() { # URL DEST
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --retry 3 --output "$2.part" "$1"
    mv "$2.part" "$2"
}
model=$dir/$LLM_MODEL_FILE
if ! { [ -f "$model" ] && echo "$LLM_MODEL_SHA256  $model" | sha256sum --check --quiet 2>/dev/null; }; then
    fetch "$LLM_MODEL_URL" "$model"
    echo "$LLM_MODEL_SHA256  $model" | sha256sum --check --quiet \
        || { rm -f "$model"; echo "model SHA-256 mismatch" >&2; exit 1; }
fi
[ -f "$dir/LICENSE.model" ] || fetch "$LLM_MODEL_LICENSE_URL" "$dir/LICENSE.model"
echo "$model"
