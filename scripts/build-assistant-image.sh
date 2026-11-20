#!/bin/bash
# Build the assistant container image (packaging/assistant/Containerfile,
# #651) from the openvibes-llm EL10 RPM (built by build-rpm.sh on
# almalinux:10).
#
# Usage: bash scripts/build-assistant-image.sh RPM_DIR [IMAGE]
#   IMAGE defaults to openvibes-assistant:dev. ENGINE (docker or podman)
#   picks the builder; the default is whichever is installed, podman first.
set -euo pipefail
cd "$(dirname "$0")/.."

rpms=${1:?usage: build-assistant-image.sh RPM_DIR [IMAGE]}
image=${2:-openvibes-assistant:dev}
engine=${ENGINE:-$(command -v podman || command -v docker || true)}
[[ -n $engine ]] || { echo "neither podman nor docker is installed" >&2; exit 1; }

mapfile -t found < <(compgen -G "$rpms/openvibes-llm-[0-9]*.rpm" || true)
[[ ${#found[@]} -eq 1 ]] || { echo "$rpms needs exactly one openvibes-llm RPM (found ${#found[@]})" >&2; exit 1; }

ctx=$(mktemp -d)
trap 'rm -rf "$ctx"' EXIT
cp "${found[0]}" "$ctx/openvibes-llm.rpm"
cp packaging/assistant/openvibes-assistant-start "$ctx/"
chmod 0755 "$ctx/openvibes-assistant-start"
"$engine" build -f packaging/assistant/Containerfile -t "$image" "$ctx"
