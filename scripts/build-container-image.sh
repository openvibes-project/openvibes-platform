#!/bin/bash
# Build the platform container image (packaging/container/Containerfile)
# from a folder of EL10 RPMs: the platform's, built by build-rpm.sh and
# build-console-rpm.sh on almalinux:10, and the rules package.
#
# Usage: bash scripts/build-container-image.sh RPM_DIR [IMAGE]
#   IMAGE defaults to openvibes-platform:dev. ENGINE (docker or podman)
#   picks the builder; the default is whichever is installed, podman first.
set -euo pipefail
cd "$(dirname "$0")/.."

rpms=${1:?usage: build-container-image.sh RPM_DIR [IMAGE]}
image=${2:-openvibes-platform:dev}
engine=${ENGINE:-$(command -v podman || command -v docker || true)}
[[ -n $engine ]] || { echo "neither podman nor docker is installed" >&2; exit 1; }

for p in admin console ingest distribution vulns signer fetch llm rules-*; do
    compgen -G "$rpms/openvibes-$p-[0-9]*.rpm" > /dev/null ||
        { echo "$rpms has no openvibes-$p RPM" >&2; exit 1; }
done

ctx=$(mktemp -d)
trap 'rm -rf "$ctx"' EXIT
mkdir "$ctx/rpms"
cp "$rpms"/openvibes-*.rpm "$ctx/rpms/"
cp packaging/container/openvibes-container-start packaging/container/openvibes-container-start.service "$ctx/"
rm -f "$ctx"/rpms/*-debuginfo-* "$ctx"/rpms/*-debugsource-* "$ctx"/rpms/openvibes-agent-*
"$engine" build -f packaging/container/Containerfile -t "$image" "$ctx"
