#!/usr/bin/env bash
# Render the checked SVG mark into the browser and app-icon sizes.
set -euo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -- "${script_dir}/.." && pwd -P)"
readonly brand_root="${repository_root}/crates/openvibes-console/web/public/brand"
readonly source_mark="${brand_root}/openvibes-mark.svg"
readonly temporary_root="$(mktemp -d)"
trap 'rm -rf -- "${temporary_root}"' EXIT

if command -v magick >/dev/null 2>&1; then
    renderer=(magick)
elif command -v convert >/dev/null 2>&1; then
    renderer=(convert)
else
    printf 'error: ImageMagick is required to render console brand assets\n' >&2
    exit 1
fi

render_icon() {
    local size="$1"
    local content_size="$2"
    local output="$3"

    "${renderer[@]}" \
        -background none \
        "${source_mark}" \
        -resize "${content_size}x${content_size}" \
        -gravity center \
        -extent "${size}x${size}" \
        -strip \
        -depth 8 \
        -define png:exclude-chunk=date,time \
        "PNG32:${temporary_root}/${output}"
}

render_icon 32 30 openvibes-favicon-32.png
render_icon 192 172 openvibes-mark-192.png
render_icon 512 460 openvibes-mark-512.png

install -m 0644 "${temporary_root}"/*.png "${brand_root}/"
