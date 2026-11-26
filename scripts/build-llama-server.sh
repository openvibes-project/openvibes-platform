#!/usr/bin/env bash
# Builds target/llama/<variant>/llama-server from the pinned llama.cpp source
# (packaging/llm/llama-cpp.pin). Variants: cpu (default; AVX2 baseline on
# x86_64, the plain ARMv8-A baseline on aarch64) and
# vulkan (NVIDIA, AMD, and Intel GPUs; needs glslc and the Vulkan headers).
#
# The build leaves out everything openvibes-llm does not use, so it is not
# there to be misused: no subprocess support (the server's built-in agent
# tools, including shell execution, and router mode), no RPC backend, no
# OpenSSL (no model downloads), no web UI, a static binary.
#
# Set LLAMA_SOURCE_TARBALL to a local copy of the pinned tarball to build
# offline; its SHA-256 is checked either way.
set -euo pipefail
cd "$(dirname "$0")/.."
variant=${1:-cpu}
case $variant in
    cpu) gpu=(-DGGML_VULKAN=OFF) ;;
    vulkan) gpu=(-DGGML_VULKAN=ON) ;;
    *) echo "usage: $0 [cpu|vulkan]" >&2; exit 2 ;;
esac
# shellcheck source=../packaging/llm/llama-cpp.pin
. packaging/llm/llama-cpp.pin

work=target/llama/src
mkdir -p "$work"
tarball=${LLAMA_SOURCE_TARBALL:-$work/$(basename "$LLAMA_SOURCE_URL")}
if [ ! -f "$tarball" ]; then
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --output "$tarball.part" "$LLAMA_SOURCE_URL"
    mv "$tarball.part" "$tarball"
fi
echo "$LLAMA_SOURCE_SHA256  $tarball" | sha256sum --check --quiet

source_dir=$work/llama.cpp-$LLAMA_CPP_COMMIT
# A folder without its CMakeLists.txt is a leftover (CI's Cargo cache
# restores target/ without the source files): extract again.
if [ ! -f "$source_dir/CMakeLists.txt" ]; then
    rm -rf "$source_dir" "$work/extract"
    mkdir -p "$work/extract"
    tar -xzf "$tarball" -C "$work/extract" --no-same-owner --no-same-permissions
    mv "$work"/extract/llama.cpp-* "$source_dir"
    rm -rf "$work/extract"
fi

# The CPU baseline the binary may assume: AVX2 on x86_64 (#605: the plain
# ARMv8-A baseline, no extensions, on aarch64).
case $(uname -m) in
    x86_64) cpu=(-DGGML_AVX=ON -DGGML_AVX2=ON -DGGML_FMA=ON -DGGML_F16C=ON -DGGML_BMI2=ON -DGGML_AVX512=OFF) ;;
    aarch64) cpu=() ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac

build=target/llama/build-$variant
cmake -S "$source_dir" -B "$build" -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF -DGGML_BACKEND_DL=OFF \
    -DGGML_NATIVE=OFF -DGGML_CPU_ALL_VARIANTS=OFF \
    "${cpu[@]}" -DGGML_RPC=OFF "${gpu[@]}" \
    -DLLAMA_SUBPROCESS=OFF -DLLAMA_OPENSSL=OFF -DLLAMA_BUILD_UI=OFF \
    -DLLAMA_USE_PREBUILT_UI=OFF -DLLAMA_LLGUIDANCE=OFF \
    -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_APP=OFF \
    -DLLAMA_BUILD_SERVER=ON -DLLAMA_BUILD_TOOLS=ON \
    -DLLAMA_BUILD_NUMBER=0 -DLLAMA_BUILD_COMMIT="${LLAMA_CPP_COMMIT:0:12}" >/dev/null
cmake --build "$build" --target llama-server -j "$(nproc)"

# The switches must have taken effect: no process spawning beyond ggml's
# crash backtrace (disabled by the unit), no TLS library.
binary=$build/bin/llama-server
if nm -D "$binary" | grep -qE ' U (posix_spawnp?|execv|execve|execvp|execvpe|fexecve|execl|execle|popen|system)@'; then
    echo "llama-server can start processes; subprocess support was not disabled" >&2
    exit 1
fi
if ldd "$binary" | grep -qE 'libssl|libcrypto|libcurl'; then
    echo "llama-server links a TLS library; downloads were not disabled" >&2
    exit 1
fi
install -D -m 0755 "$binary" "target/llama/$variant/llama-server"
install -D -m 0644 "$source_dir/LICENSE" target/llama/LICENSE.llama.cpp
echo "target/llama/$variant/llama-server"
