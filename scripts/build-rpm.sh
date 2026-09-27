#!/usr/bin/env bash
# Builds target/rpm/RPMS/x86_64/openvibes-{ingest,distribution,vulns,admin,llm}-*.rpm.
# OV_LLM=0 skips openvibes-llm (and its llama.cpp build); OV_LLM_VULKAN=1
# adds openvibes-llm-vulkan (needs glslc and the Vulkan headers).
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_NET_GIT_FETCH_WITH_CLI=true
cargo build --release --locked -p openvibes-ingest -p openvibes-distribution -p openvibes-vulns -p openvibes-admin
llm=(--without llm)
if [[ ${OV_LLM:-1} == 1 ]]; then
    cargo build --release --locked -p openvibes-llm
    scripts/build-llama-server.sh cpu
    llm=(--with llm)
    if [[ ${OV_LLM_VULKAN:-0} == 1 ]]; then
        scripts/build-llama-server.sh vulkan
        llm+=(--with vulkan)
    fi
fi
version=$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)
rpmbuild -bb packaging/rpm/openvibes-platform.spec "${llm[@]}" \
    --define "_topdir $PWD/target/rpm" --define "_sourcedir $PWD" \
    --define "ov_version $version"
ls target/rpm/RPMS/*/openvibes-*.rpm
