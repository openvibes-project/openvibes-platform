#!/usr/bin/env bash
# Builds target/rpm/RPMS/x86_64/openvibes-{ingest,distribution,vulns,admin,llm,llm-model}-*.rpm.
# openvibes-llm-model carries no model bytes (the model is fetched at run time).
# OV_LLM=0 skips openvibes-llm (and its llama.cpp build); OV_LLM_VULKAN=1
# adds openvibes-llm-vulkan (needs glslc and the Vulkan headers).
# OV_VERSION overrides the package version (a lower one for the update test);
# OV_RPM_TOPDIR the rpmbuild directory (default target/rpm); OV_RELEASE the
# RPM release (default 1; CI sets 1.1.ci<run>, board #88).
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_NET_GIT_FETCH_WITH_CLI=true
packages=(-p openvibes-ingest -p openvibes-distribution -p openvibes-vulns -p openvibes-admin -p openvibes-signer -p openvibes-fetch)
[[ ${OV_LLM:-1} == 1 ]] && packages+=(-p openvibes-llm)
cargo build --release --locked "${packages[@]}"
llm=(--without llm)
if [[ ${OV_LLM:-1} == 1 ]]; then
    scripts/build-llama-server.sh cpu
    llm=(--with llm)
    if [[ ${OV_LLM_VULKAN:-0} == 1 ]]; then
        scripts/build-llama-server.sh vulkan
        llm+=(--with vulkan)
    fi
fi
version=${OV_VERSION:-$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)}
topdir=${OV_RPM_TOPDIR:-$PWD/target/rpm}
rpmbuild -bb packaging/rpm/openvibes-platform.spec "${llm[@]}" \
    --define "_topdir $topdir" --define "_sourcedir $PWD" \
    --define "ov_version $version" --define "ov_release ${OV_RELEASE:-1}"
ls "$topdir"/RPMS/*/openvibes-*.rpm
