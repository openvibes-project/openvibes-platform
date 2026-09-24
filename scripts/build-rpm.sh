#!/usr/bin/env bash
# Builds target/rpm/RPMS/x86_64/openvibes-{ingest,distribution,admin}-*.rpm.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_NET_GIT_FETCH_WITH_CLI=true
cargo build --release --locked -p openvibes-ingest -p openvibes-distribution -p openvibes-admin
version=$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)
rpmbuild -bb packaging/rpm/openvibes-platform.spec \
    --define "_topdir $PWD/target/rpm" --define "_sourcedir $PWD" \
    --define "ov_version $version"
ls target/rpm/RPMS/*/openvibes-*.rpm
