# openvibes-ingest

The agent-facing, receive-only service on port **18423**: enrollment,
renewal, heartbeats, and finding delivery (protocol P1 and P2). Design:
[`../specs/2026-09-23-ingest-subproject-design.md`](../specs/2026-09-23-ingest-subproject-design.md),
sections 3 and 6.

## Status

Skeleton only (PM0). The binary exits with status 2. Endpoints arrive in PM3.

## What exists

`tests/protocol_fixtures.rs` runs every fixture in the `protocol/` submodule
(pinned `openvibes-protocol` revision) through the `openvibes-core` contract
types: every `valid*` fixture must parse and validate, every `invalid*` must
be refused. A protocol message without a mapped type fails the test, so a new
message cannot be missed.

## Test

`git submodule update --init && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --locked -p openvibes-ingest`
