# integration-agent

`scripts/integration-agent.sh`: the cross-repository integration test (spec
section 8). The real `openvibes-agent` binary, built at the revision the
platform pins for `openvibes-core`, runs against `openvibes-ingest` and
PostgreSQL. Everything runs as the current, unprivileged user under
`target/integration/run`, which is recreated on every run.

## What it proves

1. Platform up: a throwaway PostgreSQL cluster (Unix socket only),
   `openvibes-admin migrate` and `maintenance`, the built-in CA (root,
   intermediate, a server certificate for `localhost` and `127.0.0.1`),
   ingest on loopback until `/ready` answers.
2. The agent, with a signed test bundle (`integration_bundle` example, two
   always-true rules) and a token from `openvibes-admin token create`,
   enrolls, sends an accepted heartbeat, and delivers its findings **exactly
   once**: its queue is empty and the ids it recorded as acknowledged equal
   the ids in `findings`.

Checks read only real state: PostgreSQL rows, the agent's `queue.sqlite`,
and ingest's JSON request log.

## Run

```sh
scripts/integration-agent.sh
```

Exit 0 with one `ok:` line per check. On failure it prints `FAIL: ...`, the
tails of the ingest and agent logs, and stops every process it started.

| Variable | Default | Use |
|---|---|---|
| `OPENVIBES_BIN_DIR` | builds `target/release` | where `openvibes-ingest` and `openvibes-admin` are (e.g. `/usr/bin` after installing the RPMs) |
| `AGENT_BIN` | builds into `target/integration/agent` | a prebuilt agent at the pinned revision |
| `BUNDLE_BIN` | `cargo run` of the example | a prebuilt `integration_bundle` |
| `INGEST_PORT`, `HEALTH_PORT` | 28423, 28480 | loopback ports |

## Requirements

`postgresql-server` (`initdb`, `pg_ctl`, `createdb`, `psql`), `sqlite`,
`jq`, `curl`, a Rust toolchain, and git access to the private agent
repository (`CARGO_NET_GIT_FETCH_WITH_CLI=true` is set by the script).
`scripts/integration-lib.sh` holds the shared helpers (`agent_rev`,
`build_agent`, `wait_for`).

## How to test

The script is the test. Each check was first seen failing: no token file
(`agent enrolled` fails), a wrong finding count, a wrong key for the bundle.
