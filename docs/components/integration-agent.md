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
3. **Restart:** the agent is stopped and started; it reconnects (a new
   accepted heartbeat) and nothing is delivered twice.
4. **Renewal:** with the agent stopped, `obtained_at_ms` in its
   `identity.sqlite` is set to 0, which makes renewal due at once (it is due
   at two thirds of the lifetime). This avoids faking the clock, which would
   future-date findings that ingest then refuses. The agent gets a second
   certificate, and that certificate authenticates the next heartbeat.
5. **Revocation and re-enrollment:** with the agent stopped, it is revoked
   and its scan interval set to 60 s. On restart it queues findings, gets
   403 `identity_revoked`, forgets its identity, and keeps the findings
   queued. With a new token it re-enrolls as a new `agent_id` (the old one
   stays `revoked`) and delivers the findings it queued while revoked, again
   exactly once. The ids queued while revoked are recorded and each must
   be stored under the new `agent_id`, so a dropped batch cannot hide behind
   a later scan.

A full run takes 2 to 3 minutes, because the agent ticks every 60 s.

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
| `INTEGRATION_DIR` | `target/integration/run` | working directory; every ancestor must be owned by root or the current user (the agent refuses its state directory otherwise) |

## Requirements

`postgresql-server` (`initdb`, `pg_ctl`, `createdb`, `psql`), `sqlite`,
`jq`, `curl`, a Rust toolchain, and git access to the private agent
repository (`CARGO_NET_GIT_FETCH_WITH_CLI=true` is set by the script).
`scripts/integration-lib.sh` holds the shared helpers: `agent_rev`,
`build_agent`, `wait_for`, and `start_platform` (PostgreSQL, schema, CA,
and ingest until `/ready`, with an `EXIT` trap that stops them and prints
every log's tail on failure), which the load test reuses.

## How to test

The script is the test. Each check was first seen failing: no token file
(`agent enrolled` fails), a wrong finding count, a wrong key for the bundle,
renewal not forced, a wrong status for the revocation answer. A run that
fails early (for example `INGEST_PORT=1`) leaves no process behind.

CI: the `fedora` job installs the RPMs in a `fedora:44` container, builds
the agent and bundle tool as root (which has the git credentials), and runs
this script as an unprivileged user `ci` with `OPENVIBES_BIN_DIR=/usr/bin` and `INTEGRATION_DIR=/home/ci/run`
(`initdb` refuses root). This is spec section 1, item 1, on Fedora with
Fedora's PostgreSQL.
