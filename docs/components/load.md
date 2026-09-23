# load (openvibes-load and scripts/load/run.sh)

The load test (spec section 8; section 1, item 4). `openvibes-load` is a
workspace binary in `scripts/load/`, never packaged. It simulates N enrolled
agents with the agent's own transport (`openvibes-transport`), and
`scripts/load/run.sh` runs it against a fresh local platform (the same
`start_platform` as the integration test).

## What a tick is

Like the real agent, every tick of every simulated agent opens a **fresh
client**, so a new TLS 1.3 connection with mTLS. It sends a heartbeat, and on
that agent's findings ticks it also sends one batch (`--batch`, default 10
findings). Findings ticks come once every `--findings-every` ticks (default
60), staggered so each tick carries 1/60 of the agents rather than bursts.

## Request mix

The spec's cadence is one heartbeat a minute and one batch an hour: 60
heartbeats per batch. Reaching about 1,000 req/s at that cadence would take
60,000 enrolled agents, so the run keeps the 60:1 mix and shortens the
interval instead: 2,000 agents at 2 s give 1,000 heartbeats/s plus about 17
batches/s. This understates effects that need 60,000 distinct agents (the
`agents` table's size). The `last_seen_at` write throttle is keyed on time,
so it behaves the same.

## Measurement

- **Open loop:** ticks are due on a fixed schedule whether or not the server
  keeps up; a pool of `--workers` threads (default 256) runs them.
  `max_lag_ms` is how late the most delayed tick started.
- **Warm-up:** enrollment and the first interval are excluded. Rate, latency,
  and CPU cover the window after it (`window_s` = `--duration-s`).
- **Latency:** per request, from sending to the parsed response, including
  the TLS handshake. Nearest-rank p50, p99, and max, overall and per kind.
- **CPU:** from `/proc`, in cores (CPU seconds per second): the generator, the
  ingest process, and the postmaster with all its children.
- **Pass:** no errors (every non-2xx or transport error is counted by kind),
  lag ≤ 1 s, and an achieved rate ≥ 95 % of the target. Otherwise exit 1.

## Run

```sh
scripts/load/run.sh [AGENTS] [INTERVAL_MS] [DURATION_S]   # defaults 2000 2000 120
```

It prints a hardware block (CPU, threads, memory, kernel, PostgreSQL,
`tcp_tw_reuse` and the port range, and that everything shares one host),
then the JSON summary; it is also kept in `$LOAD_DIR/summary.json`.

| Variable | Default | Use |
|---|---|---|
| `LOAD_DIR` | `target/load/run` | working directory (recreated) |
| `LOAD_BIN` | builds `target/release/openvibes-load` | prebuilt generator |
| `OPENVIBES_BIN_DIR` | builds `target/release` | ingest and admin binaries |
| `LOAD_ARGS` | none | extra generator flags, e.g. `--workers 64` |
| `INGEST_EXTRA` | none | extra `ingest.toml` lines |
| `INGEST_PORT`, `HEALTH_PORT` | 28523, 28580 | loopback ports |

## How to test

`cargo test -p openvibes-load` covers the schedule and percentiles. The
runner's failure paths were each seen failing: an oversized batch
(`LOAD_ARGS="--findings-every 1 --batch 1001"`, errors counted, exit 1) and a
single worker (`--workers 1` at 400 agents/s, lag 1.7 s, exit 1).

The first smoke run found a real defect: a 42 ms p50 heartbeat from Nagle's
algorithm, fixed by `TCP_NODELAY` in ingest.

## Results

Filled in by the PM5 runs below.
