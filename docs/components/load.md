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

## Results (2026-09-23)

```
cpu: AMD Ryzen 9 3900X 12-Core Processor, 24 threads
memory: 31.2 GiB
kernel: 7.2.6-200.fc44.x86_64
postgresql: postgres (PostgreSQL) 18.6
tcp_tw_reuse: 2, ports: 32768-60999
generator, ingest, and PostgreSQL share this host
```

Ingest at its defaults (pool 16, `max_in_flight` 4096, release build of
`e5283d5`); PostgreSQL a fresh `initdb` cluster with default settings and
`fsync` on, Unix socket; 10 findings per batch, one batch per 60 heartbeats.
Latency columns are p50 / p99 / max in ms; CPU is cores for generator /
ingest / PostgreSQL.

| Agents | Interval | Window | Target req/s | Achieved req/s | All | Heartbeat | Findings | Max lag ms | Errors | CPU | Pass |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2000 | 2 s | 120 s | 1017 | 1017 | 1.5 / 9.8 / 198 | 1.5 / 2.5 / 8 | 10.1 / 13.8 / 198 | 2 | 0 | 0.65 / 0.64 / 0.42 | yes |
| 4000 | 2 s | 60 s | 2033 | 2033 | 1.6 / 36.4 / 159 | 1.6 / 36.3 / 159 | 10.7 / 61.0 / 133 | 609 | 0 | 1.34 / 1.38 / 0.84 | yes |

**Reading.** The spec target (about 1,000 req/s on one ingest instance)
holds with a wide margin: p99 9.8 ms, no errors, and under one core each for
ingest (0.64) and PostgreSQL (0.42). At twice the target it still passes,
but the tail grows (p99 36 ms, start lag 609 ms against the 1 s limit) while
no process is near CPU saturation, so something other than CPU (not
investigated here: candidates are WAL fsync on findings commits and the
16-connection pool) sets the next limit. Every request is a full TLS 1.3 +
mTLS handshake, as with real agents. Enrollment of 2,000 agents took 13.6 s
(147/s, 64 in parallel).

CI: the `fedora` job runs a 10 s smoke run (50 agents, findings every 5
ticks) against the installed binaries, so the tool keeps working.
