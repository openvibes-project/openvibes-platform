# load (openvibes-load and scripts/load/run.sh)

The load test (spec section 8; section 1, item 4). `openvibes-load` is a
workspace binary in `scripts/load/`, never packaged. It simulates N enrolled
agents with the agent's own transport (`openvibes-transport`), and
`scripts/load/run.sh` runs it against a fresh local platform (the same
`start_platform` as the integration test).

## What a tick is

Like the real agent, every tick of every simulated agent opens a **fresh
client**, so a new TLS 1.3 connection with mTLS. It sends a heartbeat (which
pays the handshake), and on that agent's findings ticks it also sends one
batch over the same connection (`--batch`, default 10
findings). Findings ticks come once every `--findings-every` ticks (default
60), staggered so each tick carries 1/60 of the agents rather than bursts.

## Distribution mode

With `--distribution-url` (`MODE=distribution` in `run.sh`), agents still
enroll through ingest, but every tick is one `POST /v1/rule-bundle` to
openvibes-distribution with no `current_version`: the full envelope every
time, the burst after a publish when every agent scans at once (SP2 spec
Q9). A 204 counts as an error, since this mode must measure full
responses. `run.sh` publishes a signed ~220 KB bundle
(`integration_bundle … 1 100`) through `openvibes-admin rules` first. The
summary adds `latency_ms.bundle`, `bundle_bytes`, and
`cpu_cores.distribution`.

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
- **Latency:** per request, from sending to the parsed response; the
  heartbeat's includes the TLS handshake. Queueing before a tick starts is
  not in it; it shows as lag. Nearest-rank p50, p99, and max, overall and per kind.
- **CPU:** from `/proc`, in cores (CPU seconds per second): the generator, the
  ingest process, and the postmaster with all its children. The postmaster's
  reaped-children time is included, so a backend that exits during the
  window still counts.
- **Pass:** no errors (every non-2xx or transport error is counted by kind),
  lag ≤ 1 s, and an achieved rate ≥ 95 % of the target. A worker thread that
  panics counts as an error (`worker panicked`). The achieved rate
  counts responses that **completed** inside the window, so a backlog the
  generator or server clears only later lowers it. Otherwise exit 1.

- **Memory:** at the end of the window: ingest RSS and peak RSS
  (`/proc/PID/status`), and PostgreSQL PSS summed over the postmaster and
  its children (`smaps_rollup`, so shared buffers count once).
- **Storage:** `run.sh` records the findings count and on-disk size (all
  partitions with indexes) before and after, in `$LOAD_DIR/storage.json`:
  `bytes_per_new_finding`, and with a pre-fill `prefilled_bytes_per_finding`.
  Generated findings match real agent finding sizes.

## Run

```sh
scripts/load/run.sh [AGENTS] [INTERVAL_MS] [DURATION_S]   # defaults 2000 2000 120
MODE=distribution scripts/load/run.sh 2000 2000 120        # rule bundles
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
| `PREFILL_FINDINGS` | 0 | first store N synthetic findings over the last 89 days (20 M ≈ 9.6 GB, about 5 min) |
| `INGEST_PORT`, `HEALTH_PORT` | 28523, 28580 | loopback ports |
| `MODE` | `ingest` | `distribution` for the rule-bundle run |
| `DIST_PORT`, `DIST_HEALTH_PORT` | 28524, 28581 | distribution's loopback ports |
| `BUNDLE_BIN` | `cargo run` of the example | prebuilt `integration_bundle` |

## How to test

`cargo test -p openvibes-load` covers the schedule and percentiles. The
runner's failure paths were each seen failing: an oversized batch
(`LOAD_ARGS="--findings-every 1 --batch 1001"`, errors counted, exit 1) and a
single worker (`--workers 1` at 400 agents/s, lag 1.7 s, exit 1).

The first smoke run found a real defect: a 42 ms p50 heartbeat from Nagle's
algorithm, fixed by `TCP_NODELAY` in ingest.

## Results (2026-09-23)

Memory and storage results (2026-09-24), including a run on a 20 M-finding
database, are in [`../sizing.md`](../sizing.md).

```
cpu: AMD Ryzen 9 3900X 12-Core Processor, 24 threads
memory: 31.2 GiB
kernel: 7.2.6-200.fc44.x86_64
postgresql: postgres (PostgreSQL) 18.6
tcp_tw_reuse: 2, ports: 32768-60999
generator, ingest, and PostgreSQL share this host
```

Ingest at its defaults (pool 16, `max_in_flight` 4096, release build of
the PM5 branch); PostgreSQL a fresh `initdb` cluster with default settings and
`fsync` on, Unix socket; 10 findings per batch, one batch per 60 heartbeats.
Latency columns are p50 / p99 / max in ms; CPU is cores for generator /
ingest / PostgreSQL.

| Agents | Interval | Window | Target req/s | Achieved req/s | All | Heartbeat | Findings | Max lag ms | Errors | CPU | Pass |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2000 | 2 s | 120 s | 1017 | 1017 | 1.5 / 9.7 / 86 | 1.5 / 2.4 / 7 | 10.0 / 14.1 / 86 | 2 | 0 | 0.63 / 0.63 / 0.41 | yes |
| 4000 | 2 s | 60 s | 2033 | 2051 | 1.7 / 33.1 / 157 | 1.7 / 33.1 / 157 | 10.8 / 55.2 / 157 | 561 | 0 | 1.35 / 1.38 / 0.85 | yes |

**Reading.** The spec target (about 1,000 req/s on one ingest instance)
holds with a wide margin: 1017 req/s completed, p99 9.7 ms, no errors, and
under one core each for ingest (0.63) and PostgreSQL (0.41). At twice the
target it still passes, but the tail grows (p99 33 ms, start lag 561 ms
against the 1 s limit) while no process is near CPU saturation in aggregate.
The cause is unattributed: it may be the generator (per-tick client setup,
one scheduler thread) as well as the server (WAL fsync on findings commits,
the 16-connection pool). Each tick opens one new TLS 1.3 + mTLS connection:
the heartbeat pays the handshake, and a findings batch reuses that
connection, as the real agent does. Latency is service time from sending;
queueing shows as lag. Enrollment of 2,000 agents took 13.2 s (151/s, 64 in
parallel).

CI: the `fedora` job runs a 10 s smoke run (50 agents, findings every 5
ticks) against the installed binaries, so the tool keeps working.

## Distribution results (2026-09-24)

`MODE=distribution scripts/load/run.sh 2000 2000 120`: 2,000 agents, one
full-bundle fetch every 2 s each, a new mTLS connection per fetch.

- **Host:** AMD Ryzen 9 3900X (12 cores, 24 threads), 31.2 GiB, kernel
  7.2.6-200.fc44, PostgreSQL 18.6; generator, distribution, ingest, and
  PostgreSQL on the same host; `tcp_tw_reuse` 2.
- **Envelope:** 219,892 bytes, signed, published with `openvibes-admin rules`.
- **Rate:** target 1,000 req/s, achieved 999.99 req/s (120,000 requests in
  the 120 s window, about 220 MB/s of envelopes), 0 errors, max schedule
  lag 0.7 ms. Pass.
- **Latency (whole request, handshake included):** p50 1.86 ms, p99
  2.49 ms, max 16.9 ms.
- **CPU (cores, averaged over the window):** distribution 0.77, PostgreSQL
  0.55, generator 0.85.

The spec's Q9 target holds with most of the host idle; one instance serves
the post-publish burst of 2,000 agents a second. The ingest mode smoke and
this mode both run in CI at 50 agents.
