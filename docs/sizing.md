# Sizing: platform and agent

Status 2026-09-24, after sub-project 1 (PM0–PM5) and the sizing runs.
**Measured** figures come from the tests named with them. Figures marked
*estimate* are not measured. Revise this page when new measurements replace
them.

## What was measured

### Agent

Source: a local-only run on Fedora 44 with 3,610 RPMs installed and three
collectors (processes, packages, ports).

| | Value |
|---|---|
| One scan | ~0.05–0.07 s CPU (it reads ~174 MB of RPM headers) |
| Memory | 18 MB peak RSS, 16.7 MB idle; 1 thread |
| Idle CPU | 0 |
| Binary | 6.3 MB |
| Export | 0.05–0.09 s; inventory file 432 KB |
| Network | one TLS 1.3 + mTLS connection per 60 s tick (heartbeat, plus a findings batch when queued) |

### Platform

Source: `scripts/load/run.sh`, results in
[`components/load.md`](components/load.md).
- Hardware: Ryzen 9 3900X, 24 threads, 31 GiB RAM, Fedora 44, PostgreSQL 18.6
  with default settings.
- The generator, ingest and PostgreSQL shared the one host.
- The database was fresh, with no retained data.

| Load | Ingest CPU | PostgreSQL CPU | p50 / p99 | Errors |
|---|---|---|---|---|
| 1,017 req/s | 0.63 cores | 0.41 cores | 1.5 / 9.7 ms | 0 |
| 2,051 req/s | 1.38 cores | 0.85 cores | 1.7 / 33 ms | 0 |

Memory and storage, from `scripts/load/run.sh` at the 1,017 req/s target
(2,000 agents at 2 s, 120 s measured). The second run used
`PREFILL_FINDINGS=20000000`, a database of 20 million findings spread over
the last 89 days.

| Run | Findings stored | Ingest RSS | PostgreSQL PSS | p50 / p99 | Errors |
|---|---|---|---|---|---|
| fresh database | 0 → 20,340 | 16.8 MiB | 95 MiB | 1.2 / 9.1 ms | 0 |
| 20 M findings, 89 days | 20 M → 20.02 M (9.6 GB) | 15.8 MiB | 190 MiB | 1.2 / 9.1 ms | 0 |

- **Disk per stored finding:** 480 bytes in bulk (20 M pre-filled rows) and
  524 bytes from live delivery. Both include the partitioned table, its
  primary-key index and TOAST, with finding sizes matching real agent
  findings (64-hex id, ~65-character message, one evidence key).
- **Current state:** `current_findings` costs about 320 bytes per agent and
  rule (20,000 rows took 6.5 MB).
- **A large history does not slow ingest:** latency, CPU and throughput were
  the same on the empty and the 9.6 GB database, because inserts touch only
  today's partition and its index.
- **PostgreSQL memory:** measured as PSS summed over the postmaster and its
  backends, so shared buffers count once. It ran at default settings
  (`shared_buffers` 128 MB).

At the real cadence of one heartbeat per minute and one findings batch per
hour, 1,017 req/s corresponds to about **60,000 agents**. Enrollment ran at
about 150 agents/s, so 50,000 agents enroll in roughly 6 minutes.

### Vulnerability management (VM spec §10)

Source: `crates/openvibes-vulns/examples/scale.rs` (2026-09-25), same host
and PostgreSQL 18.6 at default settings, with the pool's 10 s statement
timeout the services use. Setup:
- 10,000 synthetic Fedora 44 hosts, each with this host's real 3,613 RPMs.
- Hosts come in 20 generations: generation g has about g % of the packages
  an advisory fixes held just below the fix, so matching opens real
  vulnerabilities.
- Inventories are stored through `inventory::replace` (ingest's call, as
  `openvibes_ingest`, 16 at a time).
- The feed is the real Fedora 44 updateinfo (385 advisories), matched as
  `openvibes_vulns`.

First run (before the fixes) and second run (matching in batches of 500
hosts, feed recorded current only after its match):

| Step | 500 hosts | 10,000 hosts, first run | 10,000 hosts, second run |
|---|---|---|---|
| Ingest, all inventories | 7.9 s (64 hosts/s) | 151 s (66 hosts/s) | 149 s (67 hosts/s) |
| Ingest, per host p50 / p99 | 231 / 594 ms | 221 / 597 ms | 219 / 585 ms |
| `host_packages` | 1.8 M rows, 347 MB | 36.1 M rows, 6.7 GB (691 KiB per host) | same |
| `package_versions` | 3,686 rows, 1 MB | 3,686 rows, 1 MB | same |
| Feed import + match of every host | 1.6 s, 12,200 open | **fails: statement timeout (10 s)** | **fails: statement timeout (10.5 s)**; recorded as failed, so the next check retries |
| Re-match of every host | 0.9 s | **fails: statement timeout (10 s)** | **38 s, 244,000 open** |
| `match_host`, one host p50 / max | 43 / 44 ms | 45 / 86 ms | 19 / 22 ms |
| `vulns summary` | 50 ms | not meaningful | 632 ms |
| `vulns list` (no filter) | 0.76 s (10,000 rows) | not meaningful | **fails: statement timeout** |

Findings (second run first):
- **Fixed:** matching in batches of 500 hosts re-matches all 10,000 in
  38 s, well inside the hourly interval.
- **Fixed in a third run:** the first import after a feed's arrival had
  timed out because the newly inserted advisory rows had no planner
  statistics; the import now runs `ANALYZE` on the advisory tables
  (schema 12 grants `openvibes_vulns` `MAINTAIN`). Third run: feed import
  plus match of all 10,000 hosts in 31.6 s (244,000 open), re-match
  29.7 s, `match_host` 14 ms.
- **Fixed in a third run:** `vulns list` without filters had timed out at
  244,000 open vulnerabilities because it combined every row's CVEs and
  enrichment; it now combines each advisory's once. Third run: 0.63 s for
  the first 10,000 by priority; `--host` 36 ms; `summary` 0.8 s.
- **Found in the first run:** matching a whole release did not scale past a few thousand hosts.
  The candidates query covers every host at once and exceeds the 10 s
  statement timeout at 10,000 hosts. Per-host matching (after an inventory
  change) stays at about 45 ms.
- **A failed match is not retried.** The import records the feed as
  current before matching, so the next hourly check finds it unchanged and
  skips it. Hosts get the new advisories only when their own inventory
  changes.
- **Storage is heavy:** a row per host and package costs about 190 bytes
  (text agent id, two indexes), so 6.7 GB for 10,000 hosts and about
  34 GB for 50,000.
- **Ingest holds up:** 66 inventory replacements per second. Agents send
  only on change, so a full-fleet change (a mass update) takes about
  2.5 min per 10,000 hosts.

## Agent requirements

| | Minimum | Recommended |
|---|---|---|
| CPU | any x86_64 core | same |
| RAM | 32 MB free | 64 MB free |
| Disk | 50 MB (binary + state) | 400 MB: the queue alone may reach 256 MiB during long platform outages |
| OS | Linux (tested: Fedora 44) | same |

The agent's disk use depends on how much the local queue holds before old
data rotates out. That is not measured yet.

## Platform requirements (one host: ingest + PostgreSQL)

| | Small: ≤ 1,000 agents (~17 req/s) | Up to 50,000 agents (~850 req/s) |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 2 GB | 8 GB |
| Disk | SSD, ≈ 30 GB for 90 days (retention table) | NVMe/SSD with fast fsync, ≈ 0.15–1.4 TB for 90 days by match rate (retention table) |

- **CPU:** the measured need at 50,000 agents is about 1 core for ingest plus
  0.5 for PostgreSQL. 4 vCPU doubles that, which leaves room for:
  - server cores slower than a desktop Ryzen;
  - vacuum and maintenance;
  - the console later on.
- **RAM:**
  - What ran: ingest used 16 MiB, and PostgreSQL 95–190 MiB at default
    settings, 9.6 GB of history included. So 2 GB carries a small
    deployment, OS included.
  - 8 GB for a large fleet is headroom rather than need: it lets PostgreSQL
    get a larger `shared_buffers` and page cache for the console's reads,
    which this test did not exercise.
- **Fast fsync:** a candidate cause of the tail growth at twice the target.
  Not confirmed.

### Disk for 90-day retention

Disk grows with how many findings the agents report. Today's agent
re-reports every match on every scan; the architecture expects up to about
20 matches per host per hour at worst. The figures below use about 500 bytes
per stored finding (measured), plus 30 % headroom for WAL, vacuum and index
bloat *(estimate)*.

| Hosts | Matches per host per hour | Findings per day | Per day | 90 days, with headroom |
|---|---|---|---|---|
| 1,000 | 20 | 480 k | 0.24 GB | ≈ 28 GB |
| 10,000 | 20 | 4.8 M | 2.4 GB | ≈ 280 GB |
| 50,000 | 20 | 24 M | 12 GB | ≈ 1.4 TB |
| 50,000 | 2 | 2.4 M | 1.2 GB | ≈ 140 GB |

The planned protocol change that reports when a match starts and ends,
instead of on every scan, would move a fleet from the first rows towards
the last one. Retention days scale the 90-day column linearly.

## Open questions

- **Vulnerability management storage:** 6.7 GB per 10,000 hosts for
  package links, accepted for now; a compact per-host form would cut it
  about twentyfold.

- **Real finding rate:** the rate of a real fleet is unknown. The disk table
  brackets it; measure it on the first real deployment.
- **Scaled-down fleet:** the test's 2,000 agents at 2 s stand in for 60,000
  at 60 s. Per-agent table sizes (`agents`, `certificates`,
  `current_findings`) were measured at 2,000 agents only; they are small
  (about 320 bytes per agent and rule in `current_findings`).
- **One desktop host only.** Separate server hardware or a separate database
  host would give different numbers.
- **Not covered:** vacuum and `maintenance` partition drops while under load
  were not measured.
