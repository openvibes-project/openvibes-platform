# Sizing: platform and agent

Status 2026-09-23, after sub-project 1 (PM0–PM5). **Measured** figures come
from the tests named with them. Figures marked *estimate* are not measured.
Revise this page when new measurements replace them.

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

At the real cadence of one heartbeat per minute and one findings batch per
hour, 1,017 req/s corresponds to about **60,000 agents**. Enrollment ran at
about 150 agents/s, so 50,000 agents enroll in roughly 6 minutes.

## Agent requirements

| | Minimum | Recommended |
|---|---|---|
| CPU | any x86_64 core | same |
| RAM | 32 MB free | 64 MB free |
| Disk | 50 MB (binary + state) | 200 MB, for queue room during long platform outages |
| OS | Linux (tested: Fedora 44) | same |

The agent's disk use depends on how much the local queue holds before old
data rotates out. That is not measured yet.

## Platform requirements (one host: ingest + PostgreSQL)

| | Small: ≤ 1,000 agents (~17 req/s) | Up to 50,000 agents (~850 req/s) |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 2–4 GB *(estimate)* | 8–16 GB *(estimate)* |
| Disk | SSD, sized for retention *(unknown)* | NVMe/SSD with fast fsync, sized for retention *(unknown)* |

- **CPU:** the measured need at 50,000 agents is about 1 core for ingest plus
  0.5 for PostgreSQL. 4 vCPU doubles that, which leaves room for:
  - server cores slower than a desktop Ryzen;
  - vacuum and maintenance;
  - the console later on.
- **RAM:** an estimate. It should let PostgreSQL keep its most-used tables in
  memory (`agents`, `certificates`, `current_findings`). Ingest and
  PostgreSQL memory were not measured.
- **Fast fsync:** a candidate cause of the tail growth at twice the target.
  Not confirmed.

## Open questions

- **Disk is the main unknown, and probably the largest requirement.** With
  90-day retention, 50,000 agents at the test's synthetic rate of 10 findings
  per hour would store about 1 billion rows. The size of a stored finding is
  not measured, and a real finding rate is likely far lower.
- **Tested on an empty database only.** Behaviour with 90 days of data and
  its vacuum load is untested.
- **One desktop host only.** Separate server hardware or a separate database
  host would give different numbers.

Next measurement to close the estimates:
- extend `openvibes-load` to record ingest and PostgreSQL memory (RSS);
- record database growth per stored finding (`pg_database_size` before and
  after);
- run against a database pre-filled to 90 days of retention.
