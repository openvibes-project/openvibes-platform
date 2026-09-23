# PM5: Load Test — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure and record throughput and p99 latency for about 1,000 requests per second on one ingest instance, on stated hardware (spec section 1, item 4).

**Architecture:**
- **Generator:** `openvibes-load`, a workspace binary in `scripts/load/`, simulates N enrolled agents with the agent's own transport (`openvibes-transport`, blocking ureq). Like the real agent, every tick opens a fresh client, so every tick makes a new mTLS connection. Each tick sends a heartbeat, and on that agent's findings ticks it also sends one batch.
- **Open-loop schedule:** ticks are due at fixed times whether or not the server keeps up. A worker pool executes them, and the generator reports how far it fell behind (lag), so a saturated generator or server cannot hide behind lower latency.
- **Measurement:** after one warm-up interval, the generator records per-request latency, errors and achieved rate. It also samples CPU time from `/proc` for itself, ingest, and every PostgreSQL process.
- **Runner:** `scripts/load/run.sh` brings up the same local platform as the integration test, through a shared `start_platform`, and prints the hardware and the summary.

**Tech Stack:** Rust 1.95, `openvibes-transport` and `openvibes-core` at the pinned agent revision, `clap`, `serde_json`, std threads plus `mpsc` (no async runtime: the transport blocks), bash, PostgreSQL 18.

**Spec:** `docs/specs/2026-09-23-ingest-subproject-design.md`:
- section 1, item 4: "throughput and p99 latency for the target of about 1,000 requests per second on one ingest instance, on stated hardware";
- section 8: "Load (`scripts/load`): a generator using the agent's transport crate to simulate N agents: heartbeats every 60 s, a finding batch every hour. Reports requests per second, p50 and p99 latency, and database CPU";
- section 10: PM5 row.

## Global Constraints

- **Carried over:** PM0–PM4 constraints still apply. That means the toolchain, lints (`-D warnings -F unsafe-code`, `clippy.toml` bans), `--locked`, the commit trailer, component docs updated in the same change, and `CARGO_NET_GIT_FETCH_WITH_CLI=true`.
- **Transport:** the generator uses `openvibes-transport` exactly as the agent does. It opens one `PlatformClient` per tick and never reuses connections across ticks.
- **Request mix:** 1 findings batch per 60 heartbeats, the spec's hourly batch to per-minute heartbeat ratio. To reach 1,000 req/s without 60,000 enrolled identities, the heartbeat interval is shortened and the agent count scaled: default 2,000 agents at 2 s gives 1,000 heartbeats/s plus about 17 batches/s. Planning ruling, recorded in the results. Cost if wrong: per-agent effects that need 60,000 distinct agents, such as the `agents` table's size, are understated. The `last_seen_at` write throttle behaves the same, because it is keyed on time, not on agent count.
- **Pass/fail:** a run fails (exit 1) on any error response or transport error, on generator lag above 1 s, or when the achieved rate falls below 95 % of the target.
- **Results:** recorded results always state CPU model, core count, RAM, kernel, PostgreSQL version, that generator and server share the host, and the CPU each used.
- **Not shipped:** the generator is not packaged in the RPMs (`publish = false`).

## Review Focus

- **Generator saturation read as server capacity:** the generator reports its own CPU and schedule lag, and fails on lag above 1 s. (Task 3: a RED run with 1 worker thread must fail on lag.)
- **Errors hidden in the numbers:** any non-2xx response or transport error (503 from `max_in_flight`, 408, a connect failure) is counted by kind and fails the run; errors never just lower the latency. (Task 3: a RED run with an oversized batch must fail with counted errors.)
- **Bursty findings:** findings batches are staggered across agents, not all sent on the same tick. (Task 2 unit test `findings_are_staggered_across_agents`.)
- **Warm-up inside the measurement:** enrollment and the first interval are excluded from rate, latency and CPU. (Task 2: the window starts after one interval; the summary reports the window.)
- **Ephemeral ports:** about 1,000 new loopback connections per second leave sockets in TIME_WAIT. Fedora's default `tcp_tw_reuse=2` (loopback) keeps ports available. The runner prints it, and connect failures would show up as counted errors. (Task 3 prints the setting.)

---

### Task 1: Shared platform bootstrap

**Files:**
- Modify `scripts/integration-lib.sh` (add `start_platform` and `cleanup`).
- Modify `scripts/integration-agent.sh` (use them).
- Update `docs/components/integration-agent.md` (helpers line).

**Interfaces:**
- **Produces `start_platform`.** It reads these globals: `ROOT`, `W`, `INGEST_PORT`, `HEALTH_PORT`, and `OPENVIBES_BIN_DIR` (optional: when unset it builds `target/release`).
  - Starts: it creates `$W` fresh, starts PostgreSQL under `$W/pg`, migrates, runs maintenance, builds the CA under `$W/ca`, writes `$W/ingest.toml`, starts ingest (log `$W/ingest.log`), and waits for `/ready`.
  - Defines: `admin`, `sql`, `PIDS`, `INGEST_PID`, and the `EXIT` trap `cleanup`. On failure, `cleanup` prints the tail of every `$W/*.log`.
  - Extra ingest config: lines in `INGEST_EXTRA` are appended to `ingest.toml`.

- [ ] **Step 1: Move the code.**
  1. Cut everything in `scripts/integration-agent.sh` from `PIDS=()` down to and including `wait_for "ingest ready" ...` into a function `start_platform` in `integration-lib.sh`.
  2. Replace `rm -rf "$W"; mkdir -p "$W/pg/run" "$W/ca" "$W/agent/state"; chmod 700 ...` with `rm -rf "$W"; mkdir -p "$W/pg/run" "$W/ca"` inside the function. The integration script then runs `mkdir -p "$W/agent/state"; chmod 700 "$W/agent/state"` after `start_platform`.
  3. Define `cleanup` at file level in the lib, printing every log:

```bash
cleanup() {
    local status=$?
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    [[ -d "$W/pg/data" ]] && pg_ctl -D "$W/pg/data" -m immediate stop >/dev/null 2>&1 || true
    if ((status != 0)); then
        for log in "$W"/*.log; do
            [[ -f "$log" ]] && { echo "--- $(basename "$log") (tail)"; tail -n 20 "$log"; }
        done
    fi
    exit "$status"
}
```

  4. Inside `start_platform`, set `PIDS=()` and `trap cleanup EXIT` first. After `cat > "$W/ingest.toml"`, add `[[ -n "${INGEST_EXTRA:-}" ]] && printf '%s\n' "$INGEST_EXTRA" >> "$W/ingest.toml"`. After starting ingest, set `INGEST_PID=$!` and `PIDS+=("$INGEST_PID")`.
  5. `integration-agent.sh` keeps its variables (`W`, the ports, `AGENT_BIN`, the bundle) and calls `start_platform` where the moved block was.

- [ ] **Step 2: The integration test is this task's test.** Run `bash scripts/integration-agent.sh`. Expected: `integration: all checks passed`, the same 13 `ok:` lines as before. Then run `INGEST_PORT=1 bash scripts/integration-agent.sh`. Expected: `FAIL: ingest ready`, a `--- ingest.log (tail)` block, and afterwards no process under the run directory (`pgrep -af target/integration/run` prints nothing).

- [ ] **Step 3: Commit.**

```bash
git add scripts/integration-lib.sh scripts/integration-agent.sh docs/components/integration-agent.md
git commit -m "Share the local platform bootstrap between test scripts"
```

---

### Task 2: `openvibes-load` generator

**Files:**
- Create `scripts/load/Cargo.toml`, `scripts/load/src/main.rs`, `scripts/load/src/plan.rs`.
- Modify the workspace `Cargo.toml` (members).

**Interfaces:**
- **Produces the binary `openvibes-load`.** Flags:
  - `--url URL`, `--ca FILE` (root PEM), `--token-file FILE`;
  - `--agents N` (default 2000), `--interval-ms MS` (default 2000), `--duration-s S` (default 120);
  - `--findings-every K` (default 60), `--batch F` (default 10), `--workers W` (default 256);
  - `--ingest-pid P`, `--postmaster-pid P`, `--clk-tck T` (default 100).
- **Output:** a JSON summary on stdout. Exit 0 on pass, 1 on fail (Global Constraints), 2 on usage errors.
- **Summary fields:** `target_rps`, `achieved_rps`, `window_s`, `requests`, `errors` (map from reason to count), `max_lag_ms`, `latency_ms` {`all`, `heartbeat`, `findings`: {`p50`, `p99`, `max`}}, `cpu_cores` {`generator`, `ingest`, `postgres`}, `enroll` {`agents`, `seconds`}, `pass`.
- **Produces `plan.rs`:**
  - `first_tick(index: usize, agents: usize, interval: Duration) -> Duration`;
  - `delivers_findings(agent: usize, tick: u64, every: u64) -> bool`;
  - `percentile(sorted: &[u64], p: f64) -> u64`.

- [ ] **Step 1: Package skeleton.** In the workspace `Cargo.toml`, add `"scripts/load"` to `members`. Then write `scripts/load/Cargo.toml`:

```toml
[package]
name = "openvibes-load"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish = false

[dependencies]
clap.workspace = true
openvibes-core.workspace = true
openvibes-transport.workspace = true
serde_json.workspace = true

[lints]
workspace = true
```

- [ ] **Step 2: Write the failing unit tests.** Create `scripts/load/src/plan.rs` with only the tests, plus signatures whose bodies are `todo!()`:

```rust
//! Scheduling and statistics, kept pure so they are unit-tested.

use std::time::Duration;

/// When agent `index` of `agents` first ticks: spread evenly over one interval.
pub fn first_tick(index: usize, agents: usize, interval: Duration) -> Duration {
    todo!()
}

/// Whether `agent`'s tick number `tick` also delivers a findings batch: once
/// every `every` ticks, staggered so each tick carries 1/`every` of agents.
pub fn delivers_findings(agent: usize, tick: u64, every: u64) -> bool {
    todo!()
}

/// Nearest-rank percentile (`p` in 0–100) of ascending `sorted`; 0 if empty.
pub fn percentile(sorted: &[u64], p: f64) -> u64 {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_spread_over_one_interval() {
        let interval = Duration::from_secs(2);
        assert_eq!(first_tick(0, 4, interval), Duration::ZERO);
        assert_eq!(first_tick(1, 4, interval), Duration::from_millis(500));
        assert_eq!(first_tick(3, 4, interval), Duration::from_millis(1500));
    }

    #[test]
    fn findings_are_staggered_across_agents() {
        let per_tick: Vec<usize> = (0..3)
            .map(|tick| (0..30).filter(|&agent| delivers_findings(agent, tick, 3)).count())
            .collect();
        assert_eq!(per_tick, [10, 10, 10], "each tick carries a third of the agents");
        assert_eq!((0..6).filter(|&tick| delivers_findings(7, tick, 3)).count(), 2);
        assert!(!delivers_findings(0, 0, 0), "0 disables findings");
    }

    #[test]
    fn nearest_rank_percentiles() {
        let samples: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&samples, 50.0), 50);
        assert_eq!(percentile(&samples, 99.0), 99);
        assert_eq!(percentile(&samples, 100.0), 100);
        assert_eq!(percentile(&[7], 99.0), 7);
        assert_eq!(percentile(&[], 99.0), 0);
    }
}
```

Create a `main.rs` that only has `mod plan; fn main() {}`, with `#![forbid(unsafe_code)]`.

Run `cargo test --locked -p openvibes-load`. Expected: 3 tests FAIL with `not yet implemented`. Unused-variable warnings are fine at this step.

- [ ] **Step 3: Implement `plan.rs` (GREEN).**

```rust
pub fn first_tick(index: usize, agents: usize, interval: Duration) -> Duration {
    interval.mul_f64(index as f64 / agents.max(1) as f64)
}

pub fn delivers_findings(agent: usize, tick: u64, every: u64) -> bool {
    every > 0 && (tick + agent as u64) % every == 0
}

pub fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}
```

Run `cargo test --locked -p openvibes-load`. Expected: 3 passed.

- [ ] **Step 4: Write the generator.** `scripts/load/src/main.rs`:

```rust
#![forbid(unsafe_code)]

//! `openvibes-load`: simulates N enrolled agents against openvibes-ingest with
//! the agent's own transport. Every tick opens a fresh client (as the agent
//! does), sends a heartbeat, and on the agent's findings ticks one batch.
//! Ticks are due on a fixed schedule (open loop); the summary reports how far
//! execution lagged behind it. Test tool, never shipped.

mod plan;

use std::{
    collections::BTreeMap,
    path::PathBuf,
    process::ExitCode,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use openvibes_core::{
    Confidence, EnrollmentToken, Finding, Heartbeat, Identifier, ResourceLimits, SchemaVersion,
    Severity,
};
use openvibes_transport::{
    ClientIdentity, DEFAULT_PLATFORM_PORT, HostKey, PlatformClient, TransportConfig,
};

#[derive(Parser)]
#[command(name = "openvibes-load", about = "OpenVIBES ingest load generator (test tool)")]
struct Args {
    #[arg(long)]
    url: String,
    #[arg(long)]
    ca: PathBuf,
    #[arg(long)]
    token_file: PathBuf,
    #[arg(long, default_value_t = 2000, value_parser = clap::value_parser!(u32).range(1..=100_000))]
    agents: u32,
    #[arg(long, default_value_t = 2000, value_parser = clap::value_parser!(u64).range(10..))]
    interval_ms: u64,
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
    duration_s: u64,
    #[arg(long, default_value_t = 60)]
    findings_every: u64,
    #[arg(long, default_value_t = 10)]
    batch: usize,
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u32).range(1..=4096))]
    workers: u32,
    #[arg(long)]
    ingest_pid: Option<u32>,
    #[arg(long)]
    postmaster_pid: Option<u32>,
    #[arg(long, default_value_t = 100)]
    clk_tck: u64,
}

struct Agent {
    id: Identifier,
    identity: ClientIdentity,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Heartbeat,
    Findings,
}

struct Sample {
    kind: Kind,
    due: Instant,
    micros: u64,
    error: Option<String>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
}

fn id(value: String) -> Identifier {
    Identifier::new(value).expect("generated identifiers are valid")
}

/// Enrolls `count` agents with one multi-use token, `workers` at a time.
fn enroll(config: &TransportConfig, token: &EnrollmentToken, count: u32, workers: u32) -> Result<Vec<Agent>, String> {
    let next = Arc::new(Mutex::new(0_u32));
    let agents = Arc::new(Mutex::new(Vec::new()));
    let handles: Vec<_> = (0..workers.min(count).min(64))
        .map(|_| {
            let (next, agents, config, token) = (next.clone(), agents.clone(), config.clone(), token.clone());
            thread::spawn(move || -> Result<(), String> {
                loop {
                    {
                        let mut next = next.lock().expect("lock");
                        if *next >= count {
                            return Ok(());
                        }
                        *next += 1;
                    }
                    let key = HostKey::generate().map_err(|e| format!("key: {e}"))?;
                    let response = PlatformClient::new(&config, None)
                        .and_then(|client| client.enroll(&token, &key))
                        .map_err(|e| format!("enroll: {e}"))?;
                    let identity = ClientIdentity::from_pem(&response.certificate_chain_pem, key.expose_key_pem())
                        .map_err(|e| format!("identity: {e}"))?;
                    agents.lock().expect("lock").push(Agent { id: response.agent_id, identity });
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().map_err(|_| "enroll worker panicked".to_owned())??;
    }
    Ok(Arc::try_unwrap(agents).map_err(|_| "agents still shared")?.into_inner().expect("lock"))
}

/// One tick of one agent: fresh client, heartbeat, and maybe a batch.
fn tick(config: &TransportConfig, agent: &Agent, index: usize, tick: u64, due: Instant, args: &Args) -> Vec<Sample> {
    let mut samples = Vec::new();
    let client = match PlatformClient::new(config, Some(&agent.identity)) {
        Ok(client) => client,
        Err(error) => {
            samples.push(Sample { kind: Kind::Heartbeat, due, micros: 0, error: Some(format!("client: {error}")) });
            return samples;
        }
    };
    let heartbeat = Heartbeat {
        schema_version: SchemaVersion::V1,
        agent_id: agent.id.clone(),
        scanner_version: "load".into(),
        hostname: Some(format!("load-{index}")),
        observed_at_unix_ms: now_ms(),
        capabilities: Vec::new(),
    };
    let started = Instant::now();
    let result = client.heartbeat(&heartbeat);
    samples.push(Sample {
        kind: Kind::Heartbeat,
        due,
        micros: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        error: result.err().map(|e| format!("heartbeat: {e}")),
    });
    if plan::delivers_findings(index, tick, args.findings_every) {
        let observed = now_ms();
        let findings: Vec<Finding> = (0..args.batch)
            .map(|n| Finding {
                schema_version: SchemaVersion::V1,
                finding_id: id(format!("finding.load.{index}.{tick}.{n}")),
                scan_id: id(format!("scan.load.{index}.{tick}")),
                rule_id: id("load.rule".into()),
                rule_version: 1,
                observed_at_unix_ms: observed,
                severity: Severity::Info,
                confidence: Confidence::new(100).expect("valid confidence"),
                message: "Load test finding".into(),
                evidence: Vec::new(),
            })
            .collect();
        let started = Instant::now();
        let result = client.deliver(&findings);
        samples.push(Sample {
            kind: Kind::Findings,
            due,
            micros: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            error: result.err().map(|e| format!("findings: {e}")),
        });
    }
    samples
}

/// utime + stime of `pid` in clock ticks, from /proc/PID/stat.
fn cpu_ticks(pid: u32) -> u64 {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return 0;
    };
    // Fields after the parenthesised command name; utime and stime are the
    // 14th and 15th fields overall, so the 12th and 13th after it.
    let rest = stat.rsplit_once(')').map_or("", |(_, rest)| rest);
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let field = |n: usize| fields.get(n).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    field(11) + field(12)
}

/// The postmaster and all its children (backends, workers).
fn postgres_ticks(postmaster: u32) -> u64 {
    let mut total = cpu_ticks(postmaster);
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return total;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let parent = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u32>().ok());
        if parent == Some(postmaster) {
            total += cpu_ticks(pid);
        }
    }
    total
}

fn snapshot(args: &Args) -> [u64; 3] {
    [
        cpu_ticks(std::process::id()),
        args.ingest_pid.map_or(0, cpu_ticks),
        args.postmaster_pid.map_or(0, postgres_ticks),
    ]
}

fn stats(mut micros: Vec<u64>) -> serde_json::Value {
    micros.sort_unstable();
    let ms = |v: u64| v as f64 / 1000.0;
    serde_json::json!({
        "p50": ms(plan::percentile(&micros, 50.0)),
        "p99": ms(plan::percentile(&micros, 99.0)),
        "max": ms(micros.last().copied().unwrap_or(0)),
    })
}

fn main() -> ExitCode {
    let args = Args::parse();
    let (Ok(roots), Ok(token)) = (std::fs::read(&args.ca), std::fs::read_to_string(&args.token_file)) else {
        eprintln!("openvibes-load: cannot read --ca or --token-file");
        return ExitCode::from(2);
    };
    let Ok(token) = EnrollmentToken::new(token.trim()) else {
        eprintln!("openvibes-load: invalid token");
        return ExitCode::from(2);
    };
    let config = TransportConfig {
        base_url: args.url.clone(),
        default_port: DEFAULT_PLATFORM_PORT,
        server_roots_pem: roots,
        proxy_url: None,
        limits: ResourceLimits::V1,
    };
    let enroll_started = Instant::now();
    let agents = match enroll(&config, &token, args.agents, args.workers) {
        Ok(agents) => Arc::new(agents),
        Err(error) => {
            eprintln!("openvibes-load: {error}");
            return ExitCode::FAILURE;
        }
    };
    let enroll_seconds = enroll_started.elapsed().as_secs_f64();
    let interval = Duration::from_millis(args.interval_ms);
    let args = Arc::new(args);
    let start = Instant::now() + Duration::from_millis(100);
    let window_start = start + interval;
    let end = window_start + Duration::from_secs(args.duration_s);

    // Scheduler: emits (agent, tick, due) in due order until `end`.
    let (jobs, queue) = mpsc::channel::<(usize, u64, Instant)>();
    let queue = Arc::new(Mutex::new(queue));
    let count = agents.len();
    let scheduler = thread::spawn(move || {
        for tick in 0_u64.. {
            for index in 0..count {
                let due = start + plan::first_tick(index, count, interval) + interval * u32::try_from(tick).unwrap_or(u32::MAX);
                if due >= end {
                    return;
                }
                if let Some(wait) = due.checked_duration_since(Instant::now()) {
                    thread::sleep(wait);
                }
                if jobs.send((index, tick, due)).is_err() {
                    return;
                }
            }
        }
    });
    let workers: Vec<_> = (0..args.workers)
        .map(|_| {
            let (queue, agents, config, args) = (queue.clone(), agents.clone(), config.clone(), args.clone());
            thread::spawn(move || {
                let mut samples = Vec::new();
                let mut max_lag = Duration::ZERO;
                loop {
                    let job = queue.lock().expect("lock").recv();
                    let Ok((index, tick_number, due)) = job else {
                        return (samples, max_lag);
                    };
                    max_lag = max_lag.max(Instant::now().saturating_duration_since(due));
                    samples.extend(tick(&config, &agents[index], index, tick_number, due, &args));
                }
            })
        })
        .collect();

    if let Some(wait) = window_start.checked_duration_since(Instant::now()) {
        thread::sleep(wait);
    }
    let before = snapshot(&args);
    if let Some(wait) = end.checked_duration_since(Instant::now()) {
        thread::sleep(wait);
    }
    let after = snapshot(&args);
    let _ = scheduler.join();
    let mut samples = Vec::new();
    let mut max_lag = Duration::ZERO;
    for worker in workers {
        if let Ok((worker_samples, lag)) = worker.join() {
            samples.extend(worker_samples);
            max_lag = max_lag.max(lag);
        }
    }

    let window = (end - window_start).as_secs_f64();
    let measured: Vec<&Sample> = samples.iter().filter(|s| s.due >= window_start).collect();
    let mut errors: BTreeMap<String, u64> = BTreeMap::new();
    for sample in &samples {
        if let Some(error) = &sample.error {
            *errors.entry(error.clone()).or_default() += 1;
        }
    }
    let latencies = |kind: Option<Kind>| {
        measured
            .iter()
            .filter(|s| s.error.is_none() && kind.is_none_or(|k| s.kind == k))
            .map(|s| s.micros)
            .collect::<Vec<_>>()
    };
    let per_second = 1000.0 / args.interval_ms as f64 * count as f64;
    let target_rps = per_second
        * (1.0 + if args.findings_every > 0 { 1.0 / args.findings_every as f64 } else { 0.0 });
    let achieved_rps = measured.len() as f64 / window;
    let cores = |i: usize| (after[i].saturating_sub(before[i])) as f64 / args.clk_tck as f64 / window;
    let max_lag_ms = max_lag.as_secs_f64() * 1000.0;
    let pass = errors.is_empty() && max_lag_ms <= 1000.0 && achieved_rps >= 0.95 * target_rps;
    let summary = serde_json::json!({
        "target_rps": target_rps,
        "achieved_rps": achieved_rps,
        "window_s": window,
        "requests": measured.len(),
        "errors": errors,
        "max_lag_ms": max_lag_ms,
        "latency_ms": {
            "all": stats(latencies(None)),
            "heartbeat": stats(latencies(Some(Kind::Heartbeat))),
            "findings": stats(latencies(Some(Kind::Findings))),
        },
        "cpu_cores": { "generator": cores(0), "ingest": cores(1), "postgres": cores(2) },
        "enroll": { "agents": count, "seconds": enroll_seconds },
        "pass": pass,
    });
    println!("{summary:#}");
    if pass { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
```

If a workspace lint rejects the numeric casts in `plan.rs` or `main.rs`, or `expect`, add a file-level `#![allow(...)]` naming only that lint, with the comment "test tool; values are bounded". Ledger it as a ruling.

- [ ] **Step 5: Verify.** Run `cargo fmt --all`, then `cargo clippy --locked --workspace --all-targets -- -D warnings -F unsafe-code`, then `cargo test --locked -p openvibes-load`. Then run `cargo run -q --locked -p openvibes-load -- --help`. Expected: all clean, 3 passed, and the usage text lists every flag.

- [ ] **Step 6: Commit.**

```bash
git add Cargo.toml Cargo.lock scripts/load
git commit -m "Add the openvibes-load generator"
```

---

### Task 3: `scripts/load/run.sh` and its failure checks

**Files:**
- Create `scripts/load/run.sh` and `docs/components/load.md`.
- Update `docs/components/README.md`.

**Interfaces:**
- **Consumes:** Task 1's `start_platform`, `admin`, `INGEST_PID`, `W` and the ports; Task 2's `openvibes-load` flags.
- **Produces:** `scripts/load/run.sh [AGENTS] [INTERVAL_MS] [DURATION_S]` (defaults 2000 2000 120). Environment:
  - `LOAD_DIR` (default `target/load/run`), `LOAD_BIN` (default: build `target/release/openvibes-load`), `OPENVIBES_BIN_DIR`;
  - `LOAD_ARGS` (extra generator flags), `INGEST_EXTRA`;
  - `INGEST_PORT` and `HEALTH_PORT` (defaults 28523, 28580).

  It prints a hardware block, then the JSON summary, and exits with the generator's status.

- [ ] **Step 1: Write the runner.**

```bash
#!/usr/bin/env bash
# Load test (spec section 8): openvibes-load simulates AGENTS agents, one tick
# every INTERVAL_MS each, against a local openvibes-ingest and PostgreSQL.
# Usage: scripts/load/run.sh [AGENTS] [INTERVAL_MS] [DURATION_S]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
source "$ROOT/scripts/integration-lib.sh"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
AGENTS=${1:-2000}
INTERVAL_MS=${2:-2000}
DURATION_S=${3:-120}
W=${LOAD_DIR:-$ROOT/target/load/run}
INGEST_PORT=${INGEST_PORT:-28523}
HEALTH_PORT=${HEALTH_PORT:-28580}
if [[ -z "${LOAD_BIN:-}" ]]; then
    (cd "$ROOT" && cargo build --quiet --release --locked -p openvibes-load)
    LOAD_BIN="$ROOT/target/release/openvibes-load"
fi

start_platform
admin token create --expires 1h --uses "$AGENTS" --label load |
    sed -n 's/^token \([A-Za-z0-9_-]\{43\}\)$/\1/p' > "$W/token"
[[ -s "$W/token" ]] || { echo "FAIL: no token" >&2; exit 1; }

echo "--- hardware"
echo "cpu: $(lscpu | sed -n 's/^Model name: *//p'), $(nproc) threads"
echo "memory: $(awk '/MemTotal/ {printf "%.1f GiB", $2 / 1048576}' /proc/meminfo)"
echo "kernel: $(uname -r)"
echo "postgresql: $(postgres --version)"
echo "tcp_tw_reuse: $(cat /proc/sys/net/ipv4/tcp_tw_reuse), ports: $(tr '\t' '-' < /proc/sys/net/ipv4/ip_local_port_range)"
echo "generator, ingest, and PostgreSQL share this host"
echo "--- load: $AGENTS agents, one tick every ${INTERVAL_MS} ms, ${DURATION_S} s measured"
status=0
# shellcheck disable=SC2086  # LOAD_ARGS is a list of extra flags
"$LOAD_BIN" --url "https://127.0.0.1:$INGEST_PORT" --ca "$W/ca/root/root.crt" \
    --token-file "$W/token" --agents "$AGENTS" --interval-ms "$INTERVAL_MS" \
    --duration-s "$DURATION_S" --ingest-pid "$INGEST_PID" \
    --postmaster-pid "$(head -1 "$W/pg/data/postmaster.pid")" --clk-tck "$(getconf CLK_TCK)" \
    ${LOAD_ARGS:-} > "$W/summary.json" 2> "$W/load.log" || status=$?
cat "$W/summary.json"
exit "$status"
```

- [ ] **Step 2: Smoke run (GREEN).** Run `bash scripts/load/run.sh 50 1000 10`. Expected: the hardware block, then JSON with `"pass": true`, `"errors": {}`, `achieved_rps` ≈ 50.8, and nonzero `cpu_cores.ingest` and `cpu_cores.postgres`; exit 0.

- [ ] **Step 3: RED, errors are counted and fail the run.** Run `LOAD_ARGS="--findings-every 1 --batch 1001" bash scripts/load/run.sh 20 1000 5`. A batch over the 1,000-item limit is refused. Expected: exit 1, `"pass": false`, and `errors` holding a `findings: ...` key with a count of about 120 (20 agents × 6 ticks: 1 s warm-up plus 5 s; errors count over the whole run). If the transport refuses the batch before sending it, the key reads `findings: ...` all the same. Either way the run must fail.

- [ ] **Step 4: RED, lag is detected.** Run `LOAD_ARGS="--workers 1" bash scripts/load/run.sh 400 1000 5`. One worker cannot run 400 TLS ticks per second. Expected: exit 1, `"pass": false`, `max_lag_ms` well above 1000, and `achieved_rps` below 380.

- [ ] **Step 5: Docs.** Create `docs/components/load.md`, with sections:
  - Purpose.
  - What a tick is: a fresh client, a heartbeat, and a staggered findings batch.
  - The request-mix ruling: 1 batch per 60 heartbeats, with a shortened interval standing in for 60,000 agents.
  - Measurement: open-loop schedule, one interval of warm-up, lag, and CPU from `/proc`.
  - Pass/fail rules.
  - How to run, with the environment variables.
  - Results (filled in by Task 4).

  Add a row for it to `docs/components/README.md`.

- [ ] **Step 6: Commit.**

```bash
git add scripts/load/run.sh docs/components
git commit -m "Add the load test runner"
```

---

### Task 4: Record the results, CI smoke run, PR

**Files:**
- Modify `docs/components/load.md` (Results) and `.github/workflows/ci.yml` (fedora job).
- Update `docs/components/openvibes-ingest.md` (a "Capacity" line linking the results).

**Interfaces:**
- **Consumes:** `scripts/load/run.sh`, and `LOAD_BIN`, `LOAD_DIR` and `OPENVIBES_BIN_DIR`.

- [ ] **Step 1: Target run.** Run `bash scripts/load/run.sh` (2,000 agents at 2 s, 120 s measured, target ≈ 1,033 req/s). Expected: `"pass": true`.

  If it fails, do not tune ingest in this plan. Record the result as it is, and **stop and report to the user** with the summary and the CPU split. Raising the pool size or changing hardware is a product decision.

- [ ] **Step 2: Headroom run.** Run `bash scripts/load/run.sh 4000 2000 60` (≈ 2,067 req/s). Record it whether it passes or fails. It shows how far the target sits below saturation on this hardware.

- [ ] **Step 3: Record.** In `load.md`, "Results (2026-09-23)", add:
  - the hardware block copied verbatim from the runs;
  - a table with the columns agents, interval, target req/s, achieved req/s, p50/p99/max ms (all, heartbeat, findings), max lag, errors, and CPU cores (generator, ingest, PostgreSQL);
  - one sentence of reading: whether the target holds, and what saturates first.

  Add a line to `openvibes-ingest.md`: "Capacity: see [load.md](load.md) results."

- [ ] **Step 4: CI smoke run.** In the `fedora` job's "Build the pinned agent and the bundle tool" step, add `cargo build --release --locked -p openvibes-load`. Add a final step:

```yaml
      - name: Load smoke test against the installed binaries
        shell: bash
        run: |
          runuser -u ci -- env OPENVIBES_BIN_DIR=/usr/bin LOAD_DIR=/home/ci/load \
            LOAD_BIN="$PWD/target/release/openvibes-load" \
            bash scripts/load/run.sh 50 1000 10
```

  A shared CI runner is too small and too noisy for the full target run, so CI keeps the tool working and the result files in `docs/` hold the numbers.

- [ ] **Step 5: Commit, push, PR, CI.**

```bash
git add docs .github/workflows/ci.yml
git commit -m "Record PM5 load results and smoke-test the generator in CI"
git push -u origin pm5
gh pr create --title "PM5: load test" --body "..."
gh run watch --exit-status
```

Expected: both CI jobs green. Spec section 1, item 4 is recorded.
