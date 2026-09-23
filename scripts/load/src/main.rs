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
#[command(
    name = "openvibes-load",
    about = "OpenVIBES ingest load generator (test tool)"
)]
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
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

fn id(value: String) -> Identifier {
    Identifier::new(value).expect("generated identifiers are valid")
}

/// Enrolls `count` agents with one multi-use token, `workers` at a time.
fn enroll(
    config: &TransportConfig,
    token: &EnrollmentToken,
    count: u32,
    workers: u32,
) -> Result<Vec<Agent>, String> {
    let next = Arc::new(Mutex::new(0_u32));
    let agents = Arc::new(Mutex::new(Vec::new()));
    let handles: Vec<_> = (0..workers.min(count).min(64))
        .map(|_| {
            let (next, agents, config, token) =
                (next.clone(), agents.clone(), config.clone(), token.clone());
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
                    let identity = ClientIdentity::from_pem(
                        &response.certificate_chain_pem,
                        key.expose_key_pem(),
                    )
                    .map_err(|e| format!("identity: {e}"))?;
                    agents.lock().expect("lock").push(Agent {
                        id: response.agent_id,
                        identity,
                    });
                }
            })
        })
        .collect();
    for handle in handles {
        handle
            .join()
            .map_err(|_| "enroll worker panicked".to_owned())??;
    }
    Ok(Arc::try_unwrap(agents)
        .map_err(|_| "agents still shared")?
        .into_inner()
        .expect("lock"))
}

/// One tick of one agent: fresh client, heartbeat, and maybe a batch.
fn tick(
    config: &TransportConfig,
    agent: &Agent,
    index: usize,
    tick: u64,
    due: Instant,
    args: &Args,
) -> Vec<Sample> {
    let mut samples = Vec::new();
    let client = match PlatformClient::new(config, Some(&agent.identity)) {
        Ok(client) => client,
        Err(error) => {
            samples.push(Sample {
                kind: Kind::Heartbeat,
                due,
                micros: 0,
                error: Some(format!("client: {error}")),
            });
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
    let field = |n: usize| {
        fields
            .get(n)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };
    field(11) + field(12)
}

/// The postmaster and all its children (backends, workers).
fn postgres_ticks(postmaster: u32) -> u64 {
    let mut total = cpu_ticks(postmaster);
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return total;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
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
    let (Ok(roots), Ok(token)) = (
        std::fs::read(&args.ca),
        std::fs::read_to_string(&args.token_file),
    ) else {
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
                let due = start
                    + plan::first_tick(index, count, interval)
                    + interval * u32::try_from(tick).unwrap_or(u32::MAX);
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
            let (queue, agents, config, args) =
                (queue.clone(), agents.clone(), config.clone(), args.clone());
            thread::spawn(move || {
                let mut samples = Vec::new();
                let mut max_lag = Duration::ZERO;
                loop {
                    let job = queue.lock().expect("lock").recv();
                    let Ok((index, tick_number, due)) = job else {
                        return (samples, max_lag);
                    };
                    max_lag = max_lag.max(Instant::now().saturating_duration_since(due));
                    samples.extend(tick(
                        &config,
                        &agents[index],
                        index,
                        tick_number,
                        due,
                        &args,
                    ));
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
        * (1.0
            + if args.findings_every > 0 {
                1.0 / args.findings_every as f64
            } else {
                0.0
            });
    let achieved_rps = measured.len() as f64 / window;
    let cores =
        |i: usize| (after[i].saturating_sub(before[i])) as f64 / args.clk_tck as f64 / window;
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
    if pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
