//! Vulnerability management scale check (VM spec §10): N synthetic hosts,
//! each with a real Fedora package list, stored through the same store call
//! ingest uses, then matched against a real updateinfo feed.
//!
//! ```sh
//! rpm -qa --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n' | grep -v ^gpg-pubkey > pkgs.tsv
//! eval "$(scripts/test-db.sh)"
//! cargo run --release -p openvibes-vulns --example scale -- pkgs.tsv updateinfo.xml.zst 10000 16
//! ```
//!
//! Hosts come in 20 generations: generation g has about g% of the packages
//! an advisory fixes held just below the fixed version, so matching finds
//! real vulnerabilities and the fleet shares versions as real fleets do.
//! Creates and keeps the database `ov_scale` (dropped at the next run).

use std::{
    collections::HashMap,
    io::BufReader,
    time::{Duration, Instant},
};

use chrono::Utc;
use openvibes_vulns::{
    feed::{self, SourceId},
    matching, updateinfo,
};
use platform_store::{
    inventory::{self, PackageRow},
    vulns,
};

const GENERATIONS: usize = 20;

fn hash(parts: &[&[u8]]) -> u64 {
    // FNV-1a: deterministic, no dependency.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for byte in *part {
            h = (h ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
        }
        h = (h ^ 0xff).wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn quantile(sorted: &[Duration], q: f64) -> Duration {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

fn peak_rss_mib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .map_or(0, |kib| kib / 1024)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let hosts: usize = args[3].parse().unwrap();
    let workers: usize = args[4].parse().unwrap();
    let base: Vec<PackageRow> = std::fs::read_to_string(&args[1])
        .unwrap()
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            Some(PackageRow {
                manager: "rpm".into(),
                name: (*f.first()?).into(),
                epoch: f.get(1)?.parse().ok()?,
                version: (*f.get(2)?).into(),
                release: (*f.get(3)?).into(),
                arch: (*f.get(4)?).into(),
            })
        })
        .collect();
    let content = std::fs::read(&args[2]).unwrap();
    let advisories = updateinfo::read_zstd(BufReader::new(&content[..]), feed::MAX_OPEN_BYTES).unwrap();
    // The first fixed version per package name.
    let mut fixed: HashMap<&str, (u32, &str)> = HashMap::new();
    for advisory in &advisories {
        for p in &advisory.packages {
            fixed.entry(p.name.as_str()).or_insert((p.epoch, p.version.as_str()));
        }
    }
    let generation = |g: usize| -> Vec<PackageRow> {
        base.iter()
            .map(|p| match fixed.get(p.name.as_str()) {
                Some((epoch, version))
                    if hash(&[p.name.as_bytes(), &[1]]) % 100 < g as u64 =>
                {
                    PackageRow {
                        epoch: i32::try_from(*epoch).unwrap_or(0),
                        version: (*version).to_owned(),
                        release: "0.fc44".into(),
                        ..p.clone()
                    }
                }
                _ => p.clone(),
            })
            .collect()
    };
    let generations: Vec<Vec<PackageRow>> = (0..GENERATIONS).map(generation).collect();
    println!(
        "{} packages per host, {} advisories, {} fixed names, {hosts} hosts, {workers} workers",
        base.len(),
        advisories.len(),
        fixed.len()
    );

    let url = std::env::var("OPENVIBES_TEST_DATABASE_URL").unwrap();
    let server = platform_store::connect(&url).await.unwrap();
    let admin = server.get().await.unwrap();
    admin.batch_execute("DROP DATABASE IF EXISTS ov_scale").await.unwrap();
    admin.batch_execute("CREATE DATABASE ov_scale").await.unwrap();
    let url = url.replace("/postgres?", "/ov_scale?");
    let pool = platform_store::connect_sized(&url, workers + 2).await.unwrap();
    let mut owner = pool.get().await.unwrap();
    platform_store::migrate(&mut owner).await.unwrap();
    let ids: Vec<String> = (0..hosts)
        .map(|i| format!("agent.00000000-0000-4000-8000-{i:012}"))
        .collect();
    owner
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname)
             SELECT a, 'active', now(), 'host-' || n FROM unnest($1::text[]) WITH ORDINALITY AS x(a, n)",
            &[&ids],
        )
        .await
        .unwrap();

    // Ingest: every host's inventory through inventory::replace, as the
    // openvibes_ingest role, `workers` at a time.
    let start = Instant::now();
    let generations = std::sync::Arc::new(generations);
    let ids = std::sync::Arc::new(ids);
    let next = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..workers {
        let (pool, generations, ids, next) =
            (pool.clone(), generations.clone(), ids.clone(), next.clone());
        tasks.push(tokio::spawn(async move {
            let mut client = pool.get().await.unwrap();
            client.batch_execute("SET ROLE openvibes_ingest").await.unwrap();
            let mut times = Vec::new();
            loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if i >= ids.len() {
                    break;
                }
                let digest: [u8; 32] = {
                    let mut d = [0u8; 32];
                    d[..8].copy_from_slice(&(i as u64).to_be_bytes());
                    d
                };
                let t = Instant::now();
                inventory::replace(
                    &mut client,
                    &ids[i],
                    "fedora",
                    "44",
                    Some("6.17.4-300.fc44.x86_64"),
                    &generations[i % GENERATIONS],
                    digest,
                    Utc::now(),
                )
                .await
                .unwrap();
                times.push(t.elapsed());
            }
            times
        }));
    }
    let mut times: Vec<Duration> = Vec::new();
    for task in tasks {
        times.extend(task.await.unwrap());
    }
    times.sort();
    let ingest = start.elapsed();
    #[allow(clippy::cast_precision_loss)]
    let rate = hosts as f64 / ingest.as_secs_f64();
    println!(
        "ingest: {hosts} inventories in {ingest:.1?} ({rate:.0} hosts/s); per host p50 {:.1?} p99 {:.1?} max {:.1?}",
        quantile(&times, 0.5),
        quantile(&times, 0.99),
        times[times.len() - 1]
    );

    owner.batch_execute("VACUUM ANALYZE").await.unwrap();
    for table in ["host_packages", "package_versions", "agents"] {
        let row = owner
            .query_one(
                &format!(
                    "SELECT count(*), pg_size_pretty(pg_total_relation_size('{table}')),
                            pg_total_relation_size('{table}') FROM {table}"
                ),
                &[],
            )
            .await
            .unwrap();
        let (rows, pretty, bytes): (i64, String, i64) = (row.get(0), row.get(1), row.get(2));
        #[allow(clippy::cast_precision_loss)]
        let per_host = bytes as f64 / hosts as f64 / 1024.0;
        println!("{table}: {rows} rows, {pretty} ({per_host:.0} KiB per host)");
    }

    // Matching: the real feed imported as openvibes_vulns, which matches the
    // whole release (every host).
    let mut vulns_client = pool.get().await.unwrap();
    vulns_client.batch_execute("SET ROLE openvibes_vulns").await.unwrap();
    let source: SourceId = "fedora-44-x86_64".parse().unwrap();
    let start = Instant::now();
    let report = feed::import(&mut vulns_client, &source, &content, Utc::now()).await;
    println!("feed import + match of all hosts: {report:?} in {:.1?}", start.elapsed());
    let start = Instant::now();
    let open = matching::match_release(&mut vulns_client, "fedora", "44", Utc::now()).await;
    println!("re-match of all hosts (nothing changed): {open:?} in {:.1?}", start.elapsed());

    let mut one = Vec::new();
    for i in (0..hosts).step_by((hosts / 20).max(1)) {
        let t = Instant::now();
        matching::match_host(&mut vulns_client, &ids[i], Utc::now()).await.unwrap();
        one.push(t.elapsed());
    }
    one.sort();
    println!(
        "match_host (one host after its inventory changes): p50 {:.1?} max {:.1?}",
        quantile(&one, 0.5),
        one[one.len() - 1]
    );

    let t = Instant::now();
    let summary = vulns::summary(&vulns_client).await.unwrap();
    println!(
        "summary in {:.1?}: {} hosts, {:?}",
        t.elapsed(),
        summary.hosts,
        summary.by_severity
    );
    let t = Instant::now();
    let listed = vulns::list(&vulns_client, &vulns::ListFilter::default()).await.unwrap();
    println!("list (first 10,000 by priority) in {:.1?}: {} rows", t.elapsed(), listed.len());
    let t = Instant::now();
    let host = vulns::ListFilter {
        host: Some("host-10"),
        ..vulns::ListFilter::default()
    };
    let listed = vulns::list(&vulns_client, &host).await.unwrap();
    println!("list --host in {:.1?}: {} rows", t.elapsed(), listed.len());
    owner.batch_execute("VACUUM ANALYZE vulnerabilities").await.unwrap();
    let row = owner
        .query_one(
            "SELECT count(*), count(*) FILTER (WHERE fixed_at IS NULL),
                    pg_size_pretty(pg_total_relation_size('vulnerabilities'))
             FROM vulnerabilities",
            &[],
        )
        .await
        .unwrap();
    println!(
        "vulnerabilities: {} rows ({} open), {}",
        row.get::<_, i64>(0),
        row.get::<_, i64>(1),
        row.get::<_, String>(2)
    );
    let size: String = owner
        .query_one("SELECT pg_size_pretty(pg_database_size('ov_scale'))", &[])
        .await
        .unwrap()
        .get(0);
    println!("database: {size}; generator peak RSS {} MiB", peak_rss_mib());
}
