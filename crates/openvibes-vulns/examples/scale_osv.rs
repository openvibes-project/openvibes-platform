//! OSV scale check (OSV spec D5): N synthetic Debian 12 hosts, each with a
//! real Debian package list, stored through the same store call ingest
//! uses, then matched against OSV's real Debian `all.zip`.
//!
//! ```sh
//! # name, epoch, version, release, arch, source, source_version (tab-separated)
//! dpkg-query -W -f '...' > pkgs.tsv    # see docs/sizing.md
//! curl -sSO https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip
//! eval "$(scripts/test-db.sh)"
//! cargo run --release -p openvibes-vulns --example scale_osv -- pkgs.tsv all.zip 10000 16
//! ```
//!
//! Hosts come in 20 generations: generation g holds about g% of the source
//! packages OSV has a fix for just below that fix (`<fixed>~old`, which
//! dpkg orders first), so matching opens real vulnerabilities alongside
//! the ones Debian has not fixed yet. Creates and keeps `ov_scale_osv`.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use chrono::Utc;
use openvibes_vulns::{matching, osv};
use platform_store::{
    inventory::{self, PackageRow},
    vulns,
};

const GENERATIONS: usize = 20;

fn hash(text: &str) -> u64 {
    // FNV-1a: deterministic, no dependency.
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn quantile(sorted: &[Duration], q: f64) -> Duration {
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
            let name = (*f.first()?).to_owned();
            Some(PackageRow {
                manager: "dpkg".into(),
                epoch: f.get(1)?.parse().ok()?,
                version: (*f.get(2)?).into(),
                release: (*f.get(3)?).into(),
                arch: (*f.get(4)?).into(),
                source: f
                    .get(5)
                    .filter(|s| !s.is_empty() && **s != name)
                    .map(|s| (*s).to_owned()),
                source_version: f.get(6).filter(|s| !s.is_empty()).map(|s| (*s).to_owned()),
                name,
            })
        })
        .collect();
    let zip = std::fs::read(&args[2]).unwrap();
    let release: osv::Release = "debian-12".parse().unwrap();
    let start = Instant::now();
    let found = osv::advisories_from_zip(&zip, &release, osv::MAX_OPEN_BYTES).unwrap();
    println!(
        "read {} records, {} advisories for debian-12 in {:.1?}",
        found.records,
        found.advisories.len(),
        start.elapsed()
    );
    // The first fixed version per source package.
    let mut fixed: HashMap<&str, &str> = HashMap::new();
    for advisory in &found.advisories {
        for p in &advisory.packages {
            if let Some(version) = &p.fixed {
                fixed.entry(p.name.as_str()).or_insert(version.as_str());
            }
        }
    }
    let generation = |g: usize| -> Vec<PackageRow> {
        base.iter()
            .map(|p| {
                let source = p.source.as_deref().unwrap_or(&p.name);
                match fixed.get(source) {
                    Some(version) if hash(source) % 100 < g as u64 => PackageRow {
                        source: Some(source.to_owned()),
                        source_version: Some(format!("{version}~old")),
                        ..p.clone()
                    },
                    _ => p.clone(),
                }
            })
            .collect()
    };
    let generations = Arc::new((0..GENERATIONS).map(generation).collect::<Vec<_>>());
    println!(
        "{} packages per host, {} sources with a fix, {hosts} hosts, {workers} workers",
        base.len(),
        fixed.len()
    );

    let url = std::env::var("OPENVIBES_TEST_DATABASE_URL").unwrap();
    let server = platform_store::connect(&url).await.unwrap();
    let admin = server.get().await.unwrap();
    admin
        .batch_execute("DROP DATABASE IF EXISTS ov_scale_osv")
        .await
        .unwrap();
    admin
        .batch_execute("CREATE DATABASE ov_scale_osv")
        .await
        .unwrap();
    let url = url.replace("/postgres?", "/ov_scale_osv?");
    let pool = platform_store::connect_sized(&url, workers + 2)
        .await
        .unwrap();
    let mut owner = pool.get().await.unwrap();
    platform_store::migrate(&mut owner).await.unwrap();
    let ids: Arc<Vec<String>> = Arc::new(
        (0..hosts)
            .map(|i| format!("agent.00000000-0000-4000-8000-{i:012}"))
            .collect(),
    );
    owner
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname)
             SELECT a, 'active', now(), 'host-' || n FROM unnest($1::text[]) WITH ORDINALITY AS x(a, n)",
            &[&*ids],
        )
        .await
        .unwrap();

    let start = Instant::now();
    let next = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..workers {
        let (pool, generations, ids, next) =
            (pool.clone(), generations.clone(), ids.clone(), next.clone());
        tasks.push(tokio::spawn(async move {
            let mut client = pool.get().await.unwrap();
            client
                .batch_execute("SET ROLE openvibes_ingest")
                .await
                .unwrap();
            let mut times = Vec::new();
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= ids.len() {
                    break;
                }
                let mut digest = [0u8; 32];
                digest[..8].copy_from_slice(&(i as u64).to_be_bytes());
                let t = Instant::now();
                inventory::replace(
                    &mut client,
                    &ids[i],
                    "debian",
                    "12",
                    None,
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
    let mut times = Vec::new();
    for task in tasks {
        times.extend(task.await.unwrap());
    }
    times.sort();
    let ingest = start.elapsed();
    #[allow(clippy::cast_precision_loss)]
    let rate = hosts as f64 / ingest.as_secs_f64();
    println!(
        "ingest: {hosts} inventories in {ingest:.1?} ({rate:.0} hosts/s); per host p50 {:.1?} p99 {:.1?}",
        quantile(&times, 0.5),
        quantile(&times, 0.99)
    );
    owner
        .batch_execute("SET statement_timeout = 0")
        .await
        .unwrap();
    owner.batch_execute("VACUUM ANALYZE").await.unwrap();
    for table in ["host_packages", "package_versions"] {
        let row = owner
            .query_one(
                &format!(
                    "SELECT count(*), pg_size_pretty(pg_total_relation_size('{table}')) FROM {table}"
                ),
                &[],
            )
            .await
            .unwrap();
        println!(
            "{table}: {} rows, {}",
            row.get::<_, i64>(0),
            row.get::<_, String>(1)
        );
    }

    // The import as the service runs it: store, then match every host.
    let mut vulns_client = pool.get().await.unwrap();
    vulns_client
        .batch_execute("SET ROLE openvibes_vulns")
        .await
        .unwrap();
    let start = Instant::now();
    let report = osv::import(&mut vulns_client, &release, zip, Utc::now()).await;
    println!(
        "import + match of all hosts: {report:?} in {:.1?}",
        start.elapsed()
    );
    let start = Instant::now();
    let open = matching::match_release(&mut vulns_client, "debian", "12", Utc::now()).await;
    println!("re-match of all hosts: {open:?} in {:.1?}", start.elapsed());
    let mut one = Vec::new();
    for i in (0..hosts).step_by((hosts / 20).max(1)) {
        let t = Instant::now();
        matching::match_host(&mut vulns_client, &ids[i], Utc::now())
            .await
            .unwrap();
        one.push(t.elapsed());
    }
    one.sort();
    println!(
        "match_host: p50 {:.1?} max {:.1?}",
        quantile(&one, 0.5),
        one[one.len() - 1]
    );
    let t = Instant::now();
    let summary = vulns::summary(&vulns_client).await.unwrap();
    println!(
        "summary in {:.1?}: {} hosts, {} without a fix, {:?}",
        t.elapsed(),
        summary.hosts,
        summary.no_fix,
        summary.by_severity
    );
    let t = Instant::now();
    let listed = vulns::list(&vulns_client, &vulns::ListFilter::default())
        .await
        .unwrap();
    println!("list in {:.1?}: {} rows", t.elapsed(), listed.len());
    let t = Instant::now();
    let host = vulns::ListFilter {
        host: Some("host-10"),
        ..vulns::ListFilter::default()
    };
    let listed = vulns::list(&vulns_client, &host).await.unwrap();
    println!("list --host in {:.1?}: {} rows", t.elapsed(), listed.len());
    let row = owner
        .query_one(
            "SELECT count(*), pg_size_pretty(pg_total_relation_size('vulnerabilities')),
                    pg_size_pretty(pg_database_size('ov_scale_osv'))
             FROM vulnerabilities WHERE fixed_at IS NULL",
            &[],
        )
        .await
        .unwrap();
    println!(
        "vulnerabilities: {} open, {}; database {}; peak RSS {} MiB",
        row.get::<_, i64>(0),
        row.get::<_, String>(1),
        row.get::<_, String>(2),
        peak_rss_mib()
    );
}
