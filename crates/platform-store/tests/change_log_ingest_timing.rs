//! Ruling 26 (step 5e): what the change log adds to ingest, on a log of
//! 500,000 rows. Slow, so ignored. Run:
//! `cargo test -p platform-store --test change_log_ingest_timing -- --ignored --nocapture`
//!
//! The extra time is the difference between a changed report with changes
//! and a changed report whose keys are the same (the diff finds nothing, the
//! old rows are read either way).

mod common;

use std::time::{Duration, Instant};

use chrono::Utc;
use platform_store::{
    host_services::{self, Listener, Report, Service},
    inventory::{self, PackageRow},
};

const HOST: &str = "agent.00000000-0000-4000-8000-000000000701";

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

fn report(sha: usize, ports: impl Iterator<Item = i32>) -> Report {
    Report {
        sha256: format!("{sha:064x}"),
        owners: "complete".into(),
        truncated: false,
        listeners: ports
            .map(|port| Listener {
                protocol: "tcp".into(),
                address: "0.0.0.0".parse().unwrap(),
                port,
                exposed: true,
                service: None,
                program: None,
            })
            .collect(),
        services: (0..10)
            .map(|n| Service {
                unit: format!("unit{n}.service"),
                programs: vec![],
                processes: 1,
                run_as: None,
            })
            .collect(),
    }
}

fn packages(version: usize) -> Vec<PackageRow> {
    (0..150)
        .map(|n| PackageRow {
            manager: "rpm".into(),
            name: format!("pkg{n}"),
            epoch: 0,
            version: format!("1.{version}"),
            release: "1".into(),
            arch: "x86_64".into(),
            source: None,
            source_version: None,
        })
        .collect()
}

#[tokio::test]
#[ignore = "timing run; see the module doc"]
async fn what_the_change_log_adds_to_ingest() {
    let (db, admin) = common::migrated().await;
    common::seed_agent(&admin, HOST).await;
    admin
        .execute(
            "INSERT INTO change_log (at, agent_id, kind, key, change)
             SELECT now() - (g % 80) * interval '1 day', $1, 'listener', 'tcp/' || (g % 300), 'appeared'
             FROM generate_series(1, 500000) g",
            &[&HOST],
        )
        .await
        .unwrap();
    admin.batch_execute("ANALYZE change_log").await.unwrap();
    let mut ingest = db.pool.get().await.unwrap();
    ingest
        .batch_execute("SET ROLE \"openvibes-ingest\"")
        .await
        .unwrap();

    // Services: baseline of 20 listeners, then alternate a changed listener
    // set (one port differs) with a changed digest and the same keys.
    host_services::replace(&mut ingest, HOST, &report(0, 1000..1020), Utc::now())
        .await
        .unwrap();
    let (mut with, mut without) = (Vec::new(), Vec::new());
    for n in 1..=41_usize {
        let same = report(n * 2, 1000..1020);
        let started = Instant::now();
        host_services::replace(&mut ingest, HOST, &same, Utc::now())
            .await
            .unwrap();
        without.push(started.elapsed());
        let changed = report(
            n * 2 + 1,
            (1000..1019).chain([2000 + i32::try_from(n).unwrap()]),
        );
        let started = Instant::now();
        host_services::replace(&mut ingest, HOST, &changed, Utc::now())
            .await
            .unwrap();
        with.push(started.elapsed());
        // Back to the base set, untimed.
        host_services::replace(
            &mut ingest,
            HOST,
            &report(n * 2 + 1000, 1000..1020),
            Utc::now(),
        )
        .await
        .unwrap();
    }
    let extra = median(with.clone()).saturating_sub(median(without.clone()));
    println!(
        "services: same keys {:?}, one listener changed {:?}, extra {extra:?}",
        median(without),
        median(with)
    );
    assert!(
        extra <= Duration::from_millis(5),
        "extra {extra:?} over 5 ms"
    );

    // Packages: a 150-package upgrade against a same-keys report.
    inventory::replace(
        &mut ingest,
        HOST,
        "fedora",
        "44",
        None,
        &packages(0),
        [0; 32],
        Utc::now(),
    )
    .await
    .unwrap();
    let (mut with, mut without) = (Vec::new(), Vec::new());
    for n in 1..=21_u8 {
        let current = packages(usize::from(n) - 1);
        let started = Instant::now();
        inventory::replace(
            &mut ingest,
            HOST,
            "fedora",
            "44",
            None,
            &current,
            [n; 32],
            Utc::now(),
        )
        .await
        .unwrap();
        without.push(started.elapsed());
        let upgraded = packages(usize::from(n));
        let started = Instant::now();
        inventory::replace(
            &mut ingest,
            HOST,
            "fedora",
            "44",
            None,
            &upgraded,
            [n.wrapping_add(100); 32],
            Utc::now(),
        )
        .await
        .unwrap();
        with.push(started.elapsed());
    }
    let extra = median(with.clone()).saturating_sub(median(without.clone()));
    println!(
        "packages: same keys {:?}, 150 upgraded {:?}, extra {extra:?}",
        median(without),
        median(with)
    );
    assert!(
        extra <= Duration::from_millis(50),
        "extra {extra:?} over 50 ms"
    );
    db.drop().await;
}
