//! Devices: add, remove, counters, heads-up.

mod common;

use std::net::IpAddr;

use chrono::{Duration, Utc};
use common::TestDb;
use platform_store::devices::{self, Counters};

async fn migrated() -> TestDb {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    db
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[tokio::test]
async fn add_refuses_a_second_active_address_and_remove_frees_it() {
    let db = migrated().await;
    let c = db.pool.get().await.unwrap();
    let now = Utc::now();
    let id = devices::add(&c, "UCG Max", "unifi", ip("192.168.1.1"), "t", now)
        .await
        .unwrap()
        .unwrap();
    let again = devices::add(&c, "Other", "unifi", ip("192.168.1.1"), "t", now)
        .await
        .unwrap();
    assert_eq!(
        again,
        Err("a device with address 192.168.1.1 already exists".into())
    );
    assert!(devices::remove(&c, id, "t", now).await.unwrap());
    assert!(
        !devices::remove(&c, id, "t", now).await.unwrap(),
        "already removed"
    );
    assert!(
        devices::add(&c, "UCG Max", "unifi", ip("192.168.1.1"), "t", now)
            .await
            .unwrap()
            .is_ok()
    );
    assert_eq!(devices::active(&c).await.unwrap().len(), 1);
    db.drop().await;
}

#[tokio::test]
async fn add_checks_name_and_kind() {
    let db = migrated().await;
    let c = db.pool.get().await.unwrap();
    let now = Utc::now();
    for (name, kind) in [
        ("", "unifi"),
        ("a\u{7}b", "unifi"),
        (&"x".repeat(65)[..], "unifi"),
        ("ok", "opnsense"),
    ] {
        assert!(
            devices::add(&c, name, kind, ip("10.0.0.1"), "t", now)
                .await
                .unwrap()
                .is_err()
        );
    }
    db.drop().await;
}

#[tokio::test]
async fn flush_adds_counters_and_caps_dropped_classes_at_64_keys() {
    let db = migrated().await;
    let mut c = db.pool.get().await.unwrap();
    let now = Utc::now();
    let id = devices::add(&c, "r", "unifi", ip("10.0.0.1"), "t", now)
        .await
        .unwrap()
        .unwrap();
    let mut counters = Counters {
        received: 3,
        not_cef: 2,
        last_seen: Some(now),
        ..Counters::default()
    };
    for n in 0..70 {
        counters.classes.insert(format!("c{n:02}"), 1);
    }
    devices::flush(&mut c, id, &counters).await.unwrap();
    devices::flush(&mut c, id, &counters).await.unwrap();
    let device = devices::list(&c).await.unwrap().remove(0);
    assert_eq!((device.received, device.not_cef), (6, 4));
    let classes = device.dropped_classes.as_object().unwrap();
    assert_eq!(classes.len(), 64);
    assert_eq!(classes["c00"], 2);
    db.drop().await;
}

#[tokio::test]
async fn heads_up_only_after_ten_quiet_minutes() {
    let db = migrated().await;
    let mut c = db.pool.get().await.unwrap();
    let now = Utc::now();
    let id = devices::add(&c, "r", "unifi", ip("10.0.0.1"), "t", now)
        .await
        .unwrap()
        .unwrap();
    let device = devices::list(&c).await.unwrap().remove(0);
    assert_eq!(devices::heads_up(&device, now + Duration::minutes(9)), None);
    assert_eq!(
        devices::heads_up(&device, now + Duration::minutes(11)),
        Some(devices::NO_EVENTS)
    );
    let seen = Counters {
        received: 1,
        last_seen: Some(now),
        ..Counters::default()
    };
    devices::flush(&mut c, id, &seen).await.unwrap();
    let device = devices::list(&c).await.unwrap().remove(0);
    assert_eq!(
        devices::heads_up(&device, now + Duration::minutes(11)),
        None
    );
    // The router's SIEM setting was changed and it went quiet.
    assert_eq!(
        devices::heads_up(&device, now + Duration::hours(25)),
        Some(devices::SILENT)
    );
    db.drop().await;
}

#[tokio::test]
async fn a_mapped_ipv6_address_is_stored_as_ipv4_and_counts_as_a_duplicate() {
    // Netlog matches canonical senders; every add path (CLI now, console
    // later) must store the same form.
    let db = migrated().await;
    let c = db.pool.get().await.unwrap();
    let now = Utc::now();
    devices::add(&c, "r", "unifi", ip("::ffff:192.168.1.1"), "t", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(devices::active(&c).await.unwrap()[0].1, ip("192.168.1.1"));
    let again = devices::add(&c, "r2", "unifi", ip("192.168.1.1"), "t", now)
        .await
        .unwrap();
    assert_eq!(
        again,
        Err("a device with address 192.168.1.1 already exists".into())
    );
    db.drop().await;
}
