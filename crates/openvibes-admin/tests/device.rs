//! `openvibes-admin device`: add, list, remove, all audited.
// The test starts the CLI binary it verifies; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use common::{Fixture, row, stdout};

#[tokio::test]
async fn devices_are_added_listed_and_removed() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let added = stdout(&fixture.run(&[
        "device",
        "add",
        "--name",
        "UCG Max",
        "--address",
        "192.168.1.1",
    ]));
    assert!(
        added.starts_with("device 1 added: UCG Max (192.168.1.1)"),
        "{added}"
    );
    let again = fixture.run(&[
        "device",
        "add",
        "--name",
        "Other",
        "--address",
        "192.168.1.1",
    ]);
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already exists"));
    let list = stdout(&fixture.run(&["device", "list"]));
    assert!(
        list.starts_with("1  UCG Max  192.168.1.1  unifi  never"),
        "{list}"
    );
    stdout(&fixture.run(&["device", "remove", "1"]));
    assert_eq!(stdout(&fixture.run(&["device", "list"])), "no devices\n");
    assert!(!fixture.run(&["device", "remove", "1"]).status.success());
    let audit = fixture.audit().await;
    assert!(audit.contains(&row("device add", "ok")), "{audit:?}");
    assert!(audit.contains(&row("device remove", "ok")), "{audit:?}");
    fixture.drop().await;
}

#[tokio::test]
async fn a_noisy_signature_is_suppressed_listed_and_unsuppressed() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    stdout(&fixture.run(&[
        "device",
        "add",
        "--name",
        "UCG Max",
        "--address",
        "192.168.1.1",
    ]));
    let pool = platform_store::connect(&fixture.url).await.unwrap();
    let client = pool.get().await.unwrap();
    platform_store::ensure_partitions(&client, chrono::Utc::now().date_naive(), 1)
        .await
        .unwrap();
    let alarm: i64 = client
        .query_one(
            "INSERT INTO alarms (first_seen_day, source, device_id, alarm_id, rule_set_id,
                rule_set_version, rule_id, rule_version, severity, confidence, message,
                first_seen, last_seen, count, network, received_at)
             VALUES ((now() AT TIME ZONE 'UTC')::date, 'device', 1, 'a', 'device-unifi', 0,
                'ips.2008983', 0, 'high', 80, 'BlackSun', now(), now(), 1, '{}', now())
             RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let id = alarm.to_string();
    let bad = fixture.run(&["device", "suppress", &id, "--scope", "host", "--note", "x"]);
    assert!(!bad.status.success());
    let made = stdout(&fixture.run(&[
        "device",
        "suppress",
        &id,
        "--scope",
        "device",
        "--note",
        "our own scanner",
    ]));
    assert!(
        made.starts_with("suppression 1 created: ips.2008983 on device 1"),
        "{made}"
    );
    let list = stdout(&fixture.run(&["device", "suppressions"]));
    assert!(
        list.contains("1  device  ips.2008983  device 1  our own scanner"),
        "{list}"
    );
    stdout(&fixture.run(&["device", "unsuppress", "1"]));
    assert_eq!(
        stdout(&fixture.run(&["device", "suppressions"])),
        "no device suppressions\n"
    );
    fixture.drop().await;
}
