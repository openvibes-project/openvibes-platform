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
