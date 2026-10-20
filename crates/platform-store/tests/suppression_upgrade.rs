//! Schema 55 upgrade (roles spec §12.5): every old suppression becomes
//! active from its creation, a removed one becomes removed, program and
//! command rows mean all hosts, a host row keeps its host.

mod common;

use common::TestDb;

#[tokio::test]
async fn old_suppressions_become_active_or_removed() {
    let db = TestDb::create().await;
    let c = common::at_version(&db, 54).await;
    let device: i64 = c
        .query_one(
            "INSERT INTO devices (name, kind, address, created_by, created_at)
             VALUES ('r', 'unifi', '192.168.1.1', 't', now()) RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let hash = "a".repeat(64);
    c.batch_execute(&format!(
        "INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, agent_id, exe, args_sha256,
            device_id, note, created_by, created_at, removed_by, removed_at) VALUES
         ('baseline', 'r', 'host', 'agent.1', NULL, NULL, NULL, 'n', 'a', '2026-10-01T00:00:00Z', NULL, NULL),
         ('baseline', 'r', 'program', NULL, '/bin/sh', NULL, NULL, 'n', 'a', '2026-10-02T00:00:00Z', NULL, NULL),
         ('baseline', 'r', 'command', NULL, '/bin/sh', '{hash}', NULL, 'n', 'a', '2026-10-03T00:00:00Z', NULL, NULL),
         ('baseline', 'r', 'program', NULL, '/bin/sh', NULL, NULL, 'n', 'a', '2026-10-04T00:00:00Z', 'b', '2026-10-05T00:00:00Z'),
         ('device-unifi', 'ips.1', 'device', NULL, NULL, NULL, {device}, 'n', 'a', '2026-10-06T00:00:00Z', NULL, NULL)"
    ))
    .await
    .unwrap();
    let before = c
        .query_one(
            "SELECT to_jsonb(s) FROM alarm_suppressions s WHERE scope = 'device'",
            &[],
        )
        .await
        .unwrap()
        .get::<_, serde_json::Value>(0);
    common::step_to(&c, 55).await;
    let rows = c
        .query(
            "SELECT state, host_group_id IS NULL, agent_id, expires_at IS NULL,
                activated_at = created_at
             FROM alarm_suppressions ORDER BY id",
            &[],
        )
        .await
        .unwrap();
    let got: Vec<(String, bool, Option<String>, bool, bool)> = rows
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
        .collect();
    let row = |state: &str, agent: Option<&str>| {
        (state.to_owned(), true, agent.map(str::to_owned), true, true)
    };
    assert_eq!(
        got,
        [
            row("active", Some("agent.1")),
            row("active", None),
            row("active", None),
            row("removed", None),
            row("active", None),
        ]
    );
    // The device row keeps every old column as it was.
    let after = c
        .query_one(
            "SELECT to_jsonb(s) FROM alarm_suppressions s WHERE scope = 'device'",
            &[],
        )
        .await
        .unwrap()
        .get::<_, serde_json::Value>(0);
    for (key, value) in before.as_object().unwrap() {
        assert_eq!(&after[key], value, "{key}");
    }
    drop(c);
    db.drop().await;
}
