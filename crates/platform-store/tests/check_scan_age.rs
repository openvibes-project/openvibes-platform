//! Passing needs a recent last scan (step 5c final fix 4): a host whose
//! heartbeats are fresh but whose last scan finished two days ago is not
//! passing, on the list and on the check's page alike; a malformed scan
//! time never fails the statement.

mod common;

use chrono::Utc;
use common::checks::{every, run};
use platform_store::{
    check_summary::{Lookup, check_summary},
    console_read::AgentScope,
};

fn agent(n: u8) -> String {
    format!("agent.00000000-0000-4000-8000-0000000007{n:02}")
}

#[tokio::test]
async fn an_old_last_scan_is_not_passing() {
    let (db, c) = common::migrated().await;
    // Host 1: scan just now; host 2: two days ago; host 3: a string; host 4:
    // too many digits; host 5 fails the check (so the page exists).
    let scan = |at: &str| {
        format!(
            r#"{{"rule_sets":[{{"id":"baseline","version":1}}],"last_scan":{{"finished_at_unix_ms":{at},"collectors":{{"ports":"ok"}}}}}}"#
        )
    };
    let now_ms = Utc::now().timestamp_millis();
    let healths = [
        scan(&now_ms.to_string()),
        scan(&(now_ms - 2 * 86_400_000).to_string()),
        scan("\"soon\""),
        scan("123456789012345678901234"),
        scan(&now_ms.to_string()),
    ];
    // No rule metadata: the check is listed through host 5's finding.
    let mut sql = String::new();
    for (i, health) in healths.iter().enumerate() {
        let n = u8::try_from(i + 1).unwrap();
        sql += &format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname, health, health_at)
             VALUES ('{}', 'active', now(), now(), 'scan-{n}', '{health}', now());",
            agent(n)
        );
    }
    sql += &format!(
        "INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
             first_observed_at, last_observed_at, last_observed_day, scan_id, confidence, message, evidence,
             received_at, origin, authenticated)
         VALUES ('{}', 'baseline', 'port.x.exposed', 'f', 1, 'high', now(), now(), current_date, 's', 90, 'm', '{{}}',
             now(), 'online', true);",
        agent(5)
    );
    c.batch_execute(&sql).await.unwrap();
    let page = run(&c, &every(), &AgentScope::Global).await;
    let row = common::checks::row(&page, "baseline/port.x.exposed");
    assert_eq!((row.failing, row.passing), (1, 1), "host 1 only passes");
    let Lookup::Found(s) = check_summary(
        &c,
        "baseline",
        "port.x.exposed",
        &AgentScope::Global,
        Utc::now(),
    )
    .await
    .unwrap() else {
        panic!("the check's page")
    };
    assert_eq!(
        (s.tiles.failing, s.tiles.passing),
        (1, 1),
        "the page agrees"
    );
    drop(c);
    db.drop().await;
}
