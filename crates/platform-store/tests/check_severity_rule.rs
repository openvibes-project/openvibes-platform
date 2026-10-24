//! A check's severity is one rule on the list and its page (step 5c final
//! fix 7): the newest finding's severity, and an unknown one gives way to
//! the rule's indexed severity (a stored severity outside the known five is
//! refused by the column's CHECK today; the rule still holds if one lands).

mod common;

use chrono::Utc;
use common::checks::{every, fixture, h, row, run};
use platform_store::{
    check_summary::{Lookup, check_summary},
    console_read::AgentScope,
};

#[tokio::test]
async fn an_unknown_newest_severity_gives_way_to_the_rules() {
    let (db, c) = common::migrated().await;
    fixture(&c).await;
    // port.redis.exposed is indexed high; host 2 saw it as low an hour ago,
    // host 3 just now with a severity no list knows (the column's CHECK
    // forbids that today; dropped here so the rule is proven, not assumed).
    c.batch_execute(&format!(
        "ALTER TABLE current_findings DROP CONSTRAINT current_findings_severity_check;
         INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
             first_observed_at, last_observed_at, last_observed_day, scan_id, confidence, message, evidence,
             received_at, origin, authenticated)
         VALUES ('{}', 'baseline', 'port.redis.exposed', 'f', 1, 'low', now(), now() - interval '1 hour',
                 current_date, 's', 90, 'm', '{{}}', now(), 'online', true),
                ('{}', 'baseline', 'port.redis.exposed', 'f', 1, 'severe', now(), now(),
                 current_date, 's', 90, 'm', '{{}}', now(), 'online', true);",
        h(2),
        h(3)
    ))
    .await
    .unwrap();
    let list = run(&c, &every(), &AgentScope::Global).await;
    let listed = row(&list, "baseline/port.redis.exposed").severity.clone();
    let Lookup::Found(page) = check_summary(
        &c,
        "baseline",
        "port.redis.exposed",
        &AgentScope::Global,
        Utc::now(),
    )
    .await
    .unwrap() else {
        panic!("the check's page")
    };
    assert_eq!(listed.map(|s| s.as_str()), Some("high"), "the list");
    assert_eq!(
        page.header.severity.map(|s| s.as_str()),
        Some("high"),
        "the page agrees"
    );
    drop(c);
    db.drop().await;
}
