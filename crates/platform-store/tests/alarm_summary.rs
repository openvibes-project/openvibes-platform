//! An alarm's page above the fold (roles 5a, task 6): the alarm, its
//! commands seen (siblings), the last 24 hours, the rule text and the
//! Related card, all inside the viewer's `alarms.read` reach.

mod common;

use chrono::Utc;
use common::alarms::alarm_fleet;
use common::hosts::id;
use platform_store::{
    Client,
    alarm_summary::{AlarmPageSummary, alarm_summary},
    console_read::AgentScope,
};

/// The id of the alarm whose message is `name`.
async fn alarm(c: &Client, name: &str) -> i64 {
    c.query_one("SELECT id FROM alarms WHERE message = $1", &[&name])
        .await
        .unwrap()
        .get(0)
}

/// Adds, beside the fleet's a1 (web-01, `r`, nginx < systemd, count 3):
/// s-usual (same, count 9), s-once (same, count 1); s-exe (other program),
/// s-parent (other parent), s-host (the same on web-02, open), s-win (`r`
/// open on win-01), each count 2; and hourly starts.
async fn siblings(c: &Client) {
    c.batch_execute(&format!(
        "INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id,
                             rule_version, severity, confidence, message, first_seen, last_seen, count,
                             process, ancestors, received_at, state)
         SELECT ((now() - v.first::interval) AT TIME ZONE 'UTC')::date, v.agent, v.msg, 'rs', 1, 'r', 1, 'high', 50, v.msg,
                now() - v.first::interval, now(), v.n,
                jsonb_build_object('exe', v.exe, 'args', jsonb_build_array(v.exe, v.msg)),
                jsonb_build_array(jsonb_build_object('exe', v.parent)), now(), 'open'
         FROM (VALUES
           ('s-usual', '{h1}', '/usr/sbin/nginx', '/usr/lib/systemd/systemd', 9, '3 days'),
           ('s-once', '{h1}', '/usr/sbin/nginx', '/usr/lib/systemd/systemd', 1, '1 hour'),
           ('s-exe', '{h1}', '/usr/bin/other', '/usr/lib/systemd/systemd', 2, '1 hour'),
           ('s-parent', '{h1}', '/usr/sbin/nginx', '/usr/bin/fish', 2, '1 hour'),
           ('s-host', '{h2}', '/usr/sbin/nginx', '/usr/lib/systemd/systemd', 2, '1 hour'),
           ('s-win', '{w}', '/usr/sbin/nginx', '/usr/lib/systemd/systemd', 2, '1 hour'))
           AS v(msg, agent, exe, parent, n, first);
         INSERT INTO alarm_hourly_starts (alarm_row_id, hour, starts)
         SELECT al.id, date_trunc('hour', now()) - x.ago::interval, x.n
         FROM alarms al JOIN (VALUES
           ('a1', '0 hours', 2), ('s-usual', '0 hours', 3), ('s-usual', '23 hours', 4),
           ('s-once', '24 hours', 50), ('s-exe', '0 hours', 70), ('s-host', '1 hour', 80))
           AS x(msg, ago, n) ON x.msg = al.message;",
        h1 = id(1),
        h2 = id(2),
        w = id(4),
    ))
    .await
    .unwrap();
}

async fn setup() -> (common::TestDb, Client, common::hosts::Groups) {
    let (db, mut c) = common::migrated().await;
    let groups = alarm_fleet(&mut c).await;
    siblings(&c).await;
    (db, c, groups)
}

async fn summary(c: &Client, name: &str, scope: &AgentScope) -> Option<AlarmPageSummary> {
    let id = alarm(c, name).await;
    alarm_summary(c, id, scope, Some(scope), Utc::now())
        .await
        .unwrap()
}

fn commands(s: &AlarmPageSummary) -> Vec<String> {
    s.commands
        .iter()
        .map(|c| c.args.last().cloned().unwrap_or_default())
        .collect()
}

#[tokio::test]
async fn summary_stays_inside_the_scope() {
    let (db, c, groups) = setup().await;
    let web = AgentScope::AssetGroups(vec![groups.web.clone()]);
    let windows = AgentScope::AssetGroups(vec![groups.windows.clone()]);
    // Out of reach reads as missing, by id or by a sibling's id.
    assert!(summary(&c, "a1", &windows).await.is_none());
    assert!(summary(&c, "s-usual", &windows).await.is_none());
    assert!(
        alarm_summary(&c, i64::MAX, &AgentScope::Global, None, Utc::now())
            .await
            .unwrap()
            .is_none()
    );
    let s = summary(&c, "a1", &web).await.unwrap();
    assert!(s.commands.iter().all(|c| c.agent_id == id(1)));
    // Elsewhere: web-02 only (win-01 and the suppressed db-01 alarm are not counted).
    assert_eq!((s.elsewhere.hosts, s.elsewhere.open), (1, 1));
    let g = summary(&c, "a1", &AgentScope::Global).await.unwrap();
    assert_eq!((g.elsewhere.hosts, g.elsewhere.open), (2, 2));
    assert!(s.reaches(&web) && !s.reaches(&windows) && s.reaches(&AgentScope::Global));
    db.drop().await;
}

#[tokio::test]
async fn siblings_are_one_host_rule_program_and_parent_usual_first() {
    let (db, c, _) = setup().await;
    let s = summary(&c, "a1", &AgentScope::Global).await.unwrap();
    // a1 has no args in the fixture.
    assert_eq!(commands(&s), ["s-usual", "", "s-once"]);
    assert_eq!(
        s.commands.iter().map(|c| c.count).collect::<Vec<_>>(),
        [9, 3, 1]
    );
    assert_eq!(s.commands[0].args, ["/usr/sbin/nginx", "s-usual"]);
    db.drop().await;
}

#[tokio::test]
async fn hourly_covers_exactly_the_last_24_hours() {
    let (db, c, _) = setup().await;
    let s = summary(&c, "a1", &AgentScope::Global).await.unwrap();
    assert_eq!(s.hourly.len(), 24);
    // Oldest first: 23 hours ago holds 4, this hour 2 + 3; 24 hours ago,
    // another program and another host are left out.
    assert_eq!(s.hourly[0], 4);
    assert_eq!(s.hourly[23], 5);
    assert_eq!(s.hourly.iter().sum::<i64>(), 9);
    db.drop().await;
}

#[tokio::test]
async fn rule_text_falls_back_when_not_indexed() {
    let (db, c, _) = setup().await;
    let indexed = summary(&c, "a1", &AgentScope::Global).await.unwrap();
    assert_eq!(indexed.rule.title, "r");
    assert_eq!(indexed.rule.techniques, ["T1059.004", "T1105"]);
    let fallback = summary(&c, "a2", &AgentScope::Global).await.unwrap();
    assert_eq!(fallback.rule.title, "a2");
    assert_eq!(fallback.rule.message, "a2");
    assert!(fallback.rule.explain.is_none() && fallback.rule.check.is_none());
    assert!(fallback.rule.techniques.is_empty());
    db.drop().await;
}

#[tokio::test]
async fn related_lists_other_open_alarms_and_vulnerabilities_with_their_scope() {
    let (db, c, groups) = setup().await;
    let web = AgentScope::AssetGroups(vec![groups.web.clone()]);
    let s = summary(&c, "a1", &web).await.unwrap();
    // web-01's other open alarms: a2, s-usual, s-once, s-exe, s-parent.
    assert_eq!(s.host_alarms.total, 5);
    assert_eq!(s.host_alarms.items.len(), 5);
    assert!(s.host_alarms.items.iter().all(|a| a.message != "a1"));
    assert!(s.host_vulnerabilities.is_some());
    let id = alarm(&c, "a1").await;
    let windows = AgentScope::AssetGroups(vec![groups.windows]);
    let without = alarm_summary(&c, id, &web, Some(&windows), Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert!(without.host_vulnerabilities.is_none());
    let none = alarm_summary(&c, id, &web, None, Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert!(none.host_vulnerabilities.is_none());
    db.drop().await;
}
