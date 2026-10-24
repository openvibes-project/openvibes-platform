//! A check's page (roles spec §10.3; step 5c rulings 2, 11–15): the
//! summary and the Hosts table stay inside the viewer's scope and agree
//! with the Compliance list.

mod common;

use chrono::{DateTime, Utc};
use common::checks::{ANN, SSH, TELNET, every, fixture, h, run};
use platform_store::{
    Client,
    check_summary::{
        CheckHostSegment, CheckHostState, CheckHostsPage, CheckPageSummary, Evidence, Lookup,
        check_hosts, check_summary, evidence,
    },
    console_read::AgentScope,
    vuln_list::AssigneeSummary,
};
use serde_json::json;

fn split(key: &str) -> (&str, &str) {
    key.split_once('/').unwrap()
}

async fn summary(c: &Client, key: &str, scope: &AgentScope) -> Option<CheckPageSummary> {
    summary_at(c, key, scope, Utc::now()).await
}

async fn summary_at(
    c: &Client,
    key: &str,
    scope: &AgentScope,
    now: DateTime<Utc>,
) -> Option<CheckPageSummary> {
    let (set, rule) = split(key);
    match check_summary(c, set, rule, scope, now).await.unwrap() {
        Lookup::Found(s) => Some(s),
        Lookup::Missing => None,
        Lookup::SeveralCves(_) => unreachable!(),
    }
}

async fn hosts(
    c: &Client,
    key: &str,
    scope: &AgentScope,
    segment: CheckHostSegment,
    offset: i64,
    limit: i64,
) -> Option<CheckHostsPage> {
    hosts_in(c, key, scope, segment, None, offset, limit).await
}

async fn hosts_in(
    c: &Client,
    key: &str,
    scope: &AgentScope,
    segment: CheckHostSegment,
    state: Option<CheckHostState>,
    offset: i64,
    limit: i64,
) -> Option<CheckHostsPage> {
    let (set, rule) = split(key);
    match check_hosts(
        c,
        set,
        rule,
        scope,
        segment,
        state,
        offset,
        limit,
        Utc::now(),
    )
    .await
    .unwrap()
    {
        Lookup::Found(p) => Some(p),
        Lookup::Missing => None,
        Lookup::SeveralCves(_) => unreachable!(),
    }
}

/// Port 22 exposed on hosts 1 and 4, a redis finding on host 4 (out of
/// reach), triage history on hosts 1 and 4, and the ssh rule's expression.
const EXTRA: &str = "
UPDATE console_rule_meta SET expression = '''22'' in facts[''port.tcp.exposed'']'
  WHERE rule_id = 'port.ssh.exposed';
INSERT INTO host_listeners (agent_id, protocol, address, port, exposed) VALUES
  ('agent.00000000-0000-4000-8000-000000000001', 'tcp', '0.0.0.0', 22, true),
  ('agent.00000000-0000-4000-8000-000000000002', 'tcp', '127.0.0.1', 22, false),
  ('agent.00000000-0000-4000-8000-000000000004', 'tcp', '0.0.0.0', 22, true);
INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
                              first_observed_at, last_observed_at, last_observed_day, scan_id, confidence,
                              message, evidence, received_at, origin, authenticated, source)
VALUES ('agent.00000000-0000-4000-8000-000000000004', 'baseline', 'port.redis.exposed', 'f', 1, 'critical',
        now(), now(), current_date, 's', 90, 'm', '{}', now(), 'online', true, 'changes');
INSERT INTO console_finding_triage_history (agent_id, rule_set_id, rule_id, from_state, to_state, note,
                                            changed_at, changed_by)
VALUES ('agent.00000000-0000-4000-8000-000000000001', 'baseline', 'port.ssh.exposed', NULL, 'open', NULL,
        now() - interval '1 minute', '00000000-0000-4000-8000-0000000000a1'),
       ('agent.00000000-0000-4000-8000-000000000004', 'baseline', 'port.ssh.exposed', 'open', 'mitigated', 'x',
        now(), 'someone');";

#[tokio::test]
async fn check_summary_stays_inside_the_scope() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    c.batch_execute(EXTRA).await.unwrap();
    let scoped = AgentScope::AssetGroups(vec![web]);
    let s = summary(&c, SSH, &scoped).await.unwrap();
    let g = summary(&c, SSH, &AgentScope::Global).await.unwrap();
    assert_eq!((s.tiles.failing, s.tiles.passing), (3, 2));
    assert_eq!((g.tiles.failing, g.tiles.passing), (4, 2));
    assert_eq!((s.header.failing, s.header.checked), (3, 5));
    assert_eq!(
        (s.header.open, g.header.open),
        (2, 3),
        "open failing pairs: hosts 1 and 3 (expired acceptance), and 4 out of reach"
    );
    assert_eq!(s.header.title, "SSH port exposed");
    assert_eq!(s.header.rule_set_version, Some(2));
    assert_eq!(s.header.rule_version, Some(2));
    assert_eq!(s.header.area, "Network exposure");
    assert_eq!(s.header.severity.map(|v| v.as_str()), Some("high"));
    assert_eq!(g.header.severity.map(|v| v.as_str()), Some("critical"));
    assert!(
        matches!(&s.header.assignee, AssigneeSummary::One(id, _) if id == ANN),
        "host 1 (Ann) is the only open assigned pair: {:?}",
        s.header.assignee
    );
    assert_eq!(s.details.applies_to, "All hosts");
    let host4 = h(4);
    assert!(!s.agents.contains(&host4));
    assert!(g.agents.contains(&host4));
    assert_eq!(s.tiles.days[13], 3, "today: hosts 1-3");
    assert_eq!(g.tiles.days[13], 4);
    assert!(
        s.history
            .iter()
            .all(|e| e.agent_id.as_deref() != Some(&host4)),
        "{:?}",
        s.history
    );
    assert!(
        g.history
            .iter()
            .any(|e| e.agent_id.as_deref() == Some(&host4))
    );
    let kinds =
        |s: &CheckPageSummary, kind: &str| s.history.iter().filter(|e| e.kind == kind).count();
    assert_eq!(kinds(&s, "failing"), 3);
    assert_eq!(kinds(&s, "triage"), 1);
    assert_eq!(kinds(&s, "published"), 2, "baseline 1 and 2");
    assert!(
        s.history.windows(2).all(|w| w[0].at >= w[1].at),
        "newest first"
    );
    let first = s.tiles.first_seen.as_ref().unwrap();
    assert_eq!(
        first.hostname.as_deref(),
        Some("host-3"),
        "seen 13 days ago"
    );
    // Related: port 22 exposed on host 1 only in reach; redis fails only
    // on host 4, out of reach.
    let port = s.related.port.as_ref().unwrap();
    assert_eq!(
        (port.protocol.as_str(), port.port, port.hosts),
        ("tcp", 22, 1)
    );
    assert_eq!(g.related.port.as_ref().unwrap().hosts, 2);
    assert_eq!(s.related.same_area.checks, 0);
    assert_eq!(g.related.same_area.checks, 1);
    assert_eq!(g.related.same_area.worst.as_deref(), Some("critical"));
    assert_eq!(s.related.service, None);
    // Hosts never names host 4.
    let page = hosts(&c, SSH, &scoped, CheckHostSegment::All, 0, 100)
        .await
        .unwrap();
    assert_eq!(page.segments.all, 5);
    assert!(page.rows.iter().all(|r| r.agent_id != host4));
    // A check learnt only from out-of-reach hosts is missing, both routes.
    let secret = "site-x/secret.rule";
    assert!(summary(&c, secret, &scoped).await.is_none());
    assert!(
        hosts(&c, secret, &scoped, CheckHostSegment::All, 0, 50)
            .await
            .is_none()
    );
    assert!(summary(&c, secret, &AgentScope::Global).await.is_some());
    let nobody = AgentScope::AssetGroups(vec![]);
    assert!(summary(&c, SSH, &nobody).await.is_none());
    assert!(
        summary(&c, "baseline/no.such.rule", &AgentScope::Global)
            .await
            .is_none()
    );
    // Telnet: host 1 fixed an hour ago ("passes again"), host 4 out of reach.
    let t = summary(&c, TELNET, &scoped).await.unwrap();
    assert_eq!((t.tiles.failing, t.tiles.passing), (0, 6));
    assert_eq!(kinds(&t, "passes_again"), 1);
    assert_eq!(t.tiles.first_seen.map(|f| f.at), None);
    db.drop().await;
}

#[tokio::test]
async fn passing_in_the_tiles_agrees_with_the_list() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    for scope in [AgentScope::AssetGroups(vec![web]), AgentScope::Global] {
        let list = run(&c, &every(), &scope).await;
        assert!(!list.rows.is_empty());
        for row in &list.rows {
            let key = format!("{}/{}", row.rule_set_id, row.rule_id);
            let s = summary(&c, &key, &scope).await.unwrap();
            assert_eq!(
                (s.tiles.failing, s.tiles.passing),
                (row.failing, row.passing),
                "{key}"
            );
            assert_eq!(s.header.severity, row.severity, "{key}");
            assert_eq!(s.header.title, row.title, "{key}");
        }
    }
    db.drop().await;
}

#[tokio::test]
async fn fourteen_days_count_failing_hosts_per_utc_day() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    // Host 1 fails since 10-19; host 2 failed 10-14 to 10-21; host 3's
    // legacy row was last seen 10-17 (stale); host 4, out of reach, fails
    // since 10-01.
    c.batch_execute(
        "INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
                                       first_observed_at, last_observed_at, last_observed_day, scan_id,
                                       confidence, message, evidence, received_at, origin, authenticated,
                                       source, ended_at)
         SELECT 'agent.00000000-0000-4000-8000-00000000000' || v.h, 'baseline', 'port.days', 'f', 1, 'low',
                v.first::timestamptz, v.last::timestamptz, v.last::date, 's', 90, 'm', '{}', now(), 'online',
                true, v.src, v.ended::timestamptz
         FROM (VALUES (1, '2026-10-19 12:00Z', '2026-10-24 11:00Z', 'changes', NULL),
                      (2, '2026-10-14 12:00Z', '2026-10-21 12:00Z', 'changes', '2026-10-21 12:00Z'),
                      (3, '2026-10-12 12:00Z', '2026-10-17 12:00Z', 'scan', NULL),
                      (4, '2026-10-01 12:00Z', '2026-10-24 11:00Z', 'changes', NULL))
              v(h, first, last, src, ended)",
    )
    .await
    .unwrap();
    let now = "2026-10-24T12:00:00Z".parse().unwrap();
    let s = summary_at(
        &c,
        "baseline/port.days",
        &AgentScope::AssetGroups(vec![web]),
        now,
    )
    .await
    .unwrap();
    assert_eq!(s.tiles.days, [0, 1, 1, 2, 2, 2, 2, 1, 2, 2, 2, 1, 1, 1]);
    assert_eq!(s.tiles.failing, 1);
    let g = summary_at(&c, "baseline/port.days", &AgentScope::Global, now)
        .await
        .unwrap();
    assert_eq!(g.tiles.days[0], 1, "host 4 counts only globally");
    db.drop().await;
}

#[test]
fn evidence_never_shows_a_withheld_value() {
    let inputs = json!([
        {"key": "sshd.permitrootlogin", "status": "complete", "value": "yes"},
        {"key": "sshd.maxauthtries", "value": 6},
        {"key": "sshd.secret", "status": "masked"},
        {"key": "service.enabled", "status": "summarized", "item_count": 40},
        {"key": "sshd.banner", "status": "truncated", "value": "Authorized use onl"},
        {"status": "complete", "value": "no key"}
    ]);
    let e = |fact: &str, value: Option<&str>, status: Option<&str>| Evidence {
        fact: fact.into(),
        value: value.map(Into::into),
        status: status.map(Into::into),
    };
    assert_eq!(
        evidence(&inputs),
        [
            e("sshd.permitrootlogin", Some("yes"), None),
            e("sshd.maxauthtries", Some("6"), None),
            e("sshd.secret", None, Some("masked")),
            e("service.enabled", None, Some("summarized")),
            e("sshd.banner", None, Some("truncated")),
        ]
    );
    assert!(evidence(&json!(null)).is_empty());
}

#[tokio::test]
async fn segments_add_up_and_page() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    c.batch_execute(
        "UPDATE current_findings SET detection = '{\"inputs\":[{\"key\":\"port.tcp.exposed\",
             \"status\":\"summarized\",\"item_count\":3},{\"key\":\"os.id\",\"status\":\"complete\",\"value\":\"fedora\"}]}'
         WHERE rule_id = 'port.ssh.exposed' AND agent_id = 'agent.00000000-0000-4000-8000-000000000001'",
    )
    .await
    .unwrap();
    let scope = AgentScope::AssetGroups(vec![web]);
    let all = hosts(&c, SSH, &scope, CheckHostSegment::All, 0, 100)
        .await
        .unwrap();
    let s = all.segments;
    assert_eq!((s.all, s.failing, s.passing), (5, 3, 2));
    assert_eq!(all.total, 5);
    let names: Vec<_> = all
        .rows
        .iter()
        .map(|r| r.hostname.clone().unwrap())
        .collect();
    assert_eq!(names, ["host-1", "host-11", "host-2", "host-3", "host-9"]);
    let one = &all.rows[0];
    assert_eq!(one.state, "open");
    assert_eq!(one.assignee.as_ref().map(|a| a.1.as_str()), Some("Ann"));
    assert_eq!(one.triage_version, Some(1));
    assert_eq!(
        one.evidence,
        [
            Evidence {
                fact: "port.tcp.exposed".into(),
                value: None,
                status: Some("summarized".into())
            },
            Evidence {
                fact: "os.id".into(),
                value: Some("fedora".into()),
                status: None
            }
        ]
    );
    let states: Vec<_> = all.rows.iter().map(|r| r.state.as_str()).collect();
    assert_eq!(
        states,
        ["open", "passing", "mitigated", "open", "passing"],
        "expired acceptance is open"
    );
    assert!(all.rows[2].evidence.is_empty(), "no detection");
    assert!(
        all.rows[3].accepted_until.is_some_and(|t| t < Utc::now()),
        "host 3's expired acceptance keeps its date, as the old panel showed"
    );
    assert!(all.rows[0].accepted_until.is_none() && all.rows[1].accepted_until.is_none());
    let passing = &all.rows[1];
    assert!(
        passing.evidence.is_empty()
            && passing.triage_version.is_none()
            && passing.assignee.is_none()
    );
    assert!(passing.checked_at.is_some());
    let failing = hosts(&c, SSH, &scope, CheckHostSegment::Failing, 0, 100)
        .await
        .unwrap();
    assert_eq!(failing.total, 3);
    assert!(failing.rows.iter().all(|r| r.state != "passing"));
    let t = failing.states;
    assert_eq!(
        (t.open, t.mitigated, t.accepted_risk, t.false_positive),
        (2, 1, 0, 0),
        "the failing pairs by triage state, an expired acceptance open"
    );
    assert!(
        failing
            .rows
            .iter()
            .all(|r| r.origin.as_deref() == Some("online"))
    );
    assert!(
        all.rows[1].origin.is_none(),
        "a passing host has no finding"
    );
    let mitigated = hosts_in(
        &c,
        SSH,
        &scope,
        CheckHostSegment::Failing,
        Some(CheckHostState::Mitigated),
        0,
        100,
    )
    .await
    .unwrap();
    assert_eq!(mitigated.total, 1);
    assert_eq!(mitigated.rows.len(), 1);
    assert_eq!(mitigated.rows[0].state, "mitigated");
    assert_eq!(mitigated.states.open, 2, "counts ignore the state chosen");
    let pass = hosts(&c, SSH, &scope, CheckHostSegment::Passing, 0, 100)
        .await
        .unwrap();
    assert_eq!(pass.total, 2);
    assert!(pass.rows.iter().all(|r| r.state == "passing"));
    let p1 = hosts(&c, SSH, &scope, CheckHostSegment::All, 0, 2)
        .await
        .unwrap();
    let p3 = hosts(&c, SSH, &scope, CheckHostSegment::All, 4, 2)
        .await
        .unwrap();
    assert_eq!((p1.rows.len(), p3.rows.len(), p3.total), (2, 1, 5));
    assert_eq!(p3.rows[0].hostname.as_deref(), Some("host-9"));
    db.drop().await;
}

#[tokio::test]
async fn related_service_counts_hosts_in_reach() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    c.batch_execute(
        "INSERT INTO console_rule_meta (rule_set_id, rule_set_version, rule_id, rule_version, title, message,
                                        attack, techniques, severity, expression)
         VALUES ('hardening-linux-l1', 1, 'harden.services.avahi', 1, 'Avahi enabled', 'm', '[]', '{T1046}',
                 'low', '''avahi-daemon.service'' in facts[''service.enabled'']');
         INSERT INTO host_services (agent_id, unit, programs, processes)
         SELECT 'agent.00000000-0000-4000-8000-00000000000' || n, 'avahi-daemon.service', '{avahi-daemon}', 1
         FROM generate_series(2, 4) n;",
    )
    .await
    .unwrap();
    let s = summary(
        &c,
        "hardening-linux-l1/harden.services.avahi",
        &AgentScope::AssetGroups(vec![web]),
    )
    .await
    .unwrap();
    let service = s.related.service.unwrap();
    assert_eq!(
        (service.unit.as_str(), service.hosts),
        ("avahi-daemon.service", 2)
    );
    assert_eq!(s.related.port, None);
    assert_eq!(s.details.techniques, ["T1046"]);
    assert_eq!(s.details.applies_to, "Linux hosts");
    assert_eq!(s.header.area, "Services");
    db.drop().await;
}
