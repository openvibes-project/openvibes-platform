//! The host page's summary (roles step 4, Task 4; plan ruling 10): every
//! section above the fold, each present only where its permission reaches
//! this host.

mod common;

use chrono::Utc;
use common::hosts::{GLOBAL, everywhere, fleet, id};
use platform_store::{
    Client,
    console_read::AgentScope,
    host_list::{HostScopes, HostStatus},
    host_summary::{HostSummary, summary},
};

async fn get(c: &Client, agent: &str, s: &HostScopes<'_>) -> Option<HostSummary> {
    summary(c, agent, s, Some("0.4.2"), Utc::now())
        .await
        .unwrap()
}

#[tokio::test]
async fn summary_sections_follow_permissions() {
    let (db, c) = common::migrated().await;
    let groups = fleet(&c).await;
    let s = get(&c, id(1), &everywhere()).await.unwrap();
    assert_eq!(s.status, HostStatus::Online);
    assert_eq!(s.address.as_deref(), Some("10.0.1.5"));
    assert_eq!(s.os_family.as_deref(), Some("linux"));
    assert_eq!(s.agent_older, Some(true));
    assert_eq!(s.labels, ["prod"]);
    let names: Vec<_> = s.groups.iter().map(|g| g.1.as_str()).collect();
    assert_eq!(names, ["Alpha", "Linux", "Web"]);
    assert_eq!(s.top_alarms.as_ref().unwrap().total, 2);
    assert_eq!(s.top_failing.as_ref().unwrap().total, 1);
    assert_eq!(s.top_vulnerabilities.as_ref().unwrap().total, 0);

    // hosts.read only: the alarms, vulnerabilities and compliance sections
    // are absent; the rest is there.
    let bare = HostScopes {
        hosts: &GLOBAL,
        alarms: None,
        vulnerabilities: None,
        compliance: None,
    };
    let s = get(&c, id(1), &bare).await.unwrap();
    assert!(s.top_alarms.is_none() && s.top_failing.is_none() && s.top_vulnerabilities.is_none());
    assert_eq!(s.labels, ["prod"]);

    // alarms.read on another group does not reach this host.
    let elsewhere = AgentScope::AssetGroups(vec![groups.windows.clone()]);
    let web = AgentScope::AssetGroups(vec![groups.web.clone()]);
    let partial = HostScopes {
        hosts: &web,
        alarms: Some(&elsewhere),
        vulnerabilities: Some(&web),
        compliance: None,
    };
    let s = get(&c, id(1), &partial).await.unwrap();
    assert!(s.top_alarms.is_none());
    assert!(s.top_failing.is_none());
    assert!(s.top_vulnerabilities.is_some());
    assert!(s.reaches(&web) && !s.reaches(&elsewhere) && s.reaches(&GLOBAL));
    db.drop().await;
}

#[tokio::test]
async fn out_of_reach_and_missing_hosts_are_both_none() {
    let (db, c) = common::migrated().await;
    let groups = fleet(&c).await;
    let web = AgentScope::AssetGroups(vec![groups.web]);
    let scoped = HostScopes {
        hosts: &web,
        ..everywhere()
    };
    assert!(get(&c, id(4), &scoped).await.is_none());
    assert!(get(&c, "agent.nope", &everywhere()).await.is_none());
    // Imported and revoked hosts are global readers' only.
    assert!(get(&c, id(8), &scoped).await.is_none());
    assert!(get(&c, id(7), &scoped).await.is_none());
    db.drop().await;
}

#[tokio::test]
async fn a_revoked_host_still_answers() {
    let (db, c) = common::migrated().await;
    fleet(&c).await;
    let s = get(&c, id(7), &everywhere()).await.unwrap();
    assert_eq!(s.status, HostStatus::Revoked);
    assert!(s.agent.revoked_at.is_some());
    assert!(s.groups.is_empty());
    db.drop().await;
}

#[tokio::test]
async fn top_three_are_most_severe_then_newest_and_total_counts_all() {
    let (db, c) = common::migrated().await;
    fleet(&c).await;
    let host = id(6);
    c.batch_execute(&format!(
        "INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id,
             rule_version, severity, confidence, message, first_seen, last_seen, count, process,
             ancestors, received_at, state, note)
         SELECT ((now() - interval '10 minutes') AT TIME ZONE 'UTC')::date, '{host}', 'al-' || n, 'rs', 1,
                'r' || n, 1, s, 50, 'm' || n, now() - interval '10 minutes', now() - (n || ' minutes')::interval, 1, '{{}}',
                '[]', now(), st, 'n'
         FROM (VALUES (1, 'low', 'open'), (2, 'critical', 'open'), (3, 'high', 'open'),
                      (4, 'critical', 'open'), (5, 'critical', 'mitigated')) v(n, s, st);
         INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version,
             severity, first_observed_at, last_observed_at, last_observed_day, scan_id, confidence,
             message, evidence, received_at, origin, authenticated)
         SELECT '{host}', 'set', 'c' || n, 'f' || n, 1, s, now(), now() - (n || ' minutes')::interval,
                (now() AT TIME ZONE 'UTC')::date, 's', 50, 'm' || n, '{{}}', now(), 'online', false
         FROM (VALUES (1, 'medium'), (2, 'high'), (3, 'low'), (4, 'high')) v(n, s);
         INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url) VALUES
             ('ADV-LOW', 's', 'rocky', '9', 'low', 't', 'u'),
             ('ADV-CRIT', 's', 'rocky', '9', 'critical', 't', 'u'),
             ('ADV-MOD', 's', 'rocky', '9', 'moderate', 't', 'u'),
             ('ADV-IMP', 's', 'rocky', '9', 'important', 't', 'u'),
             ('ADV-FIXED', 's', 'rocky', '9', 'critical', 't', 'u');
         INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, last_evaluated_at, fixed_at)
         VALUES ('{host}', 'ADV-LOW', '[]', now(), now(), NULL), ('{host}', 'ADV-CRIT', '[]', now(), now(), NULL),
                ('{host}', 'ADV-MOD', '[]', now(), now(), NULL), ('{host}', 'ADV-IMP', '[]', now(), now(), NULL),
                ('{host}', 'ADV-FIXED', '[]', now(), now(), now());"
    ))
    .await
    .unwrap();
    let s = get(&c, host, &everywhere()).await.unwrap();
    let alarms = s.top_alarms.unwrap();
    let rules: Vec<_> = alarms.items.iter().map(|a| a.rule_id.as_str()).collect();
    assert_eq!((rules, alarms.total), (vec!["r2", "r4", "r3"], 4));
    let failing = s.top_failing.unwrap();
    let rules: Vec<_> = failing.items.iter().map(|f| f.rule_id.as_str()).collect();
    assert_eq!((rules, failing.total), (vec!["c2", "c4", "c1"], 4));
    let vulns = s.top_vulnerabilities.unwrap();
    let ids: Vec<_> = vulns.items.iter().map(|v| v.advisory_id.as_str()).collect();
    assert_eq!(
        (ids, vulns.total),
        (vec!["ADV-CRIT", "ADV-IMP", "ADV-MOD"], 4)
    );
    db.drop().await;
}

#[tokio::test]
async fn inventory_and_certificates_are_counted() {
    let (db, c) = common::migrated().await;
    fleet(&c).await;
    let host = id(2);
    c.batch_execute(&format!(
        "INSERT INTO package_versions (manager, name, version) VALUES ('dpkg', 'a', '1'), ('dpkg', 'b', '1');
         INSERT INTO host_packages (agent_id, package_version_id) SELECT '{host}', id FROM package_versions;
         INSERT INTO host_listeners (agent_id, protocol, address, port, exposed) VALUES
             ('{host}', 'tcp', '0.0.0.0', 22, true), ('{host}', 'tcp', '::', 22, true),
             ('{host}', 'tcp', '127.0.0.1', 5432, false);
         INSERT INTO host_services (agent_id, unit, programs, processes) VALUES ('{host}', 'sshd.service', '{{sshd}}', 1);
         INSERT INTO certificates (serial, agent_id, spki_sha256, not_before, not_after, issued_at, chain_pem)
         SELECT decode(lpad(to_hex(n), 32, '0'), 'hex'), '{host}', decode(repeat('00', 32), 'hex'),
                now(), now() + interval '1 year', now() - (n || ' days')::interval, 'pem'
         FROM generate_series(1, 7) n;"
    ))
    .await
    .unwrap();
    let s = get(&c, host, &everywhere()).await.unwrap();
    assert_eq!(
        (s.packages, s.listening_ports, s.exposed_ports, s.services),
        (2, 2, 1, 1)
    );
    assert_eq!((s.certificates.len(), s.certificate_count), (5, 7));
    assert!(s.certificates[0].issued_at > s.certificates[1].issued_at);
    db.drop().await;
}
