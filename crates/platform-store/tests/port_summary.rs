//! A port's page (roles spec §10.3; step 5e rulings 7, 8, 18, 20–22): the
//! summary and the Hosts table inside the viewer's scope.

mod common;

use chrono::Utc;
use common::ports::{A, B, C, GONE, OUTSIDE, fixture};
use deadpool_postgres::Client;
use platform_store::{
    console_read::AgentScope,
    port_related::RelatedReach,
    port_summary::{PortSegment, PortSummary, port_hosts_page, port_summary},
};

fn scoped(group: &str) -> AgentScope {
    AgentScope::AssetGroups(vec![group.to_owned()])
}

async fn summary(
    c: &Client,
    scope: &AgentScope,
    reach: &RelatedReach,
    key: (&str, u16),
) -> Option<PortSummary> {
    port_summary(c, scope, reach, key.0, key.1, Utc::now())
        .await
        .unwrap()
}

fn nothing() -> RelatedReach {
    RelatedReach::default()
}

fn all(scope: &AgentScope) -> RelatedReach {
    RelatedReach {
        compliance: Some(scope.clone()),
        vulnerabilities: Some(scope.clone()),
        alarms: Some(scope.clone()),
    }
}

#[tokio::test]
async fn port_summary_stays_inside_the_scope() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = scoped(&mine);
    let s = summary(&c, &scope, &nothing(), ("tcp", 22)).await.unwrap();
    assert_eq!(
        (s.listening, s.exposed, s.local),
        (3, 3, 0),
        "A, B, C; not the revoked or outside host"
    );
    assert_eq!(s.of, 3);
    assert_eq!((s.week_added, s.week_removed), (1, 1));
    assert_eq!(s.name, Some("SSH"));
    assert_eq!(s.services, 1);
    assert_eq!(s.programs, ["sshd"]);
    assert!(
        s.changes
            .iter()
            .all(|e| e.agent_id != OUTSIDE && e.agent_id != GONE)
    );
    assert!(
        s.by_group.iter().all(|g| g.of <= 3),
        "group sizes count hosts in reach"
    );
    let global = summary(&c, &AgentScope::Global, &nothing(), ("tcp", 22))
        .await
        .unwrap();
    assert_eq!((global.listening, global.of), (4, 4));
    // A port listened on only outside the scope is absent for the scoped viewer.
    assert!(
        summary(&c, &scope, &nothing(), ("tcp", 7777))
            .await
            .is_none()
    );
    assert!(
        summary(&c, &AgentScope::Global, &nothing(), ("tcp", 7777))
            .await
            .is_some()
    );
    let page = port_hosts_page(&c, &scope, "tcp", 22, PortSegment::All, 0, 50)
        .await
        .unwrap();
    assert!(
        page.rows
            .iter()
            .all(|r| r.agent_id != OUTSIDE && r.agent_id != GONE)
    );
    assert_eq!(page.segments.all, 3);
    db.drop().await;
}

#[tokio::test]
async fn a_port_that_went_away_stays_viewable_for_90_days() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = scoped(&mine);
    c.execute(
        "INSERT INTO change_log (at, agent_id, kind, key, change)
         VALUES (now() - interval '2 days', $1, 'listener', 'tcp/8888', 'went_away'),
                (now() - interval '100 days', $1, 'listener', 'tcp/8889', 'went_away')",
        &[&A],
    )
    .await
    .unwrap();
    let gone = summary(&c, &scope, &nothing(), ("tcp", 8888))
        .await
        .unwrap();
    assert_eq!((gone.listening, gone.exposed, gone.local), (0, 0, 0));
    assert_eq!(gone.week_removed, 1);
    assert_eq!(gone.changes.len(), 1);
    assert!(
        summary(&c, &scope, &nothing(), ("tcp", 8889))
            .await
            .is_none(),
        "older than 90 days"
    );
    assert!(summary(&c, &scope, &nothing(), ("tcp", 1)).await.is_none());
    db.drop().await;
}

#[tokio::test]
async fn first_seen_is_an_event_a_baseline_enrolment_or_before() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = scoped(&mine);
    c.execute(
        "UPDATE change_log_start SET at = now() - interval '200 days'",
        &[],
    )
    .await
    .unwrap();
    // tcp/22 has an `appeared` 10 days ago (host C); the hosts enrolled now.
    let s = summary(&c, &scope, &nothing(), ("tcp", 22)).await.unwrap();
    let seen = s.first_seen.unwrap();
    assert!(!seen.before);
    assert!(Utc::now() - seen.at > chrono::Duration::days(9));
    // 5432 is on A and C with no event: the earliest enrolment; hosts enrolled
    // before the log began show "before".
    let s = summary(&c, &scope, &nothing(), ("tcp", 5432))
        .await
        .unwrap();
    assert!(
        !s.first_seen.unwrap().before,
        "enrolled after the log began"
    );
    c.execute(
        "UPDATE agents SET enrolled_at = now() - interval '400 days' WHERE agent_id = $1",
        &[&C],
    )
    .await
    .unwrap();
    let s = summary(&c, &scope, &nothing(), ("tcp", 5432))
        .await
        .unwrap();
    let seen = s.first_seen.unwrap();
    assert!(seen.before, "a host older than the log: Before {{date}}");
    let floor = Utc::now() - chrono::Duration::days(90);
    assert!(
        (seen.at - floor).abs() < chrono::Duration::minutes(1),
        "the 90-day floor"
    );
    // A host older than the log whose port appeared 10 days ago: the event
    // is the truth, not the floor its enrolment would give.
    let s = summary(&c, &scope, &nothing(), ("tcp", 22)).await.unwrap();
    let seen = s.first_seen.unwrap();
    assert!(
        !seen.before,
        "an appeared event beats the host's old enrolment"
    );
    assert!(Utc::now() - seen.at < chrono::Duration::days(11));
    db.drop().await;
}

#[tokio::test]
async fn hosts_rows_join_addresses() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = scoped(&mine);
    let page = port_hosts_page(&c, &scope, "tcp", 443, PortSegment::All, 0, 50)
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 2);
    let b = page.rows.iter().find(|r| r.agent_id == B).unwrap();
    assert_eq!(b.bound, ["10.0.0.6", "127.0.0.1"]);
    assert!(b.exposed, "any non-loopback address");
    assert_eq!(b.hostname.as_deref(), Some("web-02"));
    assert_eq!(b.service.as_deref(), Some("nginx.service"));
    assert!(b.reported_at.is_some());
    assert!(b.owners_partial);
    let local = port_hosts_page(&c, &scope, "tcp", 5432, PortSegment::Local, 0, 50)
        .await
        .unwrap();
    assert_eq!(local.rows.len(), 1);
    assert_eq!(local.rows[0].agent_id, A);
    assert_eq!(
        (
            local.segments.all,
            local.segments.exposed,
            local.segments.local
        ),
        (2, 1, 1)
    );
    assert_eq!(local.total, 1);
    let exposed = port_hosts_page(&c, &scope, "tcp", 5432, PortSegment::Exposed, 0, 50)
        .await
        .unwrap();
    assert_eq!(exposed.rows[0].agent_id, C);
    // Paging by hostname.
    let first = port_hosts_page(&c, &scope, "tcp", 22, PortSegment::All, 0, 2)
        .await
        .unwrap();
    let rest = port_hosts_page(&c, &scope, "tcp", 22, PortSegment::All, 2, 2)
        .await
        .unwrap();
    let names: Vec<_> = first
        .rows
        .iter()
        .chain(&rest.rows)
        .map(|r| r.hostname.clone().unwrap())
        .collect();
    assert_eq!(names, ["db-01", "web-01", "web-02"]);
    assert_eq!(first.total, 3);
    let beyond = port_hosts_page(&c, &scope, "tcp", 22, PortSegment::All, 50, 10)
        .await
        .unwrap();
    assert!(beyond.rows.is_empty());
    assert_eq!(beyond.segments.all, 3, "the counts answer on an empty page");
    db.drop().await;
}

#[tokio::test]
async fn owners_not_collected_is_said() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let s = summary(&c, &scoped(&mine), &nothing(), ("tcp", 9999))
        .await
        .unwrap();
    assert_eq!(
        (s.listening, s.owners_collected),
        (1, 0),
        "no owner on the one host"
    );
    assert!(s.programs.is_empty());
    let page = port_hosts_page(&c, &scoped(&mine), "tcp", 9999, PortSegment::All, 0, 50)
        .await
        .unwrap();
    assert_eq!(page.rows[0].service, None);
    assert!(page.rows[0].owners_partial);
    let ssh = summary(&c, &scoped(&mine), &nothing(), ("tcp", 22))
        .await
        .unwrap();
    assert_eq!(ssh.owners_collected, ssh.listening);
    db.drop().await;
}

#[tokio::test]
async fn by_group_counts_listening_members_of_members() {
    let (db, c) = common::migrated().await;
    let (mine, web) = fixture(&c).await;
    let s = summary(&c, &scoped(&mine), &nothing(), ("tcp", 5432))
        .await
        .unwrap();
    let web_bar = s.by_group.iter().find(|g| g.id == web).unwrap();
    assert_eq!(
        (web_bar.name.as_str(), web_bar.listening, web_bar.of),
        ("Web", 1, 2),
        "web-01 listens, web-02 does not"
    );
    assert_eq!(s.by_group[0].id, mine, "most listening first");
    db.drop().await;
}

async fn related_data(c: &Client) {
    let k = "07".repeat(32);
    c.batch_execute(&format!(
        "INSERT INTO rule_sets (rule_set_id) VALUES ('baseline');
         INSERT INTO rule_trust_keys (rule_set_id, issuer_key_id, public_key) VALUES ('baseline', 'k', '\\x{k}');
         INSERT INTO rule_bundles (rule_set_id, version, envelope, envelope_sha256, issuer_key_id,
                                   created_at_ms, expires_at_ms, published_by)
            VALUES ('baseline', 1, '{{}}', sha256('b1'::bytea), 'k', 1, 9e15, 't');
         INSERT INTO console_rule_meta (rule_set_id, rule_set_version, rule_id, rule_version, title, message,
                                        attack, techniques, severity, expression) VALUES
            ('baseline', 1, 'port.ssh.exposed', 1, 'SSH port exposed', 'm', '[]', '{{}}', 'high',
             '''22'' in facts[''port.tcp.exposed'']'),
            ('baseline', 1, 'harden.ssh.root_login', 1, 'SSH allows root login', 'm', '[]', '{{}}', 'critical', NULL),
            ('baseline', 1, 'port.redis.exposed', 1, 'Redis exposed', 'm', '[]', '{{}}', 'high',
             '''6379'' in facts[''port.tcp.exposed'']');
         INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
                first_observed_at, last_observed_at, last_observed_day, scan_id, confidence, message, evidence,
                received_at, origin, authenticated, source, ended_at) VALUES
            ('{A}', 'baseline', 'port.ssh.exposed', 'f', 1, 'high', now(), now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes', NULL),
            ('{B}', 'baseline', 'harden.ssh.root_login', 'f', 1, 'critical', now(), now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes', NULL),
            ('{A}', 'baseline', 'harden.ssh.root_login', 'f', 1, 'critical', now(), now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes', NULL),
            ('{A}', 'baseline', 'port.redis.exposed', 'f', 1, 'high', now(), now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes', NULL),
            ('{OUTSIDE}', 'baseline', 'port.ssh.exposed', 'f', 1, 'high', now(), now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes', NULL);
         INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
            VALUES ('ADV-1', 'debian-12', 'debian', '12', 'critical', 't', 'u'), ('ADV-2', 'debian-12', 'debian', '12', 'low', 't', 'u'),
                   ('ADV-3', 'cpe-nvd', 'debian', '12', 'important', 't', 'u');
         INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, fixed_at, last_evaluated_at) VALUES
            ('{A}', 'ADV-1', '[{{\"name\":\"openssh-server\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), NULL, now()),
            ('{B}', 'ADV-1', '[{{\"name\":\"openssh-server\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), NULL, now()),
            ('{B}', 'ADV-2', '[{{\"name\":\"openssh-server\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), now(), now()),
            ('{OUTSIDE}', 'ADV-1', '[{{\"name\":\"openssh-server\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), NULL, now()),
            ('{A}', 'ADV-3', '[{{\"name\":\"openssh-server\",\"installed\":\"1\",\"fixed\":null}}]', now(), NULL, now());
         INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id, rule_version,
                severity, confidence, message, first_seen, last_seen, count, process, ancestors, received_at, state) VALUES
            ((now() AT TIME ZONE 'UTC')::date, '{A}', 'a1', 'rs', 1, 'r', 1, 'high', 50, 'm', now(), now(), 1,
             '{{\"exe\":\"/usr/sbin/sshd\"}}', '[]', now(), 'open'),
            ((now() AT TIME ZONE 'UTC')::date, '{B}', 'a2', 'rs', 1, 'r', 1, 'high', 50, 'm', now(), now(), 1,
             '{{\"exe\":\"/usr/bin/curl\"}}', '[]', now(), 'open'),
            ((now() AT TIME ZONE 'UTC')::date, '{OUTSIDE}', 'a3', 'rs', 1, 'r', 1, 'high', 50, 'm', now(), now(), 1,
             '{{\"exe\":\"/usr/sbin/sshd\"}}', '[]', now(), 'open');"
    ))
    .await
    .unwrap();
}

#[tokio::test]
async fn related_counts_listening_hosts_in_reach() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    related_data(&c).await;
    let scope = scoped(&mine);
    let s = summary(&c, &scope, &all(&scope), ("tcp", 22))
        .await
        .unwrap();
    let checks = s.related.compliance.unwrap();
    assert_eq!(checks.area, Some("SSH"));
    let ids: Vec<_> = checks
        .items
        .iter()
        .map(|i| (i.rule_id.as_str(), i.hosts))
        .collect();
    assert_eq!(
        ids,
        [("harden.ssh.root_login", 2), ("port.ssh.exposed", 1)],
        "the SSH-area check on two hosts and the port rule on one; the outside host's finding and redis are not counted"
    );
    assert_eq!(checks.items[1].title, "SSH port exposed");
    assert_eq!(checks.total, 2);
    let vulns = s.related.vulnerabilities.unwrap();
    assert_eq!(vulns.len(), 2, "openssh-server and openssh");
    assert_eq!(
        (
            vulns[0].package.as_str(),
            vulns[0].advisories,
            vulns[0].hosts
        ),
        ("openssh-server", 1, 2),
        "open ones on A and B; not the fixed pair, the outside host or a lower-confidence match"
    );
    assert_eq!((vulns[1].advisories, vulns[1].hosts), (0, 0));
    let alarms = s.related.alarms.unwrap();
    assert!(!alarms.program_not_collected);
    assert_eq!(
        (alarms.open, alarms.hosts),
        (1, 1),
        "only A's sshd alarm matches the listener program"
    );
    // An unmapped port: no package line, no area, and no program known.
    let odd = summary(&c, &scope, &all(&scope), ("tcp", 9999))
        .await
        .unwrap();
    assert_eq!(odd.related.vulnerabilities.unwrap(), []);
    assert_eq!(odd.related.compliance.unwrap().items, []);
    assert!(odd.related.alarms.unwrap().program_not_collected);
    db.drop().await;
}

#[tokio::test]
async fn related_sections_need_their_permission() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    related_data(&c).await;
    let scope = scoped(&mine);
    let s = summary(&c, &scope, &nothing(), ("tcp", 22)).await.unwrap();
    assert!(
        s.related.compliance.is_none()
            && s.related.vulnerabilities.is_none()
            && s.related.alarms.is_none()
    );
    let only_alarms = RelatedReach {
        alarms: Some(scope.clone()),
        ..RelatedReach::default()
    };
    let s = summary(&c, &scope, &only_alarms, ("tcp", 22))
        .await
        .unwrap();
    assert!(
        s.related.compliance.is_none()
            && s.related.vulnerabilities.is_none()
            && s.related.alarms.is_some()
    );
    // A narrower compliance scope (the web hosts only) counts only its hosts.
    let (_, web) = (
        0,
        c.query_one(
            "SELECT asset_group_id::text FROM console_asset_groups WHERE name = 'Web'",
            &[],
        )
        .await
        .unwrap()
        .get::<_, String>(0),
    );
    let narrow = RelatedReach {
        compliance: Some(scoped(&web)),
        ..RelatedReach::default()
    };
    let s = summary(&c, &scope, &narrow, ("tcp", 22)).await.unwrap();
    assert_eq!(s.related.compliance.unwrap().items.len(), 2);
    db.drop().await;
}
