//! A service's page (roles spec §10.3; step 5f rulings 2, 11–13): the
//! summary and the Hosts table inside the viewer's scope.

mod common;

use chrono::Utc;
use common::services::{A, B, C, GONE, OUTSIDE, fixture};
use deadpool_postgres::Client;
use platform_store::{
    console_read::AgentScope,
    port_related::RelatedReach,
    service_summary::{ServiceSegment, ServiceSummary, service_hosts_page, service_summary},
};

fn scoped(group: &str) -> AgentScope {
    AgentScope::AssetGroups(vec![group.to_owned()])
}

async fn summary(
    c: &Client,
    scope: &AgentScope,
    reach: &RelatedReach,
    unit: &str,
) -> Option<ServiceSummary> {
    service_summary(c, scope, reach, unit, Utc::now())
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
async fn summary_stays_inside_the_scope() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = scoped(&mine);
    let s = summary(&c, &scope, &nothing(), "sshd.service")
        .await
        .unwrap();
    assert_eq!((s.running, s.of, s.root, s.exposed), (3, 3, 3, 3));
    assert_eq!(s.name, Some("OpenSSH server"));
    assert_eq!(s.processes, 3);
    assert_eq!(s.programs, ["sshd"]);
    assert_eq!(s.run_as, [("root".to_owned(), 3)]);
    assert_eq!(s.packages.len(), 1);
    assert_eq!(
        (s.packages[0].name.as_str(), s.packages[0].hosts),
        ("openssh-server", 3)
    );
    assert_eq!(
        (s.package_hosts, s.versions),
        (3, Some(2)),
        "9.2p1 and 9.6p1"
    );
    assert_eq!(s.ports.len(), 1);
    assert_eq!(
        (s.ports[0].port, s.ports[0].exposed, s.ports[0].hosts),
        (22, true, 3)
    );
    assert!(
        s.changes
            .iter()
            .all(|e| e.agent_id != OUTSIDE && e.agent_id != GONE)
    );
    assert!(
        s.by_group.iter().all(|g| g.of <= 3),
        "group sizes count hosts in reach"
    );
    let global = summary(&c, &AgentScope::Global, &nothing(), "sshd.service")
        .await
        .unwrap();
    assert_eq!((global.running, global.of), (4, 4));
    // A unit run only outside the scope is absent for the scoped viewer.
    assert!(
        summary(&c, &scope, &nothing(), "far.service")
            .await
            .is_none()
    );
    assert!(
        summary(&c, &AgentScope::Global, &nothing(), "far.service")
            .await
            .is_some()
    );
    db.drop().await;
}

#[tokio::test]
async fn a_service_that_went_away_stays_viewable_for_90_days() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = scoped(&mine);
    c.execute(
        "INSERT INTO change_log (at, agent_id, kind, key, change)
         VALUES (now() - interval '2 days', $1, 'service', 'gone.service', 'went_away'),
                (now() - interval '100 days', $1, 'service', 'older.service', 'went_away')",
        &[&A],
    )
    .await
    .unwrap();
    let gone = summary(&c, &scope, &nothing(), "gone.service")
        .await
        .unwrap();
    assert_eq!((gone.running, gone.exposed, gone.root), (0, 0, 0));
    assert_eq!(gone.week_removed, 1);
    assert_eq!(gone.changes.len(), 1);
    assert_eq!(gone.versions, None);
    assert!(
        summary(&c, &scope, &nothing(), "older.service")
            .await
            .is_none()
    );
    db.drop().await;
}

#[tokio::test]
async fn this_week_first_seen_and_packages() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = scoped(&mine);
    c.execute(
        "UPDATE change_log_start SET at = now() - interval '200 days'",
        &[],
    )
    .await
    .unwrap();
    let mystery = summary(&c, &scope, &nothing(), "mystery.service")
        .await
        .unwrap();
    assert_eq!((mystery.week_added, mystery.week_removed), (1, 0));
    assert!(mystery.packages.is_empty());
    assert_eq!((mystery.package_hosts, mystery.versions), (0, None));
    assert_eq!(mystery.programs, ["helper", "mystery"]);
    assert!(mystery.ports.is_empty());
    let seen = mystery.first_seen.unwrap();
    assert!(!seen.before);
    assert!(Utc::now() - seen.at < chrono::Duration::days(3));
    // nginx appeared on A 40 days ago; B has no event, so its enrolment counts too.
    let nginx = summary(&c, &scope, &nothing(), "nginx.service")
        .await
        .unwrap();
    assert_eq!(nginx.week_added, 0);
    assert_eq!(nginx.exposed, 2);
    assert_eq!(nginx.versions, Some(2));
    let named = summary(&c, &scope, &nothing(), "named.service")
        .await
        .unwrap();
    assert_eq!(named.packages[0].name, "bind", "matched through the map");
    c.execute(
        "UPDATE agents SET enrolled_at = now() - interval '400 days' WHERE agent_id = $1",
        &[&B],
    )
    .await
    .unwrap();
    let seen = summary(&c, &scope, &nothing(), "named.service")
        .await
        .unwrap()
        .first_seen
        .unwrap();
    assert!(seen.before, "a host older than the log: Before {{date}}");
    db.drop().await;
}

#[tokio::test]
async fn hosts_rows_have_versions_ports_and_segments() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = scoped(&mine);
    let page = service_hosts_page(
        &c,
        &scope,
        &nothing(),
        "postgresql.service",
        ServiceSegment::All,
        0,
        50,
    )
    .await
    .unwrap();
    assert_eq!(
        (page.segments.all, page.segments.exposed, page.segments.root),
        (2, 1, 0)
    );
    let a = page.rows.iter().find(|r| r.agent_id == A).unwrap();
    assert_eq!(
        a.package,
        Some(("postgresql".to_owned(), "15.8".to_owned()))
    );
    assert_eq!(a.ports, [("tcp".to_owned(), 5432, false)]);
    assert_eq!((a.processes, a.run_as.as_deref()), (5, Some("postgres")));
    assert_eq!(a.hostname.as_deref(), Some("web-01"));
    assert!(a.owners_partial && a.reported_at.is_some());
    assert_eq!(
        (a.problems.alarms, a.problems.vulnerabilities),
        (None, None)
    );
    let exposed = service_hosts_page(
        &c,
        &scope,
        &nothing(),
        "postgresql.service",
        ServiceSegment::Exposed,
        0,
        50,
    )
    .await
    .unwrap();
    assert_eq!(exposed.rows.len(), 1);
    assert_eq!(exposed.rows[0].agent_id, C);
    assert_eq!(exposed.total, 1);
    let root = service_hosts_page(
        &c,
        &scope,
        &nothing(),
        "sshd.service",
        ServiceSegment::Root,
        0,
        50,
    )
    .await
    .unwrap();
    assert_eq!(root.total, 3, "A, B, C; not the revoked or outside host");
    // Paging by hostname.
    let first = service_hosts_page(
        &c,
        &scope,
        &nothing(),
        "sshd.service",
        ServiceSegment::All,
        0,
        2,
    )
    .await
    .unwrap();
    let rest = service_hosts_page(
        &c,
        &scope,
        &nothing(),
        "sshd.service",
        ServiceSegment::All,
        2,
        2,
    )
    .await
    .unwrap();
    let names: Vec<_> = first
        .rows
        .iter()
        .chain(&rest.rows)
        .map(|r| r.hostname.clone().unwrap())
        .collect();
    assert_eq!(names, ["db-01", "web-01", "web-02"]);
    let beyond = service_hosts_page(
        &c,
        &scope,
        &nothing(),
        "sshd.service",
        ServiceSegment::All,
        50,
        10,
    )
    .await
    .unwrap();
    assert!(beyond.rows.is_empty());
    assert_eq!(beyond.segments.all, 3, "the counts answer on an empty page");
    db.drop().await;
}

async fn related_data(c: &Client) {
    let k = "07".repeat(32);
    c.batch_execute(&format!(
        "INSERT INTO rule_sets (rule_set_id) VALUES ('hardening');
         INSERT INTO rule_trust_keys (rule_set_id, issuer_key_id, public_key) VALUES ('hardening', 'k', '\\x{k}');
         INSERT INTO rule_bundles (rule_set_id, version, envelope, envelope_sha256, issuer_key_id,
                                   created_at_ms, expires_at_ms, published_by)
            VALUES ('hardening', 1, '{{}}', sha256('b1'::bytea), 'k', 1, 9e15, 't');
         INSERT INTO console_rule_meta (rule_set_id, rule_set_version, rule_id, rule_version, title, message,
                                        attack, techniques, severity, expression) VALUES
            ('hardening', 1, 'harden.services.nginx', 1, 'nginx is enabled', 'm', '[]', '{{}}', 'low',
             '''nginx.service'' in facts[''service.enabled'']'),
            ('hardening', 1, 'harden.services.avahi', 1, 'Avahi is enabled', 'm', '[]', '{{}}', 'low',
             '''avahi-daemon.service'' in facts[''service.enabled'']');
         INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
                first_observed_at, last_observed_at, last_observed_day, scan_id, confidence, message, evidence,
                received_at, origin, authenticated, source, ended_at) VALUES
            ('{A}', 'hardening', 'harden.services.nginx', 'f', 1, 'low', now(), now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes', NULL),
            ('{B}', 'hardening', 'harden.services.nginx', 'f', 1, 'low', now(), now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes', NULL),
            ('{A}', 'hardening', 'harden.services.avahi', 'f', 1, 'low', now(), now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes', NULL),
            ('{OUTSIDE}', 'hardening', 'harden.services.nginx', 'f', 1, 'low', now(), now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes', NULL);
         INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
            VALUES ('ADV-1', 'debian-12', 'debian', '12', 'critical', 't', 'u'), ('ADV-2', 'debian-12', 'debian', '12', 'low', 't', 'u');
         INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, fixed_at, last_evaluated_at) VALUES
            ('{A}', 'ADV-1', '[{{\"name\":\"nginx\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), NULL, now()),
            ('{B}', 'ADV-1', '[{{\"name\":\"nginx\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), NULL, now()),
            ('{B}', 'ADV-2', '[{{\"name\":\"nginx\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), now(), now()),
            ('{OUTSIDE}', 'ADV-1', '[{{\"name\":\"nginx\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), NULL, now());
         INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id, rule_version,
                severity, confidence, message, first_seen, last_seen, count, process, ancestors, received_at, state) VALUES
            ((now() AT TIME ZONE 'UTC')::date, '{A}', 'a1', 'rs', 1, 'r', 1, 'high', 50, 'm', now(), now(), 1,
             '{{\"exe\":\"/usr/sbin/nginx\"}}', '[]', now(), 'open'),
            ((now() AT TIME ZONE 'UTC')::date, '{B}', 'a2', 'rs', 1, 'r', 1, 'high', 50, 'm', now(), now(), 1,
             '{{\"exe\":\"/usr/bin/curl\"}}', '[]', now(), 'open'),
            ((now() AT TIME ZONE 'UTC')::date, '{OUTSIDE}', 'a3', 'rs', 1, 'r', 1, 'high', 50, 'm', now(), now(), 1,
             '{{\"exe\":\"/usr/sbin/nginx\"}}', '[]', now(), 'open');"
    ))
    .await
    .unwrap();
}

#[tokio::test]
async fn related_counts_hosts_running_the_unit_in_reach() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    related_data(&c).await;
    let scope = scoped(&mine);
    let s = summary(&c, &scope, &all(&scope), "nginx.service")
        .await
        .unwrap();
    let checks = s.related.compliance.unwrap();
    let ids: Vec<_> = checks
        .items
        .iter()
        .map(|i| (i.rule_id.as_str(), i.hosts))
        .collect();
    assert_eq!(
        ids,
        [("harden.services.nginx", 2)],
        "the rule naming the unit on A and B; avahi's and the outside host's finding are not counted"
    );
    assert_eq!(checks.items[0].title, "nginx is enabled");
    let vulns = s.related.vulnerabilities.unwrap();
    assert_eq!(vulns.packages.len(), 1);
    assert_eq!(
        (
            vulns.packages[0].package.as_str(),
            vulns.packages[0].advisories,
            vulns.packages[0].hosts
        ),
        ("nginx", 1, 2),
        "open ones on A and B; not the fixed one or the outside host"
    );
    assert_eq!((vulns.advisories, vulns.hosts), (1, 2));
    let alarms = s.related.alarms.unwrap();
    assert!(!alarms.programs_not_collected);
    assert_eq!(
        (alarms.open, alarms.hosts),
        (1, 1),
        "only A's nginx alarm matches"
    );
    // Per-host problems.
    let page = service_hosts_page(
        &c,
        &scope,
        &all(&scope),
        "nginx.service",
        ServiceSegment::All,
        0,
        50,
    )
    .await
    .unwrap();
    let a = page.rows.iter().find(|r| r.agent_id == A).unwrap();
    let b = page.rows.iter().find(|r| r.agent_id == B).unwrap();
    assert_eq!(
        (a.problems.alarms, a.problems.vulnerabilities),
        (Some(1), Some(1))
    );
    assert_eq!(
        (b.problems.alarms, b.problems.vulnerabilities),
        (Some(0), Some(1))
    );
    // A unit with no package or program: nothing to count.
    let odd = summary(&c, &scope, &all(&scope), "mystery.service")
        .await
        .unwrap();
    assert_eq!(odd.related.vulnerabilities.unwrap(), Default::default());
    assert_eq!(odd.related.compliance.unwrap().items, []);
    db.drop().await;
}

#[tokio::test]
async fn related_sections_need_their_permission() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    related_data(&c).await;
    let scope = scoped(&mine);
    let s = summary(&c, &scope, &nothing(), "nginx.service")
        .await
        .unwrap();
    assert!(
        s.related.compliance.is_none()
            && s.related.vulnerabilities.is_none()
            && s.related.alarms.is_none()
    );
    let only_alarms = RelatedReach {
        alarms: Some(scope.clone()),
        ..RelatedReach::default()
    };
    let s = summary(&c, &scope, &only_alarms, "nginx.service")
        .await
        .unwrap();
    assert!(
        s.related.compliance.is_none()
            && s.related.vulnerabilities.is_none()
            && s.related.alarms.is_some()
    );
    let page = service_hosts_page(
        &c,
        &scope,
        &only_alarms,
        "nginx.service",
        ServiceSegment::All,
        0,
        50,
    )
    .await
    .unwrap();
    assert!(
        page.rows
            .iter()
            .all(|r| r.problems.vulnerabilities.is_none() && r.problems.alarms.is_some())
    );
    db.drop().await;
}
