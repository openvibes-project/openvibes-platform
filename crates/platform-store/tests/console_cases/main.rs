//! Cases: visibility by asset-group scope, exclusive items, closing and
//! reopening, outcomes with evidence, the append-only timeline, audit rows
//! and limits, all run as the `openvibes-console` role.

#[path = "../common/mod.rs"]
mod common;

mod audit;
mod close;
mod evidence;
mod exclusive;
mod limits;
mod list;
mod outcomes;
mod reopen;
mod scope;

use chrono::{DateTime, Duration, Utc};
use common::TestDb;
use platform_store::{
    Client,
    console_auth::{NewLocalUser, create_local_user},
    console_cases::{
        self as cases, AssigneeFilter, CaseChange, CaseDetail, CaseFilters, NewCase, OutcomeChange,
        Refusal,
    },
    console_read::AgentScope,
};

const ALICE: &str = "11111111-1111-4111-8111-111111111111"; // admin, global
const BOB: &str = "33333333-3333-4333-8333-333333333333"; // analyst, prod only
const CAROL: &str = "55555555-5555-4555-8555-555555555555"; // viewer: no cases.read
const DAVE: &str = "77777777-7777-4777-8777-777777777777"; // analyst, global

const WEB: &str = "agent.00000000-0000-4000-8000-000000000001"; // prod
const DB: &str = "agent.00000000-0000-4000-8000-000000000002"; // dev
const PROD: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

struct Fx {
    db: TestDb,
    /// The owner, to change the world behind the console's back.
    admin: Client,
    /// The console's role.
    console: Client,
    web_alarm: String,
    web_alarm_2: String,
    db_alarm: String,
}

fn global() -> AgentScope {
    AgentScope::Global
}

fn prod() -> AgentScope {
    AgentScope::AssetGroups(vec![PROD.into()])
}

async fn user(client: &mut Client, id: &str, binding: &str, name: &str, role: &str) {
    create_local_user(
        client,
        &NewLocalUser {
            user_id: id,
            binding_id: binding,
            username: name,
            display_name: name,
            password_phc: "$argon2id$v=19$m=19456,t=2,p=1$opaque-salt$opaque-hash",
            role_id: role,
            actor_id: "test",
            actor_kind: "local_admin",
            password_must_change: false,
            now: Utc::now(),
        },
    )
    .await
    .unwrap();
}

async fn insert_alarm(admin: &Client, agent: &str, alarm_id: &str) -> String {
    let id: i64 = admin
        .query_one(
            "INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version,
                rule_id, rule_version, severity, confidence, message, first_seen, last_seen,
                count, process, ancestors, received_at)
             VALUES ((now() AT TIME ZONE 'UTC')::date, $1, $2, 'baseline', 1, 'shell', 1,
                'medium', 80, 'A web server started a shell', now(), now(), 1,
                '{\"exe\": \"/usr/bin/sh\"}', '[]', now())
             RETURNING id",
            &[&agent, &alarm_id],
        )
        .await
        .unwrap()
        .get(0);
    id.to_string()
}

/// Two hosts (web-01 in production, db-01 not), alarms, findings,
/// vulnerabilities and software on each, and four users.
async fn setup() -> Fx {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    let now = Utc::now();
    platform_store::ensure_partitions(&admin, now.date_naive() - Duration::days(1), 3)
        .await
        .unwrap();
    admin
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at) VALUES
                ('{WEB}', 'active', now(), 'web-01', now()),
                ('{DB}', 'active', now(), 'db-01', now());
             INSERT INTO console_asset_groups VALUES ('{PROD}', 'prod', now(), 't');
             INSERT INTO console_host_group_members VALUES ('{PROD}', '{WEB}', now(), 't');
             INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id,
                rule_version, severity, first_observed_at, last_observed_at, last_observed_day,
                scan_id, confidence, message, evidence, received_at, origin, authenticated)
             VALUES
                ('{WEB}', 'baseline', 'ssh-root', 'f1', 1, 'high', now(), now(), current_date,
                 'scan.1', 90, 'Root login over SSH', '{{}}', now(), 'online', true),
                ('{DB}', 'baseline', 'ssh-root', 'f2', 1, 'low', now(), now(), current_date,
                 'scan.1', 90, 'Root login over SSH', '{{}}', now(), 'online', true);
             INSERT INTO package_versions (id, manager, name, epoch, version, release, arch) VALUES
                (1, 'rpm', 'openssl', 0, '3.0', '1', 'x86_64'),
                (2, 'rpm', 'bash', 0, '5.2', '1', 'x86_64');
             INSERT INTO host_packages VALUES ('{WEB}', 1), ('{DB}', 2);
             INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
             VALUES ('FEDORA-1', 'fedora', 'fedora', '44', 'important', 'openssl update', 'https://x'),
                    ('FEDORA-2', 'fedora', 'fedora', '44', 'low', 'bash update', 'https://x');
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at,
                fixed_at, last_evaluated_at) VALUES
                ('{WEB}', 'FEDORA-1', '[]', now(), NULL, now()),
                ('{DB}', 'FEDORA-1', '[]', now(), NULL, now());
             INSERT INTO version_vulnerabilities VALUES (2, 'FEDORA-2', 'bash', now());"
        ))
        .await
        .unwrap();
    common::seed_role(&admin, "analyst", &["cases.read", "cases.write"]).await;
    common::seed_role(&admin, "viewer", &["hosts.read"]).await;
    user(
        &mut admin,
        ALICE,
        "22222222-2222-4222-8222-222222222222",
        "alice",
        "admin",
    )
    .await;
    user(
        &mut admin,
        BOB,
        "44444444-4444-4444-8444-444444444444",
        "bob",
        "analyst",
    )
    .await;
    user(
        &mut admin,
        CAROL,
        "66666666-6666-4666-8666-666666666666",
        "carol",
        "viewer",
    )
    .await;
    user(
        &mut admin,
        DAVE,
        "88888888-8888-4888-8888-888888888888",
        "dave",
        "analyst",
    )
    .await;
    let web_alarm = insert_alarm(&admin, WEB, "alarm.1").await;
    let web_alarm_2 = insert_alarm(&admin, WEB, "alarm.2").await;
    let db_alarm = insert_alarm(&admin, DB, "alarm.3").await;
    let console = db.pool.get().await.unwrap();
    console
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    Fx {
        db,
        admin,
        console,
        web_alarm,
        web_alarm_2,
        db_alarm,
    }
}

fn finding(agent: &str) -> String {
    format!("{agent}/baseline/ssh-root")
}

fn vuln(agent: &str) -> String {
    format!("{agent}/FEDORA-1")
}

async fn open_case(
    client: &mut Client,
    scope: &AgentScope,
    user: &str,
    title: &str,
    items: &[(&str, &str)],
) -> CaseDetail {
    cases::create(
        client,
        scope,
        user,
        &NewCase {
            title,
            severity: None,
            assignee_user_id: None,
            items,
        },
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn refused_create(
    client: &mut Client,
    scope: &AgentScope,
    user: &str,
    items: &[(&str, &str)],
) -> Refusal {
    cases::create(
        client,
        scope,
        user,
        &NewCase {
            title: "Second",
            severity: None,
            assignee_user_id: None,
            items,
        },
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap_err()
}

fn same<'a>(detail: &'a CaseDetail, status: &'a str) -> CaseChange<'a> {
    CaseChange {
        expected_version: detail.summary.version,
        title: &detail.summary.title,
        severity: &detail.summary.severity,
        status,
        assignee_user_id: detail.summary.assignee.as_ref().map(|u| u.user_id.as_str()),
        resolution: None,
        resolution_note: None,
        accepted_until: None,
    }
}

fn closing<'a>(detail: &'a CaseDetail, resolution: &'a str, note: &'a str) -> CaseChange<'a> {
    CaseChange {
        resolution: Some(resolution),
        resolution_note: Some(note),
        ..same(detail, "closed")
    }
}

async fn update(
    fx: &mut Fx,
    scope: &AgentScope,
    user: &str,
    detail: &CaseDetail,
    change: &CaseChange<'_>,
) -> Result<CaseDetail, Refusal> {
    cases::update(
        &mut fx.console,
        scope,
        user,
        &detail.summary.case_id,
        change,
        Utc::now(),
    )
    .await
    .unwrap()
}

async fn fetch(fx: &Fx, scope: &AgentScope, user: &str, detail: &CaseDetail) -> Option<CaseDetail> {
    cases::get(&fx.console, scope, user, &detail.summary.case_id)
        .await
        .unwrap()
}

async fn outcome(
    fx: &mut Fx,
    scope: &AgentScope,
    user: &str,
    detail: &CaseDetail,
    item_id: &str,
    change: Option<OutcomeChange<'_>>,
) -> Result<cases::CaseItem, Refusal> {
    cases::set_outcome(
        &mut fx.console,
        scope,
        user,
        &detail.summary.case_id,
        item_id,
        change.as_ref(),
        Utc::now(),
    )
    .await
    .unwrap()
}

fn item_id<'a>(detail: &'a CaseDetail, kind: &str) -> &'a str {
    &detail
        .items
        .iter()
        .find(|item| item.kind == kind)
        .unwrap()
        .item_id
}

async fn audit_actions(fx: &Fx) -> Vec<String> {
    fx.admin
        .query(
            "SELECT action FROM audit_log WHERE action LIKE 'case.%' ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

#[tokio::test]
async fn a_case_has_a_number_a_default_severity_and_a_timeline() {
    let mut fx = setup().await;
    let web_finding = finding(WEB);
    let created = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "SSH on web-01",
        &[
            ("host", WEB),
            ("compliance_finding", &web_finding),
            ("software", "rpm/openssl"),
        ],
    )
    .await;
    let summary = &created.summary;
    assert_eq!((summary.status.as_str(), summary.version), ("open", 1));
    assert_eq!(summary.severity, "high", "the highest item severity");
    assert_eq!(
        (summary.items, summary.pending_items),
        (3, 1),
        "only the finding needs an outcome"
    );
    assert_eq!(summary.opened_by.username, "alice");
    let second = open_case(&mut fx.console, &global(), ALICE, "Another", &[]).await;
    assert_eq!(second.summary.number, summary.number + 1);
    assert_eq!(second.summary.severity, "medium", "no item severity");
    let kinds: Vec<_> = created.events.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, ["created", "item_added", "item_added", "item_added"]);
    let finding_item = created
        .items
        .iter()
        .find(|i| i.kind == "compliance_finding")
        .unwrap();
    assert_eq!(finding_item.title.as_deref(), Some("Root login over SSH"));
    assert_eq!(finding_item.hostname.as_deref(), Some("web-01"));
    assert!(!finding_item.evidence_gone);
    let host_item = created.items.iter().find(|i| i.kind == "host").unwrap();
    assert_eq!(host_item.title.as_deref(), Some("web-01"));
    // A vulnerability's severity is the advisory's, counted as a case severity.
    let by_vuln = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Vuln",
        &[("vulnerability", &vuln(WEB))],
    )
    .await;
    assert_eq!(by_vuln.summary.severity, "high", "important counts as high");
    let hand_set = cases::create(
        &mut fx.console,
        &global(),
        ALICE,
        &NewCase {
            title: "Chosen",
            severity: Some("low"),
            assignee_user_id: Some(BOB),
            items: &[("host", WEB)],
        },
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(hand_set.summary.severity, "low");
    assert_eq!(hand_set.summary.assignee.unwrap().username, "bob");
    let actions = audit_actions(&fx).await;
    assert!(actions.iter().filter(|a| *a == "case.create").count() >= 4);
    assert!(actions.iter().any(|a| a == "case.item.add"));
    fx.db.drop().await;
}
