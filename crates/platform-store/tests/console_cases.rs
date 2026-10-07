//! Cases: visibility by asset-group scope, exclusive items, closing and
//! reopening, outcomes with evidence, the append-only timeline, audit rows
//! and limits, all run as the `openvibes-console` role.

mod common;

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
             INSERT INTO console_agent_tags VALUES
                ('{WEB}', 'env', 'prod', now(), 't'), ('{DB}', 'env', 'dev', now(), 't');
             INSERT INTO console_asset_groups VALUES ('{PROD}', 'prod', now(), 't');
             INSERT INTO console_asset_group_selectors VALUES ('{PROD}', 'env', 'prod', now());
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

#[tokio::test]
async fn a_scoped_user_sees_only_cases_and_items_in_scope() {
    let mut fx = setup().await;
    let both = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Both hosts",
        &[("host", WEB), ("host", DB), ("software", "rpm/bash")],
    )
    .await;
    let only_db = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Only db-01",
        &[("host", DB), ("alarm", &fx.db_alarm.clone())],
    )
    .await;
    let empty = open_case(&mut fx.console, &global(), ALICE, "Nothing yet", &[]).await;

    // Bob sees the first case without the db-01 host: not in the items,
    // the counts or the timeline. Software is visible to every reader.
    let seen = fetch(&fx, &prod(), BOB, &both).await.unwrap();
    assert_eq!(
        seen.items
            .iter()
            .map(|i| i.reference.as_str())
            .collect::<Vec<_>>(),
        [WEB, "rpm/bash"]
    );
    assert_eq!(seen.summary.items, 2);
    let rendered = format!("{seen:?}");
    assert!(!rendered.contains(DB), "{rendered}");
    assert_eq!(
        seen.events
            .iter()
            .filter(|e| e.kind == "item_added")
            .count(),
        2
    );
    // Alice sees everything.
    let all = fetch(&fx, &global(), ALICE, &both).await.unwrap();
    assert_eq!((all.items.len(), all.summary.items), (3, 3));

    // The second case reads as absent, in `get` and in the list.
    assert!(fetch(&fx, &prod(), BOB, &only_db).await.is_none());
    assert!(fetch(&fx, &prod(), BOB, &empty).await.is_none());
    let listed = cases::list(
        &fx.console,
        &prod(),
        BOB,
        &CaseFilters {
            status: Some("all".into()),
            ..CaseFilters::default()
        },
        None,
        50,
    )
    .await
    .unwrap();
    assert_eq!(
        listed.iter().map(|c| c.number).collect::<Vec<_>>(),
        [both.summary.number]
    );
    let searched = cases::list(
        &fx.console,
        &prod(),
        BOB,
        &CaseFilters {
            q: Some(format!("C-{}", only_db.summary.number)),
            ..CaseFilters::default()
        },
        None,
        50,
    )
    .await
    .unwrap();
    assert!(searched.is_empty(), "search never finds a hidden case");
    let hidden_id = cases::get(&fx.console, &prod(), BOB, "not-a-uuid")
        .await
        .unwrap();
    assert!(hidden_id.is_none());

    // Someone who opened a case, or to whom it is assigned, sees it.
    let bobs = open_case(&mut fx.console, &prod(), BOB, "Bob's own", &[]).await;
    assert!(fetch(&fx, &prod(), BOB, &bobs).await.is_some());
    assert!(
        fetch(&fx, &global(), DAVE, &bobs).await.is_none(),
        "an empty case is seen by whoever opened it or is assigned to it"
    );
    let assigned = update(
        &mut fx,
        &global(),
        ALICE,
        &only_db,
        &CaseChange {
            assignee_user_id: Some(BOB),
            ..same(&only_db, "open")
        },
    )
    .await
    .unwrap();
    let as_assignee = fetch(&fx, &prod(), BOB, &assigned).await.unwrap();
    assert!(
        as_assignee.items.is_empty(),
        "assigned, but no item in scope"
    );
    assert_eq!(as_assignee.summary.assignee.unwrap().username, "bob");
    fx.db.drop().await;
}

#[tokio::test]
async fn an_item_out_of_scope_cannot_be_added_and_does_not_say_whether_it_exists() {
    let mut fx = setup().await;
    let case = open_case(
        &mut fx.console,
        &prod(),
        BOB,
        "Bob's case",
        &[("host", WEB)],
    )
    .await;
    let db_finding = finding(DB);
    let db_vuln = vuln(DB);
    let web_alarm = fx.web_alarm.clone();
    let db_alarm = fx.db_alarm.clone();
    let missing = format!("{DB}0");
    let hidden_and_missing: [(&str, &str); 7] = [
        ("host", DB),
        ("alarm", &db_alarm),
        ("compliance_finding", &db_finding),
        ("vulnerability", &db_vuln),
        ("software", "rpm/bash"),
        ("host", &missing),
        ("alarm", "999999"),
    ];
    for (kind, reference) in hidden_and_missing {
        let refused = cases::add_item(
            &mut fx.console,
            &prod(),
            BOB,
            &case.summary.case_id,
            kind,
            reference,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(
            refused.unwrap_err(),
            Refusal::ItemNotFound,
            "{kind} {reference}"
        );
    }
    // Creating a case with one is refused the same way, and writes nothing.
    assert_eq!(
        refused_create(
            &mut fx.console,
            &prod(),
            BOB,
            &[("host", WEB), ("host", DB)]
        )
        .await,
        Refusal::ItemNotFound
    );
    // The same items are fine for a global user, and in scope for Bob.
    for (kind, reference) in [("alarm", web_alarm.as_str()), ("software", "rpm/openssl")] {
        cases::add_item(
            &mut fx.console,
            &prod(),
            BOB,
            &case.summary.case_id,
            kind,
            reference,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    }
    let added = cases::add_item(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        "host",
        DB,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(added.unwrap().hostname.as_deref(), Some("db-01"));
    let count: i64 = fx
        .admin
        .query_one("SELECT count(*) FROM cases", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1, "the refused create left no case behind");
    fx.db.drop().await;
}

#[tokio::test]
async fn malformed_items_are_invalid_not_missing() {
    let mut fx = setup().await;
    let case = open_case(&mut fx.console, &global(), ALICE, "Shapes", &[]).await;
    for (kind, reference, field) in [
        ("port", "tcp/22", "kind"),
        ("alarm", "042", "ref"),
        ("alarm", "abc", "ref"),
        ("compliance_finding", WEB, "ref"),
        ("vulnerability", WEB, "ref"),
        ("host", "web 01", "ref"),
        ("software", "rpm", "ref"),
    ] {
        let refused = cases::add_item(
            &mut fx.console,
            &global(),
            ALICE,
            &case.summary.case_id,
            kind,
            reference,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(
            matches!(refused, Refusal::Invalid(f, _) if f == field),
            "{kind} {reference}: {refused:?}"
        );
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn an_alarm_finding_or_vulnerability_is_in_one_open_case_and_is_freed_on_close() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let web_finding = finding(WEB);
    let web_vuln = vuln(WEB);
    let exclusive: [(&str, &str); 3] = [
        ("alarm", &alarm),
        ("compliance_finding", &web_finding),
        ("vulnerability", &web_vuln),
    ];
    let first = open_case(&mut fx.console, &global(), ALICE, "First", &exclusive).await;
    let number = first.summary.number;

    // Neither a new case nor an existing one takes them, and the refusal
    // names the first case for someone who can see it.
    for (kind, reference) in exclusive {
        assert_eq!(
            refused_create(&mut fx.console, &global(), DAVE, &[(kind, reference)]).await,
            Refusal::ItemInCase(Some(number)),
            "{kind}"
        );
    }
    let second = open_case(&mut fx.console, &global(), DAVE, "Second", &[]).await;
    let refused = cases::add_item(
        &mut fx.console,
        &prod(),
        DAVE,
        &second.summary.case_id,
        "alarm",
        &alarm,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(refused.unwrap_err(), Refusal::ItemInCase(Some(number)));
    // The same item twice in one case is its own refusal.
    let twice = cases::add_item(
        &mut fx.console,
        &global(),
        ALICE,
        &first.summary.case_id,
        "alarm",
        &alarm,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(twice.unwrap_err(), Refusal::AlreadyInCase);
    // Hosts and software are not exclusive; the advisory alone is not an item.
    for (case, user) in [(&first, ALICE), (&second, DAVE)] {
        for (kind, reference) in [("host", WEB), ("software", "rpm/openssl")] {
            cases::add_item(
                &mut fx.console,
                &global(),
                user,
                &case.summary.case_id,
                kind,
                reference,
                Utc::now(),
            )
            .await
            .unwrap()
            .unwrap();
        }
    }
    // The vulnerability on another host is another item.
    cases::add_item(
        &mut fx.console,
        &global(),
        DAVE,
        &second.summary.case_id,
        "vulnerability",
        &vuln(DB),
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();

    // Closing frees them: mark each, close, and take them again.
    let mut current = first.clone();
    for item in first
        .items
        .iter()
        .filter(|i| i.kind != "host" && i.kind != "software")
    {
        outcome(
            &mut fx,
            &global(),
            ALICE,
            &current,
            &item.item_id,
            Some(OutcomeChange {
                outcome: "false_positive",
                note: Some("expected"),
            }),
        )
        .await
        .unwrap();
        current = fetch(&fx, &global(), ALICE, &first).await.unwrap();
    }
    let closed = update(
        &mut fx,
        &global(),
        ALICE,
        &current,
        &closing(&current, "false_positive", "Known"),
    )
    .await
    .unwrap();
    assert_eq!(closed.summary.status, "closed");
    assert!(closed.items.iter().all(|item| !item.active));
    for (kind, reference) in exclusive {
        cases::add_item(
            &mut fx.console,
            &global(),
            DAVE,
            &second.summary.case_id,
            kind,
            reference,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap_or_else(|refusal| panic!("{kind} should be free: {refusal:?}"));
    }
    // A closed case takes no new items.
    let refused = cases::add_item(
        &mut fx.console,
        &global(),
        ALICE,
        &closed.summary.case_id,
        "host",
        DB,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(refused.unwrap_err(), Refusal::Closed);
    // Reopening needs them to be free: they are not.
    let reopen = update(&mut fx, &global(), ALICE, &closed, &same(&closed, "open")).await;
    assert_eq!(
        reopen.unwrap_err(),
        Refusal::ItemInCase(Some(second.summary.number))
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn a_reopen_conflict_names_the_other_case_only_to_someone_who_can_see_it() {
    let mut fx = setup().await;
    let db_alarm = fx.db_alarm.clone();
    let first = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "First",
        &[("host", WEB), ("alarm", &db_alarm)],
    )
    .await;
    let db_item = item_id(&first, "alarm").to_owned();
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &first,
        &db_item,
        Some(OutcomeChange {
            outcome: "false_positive",
            note: Some("test"),
        }),
    )
    .await
    .unwrap();
    let first = fetch(&fx, &global(), ALICE, &first).await.unwrap();
    let closed = update(
        &mut fx,
        &global(),
        ALICE,
        &first,
        &closing(&first, "mitigated", "Done"),
    )
    .await
    .unwrap();
    // Someone takes the db-01 alarm in a case Bob cannot see.
    let other = open_case(
        &mut fx.console,
        &global(),
        DAVE,
        "Other",
        &[("alarm", &db_alarm)],
    )
    .await;
    let by_bob = update(&mut fx, &prod(), BOB, &closed, &same(&closed, "open")).await;
    assert_eq!(by_bob.unwrap_err(), Refusal::ItemInCase(None));
    let by_alice = update(&mut fx, &global(), ALICE, &closed, &same(&closed, "open")).await;
    assert_eq!(
        by_alice.unwrap_err(),
        Refusal::ItemInCase(Some(other.summary.number))
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn closing_needs_a_resolution_a_note_a_date_for_accepted_risk_and_every_outcome() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let web_finding = finding(WEB);
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "To close",
        &[
            ("host", WEB),
            ("alarm", &alarm),
            ("compliance_finding", &web_finding),
        ],
    )
    .await;
    let invalid = |refusal: Refusal, field: &'static str, code: &'static str| {
        assert_eq!(refusal, Refusal::Invalid(field, code));
    };
    // No resolution, no note.
    let refused = update(&mut fx, &global(), ALICE, &case, &same(&case, "closed")).await;
    invalid(refused.unwrap_err(), "resolution", "resolution_required");
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &CaseChange {
            resolution: Some("mitigated"),
            ..same(&case, "closed")
        },
    )
    .await;
    invalid(
        refused.unwrap_err(),
        "resolution_note",
        "resolution_note_required",
    );
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &closing(&case, "wontfix", "x"),
    )
    .await;
    invalid(refused.unwrap_err(), "resolution", "invalid_resolution");
    // Accepted risk needs a future date; other resolutions take none.
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &closing(&case, "accepted_risk", "ok"),
    )
    .await;
    invalid(
        refused.unwrap_err(),
        "accepted_until",
        "accepted_until_required",
    );
    let past = CaseChange {
        accepted_until: Some(Utc::now() - Duration::minutes(1)),
        ..closing(&case, "accepted_risk", "ok")
    };
    let refused = update(&mut fx, &global(), ALICE, &case, &past).await;
    invalid(
        refused.unwrap_err(),
        "accepted_until",
        "accepted_until_past",
    );
    let stray = CaseChange {
        accepted_until: Some(Utc::now() + Duration::days(1)),
        ..closing(&case, "mitigated", "ok")
    };
    let refused = update(&mut fx, &global(), ALICE, &case, &stray).await;
    invalid(
        refused.unwrap_err(),
        "accepted_until",
        "accepted_until_not_allowed",
    );
    // An open case carries no resolution fields.
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &CaseChange {
            resolution: Some("mitigated"),
            ..same(&case, "investigating")
        },
    )
    .await;
    assert!(matches!(
        refused.unwrap_err(),
        Refusal::Invalid("resolution", _)
    ));

    // With the fields right, the alarm and the finding still need outcomes.
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &closing(&case, "mitigated", "Fixed"),
    )
    .await;
    assert_eq!(refused.unwrap_err(), Refusal::ItemsUnresolved(2));
    let alarm_item = item_id(&case, "alarm").to_owned();
    let finding_item = item_id(&case, "compliance_finding").to_owned();
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &alarm_item,
        Some(OutcomeChange {
            outcome: "accepted_risk",
            note: Some("Accepted by the owner"),
        }),
    )
    .await
    .unwrap();
    let after_one = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(after_one.summary.pending_items, 1);
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &after_one,
        &closing(&after_one, "mitigated", "Fixed"),
    )
    .await;
    assert_eq!(refused.unwrap_err(), Refusal::ItemsUnresolved(1));
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &finding_item,
        Some(OutcomeChange {
            outcome: "false_positive",
            note: Some("Scanner noise"),
        }),
    )
    .await
    .unwrap();
    let ready = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(ready.summary.pending_items, 0);
    let until = Utc::now() + Duration::days(30);
    let closed = update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &CaseChange {
            accepted_until: Some(until),
            ..closing(&ready, "accepted_risk", "Risk accepted until the rebuild")
        },
    )
    .await
    .unwrap();
    let summary = &closed.summary;
    assert_eq!(summary.status, "closed");
    assert_eq!(summary.resolution.as_deref(), Some("accepted_risk"));
    assert!(summary.closed_at.is_some() && summary.accepted_until.is_some());
    assert_eq!(summary.version, ready.summary.version + 1);
    assert_eq!(
        closed.resolution_note.as_deref(),
        Some("Risk accepted until the rebuild")
    );
    let last = closed.events.last().unwrap();
    assert_eq!(last.kind, "resolved");
    assert_eq!(last.detail["resolution"], "accepted_risk");
    // Closed means the outcomes and the resolution stay as they are.
    let refused = outcome(&mut fx, &global(), ALICE, &closed, &alarm_item, None).await;
    assert_eq!(refused.unwrap_err(), Refusal::Closed);
    let other_way = CaseChange {
        resolution: Some("mitigated"),
        accepted_until: None,
        ..closing(&closed, "mitigated", "Changed my mind")
    };
    let refused = update(&mut fx, &global(), ALICE, &closed, &other_way).await;
    assert_eq!(refused.unwrap_err(), Refusal::Closed);
    // Title, severity and assignee can still be edited, and notes added.
    let renamed = update(
        &mut fx,
        &global(),
        ALICE,
        &closed,
        &CaseChange {
            title: "Renamed",
            resolution: closed.summary.resolution.as_deref(),
            resolution_note: closed.resolution_note.as_deref(),
            accepted_until: closed.summary.accepted_until,
            ..same(&closed, "closed")
        },
    )
    .await
    .unwrap();
    assert_eq!(renamed.summary.title, "Renamed");
    cases::add_note(
        &mut fx.console,
        &global(),
        ALICE,
        &closed.summary.case_id,
        "Follow-up after closing",
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    let actions = audit_actions(&fx).await;
    assert!(actions.contains(&"case.close".to_owned()), "{actions:?}");
    fx.db.drop().await;
}

#[tokio::test]
async fn closing_is_refused_for_items_the_closer_cannot_see() {
    let mut fx = setup().await;
    let db_alarm = fx.db_alarm.clone();
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Mixed",
        &[("host", WEB), ("alarm", &db_alarm)],
    )
    .await;
    let seen_by_bob = fetch(&fx, &prod(), BOB, &case).await.unwrap();
    let refused = update(
        &mut fx,
        &prod(),
        BOB,
        &seen_by_bob,
        &closing(&seen_by_bob, "mitigated", "Done"),
    )
    .await;
    assert_eq!(
        refused.unwrap_err(),
        Refusal::HiddenItemsUnresolved,
        "no count, no name of the hidden item"
    );
    // Bob cannot reach the hidden item's outcome either.
    let hidden_item = item_id(&case, "alarm").to_owned();
    let refused = outcome(
        &mut fx,
        &prod(),
        BOB,
        &seen_by_bob,
        &hidden_item,
        Some(OutcomeChange {
            outcome: "false_positive",
            note: Some("x"),
        }),
    )
    .await;
    assert_eq!(refused.unwrap_err(), Refusal::ItemNotFound);
    let removed = cases::remove_item(
        &mut fx.console,
        &prod(),
        BOB,
        &case.summary.case_id,
        &hidden_item,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(removed.unwrap_err(), Refusal::ItemNotFound);
    // Someone with the scope clears it, and then Bob can close.
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &hidden_item,
        Some(OutcomeChange {
            outcome: "false_positive",
            note: Some("Checked"),
        }),
    )
    .await
    .unwrap();
    let closed = update(
        &mut fx,
        &prod(),
        BOB,
        &seen_by_bob,
        &closing(&seen_by_bob, "mitigated", "Done"),
    )
    .await;
    assert_eq!(closed.unwrap().summary.status, "closed");
    fx.db.drop().await;
}

#[tokio::test]
async fn a_stale_version_is_refused_and_an_unchanged_update_writes_nothing() {
    let mut fx = setup().await;
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Versions",
        &[("host", WEB)],
    )
    .await;
    let renamed = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &CaseChange {
            title: "Renamed",
            ..same(&case, "open")
        },
    )
    .await
    .unwrap();
    assert_eq!(renamed.summary.version, case.summary.version + 1);
    // The old version again.
    let stale = update(
        &mut fx,
        &global(),
        DAVE,
        &case,
        &CaseChange {
            title: "Mine",
            ..same(&case, "open")
        },
    )
    .await;
    assert_eq!(stale.unwrap_err(), Refusal::Stale);
    // The current values change nothing: same version, no new audit row.
    let before = audit_actions(&fx).await.len();
    let noop = update(&mut fx, &global(), ALICE, &renamed, &same(&renamed, "open"))
        .await
        .unwrap();
    assert_eq!(noop.summary.version, renamed.summary.version);
    assert_eq!(audit_actions(&fx).await.len(), before);
    // A case nobody can see is absent, not stale.
    let db_only = open_case(&mut fx.console, &global(), ALICE, "Hidden", &[("host", DB)]).await;
    let absent = update(
        &mut fx,
        &prod(),
        BOB,
        &db_only,
        &same(&db_only, "investigating"),
    )
    .await;
    assert_eq!(absent.unwrap_err(), Refusal::NotFound);
    // Status moves between open and investigating and is on the timeline.
    let investigating = update(
        &mut fx,
        &global(),
        ALICE,
        &renamed,
        &same(&renamed, "investigating"),
    )
    .await
    .unwrap();
    assert_eq!(investigating.summary.status, "investigating");
    let status = investigating.events.last().unwrap();
    assert_eq!(status.kind, "status");
    assert_eq!(status.detail["from"], "open");
    assert_eq!(status.detail["to"], "investigating");
    fx.db.drop().await;
}

#[tokio::test]
async fn invalid_titles_severities_and_statuses_are_refused() {
    let mut fx = setup().await;
    for title in ["", " padded ", &"t".repeat(121), "tab\there"] {
        let refused = cases::create(
            &mut fx.console,
            &global(),
            ALICE,
            &NewCase {
                title,
                severity: None,
                assignee_user_id: None,
                items: &[],
            },
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(
            refused.unwrap_err(),
            Refusal::Invalid("title", "invalid_title")
        );
    }
    let refused = cases::create(
        &mut fx.console,
        &global(),
        ALICE,
        &NewCase {
            title: "ok",
            severity: Some("urgent"),
            assignee_user_id: None,
            items: &[],
        },
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(
        refused.unwrap_err(),
        Refusal::Invalid("severity", "invalid_severity")
    );
    let case = open_case(&mut fx.console, &global(), ALICE, "ok", &[]).await;
    let refused = update(&mut fx, &global(), ALICE, &case, &same(&case, "done")).await;
    assert_eq!(
        refused.unwrap_err(),
        Refusal::Invalid("status", "invalid_status")
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn resolved_needs_the_evidence_to_be_gone() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let web_finding = finding(WEB);
    let web_vuln = vuln(WEB);
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Evidence",
        &[
            ("alarm", &alarm),
            ("compliance_finding", &web_finding),
            ("vulnerability", &web_vuln),
            ("host", WEB),
            ("software", "rpm/openssl"),
        ],
    )
    .await;
    let resolved = || {
        Some(OutcomeChange {
            outcome: "resolved",
            note: None,
        })
    };
    let alarm_item = item_id(&case, "alarm").to_owned();
    let finding_item = item_id(&case, "compliance_finding").to_owned();
    let vuln_item = item_id(&case, "vulnerability").to_owned();
    // Everything is still there: nothing can be resolved.
    for item in [&alarm_item, &finding_item, &vuln_item] {
        let refused = outcome(&mut fx, &global(), ALICE, &case, item, resolved()).await;
        assert_eq!(refused.unwrap_err(), Refusal::EvidencePresent);
    }
    // Hosts and software take no outcome at all.
    for kind in ["host", "software"] {
        let refused = outcome(
            &mut fx,
            &global(),
            ALICE,
            &case,
            item_id(&case, kind),
            resolved(),
        )
        .await;
        assert_eq!(
            refused.unwrap_err(),
            Refusal::Invalid("outcome", "outcome_not_applicable")
        );
    }
    // False positive and accepted risk need a note, and a known outcome.
    for note in [None, Some("   ")] {
        let refused = outcome(
            &mut fx,
            &global(),
            ALICE,
            &case,
            &alarm_item,
            Some(OutcomeChange {
                outcome: "false_positive",
                note,
            }),
        )
        .await;
        assert!(matches!(refused.unwrap_err(), Refusal::Invalid("note", _)));
    }
    let refused = outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &alarm_item,
        Some(OutcomeChange {
            outcome: "fixed",
            note: Some("x"),
        }),
    )
    .await;
    assert_eq!(
        refused.unwrap_err(),
        Refusal::Invalid("outcome", "invalid_outcome")
    );

    // The alarm is closed as mitigated, the finding is no longer reported,
    // and the advisory no longer matches: each is now evidence.
    fx.admin
        .batch_execute(&format!(
            "UPDATE alarms SET state = 'mitigated', note = 'done' WHERE id = {alarm};
             UPDATE current_findings SET ended_at = now() WHERE agent_id = '{WEB}';
             UPDATE vulnerabilities SET fixed_at = now() WHERE agent_id = '{WEB}';"
        ))
        .await
        .unwrap();
    let fresh = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    for item in &fresh.items {
        let expected = matches!(
            item.kind.as_str(),
            "alarm" | "compliance_finding" | "vulnerability"
        );
        assert_eq!(item.evidence_gone, expected, "{}", item.kind);
    }
    for item in [&alarm_item, &finding_item, &vuln_item] {
        let saved = outcome(&mut fx, &global(), ALICE, &case, item, resolved())
            .await
            .unwrap();
        assert_eq!(saved.outcome.as_deref(), Some("resolved"));
    }
    // With all resolved the case closes...
    let ready = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(ready.summary.pending_items, 0);
    // ...unless the evidence came back in the meantime.
    fx.admin
        .batch_execute(&format!(
            "UPDATE current_findings SET ended_at = NULL WHERE agent_id = '{WEB}';"
        ))
        .await
        .unwrap();
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &closing(&ready, "mitigated", "Fixed"),
    )
    .await;
    assert_eq!(refused.unwrap_err(), Refusal::ItemsUnresolved(1));
    fx.admin
        .batch_execute(&format!(
            "UPDATE current_findings SET ended_at = now() WHERE agent_id = '{WEB}';"
        ))
        .await
        .unwrap();
    let closed = update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &closing(&ready, "mitigated", "Fixed"),
    )
    .await;
    assert_eq!(closed.unwrap().summary.status, "closed");

    // An outcome can be cleared on an open case; a vulnerability that is
    // only the no-fix kind (by package version) counts as present too.
    let bash = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "No fix",
        &[("vulnerability", &format!("{DB}/FEDORA-2"))],
    )
    .await;
    let bash_item = item_id(&bash, "vulnerability").to_owned();
    assert!(!bash.items[0].evidence_gone);
    assert_eq!(bash.items[0].severity.as_deref(), Some("low"));
    let marked = outcome(
        &mut fx,
        &global(),
        ALICE,
        &bash,
        &bash_item,
        Some(OutcomeChange {
            outcome: "accepted_risk",
            note: Some("No fix exists"),
        }),
    )
    .await
    .unwrap();
    assert_eq!(marked.outcome_note.as_deref(), Some("No fix exists"));
    let cleared = outcome(&mut fx, &global(), ALICE, &bash, &bash_item, None)
        .await
        .unwrap();
    assert_eq!((cleared.outcome, cleared.outcome_note), (None, None));
    fx.db.drop().await;
}

#[tokio::test]
async fn the_timeline_is_append_only_and_audit_rows_never_hold_note_text() {
    let mut fx = setup().await;
    let case = open_case(&mut fx.console, &global(), ALICE, "Notes", &[("host", WEB)]).await;
    let secret = "the password is hunter2";
    let note = cases::add_note(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        secret,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(note.kind, "note");
    assert_eq!(note.body.as_deref(), Some(secret));
    assert_eq!(note.actor.as_ref().unwrap().username, "alice");
    for bad in ["", "   ", "bell\u{7}", &"n".repeat(4001)] {
        let refused = cases::add_note(
            &mut fx.console,
            &global(),
            ALICE,
            &case.summary.case_id,
            bad,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(
            refused.unwrap_err(),
            Refusal::Invalid("body", "invalid_note")
        );
    }
    let hidden = cases::add_note(
        &mut fx.console,
        &prod(),
        BOB,
        "00000000-0000-4000-8000-000000000000",
        "x",
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(hidden.unwrap_err(), Refusal::NotFound);

    // A note moves the case to the top of the list.
    let listed = cases::list(
        &fx.console,
        &global(),
        ALICE,
        &CaseFilters::default(),
        None,
        10,
    )
    .await
    .unwrap();
    assert!(listed[0].updated_at >= case.summary.updated_at);

    // Nobody can edit or delete a timeline entry, not even the owner.
    let update = fx
        .admin
        .execute("UPDATE case_events SET body = 'edited'", &[])
        .await;
    assert!(update.is_err());
    let delete = fx.admin.execute("DELETE FROM case_events", &[]).await;
    assert!(delete.is_err());
    let console = fx.console.execute("DELETE FROM case_events", &[]).await;
    assert!(console.is_err(), "the console role has no DELETE either");
    let events = fetch(&fx, &global(), ALICE, &case).await.unwrap().events;
    let ids: Vec<_> = events.iter().map(|e| e.event_id).collect();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]), "oldest first");
    assert_eq!(events.last().unwrap().body.as_deref(), Some(secret));

    let audit: Vec<(String, String)> = fx
        .admin
        .query(
            "SELECT action, detail::text FROM audit_log WHERE action LIKE 'case.%'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert!(audit.iter().any(|(action, _)| action == "case.note"));
    assert!(
        audit.iter().all(|(_, detail)| !detail.contains("hunter2")),
        "{audit:?}"
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn every_change_writes_its_audit_row_in_the_same_transaction() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Audit",
        &[("alarm", &alarm)],
    )
    .await;
    let alarm_item = item_id(&case, "alarm").to_owned();
    cases::add_item(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        "host",
        WEB,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    cases::add_note(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        "n",
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &alarm_item,
        Some(OutcomeChange {
            outcome: "false_positive",
            note: Some("fp"),
        }),
    )
    .await
    .unwrap();
    let host_item = fetch(&fx, &global(), ALICE, &case)
        .await
        .unwrap()
        .items
        .iter()
        .find(|i| i.kind == "host")
        .unwrap()
        .item_id
        .clone();
    cases::remove_item(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        &host_item,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    let current = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(current.items.len(), 1, "the host is gone");
    let renamed = update(
        &mut fx,
        &global(),
        ALICE,
        &current,
        &CaseChange {
            title: "Audit 2",
            ..same(&current, "investigating")
        },
    )
    .await
    .unwrap();
    let closed = update(
        &mut fx,
        &global(),
        ALICE,
        &renamed,
        &closing(&renamed, "false_positive", "fp"),
    )
    .await
    .unwrap();
    update(&mut fx, &global(), ALICE, &closed, &same(&closed, "open"))
        .await
        .unwrap();
    let actions = audit_actions(&fx).await;
    assert_eq!(
        actions,
        [
            "case.create",
            "case.item.add",
            "case.item.add",
            "case.note",
            "case.item.outcome",
            "case.item.remove",
            "case.update",
            "case.close",
            "case.reopen",
        ]
    );
    let row = fx
        .admin
        .query_one(
            "SELECT actor, actor_kind, actor_display, target_kind, target_id
             FROM audit_log WHERE action = 'case.close'",
            &[],
        )
        .await
        .unwrap();
    let fields: Vec<String> = (0..5).map(|i| row.get(i)).collect();
    assert_eq!(
        fields,
        [ALICE, "user", "alice", "case", &case.summary.case_id]
    );
    let timeline: Vec<_> = fetch(&fx, &global(), ALICE, &case)
        .await
        .unwrap()
        .events
        .iter()
        .map(|e| e.kind.clone())
        .collect();
    assert_eq!(
        timeline,
        [
            "created",
            "item_added",
            "item_added",
            "note",
            "item_outcome",
            "item_removed",
            "status",
            "resolved",
            "reopened",
        ]
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn a_refused_change_leaves_no_trace() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let first = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "First",
        &[("alarm", &alarm)],
    )
    .await;
    let before = audit_actions(&fx).await;
    let second = open_case(&mut fx.console, &global(), ALICE, "Second", &[]).await;
    let events_before = fetch(&fx, &global(), ALICE, &second)
        .await
        .unwrap()
        .events
        .len();
    let refused = cases::add_item(
        &mut fx.console,
        &global(),
        ALICE,
        &second.summary.case_id,
        "alarm",
        &alarm,
        Utc::now(),
    )
    .await
    .unwrap();
    assert!(refused.is_err());
    assert_eq!(
        fetch(&fx, &global(), ALICE, &second)
            .await
            .unwrap()
            .events
            .len(),
        events_before
    );
    assert_eq!(
        audit_actions(&fx).await.len(),
        before.len() + 1,
        "only the create"
    );
    assert_eq!(
        fetch(&fx, &global(), ALICE, &first)
            .await
            .unwrap()
            .items
            .len(),
        1
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn for_item_finds_the_open_case_of_an_exclusive_item_and_the_cases_of_a_host() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let alarm_2 = fx.web_alarm_2.clone();
    let first = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "First",
        &[("alarm", &alarm), ("host", WEB)],
    )
    .await;
    let second = open_case(&mut fx.console, &global(), DAVE, "Second", &[("host", WEB)]).await;
    let found = cases::for_item(&fx.console, &global(), DAVE, "alarm", &alarm)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].case.number, first.summary.number);
    assert_eq!(found[0].item_id, item_id(&first, "alarm"));
    let none = cases::for_item(&fx.console, &global(), DAVE, "alarm", &alarm_2)
        .await
        .unwrap()
        .unwrap();
    assert!(none.is_empty());
    let hosts = cases::for_item(&fx.console, &global(), DAVE, "host", WEB)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        hosts.iter().map(|c| c.case.number).collect::<Vec<_>>(),
        [second.summary.number, first.summary.number],
        "newest change first"
    );
    // A case the caller cannot see is not listed, nor is its existence.
    let db_case = open_case(&mut fx.console, &global(), ALICE, "Db", &[("host", DB)]).await;
    let hidden = cases::for_item(&fx.console, &prod(), BOB, "host", DB)
        .await
        .unwrap()
        .unwrap();
    assert!(hidden.is_empty(), "{hidden:?} {db_case:?}");
    // Nor is a visible case listed for an item in it that the caller cannot see.
    open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Both",
        &[("host", WEB), ("host", DB)],
    )
    .await;
    let hidden = cases::for_item(&fx.console, &prod(), BOB, "host", DB)
        .await
        .unwrap()
        .unwrap();
    assert!(hidden.is_empty(), "{hidden:?}");
    let visible = cases::for_item(&fx.console, &prod(), BOB, "host", WEB)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(visible.len(), 3);
    let refused = cases::for_item(&fx.console, &prod(), BOB, "alarm", "nope")
        .await
        .unwrap();
    assert!(matches!(refused.unwrap_err(), Refusal::Invalid("ref", _)));
    // A closed case no longer holds its exclusive items.
    let first_item = item_id(&first, "alarm").to_owned();
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &first,
        &first_item,
        Some(OutcomeChange {
            outcome: "false_positive",
            note: Some("x"),
        }),
    )
    .await
    .unwrap();
    let ready = fetch(&fx, &global(), ALICE, &first).await.unwrap();
    update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &closing(&ready, "false_positive", "x"),
    )
    .await
    .unwrap();
    assert!(
        cases::for_item(&fx.console, &global(), DAVE, "alarm", &alarm)
            .await
            .unwrap()
            .unwrap()
            .is_empty()
    );
    let hosts = cases::for_item(&fx.console, &global(), DAVE, "host", WEB)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(hosts.len(), 3, "hosts stay listed on closed cases");
    fx.db.drop().await;
}

#[tokio::test]
async fn assignees_are_enabled_users_who_can_read_cases() {
    let mut fx = setup().await;
    let names = |users: Vec<cases::UserRef>| -> Vec<String> {
        users.into_iter().map(|u| u.username).collect()
    };
    assert_eq!(
        names(cases::assignees(&fx.console).await.unwrap()),
        ["alice", "bob", "dave"],
        "the viewer cannot read cases"
    );
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Assign",
        &[("host", WEB)],
    )
    .await;
    let viewer = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &CaseChange {
            assignee_user_id: Some(CAROL),
            ..same(&case, "open")
        },
    )
    .await;
    assert_eq!(viewer.unwrap_err(), Refusal::AssigneeUnavailable);
    for bad in ["not-a-user", "99999999-9999-4999-8999-999999999999"] {
        let refused = update(
            &mut fx,
            &global(),
            ALICE,
            &case,
            &CaseChange {
                assignee_user_id: Some(bad),
                ..same(&case, "open")
            },
        )
        .await;
        assert_eq!(refused.unwrap_err(), Refusal::AssigneeUnavailable);
    }
    fx.admin
        .execute(
            "UPDATE console_users SET enabled = false, disabled_at = now()
             WHERE user_id = $1::text::uuid",
            &[&DAVE],
        )
        .await
        .unwrap();
    assert_eq!(
        names(cases::assignees(&fx.console).await.unwrap()),
        ["alice", "bob"]
    );
    let disabled = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &CaseChange {
            assignee_user_id: Some(DAVE),
            ..same(&case, "open")
        },
    )
    .await;
    assert_eq!(disabled.unwrap_err(), Refusal::AssigneeUnavailable);
    let assigned = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &CaseChange {
            assignee_user_id: Some(BOB),
            ..same(&case, "open")
        },
    )
    .await
    .unwrap();
    let event = assigned.events.last().unwrap();
    assert_eq!(event.kind, "assigned");
    assert_eq!(
        (event.detail["from"].is_null(), event.detail["to"].as_str()),
        (true, Some("bob"))
    );
    let unassigned = update(
        &mut fx,
        &global(),
        ALICE,
        &assigned,
        &CaseChange {
            assignee_user_id: None,
            ..same(&assigned, "open")
        },
    )
    .await
    .unwrap();
    assert!(unassigned.summary.assignee.is_none());
    fx.db.drop().await;
}

#[tokio::test]
async fn the_list_filters_by_status_severity_assignee_and_text_and_pages() {
    let mut fx = setup().await;
    let mut made = Vec::new();
    for (title, severity) in [
        ("SSH on web", "high"),
        ("Disk full", "low"),
        ("Old news", "high"),
    ] {
        let case = cases::create(
            &mut fx.console,
            &global(),
            ALICE,
            &NewCase {
                title,
                severity: Some(severity),
                assignee_user_id: None,
                items: &[("host", WEB)],
            },
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
        made.push(case);
    }
    let investigating = update(
        &mut fx,
        &global(),
        ALICE,
        &made[1],
        &same(&made[1], "investigating"),
    )
    .await
    .unwrap();
    update(
        &mut fx,
        &global(),
        ALICE,
        &made[2],
        &closing(&made[2], "mitigated", "ok"),
    )
    .await
    .unwrap();
    update(
        &mut fx,
        &global(),
        ALICE,
        &made[0],
        &CaseChange {
            assignee_user_id: Some(BOB),
            ..same(&made[0], "open")
        },
    )
    .await
    .unwrap();
    let titles = |filters: CaseFilters| {
        let client = &fx.console;
        async move {
            cases::list(client, &global(), ALICE, &filters, None, 50)
                .await
                .unwrap()
                .into_iter()
                .map(|c| c.title)
                .collect::<Vec<_>>()
        }
    };
    let all = CaseFilters {
        status: Some("all".into()),
        ..CaseFilters::default()
    };
    assert_eq!(
        titles(CaseFilters::default()).await,
        ["SSH on web", "Disk full"],
        "open and investigating, newest change first"
    );
    assert_eq!(titles(all.clone()).await.len(), 3);
    for (status, expected) in [
        ("open", "SSH on web"),
        ("investigating", "Disk full"),
        ("closed", "Old news"),
    ] {
        assert_eq!(
            titles(CaseFilters {
                status: Some(status.into()),
                ..CaseFilters::default()
            })
            .await,
            [expected],
            "{status}"
        );
    }
    assert_eq!(
        titles(CaseFilters {
            severity: Some("high".into()),
            ..all.clone()
        })
        .await,
        ["SSH on web", "Old news"]
    );
    assert_eq!(
        titles(CaseFilters {
            assignee: AssigneeFilter::User(BOB.into()),
            ..all.clone()
        })
        .await,
        ["SSH on web"]
    );
    assert_eq!(
        titles(CaseFilters {
            assignee: AssigneeFilter::Nobody,
            ..all.clone()
        })
        .await
        .len(),
        2
    );
    assert_eq!(
        titles(CaseFilters {
            q: Some("DISK".into()),
            ..all.clone()
        })
        .await,
        ["Disk full"]
    );
    assert_eq!(
        titles(CaseFilters {
            q: Some(format!("c-{}", made[2].summary.number)),
            ..all.clone()
        })
        .await,
        ["Old news"]
    );
    // % and _ are text, not patterns.
    assert!(
        titles(CaseFilters {
            q: Some("%".into()),
            ..all.clone()
        })
        .await
        .is_empty()
    );
    // Pages by the last row's (updated_at, case_id).
    let first = cases::list(&fx.console, &global(), ALICE, &all, None, 2)
        .await
        .unwrap();
    assert_eq!(first.len(), 2);
    let cursor = first
        .last()
        .map(|c| (c.updated_at, c.case_id.clone()))
        .unwrap();
    let second = cases::list(&fx.console, &global(), ALICE, &all, Some(&cursor), 2)
        .await
        .unwrap();
    assert_eq!(second.len(), 1);
    let mut numbers: Vec<_> = first.iter().chain(&second).map(|c| c.number).collect();
    numbers.sort_unstable();
    numbers.dedup();
    assert_eq!(numbers.len(), 3, "no row twice, none missing");
    assert_eq!(investigating.summary.status, "investigating");
    fx.db.drop().await;
}

#[tokio::test]
async fn accepted_risk_that_runs_out_reopens_the_case() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Accept",
        &[("alarm", &alarm), ("host", WEB)],
    )
    .await;
    let alarm_item = item_id(&case, "alarm").to_owned();
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &alarm_item,
        Some(OutcomeChange {
            outcome: "accepted_risk",
            note: Some("Until the rebuild"),
        }),
    )
    .await
    .unwrap();
    let ready = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    let until = Utc::now() + Duration::hours(1);
    let closed = update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &CaseChange {
            accepted_until: Some(until),
            ..closing(&ready, "accepted_risk", "Rebuild next week")
        },
    )
    .await
    .unwrap();
    // Not yet.
    let now = Utc::now();
    assert_eq!(
        cases::reopen_expired(&mut fx.console, now).await.unwrap(),
        0
    );
    // After it runs out.
    let later: DateTime<Utc> = until + Duration::minutes(1);
    assert_eq!(
        cases::reopen_expired(&mut fx.console, later).await.unwrap(),
        1
    );
    assert_eq!(
        cases::reopen_expired(&mut fx.console, later).await.unwrap(),
        0
    );
    let reopened = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    let summary = &reopened.summary;
    assert_eq!(summary.status, "open");
    assert!(
        summary.resolution.is_none()
            && summary.accepted_until.is_none()
            && summary.closed_at.is_none()
    );
    assert_eq!(summary.version, closed.summary.version + 1);
    assert_eq!(reopened.resolution_note, None);
    let alarm = reopened.items.iter().find(|i| i.kind == "alarm").unwrap();
    assert!(
        alarm.active && alarm.outcome.is_none(),
        "the acceptance ran out with it"
    );
    let last = reopened.events.last().unwrap();
    assert_eq!(last.kind, "reopened");
    assert!(last.actor.is_none(), "the platform did it");
    assert_eq!(last.detail["reason"], "accepted_risk_expired");
    let who: String = fx
        .admin
        .query_one(
            "SELECT actor FROM audit_log WHERE action = 'case.reopen'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(who, "system");

    // A case whose item has joined another open case since stays closed.
    let again = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Again",
        &[("alarm", &fx.web_alarm_2.clone())],
    )
    .await;
    let item = item_id(&again, "alarm").to_owned();
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &again,
        &item,
        Some(OutcomeChange {
            outcome: "accepted_risk",
            note: Some("n"),
        }),
    )
    .await
    .unwrap();
    let ready = fetch(&fx, &global(), ALICE, &again).await.unwrap();
    update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &CaseChange {
            accepted_until: Some(Utc::now() + Duration::hours(1)),
            ..closing(&ready, "accepted_risk", "n")
        },
    )
    .await
    .unwrap();
    open_case(
        &mut fx.console,
        &global(),
        DAVE,
        "Took it",
        &[("alarm", &fx.web_alarm_2.clone())],
    )
    .await;
    let reopened = cases::reopen_expired(&mut fx.console, Utc::now() + Duration::hours(2))
        .await
        .unwrap();
    assert_eq!(reopened, 0);
    assert_eq!(
        fetch(&fx, &global(), ALICE, &again)
            .await
            .unwrap()
            .summary
            .status,
        "closed"
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn limits_on_items_on_creation_and_on_the_timeline_hold() {
    let mut fx = setup().await;
    let many: Vec<String> = (0..51).map(|n| format!("rpm/pkg{n}")).collect();
    let items: Vec<(&str, &str)> = many.iter().map(|r| ("software", r.as_str())).collect();
    assert_eq!(
        refused_create(&mut fx.console, &global(), ALICE, &items).await,
        Refusal::Invalid("items", "too_many_items")
    );
    let case = open_case(&mut fx.console, &global(), ALICE, "Full", &[]).await;
    fx.admin
        .execute(
            "INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, active, added_by_user_id, added_at)
             SELECT gen_random_uuid(), $1::text::uuid, 'software', 'rpm/pkg' || n, NULL, true,
                    $2::text::uuid, now()
             FROM generate_series(1, $3::int) n",
            &[&case.summary.case_id, &ALICE, &(cases::MAX_ITEMS_PER_CASE as i32)],
        )
        .await
        .unwrap();
    let refused = cases::add_item(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        "host",
        WEB,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(refused.unwrap_err(), Refusal::TooManyItems);
    fx.admin
        .execute(
            "INSERT INTO case_events (case_id, at, actor_user_id, kind, body)
             SELECT $1::text::uuid, now(), $2::text::uuid, 'note', 'n'
             FROM generate_series(1, $3::int)",
            &[
                &case.summary.case_id,
                &ALICE,
                &(cases::MAX_EVENTS_PER_CASE as i32),
            ],
        )
        .await
        .unwrap();
    let refused = cases::add_note(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        "one more",
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(refused.unwrap_err(), Refusal::TimelineFull);
    fx.db.drop().await;
}

#[tokio::test]
async fn items_can_be_removed_from_an_open_case_only() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Remove",
        &[("alarm", &alarm), ("host", WEB)],
    )
    .await;
    let alarm_item = item_id(&case, "alarm").to_owned();
    cases::remove_item(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        &alarm_item,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    let after = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(after.items.len(), 1);
    let removed = after
        .events
        .iter()
        .find(|e| e.kind == "item_removed")
        .unwrap();
    assert_eq!(removed.detail["item_ref"], alarm.as_str());
    // The alarm is free again, and the second removal finds nothing.
    open_case(
        &mut fx.console,
        &global(),
        DAVE,
        "Elsewhere",
        &[("alarm", &alarm)],
    )
    .await;
    for bad in [alarm_item.as_str(), "not-a-uuid"] {
        let refused = cases::remove_item(
            &mut fx.console,
            &global(),
            ALICE,
            &case.summary.case_id,
            bad,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(refused.unwrap_err(), Refusal::ItemNotFound);
    }
    let host_item = item_id(&after, "host").to_owned();
    let closed = update(
        &mut fx,
        &global(),
        ALICE,
        &after,
        &closing(&after, "mitigated", "ok"),
    )
    .await
    .unwrap();
    let refused = cases::remove_item(
        &mut fx.console,
        &global(),
        ALICE,
        &closed.summary.case_id,
        &host_item,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(refused.unwrap_err(), Refusal::Closed);
    fx.db.drop().await;
}

#[tokio::test]
async fn the_database_refuses_what_the_rules_forbid() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let first = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "One",
        &[("alarm", &alarm)],
    )
    .await;
    let second = open_case(&mut fx.console, &global(), ALICE, "Two", &[]).await;
    // Even a direct insert cannot put an exclusive item in two open cases.
    let result = fx
        .admin
        .execute(
            "INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, active,
                 added_by_user_id, added_at)
             VALUES (gen_random_uuid(), $1::text::uuid, 'alarm', $2, $3, true,
                 $4::text::uuid, now())",
            &[&second.summary.case_id, &alarm, &WEB, &ALICE],
        )
        .await;
    assert!(result.is_err());
    // A closed case needs its resolution, note and close time, and an
    // accepted risk its date.
    for set in [
        "status = 'closed'",
        "status = 'closed', resolution = 'mitigated'",
        "status = 'closed', resolution = 'mitigated', resolution_note = 'x'",
        "status = 'closed', resolution = 'accepted_risk', resolution_note = 'x', closed_at = now()",
        "title = ''",
        "severity = 'urgent'",
    ] {
        let result = fx
            .admin
            .execute(
                &format!("UPDATE cases SET {set} WHERE case_id = $1::text::uuid"),
                &[&first.summary.case_id],
            )
            .await;
        assert!(result.is_err(), "{set}");
    }
    // Case numbers are not reused or chosen.
    let result = fx
        .admin
        .execute(
            "UPDATE cases SET number = 1 WHERE case_id = $1::text::uuid",
            &[&second.summary.case_id],
        )
        .await;
    assert!(result.is_err());
    fx.db.drop().await;
}

/// Opens a case with a finding on each host (db-01's is hidden from a
/// production-only caller) and a host, ends both findings, marks each
/// finding `resolved` and closes the case.
async fn closed_on_resolved_findings(fx: &mut Fx, title: &str) -> CaseDetail {
    let web_finding = finding(WEB);
    let db_finding = finding(DB);
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        title,
        &[
            ("host", WEB),
            ("compliance_finding", &web_finding),
            ("compliance_finding", &db_finding),
        ],
    )
    .await;
    fx.admin
        .batch_execute("UPDATE current_findings SET ended_at = now()")
        .await
        .unwrap();
    for item in case.items.iter().filter(|i| i.kind == "compliance_finding") {
        outcome(
            fx,
            &global(),
            ALICE,
            &case,
            &item.item_id,
            Some(OutcomeChange {
                outcome: "resolved",
                note: None,
            }),
        )
        .await
        .unwrap();
    }
    let ready = fetch(fx, &global(), ALICE, &case).await.unwrap();
    update(
        fx,
        &global(),
        ALICE,
        &ready,
        &closing(&ready, "mitigated", "Fixed"),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn evidence_that_returns_reopens_a_recently_closed_case() {
    let mut fx = setup().await;
    let closed = closed_on_resolved_findings(&mut fx, "Resolved").await;
    // Nothing has come back: nothing to do.
    assert_eq!(
        cases::reopen_evidence_returned(&mut fx.console, Utc::now())
            .await
            .unwrap(),
        0
    );
    // The agent reports web-01's finding again.
    fx.admin
        .execute(
            "UPDATE current_findings SET ended_at = NULL WHERE agent_id = $1",
            &[&WEB],
        )
        .await
        .unwrap();
    assert_eq!(
        cases::reopen_due(&mut fx.console, Utc::now())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        cases::reopen_evidence_returned(&mut fx.console, Utc::now())
            .await
            .unwrap(),
        0,
        "once"
    );
    let reopened = fetch(&fx, &global(), ALICE, &closed).await.unwrap();
    let summary = &reopened.summary;
    assert_eq!(summary.status, "open");
    assert!(summary.resolution.is_none() && summary.closed_at.is_none());
    assert_eq!(summary.version, closed.summary.version + 1);
    assert_eq!(reopened.resolution_note, None);
    assert!(reopened.items.iter().all(|item| item.active));
    let back = reopened
        .items
        .iter()
        .find(|i| i.reference == finding(WEB))
        .unwrap();
    assert!(
        back.outcome.is_none() && !back.evidence_gone,
        "needs a new decision"
    );
    let still_gone = reopened
        .items
        .iter()
        .find(|i| i.reference == finding(DB))
        .unwrap();
    assert_eq!(still_gone.outcome.as_deref(), Some("resolved"));
    assert_eq!(summary.pending_items, 1);
    let tail: Vec<_> = reopened.events.iter().rev().take(2).collect();
    assert_eq!(tail[1].kind, "reopened");
    assert!(tail[1].actor.is_none());
    assert_eq!(tail[1].detail["reason"], "evidence_returned");
    assert_eq!(tail[1].detail["previous_resolution"], "mitigated");
    assert!(tail[1].detail.get("item_ref").is_none(), "names no item");
    assert_eq!(tail[0].kind, "item_outcome");
    assert_eq!(tail[0].detail["item_ref"], finding(WEB));
    assert_eq!(tail[0].detail["reason"], "evidence_returned");
    let row = fx
        .admin
        .query_one(
            "SELECT actor, detail::text FROM audit_log WHERE action = 'case.reopen'",
            &[],
        )
        .await
        .unwrap();
    let (actor, detail): (String, String) = (row.get(0), row.get(1));
    assert_eq!(actor, "system");
    assert!(
        detail.contains("evidence_returned") && detail.contains("ssh-root"),
        "{detail}"
    );
    // It must be decided and closed again before it is done.
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &reopened,
        &closing(&reopened, "mitigated", "x"),
    )
    .await;
    assert_eq!(refused.unwrap_err(), Refusal::ItemsUnresolved(1));
    fx.db.drop().await;
}

#[tokio::test]
async fn false_positive_and_accepted_risk_do_not_reopen_on_evidence() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let web_finding = finding(WEB);
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Decisions",
        &[("alarm", &alarm), ("compliance_finding", &web_finding)],
    )
    .await;
    for (kind, decision) in [
        ("alarm", "false_positive"),
        ("compliance_finding", "accepted_risk"),
    ] {
        outcome(
            &mut fx,
            &global(),
            ALICE,
            &case,
            item_id(&case, kind),
            Some(OutcomeChange {
                outcome: decision,
                note: Some("decided"),
            }),
        )
        .await
        .unwrap();
    }
    let ready = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &CaseChange {
            accepted_until: Some(Utc::now() + Duration::days(90)),
            ..closing(&ready, "accepted_risk", "Accepted")
        },
    )
    .await
    .unwrap();
    // The alarm and the finding are plainly still there.
    assert_eq!(
        cases::reopen_due(&mut fx.console, Utc::now())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        fetch(&fx, &global(), ALICE, &case)
            .await
            .unwrap()
            .summary
            .status,
        "closed"
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn a_case_is_watched_for_returning_evidence_for_a_limited_time() {
    let mut fx = setup().await;
    let closed = closed_on_resolved_findings(&mut fx, "Watched").await;
    fx.admin
        .batch_execute("UPDATE current_findings SET ended_at = NULL")
        .await
        .unwrap();
    let after = |days: i64| Utc::now() + Duration::days(days);
    assert_eq!(
        cases::reopen_evidence_returned(&mut fx.console, after(cases::EVIDENCE_WATCH_DAYS + 1))
            .await
            .unwrap(),
        0,
        "closed too long ago"
    );
    assert_eq!(
        fetch(&fx, &global(), ALICE, &closed)
            .await
            .unwrap()
            .summary
            .status,
        "closed"
    );
    assert_eq!(
        cases::reopen_evidence_returned(&mut fx.console, after(cases::EVIDENCE_WATCH_DAYS - 1))
            .await
            .unwrap(),
        1
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn a_case_stays_closed_when_a_returning_item_joined_another_open_case() {
    let mut fx = setup().await;
    let closed = closed_on_resolved_findings(&mut fx, "Taken").await;
    // Closing freed web-01's finding; someone else takes it, and it returns.
    let web_finding = finding(WEB);
    let other = open_case(
        &mut fx.console,
        &global(),
        DAVE,
        "Other",
        &[("compliance_finding", &web_finding)],
    )
    .await;
    fx.admin
        .batch_execute("UPDATE current_findings SET ended_at = NULL")
        .await
        .unwrap();
    assert_eq!(
        cases::reopen_evidence_returned(&mut fx.console, Utc::now())
            .await
            .unwrap(),
        0
    );
    let unchanged = fetch(&fx, &global(), ALICE, &closed).await.unwrap();
    assert_eq!(unchanged.summary.status, "closed");
    assert!(unchanged.items.iter().all(|i| !i.active));
    assert_eq!(
        fetch(&fx, &global(), DAVE, &other)
            .await
            .unwrap()
            .summary
            .status,
        "open"
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn reopening_on_evidence_names_no_item_the_viewer_cannot_see() {
    let mut fx = setup().await;
    let closed = closed_on_resolved_findings(&mut fx, "Hidden").await;
    fx.admin
        .execute(
            "UPDATE current_findings SET ended_at = NULL WHERE agent_id = $1",
            &[&DB],
        )
        .await
        .unwrap();
    assert_eq!(
        cases::reopen_evidence_returned(&mut fx.console, Utc::now())
            .await
            .unwrap(),
        1
    );
    let seen = fetch(&fx, &prod(), BOB, &closed).await.unwrap();
    assert_eq!(seen.summary.status, "open");
    let kinds: Vec<_> = seen.events.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds.last(), Some(&"reopened"), "{kinds:?}");
    assert!(
        !kinds.iter().rev().take(2).any(|k| *k == "item_outcome"),
        "the db-01 item's entry is not his to see"
    );
    let rendered = format!("{seen:?}");
    assert!(!rendered.contains(DB), "{rendered}");
    // Someone who sees it all gets the item's entry.
    let all = fetch(&fx, &global(), ALICE, &closed).await.unwrap();
    assert!(
        all.events
            .iter()
            .any(|e| e.kind == "item_outcome" && e.detail["to"].is_null())
    );
    fx.db.drop().await;
}
