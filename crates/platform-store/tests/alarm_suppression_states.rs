//! Suppression states, where and duration (roles spec §8), run as the
//! `openvibes-console` role.

mod common;
mod suppression_fixture;

use chrono::{DateTime, Duration, SubsecRound, Utc};
use common::TestDb;
use platform_store::{
    Client,
    alarm_suppressions::{
        self as store, Change, ListFilter, Request, State, Suppression, What, Where,
    },
    console_read::AgentScope,
    console_settings,
};
use suppression_fixture::{AGENT, as_console, setup};

const GLOBAL: AgentScope = AgentScope::Global;

fn now() -> DateTime<Utc> {
    Utc::now().trunc_subsecs(0)
}

fn ask(alarm: i64, place: Where, for_days: Option<i32>) -> Request<'static> {
    Request {
        alarm_row_id: alarm,
        what: What::Program,
        place,
        for_days,
        reason: "noisy",
    }
}

fn done(change: Change) -> Suppression {
    match change {
        Change::Done(suppression) => suppression,
        other => panic!("expected a suppression, got {other:?}"),
    }
}

async fn approval(db: &TestDb, on: bool) {
    let mut admin = db.pool.get().await.unwrap();
    let value = serde_json::json!(on);
    console_settings::set(
        &mut admin,
        "suppressions.require_approval",
        &value,
        "admin",
        now(),
    )
    .await
    .unwrap();
}

/// The source alarm's state and `suppressed_by`.
async fn alarm_state(db: &TestDb, alarm: i64) -> (String, Option<i64>) {
    let admin = db.pool.get().await.unwrap();
    let row = admin
        .query_one(
            "SELECT state, suppressed_by FROM alarms WHERE id = $1",
            &[&alarm],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1))
}

async fn audited(db: &TestDb, action: &str) -> i64 {
    let admin = db.pool.get().await.unwrap();
    admin
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = $1",
            &[&action],
        )
        .await
        .unwrap()
        .get(0)
}

async fn waiting(
    db: &TestDb,
    client: &mut Client,
    alarm: i64,
    for_days: Option<i32>,
) -> Suppression {
    approval(db, true).await;
    let request = ask(alarm, Where::All, for_days);
    done(
        store::request(client, &GLOBAL, &request, "alice", now())
            .await
            .unwrap(),
    )
}

async fn listed(client: &Client, alarm: i64) -> Vec<Suppression> {
    let filter = ListFilter {
        state: None,
        alarm_id: Some(alarm),
    };
    store::list(client, &GLOBAL, &filter, now()).await.unwrap()
}

#[tokio::test]
async fn request_is_active_at_once_without_approval() {
    let (db, alarm) = setup().await;
    let mut client = as_console(&db).await;
    let now = now();
    let s = done(
        store::request(
            &mut client,
            &GLOBAL,
            &ask(alarm, Where::All, Some(7)),
            "alice",
            now,
        )
        .await
        .unwrap(),
    );
    assert_eq!(s.state, State::Active);
    assert_eq!(s.activated_at, Some(now));
    assert_eq!(s.expires_at, Some(now + Duration::days(7)));
    assert_eq!(s.alarm_id, Some(alarm));
    assert_eq!(
        alarm_state(&db, alarm).await,
        ("false_positive".into(), Some(s.id))
    );
    let admin = db.pool.get().await.unwrap();
    let history: i64 = admin
        .query_one(
            "SELECT count(*) FROM alarm_triage_history WHERE alarm_row_id = $1 AND to_state = 'false_positive'",
            &[&alarm],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(history, 1, "the close is in the alarm's history");
    assert_eq!(audited(&db, "alarm.suppression.created").await, 1);
    drop((client, admin));
    db.drop().await;
}

#[tokio::test]
async fn request_waits_with_approval_on() {
    let (db, alarm) = setup().await;
    let mut client = as_console(&db).await;
    let s = waiting(&db, &mut client, alarm, Some(7)).await;
    assert_eq!(s.state, State::Waiting);
    assert_eq!((s.activated_at, s.expires_at), (None, None));
    assert_eq!(alarm_state(&db, alarm).await, ("open".into(), None));
    assert_eq!(audited(&db, "alarm.suppression.requested").await, 1);
    assert_eq!(audited(&db, "alarm.suppression.created").await, 0);
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn approving_starts_the_period() {
    let (db, alarm) = setup().await;
    let mut client = as_console(&db).await;
    let s = waiting(&db, &mut client, alarm, Some(30)).await;
    let later = now() + Duration::hours(1);
    let s = done(
        store::decide(&mut client, &GLOBAL, s.id, true, None, "bob", later)
            .await
            .unwrap(),
    );
    assert_eq!(s.state, State::Active);
    assert_eq!(s.activated_at, Some(later));
    assert_eq!(s.expires_at, Some(later + Duration::days(30)));
    assert_eq!(
        (s.decided_by.as_deref(), s.decided_at),
        (Some("bob"), Some(later))
    );
    assert_eq!(
        alarm_state(&db, alarm).await,
        ("false_positive".into(), Some(s.id))
    );
    assert_eq!(audited(&db, "alarm.suppression.approved").await, 1);
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn requester_cannot_decide_own() {
    let (db, alarm) = setup().await;
    let mut client = as_console(&db).await;
    let s = waiting(&db, &mut client, alarm, None).await;
    for approve in [true, false] {
        let change = store::decide(
            &mut client,
            &GLOBAL,
            s.id,
            approve,
            Some("mine"),
            "alice",
            now(),
        );
        assert_eq!(change.await.unwrap(), Change::OwnRequest);
    }
    assert_eq!(listed(&client, alarm).await, [s]);
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn rejecting_needs_a_reason() {
    let (db, alarm) = setup().await;
    let mut client = as_console(&db).await;
    let s = waiting(&db, &mut client, alarm, None).await;
    for reason in [None, Some(" ")] {
        let change = store::decide(&mut client, &GLOBAL, s.id, false, reason, "bob", now());
        assert_eq!(change.await.unwrap(), Change::Invalid("reason".into()));
    }
    let change = store::decide(
        &mut client,
        &GLOBAL,
        s.id,
        false,
        Some("not this host"),
        "bob",
        now(),
    );
    let s = done(change.await.unwrap());
    assert_eq!(s.state, State::Rejected);
    assert_eq!(s.decision_reason.as_deref(), Some("not this host"));
    assert_eq!(alarm_state(&db, alarm).await, ("open".into(), None));
    assert_eq!(audited(&db, "alarm.suppression.rejected").await, 1);
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn only_waiting_can_be_decided_or_withdrawn() {
    let (db, alarm) = setup().await;
    let mut client = as_console(&db).await;
    let s = done(
        store::request(
            &mut client,
            &GLOBAL,
            &ask(alarm, Where::All, None),
            "alice",
            now(),
        )
        .await
        .unwrap(),
    );
    let change = store::decide(&mut client, &GLOBAL, s.id, true, None, "bob", now());
    assert_eq!(change.await.unwrap(), Change::WrongState);
    let change = store::withdraw(&mut client, s.id, "alice", now());
    assert_eq!(change.await.unwrap(), Change::WrongState);
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn withdraw_is_the_requesters_own() {
    let (db, alarm) = setup().await;
    let mut client = as_console(&db).await;
    let s = waiting(&db, &mut client, alarm, None).await;
    let change = store::withdraw(&mut client, s.id, "bob", now());
    assert_eq!(
        change.await.unwrap(),
        Change::NotFound,
        "not bob's to withdraw"
    );
    let s = done(
        store::withdraw(&mut client, s.id, "alice", now())
            .await
            .unwrap(),
    );
    assert_eq!(s.state, State::Withdrawn);
    assert_eq!(s.decided_by.as_deref(), Some("alice"));
    assert!(
        listed(&client, alarm).await.is_empty(),
        "withdrawn lives in the audit log"
    );
    assert_eq!(audited(&db, "alarm.suppression.withdrawn").await, 1);
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn turning_approval_off_leaves_waiting_requests() {
    let (db, alarm) = setup().await;
    let mut client = as_console(&db).await;
    let s = waiting(&db, &mut client, alarm, None).await;
    approval(&db, false).await;
    assert_eq!(listed(&client, alarm).await[0].state, State::Waiting);
    let decided = done(
        store::decide(&mut client, &GLOBAL, s.id, true, None, "bob", now())
            .await
            .unwrap(),
    );
    assert_eq!(decided.state, State::Active);
    let fresh = done(
        store::request(
            &mut client,
            &GLOBAL,
            &ask(alarm, Where::Host, None),
            "carol",
            now(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(fresh.state, State::Active);
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn where_must_be_in_reach() {
    const OTHER: &str = "agent.00000000-0000-4000-8000-000000000402";
    let (db, alarm) = setup().await;
    let admin = db.pool.get().await.unwrap();
    common::seed_agent(&admin, OTHER).await;
    let lab = common::manual_group(&admin, "lab", &[OTHER]).await;
    let linux = common::rule_group(&admin, "linux", &[("os_family", false, &["linux"])]).await;
    let mine = common::manual_group(&admin, "mine", &[AGENT]).await;
    let mut client = as_console(&db).await;
    let scoped = AgentScope::AssetGroups(vec![lab.clone()]);
    let mut try_it = async |scope: &AgentScope, place: Where| {
        store::request(&mut client, scope, &ask(alarm, place, None), "sam", now())
            .await
            .unwrap()
    };
    assert_eq!(
        try_it(&scoped, Where::Group(linux.clone())).await,
        Change::NotInReach
    );
    assert_eq!(try_it(&scoped, Where::All).await, Change::NeedsGlobalScope);
    assert_eq!(
        try_it(&scoped, Where::Host).await,
        Change::NotFound,
        "the alarm is outside lab"
    );
    let unknown = Where::Group("00000000-0000-4000-8000-0000000000ff".into());
    assert_eq!(
        try_it(&GLOBAL, unknown).await,
        Change::Invalid("group".into())
    );
    let s = done(try_it(&GLOBAL, Where::Group(linux.clone())).await);
    assert_eq!(
        (s.host_group_id, s.host_group_name.as_deref()),
        (Some(linux), Some("linux"))
    );
    assert_eq!(s.agent_id, None);
    let s = done(
        try_it(
            &AgentScope::AssetGroups(vec![mine.clone()]),
            Where::Group(mine),
        )
        .await,
    );
    assert_eq!(s.state, State::Active);
    drop((client, admin));
    db.drop().await;
}

#[tokio::test]
async fn a_removed_suppression_keeps_removed_at_in_step() {
    let (db, alarm) = setup().await;
    let mut client = as_console(&db).await;
    let s = done(
        store::request(
            &mut client,
            &GLOBAL,
            &ask(alarm, Where::All, None),
            "alice",
            now(),
        )
        .await
        .unwrap(),
    );
    let removed = done(
        store::remove(&mut client, &GLOBAL, s.id, "bob", now())
            .await
            .unwrap(),
    );
    assert_eq!(removed.state, State::Removed);
    let admin = db.pool.get().await.unwrap();
    let row = admin
        .query_one(
            "SELECT removed_at IS NOT NULL, removed_by FROM alarm_suppressions WHERE id = $1",
            &[&s.id],
        )
        .await
        .unwrap();
    assert_eq!(
        (row.get::<_, bool>(0), row.get::<_, Option<String>>(1)),
        (true, Some("bob".into()))
    );
    assert!(listed(&client, alarm).await.is_empty());
    assert_eq!(audited(&db, "alarm.suppression.removed").await, 1);
    drop((client, admin));
    db.drop().await;
}

#[tokio::test]
async fn list_shows_expired_as_expired() {
    let (db, alarm) = setup().await;
    let mut client = as_console(&db).await;
    let then = now() - Duration::days(8);
    let s = done(
        store::request(
            &mut client,
            &GLOBAL,
            &ask(alarm, Where::All, Some(7)),
            "alice",
            then,
        )
        .await
        .unwrap(),
    );
    assert!(!s.expired, "not expired when made");
    let filter = ListFilter {
        state: Some(State::Active),
        alarm_id: None,
    };
    let active = store::list(&client, &GLOBAL, &filter, now()).await.unwrap();
    assert_eq!(active.len(), 1, "active includes expired");
    assert!(active[0].expired);
    assert_eq!(active[0].state, State::Active);
    drop(client);
    db.drop().await;
}
