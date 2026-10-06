//! Live presence: every heartbeat is recorded, so an agent is online (and
//! offline) within the 3-minute threshold, not the 5-minute write throttle.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use platform_store::{
    agents::{self, Filter},
    console_read::{self, AgentState},
    ingest,
};

const AGENT: &str = "agent.00000000-0000-4000-8000-000000000001";

#[tokio::test]
async fn heartbeats_keep_an_agent_online_between_saved_writes() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    client
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, scanner_version)
             VALUES ($1, 'active', $2, $3, '0.1.0')",
            &[
                &AGENT,
                &(now - Duration::days(1)),
                &(now - Duration::minutes(4)),
            ],
        )
        .await
        .unwrap();
    // The saved time alone is past the threshold: offline.
    let before = console_read::agent(&client, AGENT, now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.state, AgentState::Stale);
    assert_eq!(
        console_read::online_fingerprint(&client, now)
            .await
            .unwrap()
            .0,
        0
    );

    // A heartbeat inside the write throttle saves nothing to `agents` ...
    let wrote = ingest::heartbeat(
        &client,
        AGENT,
        "0.1.0",
        None,
        &[],
        None,
        now - Duration::minutes(1),
    )
    .await
    .unwrap();
    assert!(!wrote);
    // ... yet the agent reads as online, with the heartbeat's time.
    let after = console_read::agent(&client, AGENT, now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.state, AgentState::Active);
    assert_eq!(
        console_read::online_fingerprint(&client, now)
            .await
            .unwrap()
            .0,
        1
    );
    assert!(
        agents::list(&client, Filter::Offline, now)
            .await
            .unwrap()
            .is_empty()
    );
    let summary = console_read::agent_summary(&client, now).await.unwrap();
    assert_eq!((summary.active, summary.stale), (1, 0));

    // Silence past three minutes: offline again, and the fingerprint moves.
    let later = now + Duration::minutes(3);
    let gone = console_read::agent(&client, AGENT, later)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(gone.state, AgentState::Stale);
    assert_eq!(
        console_read::online_fingerprint(&client, later)
            .await
            .unwrap()
            .0,
        0
    );

    // An older heartbeat never moves presence backwards.
    ingest::heartbeat(
        &client,
        AGENT,
        "0.1.0",
        None,
        &[],
        None,
        now - Duration::minutes(2),
    )
    .await
    .unwrap();
    let seen: chrono::DateTime<Utc> = client
        .query_one(
            "SELECT seen_at FROM agent_presence WHERE agent_id = $1",
            &[&AGENT],
        )
        .await
        .unwrap()
        .get(0);
    assert!(seen > now - Duration::minutes(2));
    drop(client);
    db.drop().await;
}
