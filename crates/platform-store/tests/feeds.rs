mod common;

use chrono::{Duration, Utc};
use platform_store::feeds::{self, Accepted, AppliedFile, TrustAdded};

const KEY: [u8; 32] = [7; 32];

fn accepted(sequence: u64, digest: u8) -> Accepted<'static> {
    let now = Utc::now();
    Accepted {
        feed_id: "site",
        key_id: "k1",
        sequence,
        manifest_digest: [digest; 32],
        created_at: now,
        expires_at: now + Duration::days(7),
        origin: "bundle",
    }
}

#[tokio::test]
async fn trust_keys_are_added_once_and_ids_are_never_reused() {
    let (db, client) = common::migrated().await;
    let now = Utc::now();
    assert_eq!(
        feeds::add_trust_key(&client, "site", "k1", KEY, now)
            .await
            .unwrap(),
        TrustAdded::Added
    );
    assert_eq!(
        feeds::add_trust_key(&client, "site", "k1", KEY, now)
            .await
            .unwrap(),
        TrustAdded::AlreadyTrusted
    );
    assert_eq!(
        feeds::add_trust_key(&client, "site", "k1", [8; 32], now)
            .await
            .unwrap(),
        TrustAdded::Conflict
    );
    assert_eq!(feeds::active_trust_keys(&client).await.unwrap().len(), 1);
    assert!(
        feeds::remove_trust_key(&client, "site", "k1", now)
            .await
            .unwrap()
    );
    assert!(
        !feeds::remove_trust_key(&client, "site", "k1", now)
            .await
            .unwrap()
    );
    assert!(feeds::active_trust_keys(&client).await.unwrap().is_empty());
    // The removed id stays taken, even for the same key.
    assert_eq!(
        feeds::add_trust_key(&client, "site", "k1", KEY, now)
            .await
            .unwrap(),
        TrustAdded::Conflict
    );
    let all = feeds::trust_keys(&client, Some("site")).await.unwrap();
    assert_eq!((all.len(), all[0].removed_at.is_some()), (1, true));
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn a_lower_sequence_never_replaces_the_accepted_one() {
    let (db, client) = common::migrated().await;
    let now = Utc::now();
    feeds::add_trust_key(&client, "site", "k1", KEY, now)
        .await
        .unwrap();
    assert!(
        feeds::record_accepted(&client, &accepted(5, 1), now)
            .await
            .unwrap()
    );
    assert!(
        !feeds::record_accepted(&client, &accepted(4, 2), now)
            .await
            .unwrap()
    );
    let states = feeds::feed_states(&client).await.unwrap();
    assert_eq!(
        (states[0].sequence, states[0].manifest_digest),
        (5, [1; 32])
    );
    // The same sequence with another digest keeps the stored one; the same
    // manifest again is fine.
    assert!(
        !feeds::record_accepted(&client, &accepted(5, 9), now)
            .await
            .unwrap()
    );
    assert!(
        feeds::record_accepted(&client, &accepted(5, 1), now)
            .await
            .unwrap()
    );
    assert_eq!(
        feeds::feed_states(&client).await.unwrap()[0].manifest_digest,
        [1; 32]
    );
    assert!(
        feeds::record_accepted(&client, &accepted(6, 3), now)
            .await
            .unwrap()
    );
    assert_eq!(feeds::feed_states(&client).await.unwrap()[0].sequence, 6);
    // Only a trusted key can have state.
    let mut other = accepted(1, 1);
    other.key_id = "unknown";
    assert!(feeds::record_accepted(&client, &other, now).await.is_err());
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn applied_files_are_kept_per_source_and_kind() {
    let (db, client) = common::migrated().await;
    let now = Utc::now();
    let file = |sha: u8, age: i64| AppliedFile {
        source: "kev".into(),
        kind: "kev".into(),
        name: "kev.json".into(),
        sha256: [sha; 32],
        fetched_at: now - Duration::hours(age),
    };
    assert!(
        feeds::record_file(&client, &file(1, 5), "site", "k1", 1, now)
            .await
            .unwrap()
    );
    assert!(
        feeds::record_file(&client, &file(2, 1), "site", "k1", 2, now)
            .await
            .unwrap()
    );
    // An older fetch never replaces a newer one.
    assert!(
        !feeds::record_file(&client, &file(3, 9), "site", "k1", 3, now)
            .await
            .unwrap()
    );
    let files = feeds::applied_files(&client).await.unwrap();
    assert_eq!((files.len(), files[0].sha256), (1, [2; 32]));
    // Another file name of the same source and kind is its own row.
    let mut year = file(4, 1);
    year.name = "kev-2.json".into();
    feeds::record_file(&client, &year, "site", "k1", 3, now)
        .await
        .unwrap();
    assert_eq!(feeds::applied_files(&client).await.unwrap().len(), 2);
    drop(client);
    db.drop().await;
}

/// The real role, not the superuser: the vulnerability service reads the
/// keys and keeps the state and applied files current, but cannot trust a key.
#[tokio::test]
async fn the_vulnerability_role_can_do_exactly_what_the_grants_say() {
    let (db, client) = common::migrated().await;
    let now = Utc::now();
    feeds::add_trust_key(&client, "site", "k1", KEY, now)
        .await
        .unwrap();
    client
        .batch_execute("SET ROLE \"openvibes-vulns\"")
        .await
        .unwrap();
    assert_eq!(feeds::active_trust_keys(&client).await.unwrap().len(), 1);
    assert!(
        feeds::record_accepted(&client, &accepted(1, 1), now)
            .await
            .unwrap()
    );
    assert!(
        feeds::record_accepted(&client, &accepted(2, 2), now)
            .await
            .unwrap()
    );
    let file = AppliedFile {
        source: "kev".into(),
        kind: "kev".into(),
        name: "kev.json".into(),
        sha256: [1; 32],
        fetched_at: now,
    };
    feeds::record_file(&client, &file, "site", "k1", 2, now)
        .await
        .unwrap();
    feeds::record_file(&client, &file, "site", "k1", 3, now)
        .await
        .unwrap();
    assert_eq!(feeds::feed_states(&client).await.unwrap().len(), 1);
    // Marking a kind stale changes its hashes only; the record stays.
    assert_eq!(feeds::mark_stale(&client, "kev").await.unwrap(), 1);
    assert_eq!(feeds::mark_stale(&client, "nvd").await.unwrap(), 0);
    let applied = feeds::applied_files(&client).await.unwrap();
    assert_eq!((applied.len(), applied[0].sha256), (1, [0; 32]));
    assert!(
        feeds::add_trust_key(&client, "site", "k2", KEY, now)
            .await
            .is_err()
    );
    assert!(
        feeds::remove_trust_key(&client, "site", "k1", now)
            .await
            .is_err()
    );
    client.batch_execute("RESET ROLE").await.unwrap();
    drop(client);
    db.drop().await;
}
