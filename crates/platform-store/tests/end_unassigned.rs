//! The agent reports a set `not_assigned` (spec 2026-10-14 §5, user decision
//! 2026-10-14): its open matches end, triage is never touched, and a history
//! entry says why. Run as the `openvibes-ingest` role.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use platform_store::{
    Client,
    finding_changes::{NOT_ASSIGNED_NOTE, end_unassigned},
};

const L1: &str = "hardening-linux-l1";
const A: &str = "agent.00000000-0000-4000-8000-000000000001";
const B: &str = "agent.00000000-0000-4000-8000-000000000002";

async fn setup() -> (TestDb, Client, Client) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    for agent in [A, B] {
        admin
            .execute(
                "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', now())",
                &[&agent],
            )
            .await
            .unwrap();
    }
    let ingest = db.pool.get().await.unwrap();
    ingest
        .batch_execute("SET ROLE \"openvibes-ingest\"")
        .await
        .unwrap();
    (db, admin, ingest)
}

/// An open P13 match of `set`/`rule` on `agent`.
async fn open(admin: &Client, agent: &str, set: &str, rule: &str) {
    admin
        .execute(
            "INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id,
                 rule_version, severity, first_observed_at, last_observed_at, last_observed_day,
                 scan_id, confidence, message, evidence, received_at, origin, authenticated, source)
             VALUES ($1, $2, $3, 'finding.seed', 1, 'low', now() - interval '1 hour',
                 now() - interval '1 hour', current_date, 'scan.1', 100, 'm', '{}', now(),
                 'online', true, 'changes')",
            &[&agent, &set, &rule],
        )
        .await
        .unwrap();
}

/// (match ended, triage state or "none", history notes) of one finding.
async fn state(admin: &Client, agent: &str, set: &str, rule: &str) -> (bool, String, Vec<String>) {
    let row = admin
        .query_one(
            "SELECT c.ended_at IS NOT NULL, COALESCE(t.state, 'none'),
                    ARRAY(SELECT h.from_state || '>' || h.to_state || ' ' || h.changed_by || ': ' || h.note
                          FROM console_finding_triage_history h
                          WHERE (h.agent_id, h.rule_set_id, h.rule_id) = (c.agent_id, c.rule_set_id, c.rule_id)
                          ORDER BY h.event_id)
             FROM current_findings c
             LEFT JOIN console_finding_triage t USING (agent_id, rule_set_id, rule_id)
             WHERE c.agent_id = $1 AND c.rule_set_id = $2 AND c.rule_id = $3",
            &[&agent, &set, &rule],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

fn note(state: &str) -> Vec<String> {
    vec![format!("{state}>{state} system: {NOT_ASSIGNED_NOTE}")]
}

fn untouched() -> (bool, String, Vec<String>) {
    (false, "none".into(), Vec::new())
}

#[tokio::test]
async fn ends_only_this_hosts_open_matches_of_the_set() {
    let (db, admin, mut ingest) = setup().await;
    open(&admin, A, L1, "harden.ssh.x").await;
    open(&admin, A, L1, "harden.ssh.y").await;
    open(&admin, A, "hardening-linux-l2", "harden.audit.z").await;
    open(&admin, A, "baseline", "base.rule").await;
    open(&admin, B, L1, "harden.ssh.x").await;
    let n = end_unassigned(&mut ingest, A, &[L1.to_owned()], Utc::now())
        .await
        .unwrap();
    assert_eq!(n, 2);
    // Ended, no triage row created, one history entry by the system.
    for rule in ["harden.ssh.x", "harden.ssh.y"] {
        assert_eq!(
            state(&admin, A, L1, rule).await,
            (true, "none".into(), note("open"))
        );
    }
    assert_eq!(
        state(&admin, A, "hardening-linux-l2", "harden.audit.z").await,
        untouched()
    );
    assert_eq!(state(&admin, A, "baseline", "base.rule").await, untouched());
    assert_eq!(state(&admin, B, L1, "harden.ssh.x").await, untouched());
    let audits: i64 = admin
        .query_one("SELECT count(*) FROM audit_log", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        audits, 0,
        "a match ending writes no audit row, as for any match end"
    );
    drop((admin, ingest));
    db.drop().await;
}

/// The health report ingest stored for `agent` `ago` before now, listing
/// L1 with `l1_state` (the previous heartbeat).
async fn reported(admin: &Client, agent: &str, l1_state: Option<&str>, ago: &str) {
    let health = serde_json::json!({"rule_sets": [{"id": L1, "state": l1_state}]});
    admin
        .execute(
            "UPDATE agents SET health = $2, health_at = now() - $3::text::interval
             WHERE agent_id = $1",
            &[&agent, &health, &ago],
        )
        .await
        .unwrap();
}

/// The agent ended the match itself through P13, `ago` before now.
async fn ended(admin: &Client, agent: &str, set: &str, rule: &str, ago: &str) {
    admin
        .execute(
            "UPDATE current_findings SET ended_at = now() - $4::text::interval,
                 end_approximate = false
             WHERE agent_id = $1 AND rule_set_id = $2 AND rule_id = $3",
            &[&agent, &set, &rule, &ago],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn repeated_reports_end_nothing_more() {
    let (db, admin, mut ingest) = setup().await;
    reported(&admin, A, None, "1 hour").await;
    open(&admin, A, L1, "harden.ssh.x").await;
    let sets = [L1.to_owned()];
    assert_eq!(
        end_unassigned(&mut ingest, A, &sets, Utc::now())
            .await
            .unwrap(),
        1
    );
    // Ingest stores the report; the next heartbeats say the same.
    reported(&admin, A, Some("not_assigned"), "0 seconds").await;
    for _ in 0..3 {
        assert_eq!(
            end_unassigned(&mut ingest, A, &sets, Utc::now())
                .await
                .unwrap(),
            0
        );
    }
    assert_eq!(state(&admin, A, L1, "harden.ssh.x").await.2, note("open"));
    drop((admin, ingest));
    db.drop().await;
}

#[tokio::test]
async fn a_retried_report_notes_nothing_more() {
    // The heartbeat failed after this ran, so the report was not stored and
    // the agent sends it again.
    let (db, admin, mut ingest) = setup().await;
    reported(&admin, A, None, "1 hour").await;
    open(&admin, A, L1, "harden.ssh.x").await;
    let sets = [L1.to_owned()];
    for want in [1, 0] {
        let got = end_unassigned(&mut ingest, A, &sets, Utc::now())
            .await
            .unwrap();
        assert_eq!(got, want);
    }
    assert_eq!(state(&admin, A, L1, "harden.ssh.x").await.2, note("open"));
    drop((admin, ingest));
    db.drop().await;
}

#[tokio::test]
async fn a_set_already_reported_not_assigned_ends_nothing() {
    let (db, admin, mut ingest) = setup().await;
    reported(&admin, A, Some("not_assigned"), "1 minute").await;
    open(&admin, A, L1, "harden.ssh.x").await;
    assert_eq!(
        end_unassigned(&mut ingest, A, &[L1.to_owned()], Utc::now())
            .await
            .unwrap(),
        0
    );
    assert_eq!(state(&admin, A, L1, "harden.ssh.x").await, untouched());
    drop((admin, ingest));
    db.drop().await;
}

/// The lab's sequence (task 9): the agent ends the set's matches through
/// P13 in the scan that got the 410, then reports `not_assigned`.
#[tokio::test]
async fn matches_the_agent_ended_since_the_last_report_get_the_note() {
    let (db, admin, mut ingest) = setup().await;
    reported(&admin, A, None, "1 hour").await;
    reported(&admin, B, None, "1 hour").await;
    for (agent, set, rule, ago) in [
        (A, L1, "harden.ssh.x", "1 minute"),
        (A, L1, "harden.ssh.y", "1 minute"),
        (A, L1, "harden.ssh.fixed", "2 hours"),
        (A, "hardening-linux-l2", "harden.audit.z", "1 minute"),
        (B, L1, "harden.ssh.x", "1 minute"),
    ] {
        open(&admin, agent, set, rule).await;
        ended(&admin, agent, set, rule, ago).await;
    }
    let sets = [L1.to_owned()];
    assert_eq!(
        end_unassigned(&mut ingest, A, &sets, Utc::now())
            .await
            .unwrap(),
        2
    );
    for rule in ["harden.ssh.x", "harden.ssh.y"] {
        assert_eq!(
            state(&admin, A, L1, rule).await,
            (true, "none".into(), note("open"))
        );
    }
    let kept: i64 = admin
        .query_one(
            "SELECT count(*) FROM current_findings
             WHERE ended_at < now() - interval '30 seconds' AND NOT end_approximate",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(kept, 5, "the agent's own end times are kept");
    let none = (true, "none".into(), Vec::new());
    assert_eq!(state(&admin, A, L1, "harden.ssh.fixed").await, none);
    assert_eq!(
        state(&admin, A, "hardening-linux-l2", "harden.audit.z").await,
        none
    );
    assert_eq!(state(&admin, B, L1, "harden.ssh.x").await, none);
    // The next heartbeat says the same: no new note.
    reported(&admin, A, Some("not_assigned"), "0 seconds").await;
    assert_eq!(
        end_unassigned(&mut ingest, A, &sets, Utc::now())
            .await
            .unwrap(),
        0
    );
    assert_eq!(state(&admin, A, L1, "harden.ssh.x").await.2, note("open"));
    drop((admin, ingest));
    db.drop().await;
}

#[tokio::test]
async fn a_non_assignable_set_ends_nothing() {
    let (db, admin, mut ingest) = setup().await;
    open(&admin, A, "baseline", "base.rule").await;
    assert_eq!(
        end_unassigned(&mut ingest, A, &["baseline".to_owned()], Utc::now())
            .await
            .unwrap(),
        0
    );
    assert_eq!(state(&admin, A, "baseline", "base.rule").await, untouched());
    drop((admin, ingest));
    db.drop().await;
}

#[tokio::test]
async fn triage_is_never_touched() {
    let (db, admin, mut ingest) = setup().await;
    open(&admin, A, L1, "harden.ssh.x").await;
    admin
        .execute(
            "INSERT INTO console_finding_triage (agent_id, rule_set_id, rule_id, state, rule_version,
                 note, accepted_until, version, updated_at, updated_by)
             VALUES ($1, $2, 'harden.ssh.x', 'accepted_risk', 1, 'known',
                 now() + interval '30 days', 3, now() - interval '1 day', 'analyst')",
            &[&A, &L1],
        )
        .await
        .unwrap();
    end_unassigned(
        &mut ingest,
        A,
        &[L1.to_owned()],
        Utc::now() + Duration::seconds(1),
    )
    .await
    .unwrap();
    let row = admin
        .query_one(
            "SELECT state, note, version, updated_by FROM console_finding_triage",
            &[],
        )
        .await
        .unwrap();
    let triage: (String, String, i64, String) = (row.get(0), row.get(1), row.get(2), row.get(3));
    assert_eq!(
        triage,
        ("accepted_risk".into(), "known".into(), 3, "analyst".into())
    );
    assert_eq!(
        state(&admin, A, L1, "harden.ssh.x").await.2,
        note("accepted_risk")
    );
    drop((admin, ingest));
    db.drop().await;
}

/// The migration's assignable sets are exactly the protocol's (P20 vector).
#[tokio::test]
async fn the_assignable_sets_match_the_protocol_vector() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/vectors/project-rule-sets.json");
    let vector: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut want: Vec<&str> = vector["sets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|set| set["assignable"] == true)
        .map(|set| set["id"].as_str().unwrap())
        .collect();
    want.sort_unstable();
    let (db, admin, ingest) = setup().await;
    let got: Vec<String> = admin
        .query(
            "SELECT rule_set_id FROM rule_set_assignment ORDER BY 1",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(got, want);
    drop((admin, ingest));
    db.drop().await;
}
