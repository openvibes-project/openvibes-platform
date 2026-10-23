//! The bulk cap counts the pairs a vulnerability action changes: a CVE row's
//! closed pairs are not expanded, so a widespread, mostly closed advisory
//! still closes or assigns its few open pairs.

mod common;

use chrono::Utc;
use platform_store::{
    bulk_triage::{self as bulk, BulkChange, MAX_ITEMS},
    console_read::AgentScope,
};

const FIRST: &str = "agent.00000000-0000-4000-8000-000000000001";

#[tokio::test]
async fn closed_pairs_do_not_count_toward_the_cap() {
    let (db, mut c) = common::migrated().await;
    // MAX_ITEMS + 1 mitigated pairs and three open ones (one with no triage
    // row, one open, one expired acceptance) of one advisory.
    let closed = MAX_ITEMS + 1;
    c.batch_execute(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at)
         SELECT 'agent.00000000-0000-4000-8000-' || lpad(n::text, 12, '0'), 'active', now(), 'h-' || n, now() FROM generate_series(1, {closed} + 3) n;
         INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
         VALUES ('WIDE-1', 'fedora', 'fedora', '44', 'important', 'wide', 'https://x');
         INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, fixed_at, last_evaluated_at)
         SELECT agent_id, 'WIDE-1', '[]', now(), NULL, now() FROM agents;
         INSERT INTO vulnerability_triage (agent_id, advisory_id, state, note, accepted_until, version, updated_at, updated_by)
         SELECT 'agent.00000000-0000-4000-8000-' || lpad(n::text, 12, '0'), 'WIDE-1', 'mitigated', 'n', NULL::timestamptz, 1, now(), 't' FROM generate_series(1, {closed}) n
         UNION ALL SELECT 'agent.00000000-0000-4000-8000-' || lpad(({closed} + 1)::text, 12, '0'), 'WIDE-1', 'open', NULL, NULL, 1, now(), 't'
         UNION ALL SELECT 'agent.00000000-0000-4000-8000-' || lpad(({closed} + 2)::text, 12, '0'), 'WIDE-1', 'accepted_risk', 'n', now() - interval '1 day', 1, now(), 't';"
    ))
    .await
    .unwrap();
    let wide = [("WIDE-1".to_owned(), None)];
    let close = BulkChange::State {
        state: "mitigated",
        note: Some("patched"),
        accepted_until: None,
    };
    let now = Utc::now();
    let done = bulk::vulnerabilities(&mut c, &AgentScope::Global, &wide, close, "ann", now)
        .await
        .unwrap()
        .expect("only the open pairs count toward the cap");
    assert_eq!((done.changed, done.skipped.len()), (3, 0), "{done:?}");
    // Nothing is open now: the advisory says so, and a list row (open_only)
    // on one closed host does too.
    let done = bulk::vulnerabilities(&mut c, &AgentScope::Global, &wide, close, "ann", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(done.skipped, [("WIDE-1".to_owned(), "not open")]);
    let one = [("WIDE-1".to_owned(), Some(FIRST.to_owned()))];
    let assign = BulkChange::Assign(None);
    let done = bulk::vulnerabilities_open_only(
        &mut c,
        &AgentScope::Global,
        &one,
        &[true],
        assign,
        "ann",
        now,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(done.skipped, [(format!("{FIRST}/WIDE-1"), "not open")]);
    // A reopen still expands every pair, so it is still capped.
    let reopen = BulkChange::State {
        state: "open",
        note: None,
        accepted_until: None,
    };
    let refused = bulk::vulnerabilities(&mut c, &AgentScope::Global, &wide, reopen, "ann", now)
        .await
        .unwrap();
    assert_eq!(refused, Err(bulk::BulkRefusal::Count));
    drop(c);
    db.drop().await;
}
