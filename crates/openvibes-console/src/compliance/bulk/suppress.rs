//! Bulk "Suppress…" on alarms.

use axum::response::Response;
use chrono::{DateTime, Utc};
use platform_store::{
    alarm_suppressions::{self, Change, Request, State as SuppressionState, What, Where},
    bulk_triage::BulkResult,
    console_read::AgentScope,
};

use super::respond;
use crate::access::guard::unavailable_auth;

/// A rule set, rule and program, and the selected alarms of it.
type Group = ((String, String, Option<String>), Vec<i64>);

/// One `program` suppression per distinct rule and program among the
/// selected alarms; activation closes every selected alarm of that rule
/// and program, later ones close as they arrive. With approval on each
/// waits and its alarms are skipped as requested.
pub(super) async fn suppress(
    client: &mut platform_store::Client,
    scope: &AgentScope,
    user_id: &str,
    ids: &[i64],
    note: &str,
    now: DateTime<Utc>,
) -> Response {
    let Ok(rows) = client
        .query(
            "SELECT id, rule_set_id, rule_id, process->>'exe' FROM alarms
             WHERE id = ANY($1) AND source = 'agent' ORDER BY id",
            &[&ids],
        )
        .await
    else {
        return unavailable_auth();
    };
    // The lowest id of each rule and program is the suppression's source.
    let mut groups: Vec<Group> = Vec::new();
    for row in &rows {
        let key = (row.get(1), row.get(2), row.get(3));
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, members)) => members.push(row.get(0)),
            None => groups.push((key, vec![row.get(0)])),
        }
    }
    let mut result = BulkResult::default();
    for (_, members) in &groups {
        let request = Request {
            alarm_row_id: members[0],
            what: What::Program,
            place: Where::All,
            for_days: None,
            reason: note,
        };
        let made = alarm_suppressions::request(client, scope, &request, user_id, now).await;
        let skipped = match made {
            Err(_) => return unavailable_auth(),
            // Approval on: requested, not yet quieting anything.
            Ok(Change::Done(made)) if made.state == SuppressionState::Waiting => {
                "Suppression requested, waiting for approval"
            }
            Ok(Change::Done(made)) => {
                let closed = alarm_suppressions::close_covered(
                    client, scope, made.id, members, user_id, now,
                )
                .await;
                let Ok(closed) = closed else {
                    return unavailable_auth();
                };
                result.changed += closed.len();
                for id in members.iter().filter(|id| !closed.contains(id)) {
                    result
                        .skipped
                        .push((id.to_string(), "not open, or out of scope"));
                }
                continue;
            }
            Ok(Change::NeedsGlobalScope) => "program suppressions need global scope",
            Ok(Change::NotInReach) => "outside your suppress reach",
            Ok(Change::Invalid(field)) if field == "reason" => {
                "the note must be 1 to 4,000 characters"
            }
            Ok(Change::Invalid(_)) => "this alarm can't be suppressed",
            Ok(Change::NotFound | Change::WrongState | Change::OwnRequest) => {
                "not found or out of scope"
            }
        };
        for id in members {
            result.skipped.push((id.to_string(), skipped));
        }
    }
    respond(result, None)
}
