//! Triage history for the detail view's History tab (triage v2, spec
//! `2026-10-10-bulk-triage-design.md` §5): the state changes and notes of
//! one alarm, or of a compliance finding or a vulnerability across the
//! hosts in the caller's scope, newest first.

use chrono::{DateTime, Utc};

use crate::{
    Client, StoreError,
    console_read::{AgentScope, agent_visibility},
};

/// Most events one History tab shows.
pub const LIMIT: i64 = 200;

/// One triage change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriageEvent {
    /// The host.
    pub agent_id: String,
    /// Its name, when known.
    pub hostname: Option<String>,
    /// The state before; none for the first triage.
    pub from_state: Option<String>,
    /// The state after.
    pub to_state: String,
    /// The note given.
    pub note: Option<String>,
    /// When.
    pub changed_at: DateTime<Utc>,
    /// Who (a user id, or `migration`/`system`).
    pub changed_by: String,
}

/// Whose history.
#[derive(Clone, Copy, Debug)]
pub enum Subject<'a> {
    /// One alarm, by row id.
    Alarm(i64),
    /// A compliance rule across its hosts.
    Finding {
        /// Rule set.
        rule_set_id: &'a str,
        /// Rule.
        rule_id: &'a str,
    },
    /// An advisory across its hosts.
    Vulnerability(&'a str),
}

/// The subject's triage changes on hosts in `scope`, newest first, at most
/// [`LIMIT`].
pub async fn events(
    client: &Client,
    scope: &AgentScope,
    subject: Subject<'_>,
) -> Result<Vec<TriageEvent>, StoreError> {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let (global, groups) = (scope.is_global(), scope.group_ids());
    let columns =
        "a.agent_id, a.hostname, h.from_state, h.to_state, h.note, h.changed_at, h.changed_by";
    let rows = match subject {
        Subject::Alarm(id) => {
            client
                .query(
                    &format!(
                        "SELECT {columns} FROM alarm_triage_history h
                         JOIN alarms x ON x.id = h.alarm_row_id AND x.first_seen_day = h.first_seen_day
                         JOIN agents a ON a.agent_id = x.agent_id
                         WHERE h.alarm_row_id = $3 AND {visible}
                         ORDER BY h.event_id DESC LIMIT {LIMIT}"
                    ),
                    &[&global, &groups, &id],
                )
                .await?
        }
        Subject::Finding {
            rule_set_id,
            rule_id,
        } => {
            client
                .query(
                    &format!(
                        "SELECT {columns} FROM console_finding_triage_history h
                         JOIN agents a ON a.agent_id = h.agent_id
                         WHERE h.rule_set_id = $3 AND h.rule_id = $4 AND {visible}
                         ORDER BY h.event_id DESC LIMIT {LIMIT}"
                    ),
                    &[&global, &groups, &rule_set_id, &rule_id],
                )
                .await?
        }
        Subject::Vulnerability(advisory_id) => {
            client
                .query(
                    &format!(
                        "SELECT {columns} FROM vulnerability_triage_history h
                         JOIN agents a ON a.agent_id = h.agent_id
                         WHERE h.advisory_id = $3 AND {visible}
                         ORDER BY h.event_id DESC LIMIT {LIMIT}"
                    ),
                    &[&global, &groups, &advisory_id],
                )
                .await?
        }
    };
    Ok(rows
        .iter()
        .map(|r| TriageEvent {
            agent_id: r.get(0),
            hostname: r.get(1),
            from_state: r.get(2),
            to_state: r.get(3),
            note: r.get(4),
            changed_at: r.get(5),
            changed_by: r.get(6),
        })
        .collect())
}
