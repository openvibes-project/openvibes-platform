//! The bodies of the alarm suppression API, the view of one row with the
//! caller's `can_*` flags, and the answer each store outcome maps to.

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, SecondsFormat, Utc};
use platform_store::{
    Client, StoreError,
    alarm_suppressions::{self as store, Change, Facts, State, Suppression},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    FieldError, Permission, ProblemDetails,
    access::{
        auth::{PresentedCredentials, presented_credentials},
        editor::authenticated_editor,
        guard::scope_of,
        guard::unavailable_auth,
    },
    http::problem::problem_response,
};

/// Where a suppression applies.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AlarmSuppressionWhereView {
    /// `host`, `group`, `all` or `device`.
    pub kind: String,
    /// The host, for `host`.
    pub agent_id: Option<String>,
    /// Its name, for `host`.
    pub hostname: Option<String>,
    /// The group, for `group`.
    pub group_id: Option<String>,
    /// Its name, while the group exists.
    pub group_name: Option<String>,
}

/// One suppression as the caller sees it.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AlarmSuppressionView {
    /// Its id; closed alarms say "suppressed by #id".
    pub id: String,
    /// Rule set of the rule.
    pub rule_set_id: String,
    /// Rule it quiets.
    pub rule_id: String,
    /// `program`, `command`, or the legacy `host`, `device` or `signature`.
    pub what: String,
    /// Its host, group or all hosts.
    #[serde(rename = "where")]
    pub place: AlarmSuppressionWhereView,
    /// The program, for `program` and `command`.
    pub exe: Option<String>,
    /// SHA-256 of the masked args' JSON array, for `command`.
    pub args_sha256: Option<String>,
    /// 7, 30, or null (until removed).
    pub for_days: Option<i32>,
    /// `waiting`, `active`, `expired`, `rejected`, `withdrawn` or `removed`.
    pub status: String,
    /// The requester's reason.
    pub reason: String,
    /// The requester's display name.
    pub requested_by: String,
    /// When (RFC 3339).
    pub requested_at: String,
    /// Who approved, rejected or withdrew it.
    pub decided_by: Option<String>,
    /// When (RFC 3339).
    pub decided_at: Option<String>,
    /// The approver's reason (always given to reject).
    pub decision_reason: Option<String>,
    /// When it became active (RFC 3339).
    pub activated_at: Option<String>,
    /// When it stops applying (RFC 3339).
    pub expires_at: Option<String>,
    /// The source alarm; null for rows made before approvals.
    pub alarm_id: Option<String>,
    /// For a waiting row in a list: alarms of the last 7 days on hosts
    /// the caller reaches it would have closed.
    pub would_close: Option<i64>,
    /// `would_close` stopped at 10,000: there may be more.
    pub would_close_capped: bool,
    /// The caller may approve or reject it.
    pub can_decide: bool,
    /// The caller may withdraw it (their own waiting request).
    pub can_withdraw: bool,
    /// The caller may remove it.
    pub can_remove: bool,
}

/// Waiting, active (with expired) and rejected suppressions the caller
/// may read.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AlarmSuppressionList {
    /// Waiting oldest first, then active and rejected newest first.
    pub items: Vec<AlarmSuppressionView>,
}

/// A host group the suppress form offers.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AlarmSuppressionGroup {
    /// The group id.
    pub id: String,
    /// Its name.
    pub name: String,
}

/// What the suppress form may offer the caller.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AlarmSuppressionOptions {
    /// New suppressions wait for someone else's approval.
    pub require_approval: bool,
    /// The caller may suppress on all hosts.
    pub all_hosts: bool,
    /// The groups the caller's `alarms.suppress` reaches.
    pub groups: Vec<AlarmSuppressionGroup>,
}

/// What to quiet.
#[derive(Clone, Copy, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SuppressWhat {
    /// The alarm's program, with any arguments.
    Program,
    /// The alarm's exact command line.
    Command,
}

/// Where to quiet it.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum SuppressWhere {
    /// The alarm's host.
    Host,
    /// One host group.
    Group {
        /// The group id.
        group_id: String,
    },
    /// Every host (needs `alarms.suppress` on all hosts).
    All,
}

/// "Don't alarm on this again", derived from one alarm.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateAlarmSuppressionRequest {
    /// The platform's id of the alarm to derive it from.
    pub alarm_id: String,
    /// Program or command.
    pub what: SuppressWhat,
    /// Its host, a group, or all hosts.
    #[serde(rename = "where")]
    pub place: SuppressWhere,
    /// 7, 30, or null (until removed), counted from activation.
    #[serde(default)]
    pub for_days: Option<i32>,
    /// Why, 1 to 4,000 characters.
    pub reason: String,
}

/// Rejecting a waiting request.
#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RejectAlarmSuppressionRequest {
    /// Why, 1 to 4,000 characters (required).
    #[serde(default)]
    pub reason: Option<String>,
}

fn time(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// `writes`: the caller may act at all (a session, not a bearer token).
fn view(s: Suppression, facts: Facts, me: &str, writes: bool) -> AlarmSuppressionView {
    let waiting = writes && s.state == State::Waiting;
    let own = s.created_by == me;
    let status = if s.expired {
        "expired"
    } else {
        s.state.as_str()
    };
    let kind = match (s.scope.as_str(), &s.agent_id, &s.host_group_id) {
        ("device" | "signature", _, _) => "device",
        (_, Some(_), _) => "host",
        (_, _, Some(_)) => "group",
        _ => "all",
    };
    AlarmSuppressionView {
        id: s.id.to_string(),
        what: s.scope,
        place: AlarmSuppressionWhereView {
            kind: kind.into(),
            agent_id: s.agent_id,
            hostname: facts.hostname,
            group_id: s.host_group_id,
            group_name: s.host_group_name,
        },
        rule_set_id: s.rule_set_id,
        rule_id: s.rule_id,
        exe: s.exe,
        args_sha256: s.args_sha256,
        for_days: s.for_days,
        status: status.into(),
        reason: s.note,
        requested_by: facts.requested_by,
        requested_at: time(s.created_at),
        decided_by: facts.decided_by,
        decided_at: s.decided_at.map(time),
        decision_reason: s.decision_reason,
        activated_at: s.activated_at.map(time),
        expires_at: s.expires_at.map(time),
        alarm_id: s.alarm_id.map(|id| id.to_string()),
        would_close: s.would_close,
        would_close_capped: s.would_close_capped,
        can_decide: waiting && !own && facts.approvable,
        can_withdraw: waiting && own,
        can_remove: writes && s.state == State::Active && facts.removable,
    }
}

/// `rows` as caller `me` sees them, with its flags. A bearer token gets
/// every `can_*` false: every write refuses it.
pub(super) async fn views(
    client: &Client,
    headers: &HeaderMap,
    me: &str,
    rows: Vec<Suppression>,
) -> Result<Vec<AlarmSuppressionView>, StoreError> {
    let writes = !matches!(
        presented_credentials(headers),
        Ok(PresentedCredentials::Bearer(_))
    );
    let (approve, suppress) = if writes {
        let caps = authenticated_editor(client, headers, me)
            .await?
            .capabilities;
        (
            scope_of(&caps, Permission::AlarmsSuppressionsApprove),
            scope_of(&caps, Permission::AlarmsSuppress),
        )
    } else {
        (None, None)
    };
    let ids: Vec<i64> = rows.iter().map(|row| row.id).collect();
    let mut facts = store::facts(client, &ids, approve.as_ref(), suppress.as_ref()).await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let facts = facts.remove(&row.id).unwrap_or_default();
            view(row, facts, me, writes)
        })
        .collect())
}

/// The view of a committed write when its facts could not be read: the
/// write stands, so it answers with no `can_*` and stored ids for names.
fn bare_view(row: Suppression, me: &str) -> AlarmSuppressionView {
    let facts = Facts {
        requested_by: row.created_by.clone(),
        decided_by: row.decided_by.clone(),
        ..Facts::default()
    };
    view(row, facts, me, false)
}

/// The answer to a write: `done` with the view (no body for 204), or the
/// refusal of roles spec §8; `missing` is the 404 code.
pub(super) async fn answer(
    client: &Client,
    headers: &HeaderMap,
    me: &str,
    change: Result<Change, StoreError>,
    done: StatusCode,
    missing: &'static str,
) -> Response {
    let problem = match change {
        Err(_) => return unavailable_auth(),
        Ok(Change::Done(_)) if done == StatusCode::NO_CONTENT => return done.into_response(),
        Ok(Change::Done(row)) => {
            // The write committed: a failed lookup must not answer 503.
            let view = match views(client, headers, me, vec![row.clone()]).await {
                Ok(mut views) => views.remove(0),
                Err(_) => bare_view(row, me),
            };
            return (done, Json(view)).into_response();
        }
        Ok(Change::NotFound) => {
            ProblemDetails::not_found(missing, "Alarm or suppression not found")
        }
        Ok(Change::NeedsGlobalScope) => ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "global_scope_required",
            "Only someone who reaches every host may suppress on all hosts",
        ),
        Ok(Change::NotInReach) => ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ),
        Ok(Change::WrongState) => ProblemDetails::new(
            StatusCode::CONFLICT,
            "suppression_not_waiting",
            "This suppression is no longer waiting",
        ),
        Ok(Change::OwnRequest) => ProblemDetails::new(
            StatusCode::CONFLICT,
            "own_request",
            "You can't approve or reject your own request",
        ),
        Ok(Change::Invalid(field)) => return invalid(&field),
    };
    problem_response(problem)
}

/// 422 naming the invalid field (`reason`, `for`, `group`, `command` or
/// `body`).
pub(super) fn invalid(field: &str) -> Response {
    let mut problem = ProblemDetails::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_suppression",
        "Check the suppression's fields",
    );
    problem.field_errors = Some(vec![FieldError {
        field: field.to_owned(),
        code: "invalid".to_owned(),
        message: match field {
            "reason" => "Give a reason of 1 to 4,000 characters",
            "for" => "Choose 7 days, 30 days or until removed",
            "group" => "The group no longer exists",
            "command" => "This alarm's command line can't be matched",
            _ => "Send alarm_id, what, where, for_days and reason",
        }
        .to_owned(),
    }]);
    problem_response(problem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_view_offers_no_action() {
        let now = Utc::now();
        let row = Suppression {
            id: 7,
            rule_set_id: "baseline".into(),
            rule_id: "r".into(),
            scope: "program".into(),
            agent_id: None,
            exe: Some("/usr/bin/sh".into()),
            args_sha256: None,
            device_id: None,
            note: "noise".into(),
            created_by: "me".into(),
            created_at: now,
            state: State::Waiting,
            expired: false,
            host_group_id: None,
            host_group_name: None,
            for_days: Some(7),
            activated_at: None,
            expires_at: None,
            decided_by: None,
            decided_at: None,
            decision_reason: None,
            alarm_id: Some(1),
            would_close: None,
            would_close_capped: false,
        };
        let view = bare_view(row, "me");
        assert_eq!(
            (view.status.as_str(), view.requested_by.as_str()),
            ("waiting", "me")
        );
        assert!(!view.can_withdraw && !view.can_decide && !view.can_remove);
    }
}
