//! Checks and answers of the host-group handlers: a proposed rule or pick
//! of hosts, and the store's outcomes as HTTP answers.

use axum::{
    extract::Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use platform_store::host_group_writes::{self as writes, GroupContent, GroupWrite};
use platform_store::host_groups::Condition;

use super::groups_types::{GroupCondition, HostGroupView};
use crate::access::guard::unavailable_auth;
use crate::http::problem::{FieldError, ProblemDetails, problem_response};

/// Picked hosts in one manual group, at most.
const MAX_PICKED: usize = 10_000;

/// A group's proposed content, owned.
pub(super) enum Content {
    Rule(Vec<Condition>),
    Manual(Vec<String>),
}

impl Content {
    pub(super) fn rule(conditions: Vec<GroupCondition>) -> Self {
        Self::Rule(conditions.into_iter().map(Into::into).collect())
    }

    /// Itself when valid; otherwise 422 `invalid_condition` naming the
    /// field (or `conditions`), or 400 for too many picked hosts or a bad id.
    pub(super) fn checked(self) -> Result<Self, ProblemDetails> {
        match &self {
            Self::Rule(conditions) => {
                if let Some(part) = invalid_rule(conditions) {
                    return Err(condition_problem(&part));
                }
            }
            Self::Manual(picked) => {
                if picked.len() > MAX_PICKED {
                    return Err(invalid("agent_ids", "Pick at most 10000 hosts"));
                }
                if picked.iter().any(|id| !(1..=255).contains(&id.len())) {
                    return Err(invalid("agent_ids", "Host ids are 1–255 characters"));
                }
            }
        }
        Ok(self)
    }

    pub(super) fn as_ref(&self) -> GroupContent<'_> {
        match self {
            Self::Rule(conditions) => GroupContent::Rule(conditions),
            Self::Manual(picked) => GroupContent::Manual(picked),
        }
    }
}

/// The malformed part of a rule: `conditions` when there are none or more
/// than 16, else the first bad condition's field. The store checks the
/// values of each field; a distribution must also read `<id> <release>`.
fn invalid_rule(conditions: &[Condition]) -> Option<String> {
    if conditions.is_empty() {
        return Some("conditions".into());
    }
    let distribution = |v: &str| {
        let ok = |part: &str| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        };
        v.split_once(' ')
            .is_some_and(|(id, release)| ok(id) && ok(release))
    };
    if let Some(c) = conditions
        .iter()
        .find(|c| c.field == "distribution" && !c.values.iter().all(|v| distribution(v)))
    {
        return Some(c.field.clone());
    }
    writes::invalid_content(&GroupContent::Rule(conditions))
}

pub(super) fn answer(
    status: StatusCode,
    written: Result<GroupWrite, platform_store::StoreError>,
) -> Response {
    match written {
        Ok(GroupWrite::Saved(group)) => (status, Json(HostGroupView::from(group))).into_response(),
        Ok(GroupWrite::NameTaken) => conflict("group_name_taken", "Another group has this name"),
        Ok(GroupWrite::Stale) => conflict("stale_group", "The group changed since you read it"),
        Ok(GroupWrite::NotFound) => group_not_found(),
        Ok(GroupWrite::InUse(roles)) => {
            let mut problem = ProblemDetails::new(
                StatusCode::CONFLICT,
                "group_in_use",
                "Roles still use this group",
            );
            problem.extra.roles = Some(roles);
            problem_response(problem)
        }
        Ok(GroupWrite::UnknownHost(agent_id)) => {
            let mut problem = ProblemDetails::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unknown_host",
                "A picked host does not exist",
            );
            problem.field_errors = Some(vec![FieldError {
                field: "agent_ids".into(),
                code: "unknown_host".into(),
                message: format!("No active host {agent_id}"),
            }]);
            problem_response(problem)
        }
        Ok(GroupWrite::Invalid(part)) if part == "name" => problem_response(invalid(
            "name",
            "Use 1 to 128 characters, without control characters",
        )),
        Ok(GroupWrite::Invalid(part)) if part == "description" => {
            problem_response(invalid("description", "Use at most 500 characters"))
        }
        Ok(GroupWrite::Invalid(part)) => invalid_condition(&part),
        Err(_) => unavailable_auth(),
    }
}

pub(super) fn invalid(field: &str, message: &str) -> ProblemDetails {
    let mut problem = ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_group",
        "The host group is invalid",
    );
    problem.field_errors = Some(vec![FieldError {
        field: field.to_owned(),
        code: "invalid".to_owned(),
        message: message.to_owned(),
    }]);
    problem
}

pub(super) fn invalid_condition(field: &str) -> Response {
    problem_response(condition_problem(field))
}

fn condition_problem(field: &str) -> ProblemDetails {
    let mut problem = ProblemDetails::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_condition",
        "A condition is invalid",
    );
    problem.field_errors = Some(vec![FieldError {
        field: field.to_owned(),
        code: "invalid".to_owned(),
        message: "Use 1 to 16 conditions on os_family, distribution, hostname or ip, \
                  each with 1 to 64 valid values"
            .to_owned(),
    }]);
    problem
}

fn conflict(code: &'static str, title: &'static str) -> Response {
    problem_response(ProblemDetails::new(StatusCode::CONFLICT, code, title))
}

pub(super) fn group_not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "group_not_found",
        "No such host group",
    ))
}
