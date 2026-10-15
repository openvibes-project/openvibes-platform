//! Request checks several areas share: a UUID, an agent id, and the answer
//! to a bad finding or vulnerability query.

use axum::{http::StatusCode, response::Response};

use crate::http::problem::{ProblemDetails, problem_response};

pub(crate) fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

pub(crate) fn valid_agent_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

/// The 400 answer to finding and vulnerability list parameters that do not parse.
pub(crate) fn invalid_finding_query() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_query",
        "Finding query parameters are invalid",
    ))
}
