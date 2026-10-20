//! Alarms: the list, one alarm and its triage, suppressions, and the rule and
//! detection evidence behind findings and alarms.

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use crate::http::AuthHttpState;

pub(crate) mod alarm;
pub(crate) mod detection;
pub(crate) mod suppression_decisions;
pub(crate) mod suppression_types;
pub(crate) mod suppressions;

pub use alarm::{
    AlarmDetailView, AlarmPage, AlarmSummaryView, AlarmTriageView, UpdateAlarmTriageRequest,
};
pub use detection::DetectionView;
pub use suppression_types::{
    AlarmSuppressionGroup, AlarmSuppressionList, AlarmSuppressionOptions, AlarmSuppressionView,
    AlarmSuppressionWhereView, CreateAlarmSuppressionRequest, RejectAlarmSuppressionRequest,
    SuppressWhat, SuppressWhere,
};

/// Alarms and their triage, suppressions, and the rule behind a finding or
/// an alarm.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route(
            "/v1/compliance/latest/{agent_id}/{rule_set_id}/{rule_id}/rule/{finding_id}",
            get(detection::finding_rule),
        )
        .route("/v1/alarms/{id}/rule", get(detection::alarm_rule))
        .route("/v1/alarms", get(alarm::list_alarms))
        .route("/v1/alarms/{alarm_id}", get(alarm::get_alarm))
        .route(
            "/v1/alarms/{alarm_id}/triage",
            put(alarm::update_alarm_triage),
        )
        .route(
            "/v1/alarm-suppressions",
            get(suppressions::list_suppressions).post(suppressions::create_suppression),
        )
        .route(
            "/v1/alarm-suppressions/options",
            get(suppressions::suppression_options),
        )
        .route(
            "/v1/alarm-suppressions/{suppression_id}",
            delete(suppression_decisions::remove_suppression),
        )
        .route(
            "/v1/alarm-suppressions/{suppression_id}/approve",
            post(suppression_decisions::approve_suppression),
        )
        .route(
            "/v1/alarm-suppressions/{suppression_id}/reject",
            post(suppression_decisions::reject_suppression),
        )
        .route(
            "/v1/alarm-suppressions/{suppression_id}/withdraw",
            post(suppression_decisions::withdraw_suppression),
        )
}
