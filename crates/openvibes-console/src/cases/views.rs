use chrono::{DateTime, SecondsFormat, Utc};
use platform_store::console_cases::{
    CaseDetail, CaseEvent, CaseItem, CaseSummary, ItemCase, UserRef,
};

use super::types::{
    CaseDetailView, CaseEventView, CaseItemView, CaseSummaryView, CaseUserView, ItemCaseView,
};
pub(super) fn time(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub(super) fn user_view(user: UserRef) -> CaseUserView {
    CaseUserView {
        user_id: user.user_id,
        username: user.username,
        display_name: user.display_name,
    }
}

pub(super) fn summary_view(case: CaseSummary) -> CaseSummaryView {
    CaseSummaryView {
        case_id: case.case_id,
        number: case.number,
        title: case.title,
        status: case.status,
        resolution: case.resolution,
        accepted_until: case.accepted_until.map(time),
        severity: case.severity,
        assignee: case.assignee.map(user_view),
        opened_by: user_view(case.opened_by),
        created_at: time(case.created_at),
        updated_at: time(case.updated_at),
        closed_at: case.closed_at.map(time),
        version: case.version.try_into().unwrap_or_default(),
        item_count: case.items,
        pending_item_count: case.pending_items,
    }
}

pub(super) fn item_view(item: CaseItem) -> CaseItemView {
    CaseItemView {
        item_id: item.item_id,
        kind: item.kind,
        reference: item.reference,
        agent_id: item.agent_id,
        hostname: item.hostname,
        active: item.active,
        outcome: item.outcome,
        outcome_note: item.outcome_note,
        outcome_until: item.outcome_until.map(time),
        added_by: user_view(item.added_by),
        added_at: time(item.added_at),
        title: item.title,
        severity: item.severity,
        evidence_gone: item.evidence_gone,
    }
}

pub(super) fn event_view(event: CaseEvent) -> CaseEventView {
    CaseEventView {
        event_id: event.event_id,
        at: time(event.at),
        actor: event.actor.map(user_view),
        kind: event.kind,
        body: event.body,
        detail: event.detail,
    }
}

pub(super) fn detail_view(detail: CaseDetail) -> CaseDetailView {
    CaseDetailView {
        case: summary_view(detail.summary),
        resolution_note: detail.resolution_note,
        items: detail.items.into_iter().map(item_view).collect(),
        events: detail.events.into_iter().map(event_view).collect(),
    }
}

pub(super) fn item_case_view(found: ItemCase) -> ItemCaseView {
    ItemCaseView {
        case: summary_view(found.case),
        item_id: found.item_id,
        outcome: found.outcome,
    }
}
