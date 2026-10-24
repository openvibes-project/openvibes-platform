//! Who sees a case and its items, in SQL, and reading what the viewer sees.

use deadpool_postgres::GenericClient;
use tokio_postgres::Row;

use super::{CaseDetail, CaseEvent, CaseItem, CaseSummary, UserRef, Viewer, is_uuid};
use crate::{StoreError, console_read::agent_visibility};

/// Items an item row may be seen through: software always, the rest when
/// their agent is in the caller's scope. Uses `$1` and `$2`.
pub(crate) fn item_visible(item: &str) -> String {
    format!(
        "({item}.agent_id IS NULL OR EXISTS (SELECT 1 FROM agents a
            WHERE a.agent_id = {item}.agent_id AND {}))",
        agent_visibility("a.agent_id", "$1", "$2")
    )
}

/// A case the caller can see: they opened it, it is assigned to them, or
/// one of its items is visible to them; a case with no items also when
/// their scope is every host (spec §6, step 5d ruling 4). Uses `$1`, `$2`
/// and `$3`.
pub(crate) fn case_visible(case: &str) -> String {
    let has_visible_item = format!(
        "EXISTS (SELECT 1 FROM case_items vi WHERE vi.case_id = {case}.case_id AND {})",
        item_visible("vi")
    );
    case_visible_with(case, &has_visible_item)
}

/// [`case_visible`] with `has_visible_item`, an SQL test that the case holds
/// an item [`item_visible`] passes, worked out by the caller (the Cases
/// list reads it from items it has already filtered, rather than one
/// lookup per case).
pub(crate) fn case_visible_with(case: &str, has_visible_item: &str) -> String {
    format!(
        "({case}.opened_by_user_id = $3::text::uuid
          OR {case}.assignee_user_id IS NOT DISTINCT FROM $3::text::uuid
          OR {has_visible_item}
          OR ($1::boolean
              AND NOT EXISTS (SELECT 1 FROM case_items ei WHERE ei.case_id = {case}.case_id)))"
    )
}

pub(super) const CASE_COLUMNS: &str = "c.case_id::text, c.number, c.title, c.status, c.resolution,
    c.accepted_until, c.severity, c.assignee_user_id::text, au.username, au.display_name,
    c.opened_by_user_id::text, ou.username, ou.display_name, c.created_at, c.updated_at,
    c.closed_at, c.version::bigint, c.resolution_note";

pub(super) const CASE_JOINS: &str = "JOIN console_users ou ON ou.user_id = c.opened_by_user_id
    LEFT JOIN console_users au ON au.user_id = c.assignee_user_id";

/// Counts of the case's items the caller can see (columns 18 and 19).
pub(super) fn case_counts() -> String {
    let visible = item_visible("ci");
    format!(
        "(SELECT count(*) FROM case_items ci WHERE ci.case_id = c.case_id AND {visible}),
         (SELECT count(*) FROM case_items ci WHERE ci.case_id = c.case_id
            AND ci.kind IN ('alarm', 'compliance_finding', 'vulnerability') AND ci.outcome IS NULL
            AND {visible})"
    )
}

/// The agent of a finding or vulnerability item, or its other parts.
pub(super) const REF_PART_2: &str = "split_part(i.ref, '/', 2)";
pub(super) const REF_PART_3: &str = "split_part(i.ref, '/', 3)";
/// Everything after the first `/`: an advisory id, a package name.
pub(super) const REF_TAIL: &str = "substr(i.ref, strpos(i.ref, '/') + 1)";

/// What to show for an item (alias `i`, hosts joined as `ha`).
pub(super) fn item_title() -> String {
    format!(
        "CASE i.kind
            WHEN 'alarm' THEN (SELECT al.message FROM alarms al WHERE al.id = i.ref::bigint AND al.source = 'agent')
            WHEN 'compliance_finding' THEN (SELECT f.message FROM current_findings f
                WHERE f.agent_id = i.agent_id AND f.rule_set_id = {REF_PART_2}
                  AND f.rule_id = {REF_PART_3})
            WHEN 'vulnerability' THEN (SELECT ad.title FROM advisories ad
                WHERE ad.advisory_id = {REF_TAIL})
            WHEN 'host' THEN ha.hostname
            ELSE {REF_TAIL}
        END"
    )
}

/// An item's own severity.
pub(super) fn item_severity() -> String {
    format!(
        "CASE i.kind
            WHEN 'alarm' THEN (SELECT al.severity FROM alarms al WHERE al.id = i.ref::bigint AND al.source = 'agent')
            WHEN 'compliance_finding' THEN (SELECT f.severity FROM current_findings f
                WHERE f.agent_id = i.agent_id AND f.rule_set_id = {REF_PART_2}
                  AND f.rule_id = {REF_PART_3})
            WHEN 'vulnerability' THEN (SELECT ad.severity FROM advisories ad
                WHERE ad.advisory_id = {REF_TAIL})
        END"
    )
}

/// True when the evidence an item stands for is gone (alias `i`).
pub(super) fn item_gone() -> String {
    format!(
        "CASE i.kind
            WHEN 'alarm' THEN NOT EXISTS (SELECT 1 FROM alarms al
                WHERE al.id = i.ref::bigint AND al.source = 'agent' AND al.state <> 'mitigated')
            WHEN 'compliance_finding' THEN NOT EXISTS (SELECT 1 FROM current_findings f
                WHERE f.agent_id = i.agent_id AND f.rule_set_id = {REF_PART_2}
                  AND f.rule_id = {REF_PART_3} AND f.ended_at IS NULL)
            WHEN 'vulnerability' THEN
                NOT EXISTS (SELECT 1 FROM vulnerabilities v
                    WHERE v.agent_id = i.agent_id AND v.advisory_id = {REF_TAIL}
                      AND v.fixed_at IS NULL)
                AND NOT EXISTS (SELECT 1 FROM version_vulnerabilities vv
                    JOIN host_packages hp ON hp.package_version_id = vv.package_version_id
                    WHERE hp.agent_id = i.agent_id AND vv.advisory_id = {REF_TAIL})
            ELSE false
        END"
    )
}

pub(super) fn user_ref(id: String, username: String, display_name: String) -> UserRef {
    UserRef {
        user_id: id,
        username,
        display_name,
    }
}

pub(super) fn summary_from_row(row: &Row) -> CaseSummary {
    CaseSummary {
        case_id: row.get(0),
        number: row.get(1),
        title: row.get(2),
        status: row.get(3),
        resolution: row.get(4),
        accepted_until: row.get(5),
        severity: row.get(6),
        assignee: row
            .get::<_, Option<String>>(7)
            .map(|id| user_ref(id, row.get(8), row.get(9))),
        opened_by: user_ref(row.get(10), row.get(11), row.get(12)),
        created_at: row.get(13),
        updated_at: row.get(14),
        closed_at: row.get(15),
        version: row.get(16),
        items: row.get(18),
        pending_items: row.get(19),
    }
}

pub(super) fn item_from_row(row: &Row) -> CaseItem {
    CaseItem {
        item_id: row.get(0),
        kind: row.get(1),
        reference: row.get(2),
        agent_id: row.get(3),
        hostname: row.get(4),
        active: row.get(5),
        outcome: row.get(6),
        outcome_note: row.get(7),
        added_by: user_ref(row.get(8), row.get(9), row.get(10)),
        added_at: row.get(11),
        title: row.get(12),
        severity: row.get(13),
        evidence_gone: row.get(14),
        outcome_until: row.get(15),
    }
}

pub(super) fn event_from_row(row: &Row) -> CaseEvent {
    CaseEvent {
        event_id: row.get(0),
        at: row.get(1),
        actor: row
            .get::<_, Option<String>>(2)
            .map(|id| user_ref(id, row.get(3), row.get(4))),
        kind: row.get(5),
        body: row.get(6),
        detail: row.get(7),
    }
}

/// The case, if the viewer can see it.
pub(super) async fn read_summary(
    db: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
) -> Result<Option<(CaseSummary, Option<String>)>, StoreError> {
    if !is_uuid(case_id) {
        return Ok(None);
    }
    let counts = case_counts();
    let visible = case_visible("c");
    let row = db
        .query_opt(
            &format!(
                "SELECT {CASE_COLUMNS}, {counts} FROM cases c {CASE_JOINS}
                 WHERE c.case_id = $4::text::uuid AND {visible}"
            ),
            viewer_params!(viewer, &case_id),
        )
        .await?;
    Ok(row.map(|row| (summary_from_row(&row), row.get(17))))
}

/// The viewer's visible items, oldest first; one when `item_id` is given.
pub(super) async fn read_items(
    db: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
    item_id: Option<&str>,
) -> Result<Vec<CaseItem>, StoreError> {
    let (title, severity, gone, visible) = (
        item_title(),
        item_severity(),
        item_gone(),
        item_visible("i"),
    );
    let rows = db
        .query(
            &format!(
                "SELECT i.item_id::text, i.kind, i.ref, i.agent_id, ha.hostname, i.active,
                    i.outcome, i.outcome_note, i.added_by_user_id::text, ub.username,
                    ub.display_name, i.added_at, {title}, {severity}, {gone}, i.outcome_until
                 FROM case_items i
                 JOIN console_users ub ON ub.user_id = i.added_by_user_id
                 LEFT JOIN agents ha ON ha.agent_id = i.agent_id
                 WHERE i.case_id = $4::text::uuid AND {visible} AND $3::text IS NOT NULL
                   AND ($5::text IS NULL OR i.item_id = $5::text::uuid)
                 ORDER BY i.added_at, i.seq"
            ),
            viewer_params!(viewer, &case_id, &item_id),
        )
        .await?;
    Ok(rows.iter().map(item_from_row).collect())
}

/// The timeline without entries about items the viewer cannot see.
pub(super) async fn read_events(
    db: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
) -> Result<Vec<CaseEvent>, StoreError> {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let rows = db
        .query(
            &format!(
                "SELECT e.event_id, e.at, e.actor_user_id::text, u.username, u.display_name,
                    e.kind, e.body, e.detail
                 FROM case_events e LEFT JOIN console_users u ON u.user_id = e.actor_user_id
                 WHERE e.case_id = $4::text::uuid AND $3::text IS NOT NULL
                   AND (e.detail->>'item_agent_id' IS NULL OR EXISTS (
                        SELECT 1 FROM agents a
                        WHERE a.agent_id = e.detail->>'item_agent_id' AND {visible}))
                 ORDER BY e.event_id"
            ),
            viewer_params!(viewer, &case_id),
        )
        .await?;
    Ok(rows.iter().map(event_from_row).collect())
}

pub(super) async fn read_detail(
    db: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
) -> Result<Option<CaseDetail>, StoreError> {
    let Some((summary, resolution_note)) = read_summary(db, viewer, case_id).await? else {
        return Ok(None);
    };
    Ok(Some(CaseDetail {
        summary,
        resolution_note,
        items: read_items(db, viewer, case_id, None).await?,
        events: read_events(db, viewer, case_id).await?,
    }))
}
