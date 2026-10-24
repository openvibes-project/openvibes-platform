//! Listing and reading cases, their assignees, and the cases that hold an item.

use chrono::{DateTime, Utc};
use deadpool_postgres::GenericClient;

use super::{
    CaseDetail, CaseSummary, FOR_ITEM_LIMIT, ItemCase, ItemKind, Refusal, UserRef, Viewer, is_uuid,
    items::parse_ref,
    visibility::{
        CASE_COLUMNS, CASE_JOINS, case_counts, case_visible, item_visible, read_detail,
        summary_from_row, user_ref,
    },
};
use crate::{Client, StoreError, console_read::AgentScope};

/// The `C-104`, `c104` or `104` a search text may be.
pub(crate) fn case_number(text: &str) -> Option<i64> {
    let digits = text
        .strip_prefix("C-")
        .or_else(|| text.strip_prefix("c-"))
        .or_else(|| text.strip_prefix(['C', 'c']))
        .unwrap_or(text);
    digits.parse().ok().filter(|number: &i64| *number > 0)
}

/// Filters for [`list`].
#[derive(Clone, Debug, Default)]
pub struct CaseFilters {
    /// `open`, `investigating`, `closed`, `all`, or `None` for open and
    /// investigating.
    pub status: Option<String>,
    /// Exact severity.
    pub severity: Option<String>,
    /// Who the case is assigned to.
    pub assignee: AssigneeFilter,
    /// Text in the title, or a case number (`C-104`, `104`).
    pub q: Option<String>,
}

/// Who a case is assigned to, for [`CaseFilters`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum AssigneeFilter {
    /// Anyone, or nobody.
    #[default]
    Anyone,
    /// Nobody.
    Nobody,
    /// This user id.
    User(String),
}

/// Where the next page starts: after this `(updated_at, case_id)`.
pub type CaseCursor = (DateTime<Utc>, String);

/// The cases the caller can see, newest change first.
pub async fn list(
    client: &Client,
    scope: &AgentScope,
    user_id: &str,
    filters: &CaseFilters,
    after: Option<&CaseCursor>,
    limit: i64,
) -> Result<Vec<CaseSummary>, StoreError> {
    let viewer = Viewer::new(scope, user_id);
    let status = filters.status.as_deref().unwrap_or("active");
    let (mode, who): (&str, Option<&str>) = match &filters.assignee {
        AssigneeFilter::Anyone => ("any", None),
        AssigneeFilter::Nobody => ("none", None),
        AssigneeFilter::User(id) if is_uuid(id) => ("user", Some(id.as_str())),
        // Not a user id: matches nobody.
        AssigneeFilter::User(_) => ("user", Some("00000000-0000-0000-0000-000000000000")),
    };
    let q = filters
        .q
        .as_deref()
        .map(str::trim)
        .filter(|q| !q.is_empty());
    let number = q.and_then(case_number);
    let (cursor_at, cursor_id) = after.map_or((None, None), |(at, id)| {
        (Some(*at), is_uuid(id).then_some(id.as_str()))
    });
    let (counts, visible) = (case_counts(), case_visible("c"));
    let rows = client
        .query(
            &format!(
                "SELECT {CASE_COLUMNS}, {counts} FROM cases c {CASE_JOINS}
                 WHERE {visible}
                   AND ($4::text = 'all' OR ($4 = 'active' AND c.status <> 'closed')
                        OR c.status = $4)
                   AND ($5::text IS NULL OR c.severity = $5)
                   AND ($6::text = 'any' OR ($6 = 'none' AND c.assignee_user_id IS NULL)
                        OR ($6 = 'user' AND c.assignee_user_id = $7::text::uuid))
                   AND ($8::text IS NULL OR c.number = $9::bigint
                        OR strpos(lower(c.title), lower($8)) > 0)
                   AND ($10::timestamptz IS NULL
                        OR (c.updated_at, c.case_id) < ($10, $11::text::uuid))
                 ORDER BY c.updated_at DESC, c.case_id DESC LIMIT $12"
            ),
            viewer_params!(
                viewer,
                &status,
                &filters.severity,
                &mode,
                &who,
                &q,
                &number,
                &cursor_at,
                &cursor_id,
                &limit
            ),
        )
        .await?;
    Ok(rows.iter().map(summary_from_row).collect())
}

/// One case with its visible items and timeline, if the caller can see it.
pub async fn get(
    client: &Client,
    scope: &AgentScope,
    user_id: &str,
    case_id: &str,
) -> Result<Option<CaseDetail>, StoreError> {
    read_detail(client, &Viewer::new(scope, user_id), case_id).await
}

/// An enabled user who holds `cases.read` through a live role binding.
pub(super) const READS_CASES: &str = "u.enabled AND EXISTS (
    SELECT 1 FROM console_role_bindings b
    JOIN console_role_permissions rp ON rp.role_id = b.role_id
    WHERE b.user_id = u.user_id AND b.revoked_at IS NULL AND rp.permission_id = 'cases.read')";

/// Users a case can be assigned to: enabled users with `cases.read`.
pub async fn assignees(client: &Client) -> Result<Vec<UserRef>, StoreError> {
    let rows = client
        .query(
            &format!(
                "SELECT u.user_id::text, u.username, u.display_name FROM console_users u
                 WHERE {READS_CASES} ORDER BY lower(u.display_name), u.username"
            ),
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| user_ref(row.get(0), row.get(1), row.get(2)))
        .collect())
}

pub(super) async fn assignee_available(
    db: &impl GenericClient,
    user_id: &str,
) -> Result<bool, StoreError> {
    if !is_uuid(user_id) {
        return Ok(false);
    }
    Ok(db
        .query_opt(
            &format!(
                "SELECT 1 FROM console_users u WHERE u.user_id = $1::text::uuid AND {READS_CASES}"
            ),
            &[&user_id],
        )
        .await?
        .is_some())
}

/// The cases that hold an item, visible ones only. An alarm, finding or
/// vulnerability has at most one: the open case that holds it. A host or
/// software item can be in many, open or closed, newest change first.
pub async fn for_item(
    client: &Client,
    scope: &AgentScope,
    user_id: &str,
    kind: &str,
    reference: &str,
) -> Result<Result<Vec<ItemCase>, Refusal>, StoreError> {
    let Some(kind) = ItemKind::parse(kind) else {
        return Ok(Err(Refusal::Invalid("kind", "invalid_kind")));
    };
    if parse_ref(kind, reference).is_none() {
        return Ok(Err(Refusal::Invalid("ref", "invalid_ref")));
    }
    let viewer = Viewer::new(scope, user_id);
    // The item itself must be visible: a case that holds it is not
    // listed to someone who cannot see it, even if they see the case.
    let (counts, visible, item) = (case_counts(), case_visible("c"), item_visible("i"));
    let exclusive = kind.exclusive();
    let rows = client
        .query(
            &format!(
                "SELECT {CASE_COLUMNS}, {counts}, i.item_id::text, i.outcome
                 FROM case_items i JOIN cases c ON c.case_id = i.case_id {CASE_JOINS}
                 WHERE i.kind = $4 AND i.ref = $5 AND ($6 OR i.active) AND {visible}
                   AND {item}
                 ORDER BY c.updated_at DESC, c.case_id DESC LIMIT $7"
            ),
            viewer_params!(
                viewer,
                &kind.as_str(),
                &reference,
                &!exclusive,
                &FOR_ITEM_LIMIT
            ),
        )
        .await?;
    Ok(Ok(rows
        .iter()
        .map(|row| ItemCase {
            case: summary_from_row(row),
            item_id: row.get(20),
            outcome: row.get(21),
        })
        .collect()))
}

/// Most rows [`active_items`] returns.
pub const ACTIVE_ITEMS_LIMIT: i64 = 20_000;

/// Every alarm, finding or vulnerability (`kind`) active in an open case
/// the caller can see, with that case's number: the lists' case badges
/// (triage v2: "being worked on" means in a case). `None` for a kind that
/// is not one-case-only.
pub async fn active_items(
    client: &Client,
    scope: &AgentScope,
    user_id: &str,
    kind: &str,
) -> Result<Option<Vec<(String, i64)>>, StoreError> {
    let Some(kind) = ItemKind::parse(kind).filter(|k| k.exclusive()) else {
        return Ok(None);
    };
    let viewer = Viewer::new(scope, user_id);
    let (visible, item) = (case_visible("c"), item_visible("i"));
    let rows = client
        .query(
            &format!(
                "SELECT i.ref, c.number FROM case_items i JOIN cases c ON c.case_id = i.case_id
                 WHERE i.kind = $4 AND i.active AND {visible} AND {item}
                 ORDER BY c.number LIMIT $5"
            ),
            viewer_params!(viewer, &kind.as_str(), &ACTIVE_ITEMS_LIMIT),
        )
        .await?;
    Ok(Some(rows.iter().map(|r| (r.get(0), r.get(1))).collect()))
}
