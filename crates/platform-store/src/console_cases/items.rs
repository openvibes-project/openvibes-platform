//! Items: checking what one points at, opening a case with items, adding and
//! removing them.

use chrono::{DateTime, Utc};
use deadpool_postgres::GenericClient;
use serde_json::json;

use super::{
    CaseDetail, CaseItem, ItemKind, MAX_ITEMS_ON_CREATE, MAX_ITEMS_PER_CASE, NewCase, Refusal,
    Viewer,
    close::lock_case,
    default_severity,
    events::{audit, push_event, touch, username},
    is_uuid,
    list::assignee_available,
    refuse, severity_ok, title_ok, unique_violation,
    visibility::{case_visible, item_gone, item_visible, read_detail, read_items},
};
use crate::{
    Client, StoreError,
    console_read::{AgentScope, agent_visibility},
};

pub(super) fn identifier_ok(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

pub(super) fn free_text_ok(text: &str, longest: usize) -> bool {
    !text.is_empty() && text.chars().count() <= longest && !text.chars().any(char::is_control)
}

/// The parts of an item's ref, checked for its kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Parsed<'a> {
    Alarm(i64),
    Finding(&'a str, &'a str, &'a str),
    Vulnerability(&'a str, &'a str),
    Host(&'a str),
    Software(&'a str, &'a str),
    Port(&'a str, i32),
}

/// Checks `reference` against the shape its kind has in the console, so
/// that what is stored is exactly what the panels would write.
pub(super) fn parse_ref(kind: ItemKind, reference: &str) -> Option<Parsed<'_>> {
    match kind {
        ItemKind::Alarm => {
            let id: i64 = reference.parse().ok()?;
            (id > 0 && id.to_string() == reference).then_some(Parsed::Alarm(id))
        }
        ItemKind::Finding => {
            let mut parts = reference.split('/');
            let (agent, set, rule) = (parts.next()?, parts.next()?, parts.next()?);
            // A rule set may be empty (findings from before rule sets).
            (parts.next().is_none()
                && identifier_ok(agent)
                && (set.is_empty() || identifier_ok(set))
                && identifier_ok(rule))
            .then_some(Parsed::Finding(agent, set, rule))
        }
        ItemKind::Vulnerability => {
            let (agent, advisory) = reference.split_once('/')?;
            (identifier_ok(agent) && free_text_ok(advisory, 256))
                .then_some(Parsed::Vulnerability(agent, advisory))
        }
        ItemKind::Host => identifier_ok(reference).then_some(Parsed::Host(reference)),
        ItemKind::Software => {
            let (manager, name) = reference.split_once('/')?;
            (identifier_ok(manager) && free_text_ok(name, 256))
                .then_some(Parsed::Software(manager, name))
        }
        ItemKind::Port => {
            let (protocol, number) = reference.split_once('/')?;
            let port: i32 = number.parse().ok()?;
            (matches!(protocol, "tcp" | "udp")
                && (1..=65535).contains(&port)
                && port.to_string() == number)
                .then_some(Parsed::Port(protocol, port))
        }
    }
}

/// What an item resolves to when it is added.
pub(super) struct Resolved<'a> {
    kind: ItemKind,
    reference: &'a str,
    agent_id: Option<String>,
    severity: Option<String>,
}

/// Checks the item's shape and that the viewer can see the object it
/// points at; a missing and a hidden object are the same answer.
pub(super) async fn resolve_item<'a>(
    db: &impl GenericClient,
    viewer: &Viewer<'_>,
    kind: &str,
    reference: &'a str,
) -> Result<Result<Resolved<'a>, Refusal>, StoreError> {
    let Some(kind) = ItemKind::parse(kind) else {
        return Ok(Err(Refusal::Invalid("kind", "invalid_kind")));
    };
    let Some(parsed) = parse_ref(kind, reference) else {
        return Ok(Err(Refusal::Invalid("ref", "invalid_ref")));
    };
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let found = match parsed {
        Parsed::Alarm(id) => {
            db.query_opt(
                &format!(
                    "SELECT al.agent_id, al.severity FROM alarms al
                     JOIN agents a ON a.agent_id = al.agent_id WHERE al.id = $3 AND {visible}"
                ),
                &[&viewer.global, &viewer.groups, &id],
            )
            .await?
        }
        Parsed::Finding(agent, set, rule) => {
            db.query_opt(
                &format!(
                    "SELECT f.agent_id, f.severity FROM current_findings f
                     JOIN agents a ON a.agent_id = f.agent_id
                     WHERE f.agent_id = $3 AND f.rule_set_id = $4 AND f.rule_id = $5
                       AND {visible}"
                ),
                &[&viewer.global, &viewer.groups, &agent, &set, &rule],
            )
            .await?
        }
        Parsed::Vulnerability(agent, advisory) => {
            db.query_opt(
                &format!(
                    "SELECT a.agent_id, (SELECT ad.severity FROM advisories ad
                                         WHERE ad.advisory_id = $4)
                     FROM agents a WHERE a.agent_id = $3 AND {visible}
                       AND (EXISTS (SELECT 1 FROM vulnerabilities v
                                    WHERE v.agent_id = a.agent_id AND v.advisory_id = $4)
                            OR EXISTS (SELECT 1 FROM version_vulnerabilities vv
                                JOIN host_packages hp
                                  ON hp.package_version_id = vv.package_version_id
                                WHERE hp.agent_id = a.agent_id AND vv.advisory_id = $4))"
                ),
                &[&viewer.global, &viewer.groups, &agent, &advisory],
            )
            .await?
        }
        Parsed::Host(agent) => {
            db.query_opt(
                &format!(
                    "SELECT a.agent_id, NULL::text FROM agents a
                     WHERE a.agent_id = $3 AND {visible}"
                ),
                &[&viewer.global, &viewer.groups, &agent],
            )
            .await?
        }
        // Software is visible to a reader, but only if a host they can see
        // has it, so that adding it never says whether other hosts do.
        Parsed::Software(manager, name) => {
            db.query_opt(
                &format!(
                    "SELECT NULL::text, NULL::text WHERE EXISTS (
                        SELECT 1 FROM package_versions pv
                        JOIN host_packages hp ON hp.package_version_id = pv.id
                        JOIN agents a ON a.agent_id = hp.agent_id
                        WHERE pv.manager = $3 AND pv.name = $4 AND {visible})"
                ),
                &[&viewer.global, &viewer.groups, &manager, &name],
            )
            .await?
        }
        // Like software: only if a host in reach listens on it.
        Parsed::Port(protocol, port) => {
            db.query_opt(
                &format!(
                    "SELECT NULL::text, NULL::text WHERE EXISTS (
                        SELECT 1 FROM host_listeners l
                        JOIN agents a ON a.agent_id = l.agent_id
                        WHERE l.protocol = $3 AND l.port = $4 AND a.status <> 'revoked' AND {visible})"
                ),
                &[&viewer.global, &viewer.groups, &protocol, &port],
            )
            .await?
        }
    };
    Ok(match found {
        Some(row) => Ok(Resolved {
            kind,
            reference,
            agent_id: row.get(0),
            severity: row.get(1),
        }),
        None => Err(Refusal::ItemNotFound),
    })
}

/// Adds a resolved item to an open case (locked by the caller).
pub(super) async fn insert_item(
    tx: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
    item: &Resolved<'_>,
    now: DateTime<Utc>,
) -> Result<Result<String, Refusal>, StoreError> {
    let kind = item.kind.as_str();
    let held: i64 = tx
        .query_one(
            "SELECT count(*) FROM case_items WHERE case_id = $1::text::uuid",
            &[&case_id],
        )
        .await?
        .get(0);
    if held >= MAX_ITEMS_PER_CASE {
        return Ok(Err(Refusal::TooManyItems));
    }
    let same = tx
        .query_opt(
            "SELECT 1 FROM case_items WHERE case_id = $1::text::uuid AND kind = $2 AND ref = $3",
            &[&case_id, &kind, &item.reference],
        )
        .await?;
    if same.is_some() {
        return Ok(Err(Refusal::AlreadyInCase));
    }
    if item.kind.exclusive() {
        let visible = case_visible("oc");
        let other = tx
            .query_opt(
                &format!(
                    "SELECT oc.number, {visible} FROM case_items o
                     JOIN cases oc ON oc.case_id = o.case_id
                     WHERE o.kind = $5 AND o.ref = $6 AND o.active
                       AND o.case_id <> $4::text::uuid"
                ),
                viewer_params!(viewer, &case_id, &kind, &item.reference),
            )
            .await?;
        if let Some(row) = other {
            let number: i64 = row.get(0);
            let seen: bool = row.get(1);
            return Ok(Err(Refusal::ItemInCase(seen.then_some(number))));
        }
    }
    let inserted = tx
        .query_one(
            "INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, active,
                 added_by_user_id, added_at)
             VALUES (gen_random_uuid(), $1::text::uuid, $2, $3, $4, true, $5::text::uuid, $6)
             RETURNING item_id::text",
            &[
                &case_id,
                &kind,
                &item.reference,
                &item.agent_id,
                &viewer.user_id,
                &now,
            ],
        )
        .await;
    match inserted {
        Ok(row) => Ok(Ok(row.get(0))),
        // Two requests raced past the checks above.
        Err(error) if unique_violation(&error) => Ok(Err(Refusal::ItemInCase(None))),
        Err(error) => Err(error.into()),
    }
}

/// The item's timeline entry and audit row. The agent goes into the
/// detail so that the timeline can be filtered by scope.
pub(super) async fn record_item_added(
    tx: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
    number: i64,
    item: &Resolved<'_>,
    item_id: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let kind = item.kind.as_str();
    push_event(
        tx,
        case_id,
        now,
        Some(viewer.user_id),
        "item_added",
        None,
        json!({ "item_id": item_id, "item_kind": kind, "item_ref": item.reference,
                "item_agent_id": item.agent_id }),
    )
    .await?;
    audit(
        tx,
        Some(viewer.user_id),
        "case.item.add",
        case_id,
        json!({ "number": number, "kind": kind, "ref": item.reference }),
    )
    .await
}

/// Opens a case. The caller sees it afterwards because they opened it.
pub async fn create(
    client: &mut Client,
    scope: &AgentScope,
    user_id: &str,
    new: &NewCase<'_>,
    now: DateTime<Utc>,
) -> Result<Result<CaseDetail, Refusal>, StoreError> {
    if !title_ok(new.title) {
        return Ok(Err(Refusal::Invalid("title", "invalid_title")));
    }
    if new.severity.is_some_and(|severity| !severity_ok(severity)) {
        return Ok(Err(Refusal::Invalid("severity", "invalid_severity")));
    }
    if new.items.len() > MAX_ITEMS_ON_CREATE {
        return Ok(Err(Refusal::Invalid("items", "too_many_items")));
    }
    let viewer = Viewer::new(scope, user_id);
    let tx = client.transaction().await?;
    if let Some(assignee) = new.assignee_user_id
        && !assignee_available(&tx, assignee).await?
    {
        return refuse(tx, Refusal::AssigneeUnavailable).await;
    }
    let mut resolved = Vec::with_capacity(new.items.len());
    for (kind, reference) in new.items {
        match resolve_item(&tx, &viewer, kind, reference).await? {
            Ok(item) => resolved.push(item),
            Err(refusal) => return refuse(tx, refusal).await,
        }
    }
    let severity = new
        .severity
        .unwrap_or_else(|| default_severity(resolved.iter().map(|item| item.severity.as_deref())));
    let row = tx
        .query_one(
            "INSERT INTO cases (case_id, title, status, severity, assignee_user_id,
                 opened_by_user_id, created_at, updated_at)
             VALUES (gen_random_uuid(), $1, 'open', $2, $3::text::uuid, $4::text::uuid, $5, $5)
             RETURNING case_id::text, number",
            &[&new.title, &severity, &new.assignee_user_id, &user_id, &now],
        )
        .await?;
    let (case_id, number): (String, i64) = (row.get(0), row.get(1));
    push_event(
        &tx,
        &case_id,
        now,
        Some(user_id),
        "created",
        None,
        json!({ "severity": severity }),
    )
    .await?;
    if let Some(assignee) = new.assignee_user_id {
        let name = username(&tx, Some(assignee)).await?;
        push_event(
            &tx,
            &case_id,
            now,
            Some(user_id),
            "assigned",
            None,
            json!({ "from": null, "to": name }),
        )
        .await?;
    }
    audit(
        &tx,
        Some(user_id),
        "case.create",
        &case_id,
        json!({ "number": number, "severity": severity, "items": resolved.len() }),
    )
    .await?;
    for item in &resolved {
        match insert_item(&tx, &viewer, &case_id, item, now).await? {
            Ok(item_id) => {
                record_item_added(&tx, &viewer, &case_id, number, item, &item_id, now).await?;
            }
            Err(refusal) => return refuse(tx, refusal).await,
        }
    }
    let Some(created) = read_detail(&tx, &viewer, &case_id).await? else {
        return Err(StoreError::Query);
    };
    tx.commit().await?;
    Ok(Ok(created))
}

/// Adds one item to an open case. The viewer must see the object; a
/// missing and a hidden object are the same answer. An alarm, finding or
/// vulnerability that another open case holds is refused.
pub async fn add_item(
    client: &mut Client,
    scope: &AgentScope,
    user_id: &str,
    case_id: &str,
    kind: &str,
    reference: &str,
    now: DateTime<Utc>,
) -> Result<Result<CaseItem, Refusal>, StoreError> {
    let viewer = Viewer::new(scope, user_id);
    let tx = client.transaction().await?;
    let Some(current) = lock_case(&tx, &viewer, case_id).await? else {
        return refuse(tx, Refusal::NotFound).await;
    };
    if current.status == "closed" {
        return refuse(tx, Refusal::Closed).await;
    }
    let item = match resolve_item(&tx, &viewer, kind, reference).await? {
        Ok(item) => item,
        Err(refusal) => return refuse(tx, refusal).await,
    };
    let item_id = match insert_item(&tx, &viewer, case_id, &item, now).await? {
        Ok(item_id) => item_id,
        Err(refusal) => return refuse(tx, refusal).await,
    };
    record_item_added(&tx, &viewer, case_id, current.number, &item, &item_id, now).await?;
    touch(&tx, case_id, now).await?;
    let mut items = read_items(&tx, &viewer, case_id, Some(&item_id)).await?;
    let Some(added) = items.pop() else {
        return Err(StoreError::Query);
    };
    tx.commit().await?;
    Ok(Ok(added))
}

/// An item of the case the viewer can see, as stored.
pub(super) struct StoredItem {
    pub(super) kind: ItemKind,
    pub(super) reference: String,
    pub(super) agent_id: Option<String>,
    pub(super) outcome: Option<String>,
    pub(super) gone: bool,
}

pub(super) async fn lock_item(
    tx: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
    item_id: &str,
) -> Result<Option<StoredItem>, StoreError> {
    if !is_uuid(item_id) {
        return Ok(None);
    }
    let (gone, visible) = (item_gone(), item_visible("i"));
    let row = tx
        .query_opt(
            &format!(
                "SELECT i.kind, i.ref, i.agent_id, i.outcome, {gone} FROM case_items i
                 WHERE i.case_id = $4::text::uuid AND i.item_id = $5::text::uuid
                   AND {visible} AND $3::text IS NOT NULL
                 FOR UPDATE OF i"
            ),
            viewer_params!(viewer, &case_id, &item_id),
        )
        .await?;
    Ok(row.and_then(|row| {
        Some(StoredItem {
            kind: ItemKind::parse(&row.get::<_, String>(0))?,
            reference: row.get(1),
            agent_id: row.get(2),
            outcome: row.get(3),
            gone: row.get(4),
        })
    }))
}

/// Removes an item from an open case. The timeline keeps that it was there.
pub async fn remove_item(
    client: &mut Client,
    scope: &AgentScope,
    user_id: &str,
    case_id: &str,
    item_id: &str,
    now: DateTime<Utc>,
) -> Result<Result<(), Refusal>, StoreError> {
    let viewer = Viewer::new(scope, user_id);
    let tx = client.transaction().await?;
    let Some(current) = lock_case(&tx, &viewer, case_id).await? else {
        return refuse(tx, Refusal::NotFound).await;
    };
    if current.status == "closed" {
        return refuse(tx, Refusal::Closed).await;
    }
    let Some(item) = lock_item(&tx, &viewer, case_id, item_id).await? else {
        return refuse(tx, Refusal::ItemNotFound).await;
    };
    tx.execute(
        "DELETE FROM case_items WHERE item_id = $1::text::uuid",
        &[&item_id],
    )
    .await?;
    push_event(
        &tx,
        case_id,
        now,
        Some(user_id),
        "item_removed",
        None,
        json!({ "item_id": item_id, "item_kind": item.kind.as_str(),
                "item_ref": item.reference, "item_agent_id": item.agent_id }),
    )
    .await?;
    touch(&tx, case_id, now).await?;
    audit(
        &tx,
        Some(user_id),
        "case.item.remove",
        case_id,
        json!({ "number": current.number, "kind": item.kind.as_str(), "ref": item.reference }),
    )
    .await?;
    tx.commit().await?;
    Ok(Ok(()))
}
