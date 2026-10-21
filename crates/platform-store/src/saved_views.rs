//! Saved views (a named URL query) and hidden list columns, per person and
//! page (roles spec §10). Pages and column keys are validated by the console.

use chrono::{DateTime, Utc};

use crate::{Client, StoreError};

/// Most saved views one person may keep per page.
pub const MAX_VIEWS_PER_PAGE: i64 = 50;

/// One saved view.
#[derive(Clone, Debug, PartialEq)]
pub struct SavedView {
    /// Stable UUID.
    pub id: String,
    /// The list page, such as `hosts`.
    pub page: String,
    /// 1–60 characters, unique per person and page regardless of case.
    pub name: String,
    /// The URL query string (at most 1000 characters).
    pub query: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Result of [`create`].
#[derive(Clone, Debug, PartialEq)]
pub enum ViewWrite {
    /// Stored.
    Saved(SavedView),
    /// The person already has a view of that name on the page.
    NameTaken,
    /// The person already has [`MAX_VIEWS_PER_PAGE`] on the page.
    TooMany,
}

const COLUMNS: &str = "view_id::text, page, name, query, created_at";

fn is_uuid(id: &str) -> bool {
    id.len() == 36
        && id.char_indices().all(|(index, c)| match index {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// The person's views on a page, by name regardless of case.
pub async fn list(
    client: &Client,
    user_id: &str,
    page: &str,
) -> Result<Vec<SavedView>, StoreError> {
    let rows = client
        .query(
            &format!(
                "SELECT {COLUMNS} FROM console_saved_views
                 WHERE user_id = $1::text::uuid AND page = $2
                 ORDER BY lower(name), name, view_id"
            ),
            &[&user_id, &page],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| SavedView {
            id: r.get(0),
            page: r.get(1),
            name: r.get(2),
            query: r.get(3),
            created_at: r.get(4),
        })
        .collect())
}

/// Saves a view (at most 50 per person and page).
pub async fn create(
    client: &mut Client,
    user_id: &str,
    page: &str,
    name: &str,
    query: &str,
    now: DateTime<Utc>,
) -> Result<ViewWrite, StoreError> {
    let tx = client.transaction().await?;
    // Serialises concurrent creates by one person so the limit holds.
    tx.execute(
        "SELECT 1 FROM console_users WHERE user_id = $1::text::uuid FOR UPDATE",
        &[&user_id],
    )
    .await?;
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM console_saved_views WHERE user_id = $1::text::uuid AND page = $2",
            &[&user_id, &page],
        )
        .await?
        .get(0);
    if count >= MAX_VIEWS_PER_PAGE {
        return Ok(ViewWrite::TooMany);
    }
    let row = tx
        .query_opt(
            &format!(
                "INSERT INTO console_saved_views (user_id, page, name, query, created_at)
                 VALUES ($1::text::uuid, $2, $3, $4, $5)
                 ON CONFLICT (user_id, page, lower(name)) DO NOTHING
                 RETURNING {COLUMNS}"
            ),
            &[&user_id, &page, &name, &query, &now],
        )
        .await?;
    let Some(r) = row else {
        return Ok(ViewWrite::NameTaken);
    };
    let view = SavedView {
        id: r.get(0),
        page: r.get(1),
        name: r.get(2),
        query: r.get(3),
        created_at: r.get(4),
    };
    tx.commit().await?;
    Ok(ViewWrite::Saved(view))
}

/// Deletes the person's own view; false when there is none such.
pub async fn delete(client: &Client, user_id: &str, id: &str) -> Result<bool, StoreError> {
    if !is_uuid(id) {
        return Ok(false);
    }
    let n = client
        .execute(
            "DELETE FROM console_saved_views
             WHERE view_id = $2::text::uuid AND user_id = $1::text::uuid",
            &[&user_id, &id],
        )
        .await?;
    Ok(n > 0)
}

/// The column keys the person hid on a page.
pub async fn hidden_columns(
    client: &Client,
    user_id: &str,
    page: &str,
) -> Result<Vec<String>, StoreError> {
    let row = client
        .query_opt(
            "SELECT hidden FROM console_list_columns WHERE user_id = $1::text::uuid AND page = $2",
            &[&user_id, &page],
        )
        .await?;
    Ok(row.map(|r| r.get(0)).unwrap_or_default())
}

/// Replaces the hidden column keys of a page.
pub async fn set_hidden_columns(
    client: &Client,
    user_id: &str,
    page: &str,
    hidden: &[String],
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    client
        .execute(
            "INSERT INTO console_list_columns (user_id, page, hidden, changed_at)
             VALUES ($1::text::uuid, $2, $3, $4)
             ON CONFLICT (user_id, page) DO UPDATE SET hidden = $3, changed_at = $4",
            &[&user_id, &page, &hidden, &now],
        )
        .await?;
    Ok(())
}
