//! The rule-metadata index (`console_rule_meta`, schema 59): what each rule
//! of a stored bundle says, for the alarm list's technique filter and the
//! alarm page's "What happened" card. The console fills it from bundles it
//! has verified; this module does not verify anything.

use serde_json::{Value, json};

use crate::{Client, StoreError};

/// One rule of a verified bundle, ready to index.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleMetaRow {
    /// Rule id within its set.
    pub rule_id: String,
    /// Rule version.
    pub rule_version: i64,
    /// Rule title.
    pub title: String,
    /// The rule's finding message.
    pub message: String,
    /// What a match means, at most 600 characters.
    pub explain: Option<String>,
    /// What a person should look at, at most 600 characters.
    pub check: Option<String>,
    /// ATT&CK `(tactic, technique)` pairs.
    pub attack: Vec<(String, Option<String>)>,
}

/// An indexed rule.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleMeta {
    /// Rule title.
    pub title: String,
    /// The rule's finding message.
    pub message: String,
    /// What a match means.
    pub explain: Option<String>,
    /// What a person should look at.
    pub check: Option<String>,
    /// ATT&CK `(tactic, technique)` pairs.
    pub attack: Vec<(String, Option<String>)>,
}

/// Indexes the rules of one stored bundle. Storing the same bundle again
/// rewrites its rows; a bundle's content never changes once stored.
/// `techniques` is derived here: the distinct technique ids of `attack`.
pub async fn upsert_from_bundle(
    client: &Client,
    set: &str,
    version: i64,
    rows: &[RuleMetaRow],
) -> Result<(), StoreError> {
    let ids: Vec<&str> = rows.iter().map(|r| r.rule_id.as_str()).collect();
    let versions: Vec<i64> = rows.iter().map(|r| r.rule_version).collect();
    let titles: Vec<&str> = rows.iter().map(|r| r.title.as_str()).collect();
    let messages: Vec<&str> = rows.iter().map(|r| r.message.as_str()).collect();
    let explains: Vec<Option<&str>> = rows.iter().map(|r| r.explain.as_deref()).collect();
    let checks: Vec<Option<&str>> = rows.iter().map(|r| r.check.as_deref()).collect();
    let attacks: Vec<Value> = rows
        .iter()
        .map(|r| {
            r.attack
                .iter()
                .map(|(tactic, technique)| json!({"tactic": tactic, "technique": technique}))
                .collect()
        })
        .collect();
    client
        .execute(
            "INSERT INTO console_rule_meta (rule_set_id, rule_set_version, rule_id, rule_version,
                 title, message, explain, \"check\", attack, techniques)
             SELECT $1, $2, r.id, r.version, r.title, r.message, r.explain, r.chk, r.attack,
                 ARRAY(SELECT DISTINCT e->>'technique' FROM jsonb_array_elements(r.attack) e
                       WHERE e->>'technique' IS NOT NULL ORDER BY 1)
             FROM unnest($3::text[], $4::bigint[], $5::text[], $6::text[], $7::text[],
                         $8::text[], $9::jsonb[])
                  AS r(id, version, title, message, explain, chk, attack)
             ON CONFLICT (rule_set_id, rule_set_version, rule_id) DO UPDATE SET
                 rule_version = EXCLUDED.rule_version, title = EXCLUDED.title,
                 message = EXCLUDED.message, explain = EXCLUDED.explain,
                 \"check\" = EXCLUDED.\"check\", attack = EXCLUDED.attack,
                 techniques = EXCLUDED.techniques",
            &[
                &set, &version, &ids, &versions, &titles, &messages, &explains, &checks, &attacks,
            ],
        )
        .await?;
    Ok(())
}

/// The indexed rule, or `None` when its bundle was never indexed (old data
/// or an unverifiable bundle): the caller then resolves the bundle itself.
pub async fn get(
    client: &Client,
    set: &str,
    set_version: i64,
    rule_id: &str,
    rule_version: i64,
) -> Result<Option<RuleMeta>, StoreError> {
    let row = client
        .query_opt(
            "SELECT title, message, explain, \"check\", attack FROM console_rule_meta
             WHERE rule_set_id = $1 AND rule_set_version = $2 AND rule_id = $3
               AND rule_version = $4",
            &[&set, &set_version, &rule_id, &rule_version],
        )
        .await?;
    Ok(row.map(|row| {
        let attack: Value = row.get(4);
        RuleMeta {
            title: row.get(0),
            message: row.get(1),
            explain: row.get(2),
            check: row.get(3),
            attack: attack
                .as_array()
                .into_iter()
                .flatten()
                .map(|pair| {
                    (
                        pair["tactic"].as_str().unwrap_or_default().to_owned(),
                        pair["technique"].as_str().map(str::to_owned),
                    )
                })
                .collect(),
        }
    }))
}

/// Up to `limit` stored bundles `(set, version)` with no indexed rule, for
/// the console's start-up backfill. Unverifiable bundles stay listed.
pub async fn missing_bundles(
    client: &Client,
    limit: i64,
) -> Result<Vec<(String, i64)>, StoreError> {
    Ok(client
        .query(
            "SELECT b.rule_set_id, b.version FROM rule_bundles b
             WHERE NOT EXISTS (SELECT 1 FROM console_rule_meta m
                               WHERE m.rule_set_id = b.rule_set_id
                                 AND m.rule_set_version = b.version)
             ORDER BY b.rule_set_id, b.version LIMIT $1",
            &[&limit],
        )
        .await?
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect())
}
