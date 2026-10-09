//! Resolving a missing or unknown `rule_set` from the findings, so a model
//! that guesses a set name (or leaves it out) still gets an answer. Notes
//! and errors here are fixed text; model text is only ever compared with
//! host data, never echoed.

use chrono::{DateTime, Duration};
use platform_store::assistant::{FindingGroup, GroupFilter, Page};
use serde_json::{Map, Value, json};

use super::{
    LookupError, LookupOutput, Lookups, MAX_WINDOW_HOURS, Source, agent_cite, finding_cite, time,
};

/// Result note when a rule matches no finding.
pub const NOTE_NO_FINDING: &str = "no finding with this rule";
/// Result note when a rule has only findings older than the window.
pub const NOTE_NONE_IN_WINDOW: &str = "no finding with this rule in the window";
/// Result note when a searched rule set has no findings.
pub const NOTE_SET_NOT_FOUND: &str = "rule set not found; showing all rule sets";

/// Most groups read when looking for the sets of a rule (the store caps at 100).
const GROUPS: u32 = 100;

impl<S: Source> Lookups<S> {
    /// The distinct `(rule set, rule id)` pairs with a finding group for
    /// `rule` (exact id, case-insensitive), over the longest window so a
    /// quiet rule still resolves. The id is the store's, not the model's.
    // ponytail: reads 100 groups matched by substring; a short common id on
    // a large fleet can miss the exact group. Upgrade: exact rule filter in
    // the store.
    pub(crate) async fn rule_sets_for(
        &self,
        rule: &str,
    ) -> Result<Vec<(String, String)>, LookupError> {
        let filter = GroupFilter {
            text: Some(rule),
            min_severity: None,
            rule_set_id: None,
        };
        let since = self.now - Duration::hours(i64::from(MAX_WINDOW_HOURS));
        let page = self
            .source
            .finding_groups(&filter, since, GROUPS)
            .await
            .map_err(|_| LookupError::Store)?;
        let mut sets: Vec<(String, String)> = page
            .items
            .into_iter()
            .filter(|g| g.rule_id.eq_ignore_ascii_case(rule))
            .map(|g| (g.rule_set_id, g.rule_id))
            .collect();
        sets.sort();
        sets.dedup();
        Ok(sets)
    }

    /// `Some(all-sets page)` when `rule_set` has no finding group at all.
    pub(crate) async fn search_all_if_set_unknown(
        &self,
        text: &Option<String>,
        min_severity: Option<&'static str>,
        rule_set: &Option<String>,
        window_hours: u32,
        items: u32,
    ) -> Result<Option<Page<FindingGroup>>, LookupError> {
        let store_error = |_| LookupError::Store;
        let since = self.now - Duration::hours(i64::from(window_hours));
        let any = GroupFilter {
            text: None,
            min_severity: None,
            rule_set_id: rule_set.as_deref(),
        };
        let long = self.now - Duration::hours(i64::from(MAX_WINDOW_HOURS));
        if self
            .source
            .finding_groups(&any, long, 1)
            .await
            .map_err(store_error)?
            .total
            > 0
        {
            return Ok(None);
        }
        let all = GroupFilter {
            text: text.as_deref(),
            min_severity,
            rule_set_id: None,
        };
        let page = self
            .source
            .finding_groups(&all, since, items)
            .await
            .map_err(store_error)?;
        Ok(Some(page))
    }

    /// The set `rule_description` reads: the named one when it has the rule,
    /// else the rule's only set; with the store's spelling of the rule id.
    /// Several is an error; none keeps the named set and the given id (the
    /// bundle may know a rule with no findings yet).
    pub(crate) async fn rule_set_for_description(
        &self,
        named: Option<&str>,
        rule: &str,
    ) -> Result<(String, String), LookupError> {
        let mut found = self.rule_sets_for(rule).await?;
        if let Some(set) = named
            && found.iter().any(|(s, _)| s == set)
        {
            found.retain(|(s, _)| s == set);
        }
        match found.len() {
            0 => Ok((named.unwrap_or_default().to_owned(), rule.to_owned())),
            1 => Ok(found.remove(0)),
            _ => Err(LookupError::AmbiguousRule),
        }
    }

    /// `finding_endpoints`: one set as before, several merged (each item
    /// names its set), none an empty result with a note.
    pub(crate) async fn finding_endpoints_resolved(
        &self,
        mut summary: Map<String, Value>,
        named: Option<&str>,
        rule: &str,
        since: DateTime<chrono::Utc>,
        window_hours: u32,
        items: u32,
    ) -> Result<LookupOutput, LookupError> {
        let mut sets = self.rule_sets_for(rule).await?;
        if let Some(set) = named
            && sets.iter().any(|(s, _)| s == set)
        {
            sets.retain(|(s, _)| s == set);
        }
        // A named set with no recent group is still asked, so
        // `not_seen_in_window` reports older sightings.
        let mut fallback = false;
        if sets.is_empty()
            && let Some(set) = named
        {
            fallback = true;
            sets.push((set.to_owned(), rule.to_owned()));
        }
        summary.insert("window_hours".into(), json!(window_hours));
        if sets.is_empty() {
            summary.insert("note".into(), json!(NOTE_NO_FINDING));
            return Ok(LookupOutput::page(summary, Vec::new(), 0));
        }
        let many = sets.len() > 1;
        let (mut all, mut total, mut older) = (Vec::new(), 0, 0);
        for (set, rule) in &sets {
            let page = self
                .source
                .finding_endpoints(set, rule, since, items)
                .await
                .map_err(|_| LookupError::Store)?;
            total += page.total;
            older += page.older;
            for e in &page.items {
                let mut item = json!({
                    "cite": agent_cite(&e.agent_id),
                    "hostname": e.hostname,
                    "first_observed": time(e.first_observed_at),
                    "last_observed": time(e.last_observed_at),
                    "rule_version": e.rule_version,
                    "severity": e.severity,
                });
                if many {
                    item["rule_set"] = json!(if set.is_empty() { "~unknown" } else { set });
                    item["finding"] = json!(finding_cite(set, rule));
                }
                all.push(item);
            }
        }
        if many {
            all.sort_by(|a, b| {
                b["last_observed"]
                    .as_str()
                    .cmp(&a["last_observed"].as_str())
            });
            all.truncate(items as usize);
        } else if fallback {
            // Only model text names this finding: no cite, no echo.
            let note = if older > 0 {
                NOTE_NONE_IN_WINDOW
            } else {
                NOTE_NO_FINDING
            };
            summary.insert("note".into(), json!(note));
        } else {
            summary.insert(
                "finding".into(),
                json!(finding_cite(&sets[0].0, &sets[0].1)),
            );
        }
        summary.insert("not_seen_in_window".into(), json!(older));
        Ok(LookupOutput::page(summary, all, total))
    }
}
