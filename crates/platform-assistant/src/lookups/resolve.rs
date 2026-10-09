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
/// Result note when a searched rule set has no findings.
pub const NOTE_SET_NOT_FOUND: &str = "rule set not found; showing all rule sets";

/// Most groups read when looking for the sets of a rule (the store caps at 100).
const GROUPS: u32 = 100;

impl<S: Source> Lookups<S> {
    /// The distinct rule sets with a finding group for `rule` (exact id,
    /// case-insensitive), over the longest window so a quiet rule still
    /// resolves.
    pub(crate) async fn rule_sets_for(&self, rule: &str) -> Result<Vec<String>, LookupError> {
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
        let mut sets: Vec<String> = page
            .items
            .into_iter()
            .filter(|g| g.rule_id.eq_ignore_ascii_case(rule))
            .map(|g| g.rule_set_id)
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
    /// else the rule's only set. Several sets is an error; none keeps the
    /// named set (the bundle may know a rule with no findings yet).
    pub(crate) async fn rule_set_for_description(
        &self,
        named: Option<&str>,
        rule: &str,
    ) -> Result<String, LookupError> {
        let sets = self.rule_sets_for(rule).await?;
        match (named, sets.as_slice()) {
            (Some(set), _) if sets.iter().any(|s| s == set) => Ok(set.to_owned()),
            (_, [one]) => Ok(one.clone()),
            (_, [_, _, ..]) => Err(LookupError::AmbiguousRule),
            (named, []) => Ok(named.unwrap_or_default().to_owned()),
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
        if let Some(set) = named.filter(|set| sets.iter().any(|s| s == set)) {
            sets = vec![set.to_owned()];
        }
        summary.insert("window_hours".into(), json!(window_hours));
        if sets.is_empty() {
            summary.insert("note".into(), json!(NOTE_NO_FINDING));
            return Ok(LookupOutput::page(summary, Vec::new(), 0));
        }
        let many = sets.len() > 1;
        let (mut all, mut total, mut older) = (Vec::new(), 0, 0);
        for set in &sets {
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
        } else {
            summary.insert("finding".into(), json!(finding_cite(&sets[0], rule)));
        }
        summary.insert("not_seen_in_window".into(), json!(older));
        Ok(LookupOutput::page(summary, all, total))
    }
}
