//! Bounded global read models for the human console.

use chrono::{DateTime, Duration, NaiveDate, Utc};
use tokio_postgres::Row;

use crate::{Client, StoreError, status::OFFLINE_AFTER_MINUTES};

/// Maximum rows returned by one page.
pub const MAX_PAGE_SIZE: u16 = 100;

/// SQL visibility for agent-bound console reads. Scoped groups use the
/// version-one exact-tag conjunction selectors stored in schema 8.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum AgentScope {
    /// Every agent is visible to the caller.
    Global,
    /// Agents matching at least one listed asset group are visible.
    AssetGroups(Vec<String>),
}

impl AgentScope {
    fn is_global(&self) -> bool {
        matches!(self, Self::Global)
    }

    fn group_ids(&self) -> Vec<String> {
        match self {
            Self::Global => Vec::new(),
            Self::AssetGroups(ids) => ids.clone(),
        }
    }
}

/// Builds the SQL predicate shared by finding reads; its only interpolated
/// values are internal aliases and positional parameter numbers.
fn agent_visibility(agent_id: &str, global: &str, groups: &str) -> String {
    format!(
        "({global}::boolean OR EXISTS (
            SELECT 1 FROM console_asset_group_selectors s
            WHERE s.asset_group_id::text = ANY({groups}::text[])
              AND NOT EXISTS (
                SELECT 1 FROM console_asset_group_selectors required
                WHERE required.asset_group_id = s.asset_group_id
                  AND NOT EXISTS (
                    SELECT 1 FROM console_agent_tags t
                    WHERE t.agent_id = {agent_id}
                      AND t.tag_key = required.tag_key
                      AND t.tag_value = required.tag_value
                  )
              )
        ))"
    )
}

/// A validated bounded page size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageLimit(u16);

impl PageLimit {
    /// Creates a page size from 1 through [`MAX_PAGE_SIZE`].
    pub fn new(value: u16) -> Option<Self> {
        (1..=MAX_PAGE_SIZE).contains(&value).then_some(Self(value))
    }

    fn value(self) -> i64 {
        i64::from(self.0)
    }
}

/// Current lifecycle state after applying the stale-heartbeat threshold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentState {
    /// Enrolled and recently reporting.
    Active,
    /// Enrolled, but no heartbeat within the stale interval.
    Stale,
    /// Revoked by an operator.
    Revoked,
}

impl AgentState {
    fn as_db_filter(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Revoked => "revoked",
        }
    }
}

/// Operator-facing agent record. It contains no certificate PEM or key bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Agent {
    /// Platform-assigned id.
    pub agent_id: String,
    /// Latest authenticated heartbeat hostname; it is an operator label.
    pub hostname: Option<String>,
    /// Lifecycle state computed for the supplied `now`.
    pub state: AgentState,
    /// Enrollment time.
    pub enrolled_at: DateTime<Utc>,
    /// Revocation time.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Latest heartbeat time.
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Reported agent version.
    pub scanner_version: Option<String>,
    /// Reported agent capabilities.
    pub capabilities: Vec<String>,
}

/// Cursor for agent order: last seen descending/nulls last, then id ascending.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentCursor {
    /// Last-seen timestamp of the previous page's last record.
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Id of the previous page's last record.
    pub agent_id: String,
}

/// Agent-list query. Free text is deliberately absent until indexed search is approved.
#[derive(Clone, Debug)]
pub struct AgentQuery {
    /// Optional lifecycle state filter.
    pub state: Option<AgentState>,
    /// Exclusive keyset cursor.
    pub after: Option<AgentCursor>,
    /// Bounded page size.
    pub limit: PageLimit,
}

/// Bounded result page with an exclusive continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T, C> {
    /// At most the requested number of records.
    pub items: Vec<T>,
    /// Cursor to request the next page, if one exists.
    pub next: Option<C>,
}

/// Summary of globally visible agents.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AgentSummary {
    /// All enrolled agents.
    pub total: i64,
    /// Recently reporting agents.
    pub active: i64,
    /// Agents beyond the heartbeat threshold.
    pub stale: i64,
    /// Revoked agents.
    pub revoked: i64,
}

/// Certificate metadata exposed to the console, with no PEM content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    /// 16-byte certificate serial.
    pub serial: Vec<u8>,
    /// Validity start.
    pub not_before: DateTime<Utc>,
    /// Expiry.
    pub not_after: DateTime<Utc>,
    /// Issuance time.
    pub issued_at: DateTime<Utc>,
}

/// Cursor for certificate order: issuance descending, serial ascending.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateCursor {
    /// Issuance time of the previous page's last record.
    pub issued_at: DateTime<Utc>,
    /// Serial of the previous page's last record.
    pub serial: Vec<u8>,
}

/// Finding severity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    /// Critical.
    Critical,
    /// High.
    High,
    /// Medium.
    Medium,
    /// Low.
    Low,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

/// Full latest observation snapshot retained independently of history partitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LatestFinding {
    /// Finding identifier.
    pub finding_id: String,
    /// Agent id.
    pub agent_id: String,
    /// Current hostname label, if present.
    pub hostname: Option<String>,
    /// Rule-set id (`""` means pre-P6 unknown).
    pub rule_set_id: String,
    /// Rule id within the rule set.
    pub rule_id: String,
    /// Signed rule version.
    pub rule_version: i64,
    /// Latest severity.
    pub severity: Severity,
    /// Confidence percentage.
    pub confidence: i16,
    /// Latest message.
    pub message: String,
    /// Latest evidence values.
    pub evidence: Vec<String>,
    /// Scan id.
    pub scan_id: String,
    /// Whether the event arrived over authenticated agent transport.
    pub authenticated: bool,
    /// `online` or `import` provenance.
    pub origin: String,
    /// First observation time.
    pub first_observed_at: DateTime<Utc>,
    /// Latest observation time.
    pub last_observed_at: DateTime<Utc>,
    /// Platform receive time for the latest observation.
    pub received_at: DateTime<Utc>,
}

/// Cursor for latest-finding order: time descending, then composite identity ascending.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LatestCursor {
    /// Latest observation time of the previous page's last record.
    pub last_observed_at: DateTime<Utc>,
    /// Agent id of that record.
    pub agent_id: String,
    /// Rule-set id of that record.
    pub rule_set_id: String,
    /// Rule id of that record.
    pub rule_id: String,
}

/// Latest-finding list query.
#[derive(Clone, Debug)]
pub struct LatestQuery {
    /// Optional allow-listed severity filter.
    pub severity: Option<Severity>,
    /// Exclusive keyset cursor.
    pub after: Option<LatestCursor>,
    /// Bounded page size.
    pub limit: PageLimit,
}

/// Summary of globally visible latest observations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FindingSummary {
    /// Latest rows.
    pub total: i64,
    /// Distinct affected agents.
    pub impacted_agents: i64,
    /// Critical rows.
    pub critical: i64,
    /// High rows.
    pub high: i64,
    /// Medium rows.
    pub medium: i64,
    /// Low rows.
    pub low: i64,
}

/// Cursor for historical order: observation time descending, day descending, id ascending.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryCursor {
    /// Observation time of the previous page's last record.
    pub observed_at: DateTime<Utc>,
    /// Partition day of that record.
    pub observed_day: NaiveDate,
    /// Finding id of that record.
    pub finding_id: String,
}

/// Bounded historical-event query. `since` is required for partition pruning.
#[derive(Clone, Debug)]
pub struct HistoryQuery {
    /// Earliest allowed observation time, normally the retention cutoff.
    pub since: DateTime<Utc>,
    /// Optional exact agent filter.
    pub agent_id: Option<String>,
    /// Optional exact rule-set filter.
    pub rule_set_id: Option<String>,
    /// Optional exact rule filter.
    pub rule_id: Option<String>,
    /// Exclusive keyset cursor.
    pub after: Option<HistoryCursor>,
    /// Bounded page size.
    pub limit: PageLimit,
}

/// One immutable history event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingEvent {
    /// Finding id.
    pub finding_id: String,
    /// Partition day.
    pub observed_day: NaiveDate,
    /// Agent id.
    pub agent_id: String,
    /// Rule-set id.
    pub rule_set_id: String,
    /// Rule id.
    pub rule_id: String,
    /// Rule version.
    pub rule_version: i64,
    /// Severity.
    pub severity: Severity,
    /// Confidence percentage.
    pub confidence: i16,
    /// Message.
    pub message: String,
    /// Evidence.
    pub evidence: Vec<String>,
    /// Scan id.
    pub scan_id: String,
    /// Whether authenticated transport was used.
    pub authenticated: bool,
    /// `online` or `import` provenance.
    pub origin: String,
    /// Agent/import observation time.
    pub observed_at: DateTime<Utc>,
    /// Platform receive time.
    pub received_at: DateTime<Utc>,
}

/// Ensures callers fail closed unless migrations exactly match this binary.
pub async fn schema_is_current(client: &Client) -> Result<bool, StoreError> {
    Ok(crate::schema_version(client).await? == Some(crate::SCHEMA_VERSION))
}

/// Counts all, active, stale, and revoked agents in one aggregate query.
pub async fn agent_summary(
    client: &Client,
    now: DateTime<Utc>,
) -> Result<AgentSummary, StoreError> {
    agent_summary_in_scope(client, now, &AgentScope::Global).await
}

/// Counts only agents visible through the supplied SQL-enforced scope.
pub async fn agent_summary_in_scope(
    client: &Client,
    now: DateTime<Utc>,
    scope: &AgentScope,
) -> Result<AgentSummary, StoreError> {
    let threshold = now - Duration::minutes(OFFLINE_AFTER_MINUTES);
    let groups = scope.group_ids();
    let global = scope.is_global();
    let row = client
        .query_one(
            "SELECT count(*),
                    count(*) FILTER (WHERE a.status = 'active'
                        AND a.last_seen_at IS NOT NULL AND a.last_seen_at >= $1),
                    count(*) FILTER (WHERE a.status = 'active'
                        AND (a.last_seen_at IS NULL OR a.last_seen_at < $1)),
                    count(*) FILTER (WHERE a.status = 'revoked')
             FROM agents a
             WHERE ($2::boolean OR EXISTS (
                    SELECT 1 FROM console_asset_group_selectors s
                    WHERE s.asset_group_id::text = ANY($3::text[])
                      AND NOT EXISTS (
                        SELECT 1 FROM console_asset_group_selectors required
                        WHERE required.asset_group_id = s.asset_group_id
                          AND NOT EXISTS (
                            SELECT 1 FROM console_agent_tags t
                            WHERE t.agent_id = a.agent_id
                              AND t.tag_key = required.tag_key
                              AND t.tag_value = required.tag_value
                          )
                      )
             ))",
            &[&threshold, &global, &groups],
        )
        .await?;
    Ok(AgentSummary {
        total: row.get(0),
        active: row.get(1),
        stale: row.get(2),
        revoked: row.get(3),
    })
}

/// Returns agents in stable keyset order; scans at most `limit + 1` rows.
pub async fn agents(
    client: &Client,
    query: &AgentQuery,
    now: DateTime<Utc>,
) -> Result<Page<Agent, AgentCursor>, StoreError> {
    agents_in_scope(client, query, now, &AgentScope::Global).await
}

/// Returns only agents visible through the supplied global or asset-group
/// scope. Selector membership is applied in SQL before status filters,
/// keyset pagination, and ordering.
pub async fn agents_in_scope(
    client: &Client,
    query: &AgentQuery,
    now: DateTime<Utc>,
    scope: &AgentScope,
) -> Result<Page<Agent, AgentCursor>, StoreError> {
    let threshold = now - Duration::minutes(OFFLINE_AFTER_MINUTES);
    let state = query.state.map(AgentState::as_db_filter);
    let cursor_seen = query.after.as_ref().and_then(|cursor| cursor.last_seen_at);
    let cursor_id = query.after.as_ref().map(|cursor| cursor.agent_id.as_str());
    let groups = scope.group_ids();
    let global = scope.is_global();
    let rows = client
        .query(
            "SELECT a.agent_id, a.hostname,
                    CASE WHEN a.status = 'revoked' THEN 'revoked'
                         WHEN a.last_seen_at IS NULL OR a.last_seen_at < $1 THEN 'stale'
                         ELSE 'active' END AS state,
                    a.enrolled_at, a.revoked_at, a.last_seen_at, a.scanner_version, a.capabilities
             FROM agents a
             WHERE ($2::text IS NULL OR
                    ($2 = 'active' AND a.status = 'active'
                        AND a.last_seen_at IS NOT NULL AND a.last_seen_at >= $1) OR
                    ($2 = 'stale' AND a.status = 'active'
                        AND (a.last_seen_at IS NULL OR a.last_seen_at < $1)) OR
                    ($2 = 'revoked' AND a.status = 'revoked'))
               AND ($7::boolean OR EXISTS (
                    SELECT 1 FROM console_asset_group_selectors s
                    WHERE s.asset_group_id::text = ANY($8::text[])
                      AND NOT EXISTS (
                        SELECT 1 FROM console_asset_group_selectors required
                        WHERE required.asset_group_id = s.asset_group_id
                          AND NOT EXISTS (
                            SELECT 1 FROM console_agent_tags t
                            WHERE t.agent_id = a.agent_id
                              AND t.tag_key = required.tag_key
                              AND t.tag_value = required.tag_value
                          )
                      )
               ))
               AND ($5::boolean = false OR
                    ($3::timestamptz IS NOT NULL AND
                        (a.last_seen_at < $3 OR (a.last_seen_at = $3 AND a.agent_id > $4)
                         OR a.last_seen_at IS NULL)) OR
                    ($3::timestamptz IS NULL AND a.last_seen_at IS NULL AND a.agent_id > $4))
             ORDER BY a.last_seen_at DESC NULLS LAST, a.agent_id ASC
             LIMIT $6",
            &[
                &threshold,
                &state,
                &cursor_seen,
                &cursor_id,
                &query.after.is_some(),
                &(query.limit.value() + 1),
                &global,
                &groups,
            ],
        )
        .await?;
    let mut items: Vec<_> = rows.iter().map(agent_from_row).collect();
    let next = if items.len() > usize::from(query.limit.0) {
        items.pop();
        items.last().map(|agent| AgentCursor {
            last_seen_at: agent.last_seen_at,
            agent_id: agent.agent_id.clone(),
        })
    } else {
        None
    };
    Ok(Page { items, next })
}

/// Returns one agent without certificate private material.
pub async fn agent(
    client: &Client,
    agent_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<Agent>, StoreError> {
    agent_in_scope(client, agent_id, now, &AgentScope::Global).await
}

/// Returns an agent only when it belongs to the supplied SQL-enforced scope.
/// An out-of-scope id is indistinguishable from an absent id.
pub async fn agent_in_scope(
    client: &Client,
    agent_id: &str,
    now: DateTime<Utc>,
    scope: &AgentScope,
) -> Result<Option<Agent>, StoreError> {
    let threshold = now - Duration::minutes(OFFLINE_AFTER_MINUTES);
    let groups = scope.group_ids();
    let global = scope.is_global();
    let row = client
        .query_opt(
            "SELECT a.agent_id, a.hostname,
                    CASE WHEN a.status = 'revoked' THEN 'revoked'
                         WHEN a.last_seen_at IS NULL OR a.last_seen_at < $2 THEN 'stale'
                         ELSE 'active' END AS state,
                    a.enrolled_at, a.revoked_at, a.last_seen_at, a.scanner_version, a.capabilities
             FROM agents a WHERE a.agent_id = $1
               AND ($3::boolean OR EXISTS (
                    SELECT 1 FROM console_asset_group_selectors s
                    WHERE s.asset_group_id::text = ANY($4::text[])
                      AND NOT EXISTS (
                        SELECT 1 FROM console_asset_group_selectors required
                        WHERE required.asset_group_id = s.asset_group_id
                          AND NOT EXISTS (
                            SELECT 1 FROM console_agent_tags t
                            WHERE t.agent_id = a.agent_id
                              AND t.tag_key = required.tag_key
                              AND t.tag_value = required.tag_value
                          )
                      )
               ))",
            &[&agent_id, &threshold, &global, &groups],
        )
        .await?;
    Ok(row.as_ref().map(agent_from_row))
}

/// Returns one page of certificate metadata, never certificate chains.
pub async fn certificates(
    client: &Client,
    agent_id: &str,
    after: Option<&CertificateCursor>,
    limit: PageLimit,
) -> Result<Page<Certificate, CertificateCursor>, StoreError> {
    certificates_in_scope(client, agent_id, after, limit, &AgentScope::Global).await
}

/// Pages certificate metadata only when the owning agent is visible in SQL.
/// Out-of-scope agents return an empty page, matching an agent with no
/// certificates and avoiding an object-existence side channel.
pub async fn certificates_in_scope(
    client: &Client,
    agent_id: &str,
    after: Option<&CertificateCursor>,
    limit: PageLimit,
    scope: &AgentScope,
) -> Result<Page<Certificate, CertificateCursor>, StoreError> {
    let issued = after.map(|cursor| cursor.issued_at);
    let serial = after.map(|cursor| cursor.serial.as_slice());
    let groups = scope.group_ids();
    let global = scope.is_global();
    let rows = client
        .query(
            "SELECT c.serial, c.not_before, c.not_after, c.issued_at FROM certificates c
             WHERE c.agent_id = $1
               AND EXISTS (
                   SELECT 1 FROM agents a
                   WHERE a.agent_id = c.agent_id
                     AND ($6::boolean OR EXISTS (
                        SELECT 1 FROM console_asset_group_selectors s
                        WHERE s.asset_group_id::text = ANY($7::text[])
                          AND NOT EXISTS (
                            SELECT 1 FROM console_asset_group_selectors required
                            WHERE required.asset_group_id = s.asset_group_id
                              AND NOT EXISTS (
                                SELECT 1 FROM console_agent_tags t
                                WHERE t.agent_id = a.agent_id
                                  AND t.tag_key = required.tag_key
                                  AND t.tag_value = required.tag_value
                              )
                          )
                     ))
               )
               AND ($4::boolean = false OR c.issued_at < $2
                    OR (c.issued_at = $2 AND c.serial > $3))
             ORDER BY c.issued_at DESC, c.serial ASC LIMIT $5",
            &[
                &agent_id,
                &issued,
                &serial,
                &after.is_some(),
                &(limit.value() + 1),
                &global,
                &groups,
            ],
        )
        .await?;
    let mut items: Vec<_> = rows.iter().map(certificate_from_row).collect();
    let next = if items.len() > usize::from(limit.0) {
        items.pop();
        items.last().map(|certificate| CertificateCursor {
            issued_at: certificate.issued_at,
            serial: certificate.serial.clone(),
        })
    } else {
        None
    };
    Ok(Page { items, next })
}

/// Counts current observations and severities in one aggregate query.
pub async fn finding_summary(client: &Client) -> Result<FindingSummary, StoreError> {
    finding_summary_in_scope(client, &AgentScope::Global).await
}

/// Counts current observations and severities for agents visible in SQL.
pub async fn finding_summary_in_scope(
    client: &Client,
    scope: &AgentScope,
) -> Result<FindingSummary, StoreError> {
    let groups = scope.group_ids();
    let global = scope.is_global();
    let visible_agent = agent_visibility("a.agent_id", "$1", "$2");
    let row = client
        .query_one(
            &format!(
                "SELECT count(*), count(DISTINCT c.agent_id),
                        count(*) FILTER (WHERE c.severity = 'critical'),
                        count(*) FILTER (WHERE c.severity = 'high'),
                        count(*) FILTER (WHERE c.severity = 'medium'),
                        count(*) FILTER (WHERE c.severity = 'low')
                 FROM current_findings c JOIN agents a USING (agent_id)
                 WHERE {visible_agent}"
            ),
            &[&global, &groups],
        )
        .await?;
    Ok(FindingSummary {
        total: row.get(0),
        impacted_agents: row.get(1),
        critical: row.get(2),
        high: row.get(3),
        medium: row.get(4),
        low: row.get(5),
    })
}

/// Returns latest observations in stable keyset order.
pub async fn latest_findings(
    client: &Client,
    query: &LatestQuery,
) -> Result<Page<LatestFinding, LatestCursor>, StoreError> {
    latest_findings_in_scope(client, query, &AgentScope::Global).await
}

/// Returns latest observations only for agents visible through the supplied
/// SQL-enforced scope, before filters, ordering, or cursor pagination.
pub async fn latest_findings_in_scope(
    client: &Client,
    query: &LatestQuery,
    scope: &AgentScope,
) -> Result<Page<LatestFinding, LatestCursor>, StoreError> {
    let severity = query.severity.map(Severity::as_str);
    let cursor = query.after.as_ref();
    let groups = scope.group_ids();
    let global = scope.is_global();
    let visible_agent = agent_visibility("a.agent_id", "$8", "$9");
    let rows = client
        .query(
            &format!(
                "SELECT c.last_finding_id, c.agent_id, a.hostname, c.rule_set_id, c.rule_id,
                    c.rule_version, c.severity, c.confidence, c.message, c.evidence,
                    c.scan_id, c.authenticated, c.origin, c.first_observed_at,
                    c.last_observed_at, c.received_at
             FROM current_findings c JOIN agents a USING (agent_id)
             WHERE {visible_agent}
               AND ($1::text IS NULL OR c.severity = $1)
               AND ($6::boolean = false OR
                    c.last_observed_at < $2 OR
                    (c.last_observed_at = $2 AND
                        (c.agent_id, c.rule_set_id, c.rule_id) > ($3, $4, $5)))
             ORDER BY c.last_observed_at DESC, c.agent_id ASC,
                      c.rule_set_id ASC, c.rule_id ASC
             LIMIT $7"
            ),
            &[
                &severity,
                &cursor.map(|value| value.last_observed_at),
                &cursor.map(|value| value.agent_id.as_str()),
                &cursor.map(|value| value.rule_set_id.as_str()),
                &cursor.map(|value| value.rule_id.as_str()),
                &cursor.is_some(),
                &(query.limit.value() + 1),
                &global,
                &groups,
            ],
        )
        .await?;
    let mut items: Vec<_> = rows.iter().map(latest_from_row).collect();
    let next = if items.len() > usize::from(query.limit.0) {
        items.pop();
        items.last().map(|finding| LatestCursor {
            last_observed_at: finding.last_observed_at,
            agent_id: finding.agent_id.clone(),
            rule_set_id: finding.rule_set_id.clone(),
            rule_id: finding.rule_id.clone(),
        })
    } else {
        None
    };
    Ok(Page { items, next })
}

/// Finds a latest observation by its composite primary key.
pub async fn latest_finding(
    client: &Client,
    agent_id: &str,
    rule_set_id: &str,
    rule_id: &str,
) -> Result<Option<LatestFinding>, StoreError> {
    latest_finding_in_scope(client, agent_id, rule_set_id, rule_id, &AgentScope::Global).await
}

/// Finds one latest observation only when its agent is visible in SQL.
pub async fn latest_finding_in_scope(
    client: &Client,
    agent_id: &str,
    rule_set_id: &str,
    rule_id: &str,
    scope: &AgentScope,
) -> Result<Option<LatestFinding>, StoreError> {
    let groups = scope.group_ids();
    let global = scope.is_global();
    let visible_agent = agent_visibility("a.agent_id", "$4", "$5");
    let row = client
        .query_opt(
            &format!(
                "SELECT c.last_finding_id, c.agent_id, a.hostname, c.rule_set_id, c.rule_id,
                    c.rule_version, c.severity, c.confidence, c.message, c.evidence,
                    c.scan_id, c.authenticated, c.origin, c.first_observed_at,
                    c.last_observed_at, c.received_at
             FROM current_findings c JOIN agents a USING (agent_id)
             WHERE c.agent_id = $1 AND c.rule_set_id = $2 AND c.rule_id = $3
               AND {visible_agent}"
            ),
            &[&agent_id, &rule_set_id, &rule_id, &global, &groups],
        )
        .await?;
    Ok(row.as_ref().map(latest_from_row))
}

/// Returns a bounded history page in a required time window.
pub async fn finding_history(
    client: &Client,
    query: &HistoryQuery,
) -> Result<Page<FindingEvent, HistoryCursor>, StoreError> {
    finding_history_in_scope(client, query, &AgentScope::Global).await
}

/// Returns retained history only for agents visible in SQL, while preserving
/// the required lower time bound for partition pruning.
pub async fn finding_history_in_scope(
    client: &Client,
    query: &HistoryQuery,
    scope: &AgentScope,
) -> Result<Page<FindingEvent, HistoryCursor>, StoreError> {
    let cursor = query.after.as_ref();
    let groups = scope.group_ids();
    let global = scope.is_global();
    let visible_agent = agent_visibility("f.agent_id", "$11", "$12");
    let rows = client
        .query(
            &format!(
            "SELECT f.finding_id, f.observed_day, f.agent_id, f.rule_set_id, f.rule_id, f.rule_version,
                    severity, confidence, message, evidence, scan_id, authenticated,
                    origin, observed_at, received_at
             FROM findings f
             WHERE f.observed_day >= $1 AND f.observed_at >= $2
               AND {visible_agent}
               AND ($3::text IS NULL OR f.agent_id = $3)
               AND ($4::text IS NULL OR f.rule_set_id = $4)
               AND ($5::text IS NULL OR f.rule_id = $5)
               AND ($9::boolean = false OR f.observed_at < $6
                    OR (f.observed_at = $6 AND f.observed_day < $7)
                    OR (f.observed_at = $6 AND f.observed_day = $7 AND f.finding_id > $8))
             ORDER BY f.observed_at DESC, f.observed_day DESC, f.finding_id ASC
             LIMIT $10"),
            &[
                &query.since.date_naive(),
                &query.since,
                &query.agent_id,
                &query.rule_set_id,
                &query.rule_id,
                &cursor.map(|value| value.observed_at),
                &cursor.map(|value| value.observed_day),
                &cursor.map(|value| value.finding_id.as_str()),
                &cursor.is_some(),
                &(query.limit.value() + 1),
                &global,
                &groups,
            ],
        )
        .await?;
    let mut items: Vec<_> = rows.iter().map(history_from_row).collect();
    let next = if items.len() > usize::from(query.limit.0) {
        items.pop();
        items.last().map(|event| HistoryCursor {
            observed_at: event.observed_at,
            observed_day: event.observed_day,
            finding_id: event.finding_id.clone(),
        })
    } else {
        None
    };
    Ok(Page { items, next })
}

/// Returns one retained history event by its partition primary key.
pub async fn finding_event(
    client: &Client,
    observed_day: NaiveDate,
    finding_id: &str,
) -> Result<Option<FindingEvent>, StoreError> {
    finding_event_in_scope(client, observed_day, finding_id, &AgentScope::Global).await
}

/// Returns a retained event only when its agent is visible through the
/// supplied scope; hidden events are indistinguishable from absent events.
pub async fn finding_event_in_scope(
    client: &Client,
    observed_day: NaiveDate,
    finding_id: &str,
    scope: &AgentScope,
) -> Result<Option<FindingEvent>, StoreError> {
    let groups = scope.group_ids();
    let global = scope.is_global();
    let visible_agent = agent_visibility("f.agent_id", "$3", "$4");
    let row = client
        .query_opt(
            &format!(
            "SELECT f.finding_id, f.observed_day, f.agent_id, f.rule_set_id, f.rule_id, f.rule_version,
                    severity, confidence, message, evidence, scan_id, authenticated,
                    origin, observed_at, received_at
             FROM findings f WHERE f.observed_day = $1 AND f.finding_id = $2
               AND {visible_agent}"),
            &[&observed_day, &finding_id, &global, &groups],
        )
        .await?;
    Ok(row.as_ref().map(history_from_row))
}

fn agent_from_row(row: &Row) -> Agent {
    Agent {
        agent_id: row.get(0),
        hostname: row.get(1),
        state: match row.get::<_, &str>(2) {
            "revoked" => AgentState::Revoked,
            "stale" => AgentState::Stale,
            _ => AgentState::Active,
        },
        enrolled_at: row.get(3),
        revoked_at: row.get(4),
        last_seen_at: row.get(5),
        scanner_version: row.get(6),
        capabilities: row.get(7),
    }
}

fn certificate_from_row(row: &Row) -> Certificate {
    Certificate {
        serial: row.get(0),
        not_before: row.get(1),
        not_after: row.get(2),
        issued_at: row.get(3),
    }
}

fn latest_from_row(row: &Row) -> LatestFinding {
    LatestFinding {
        finding_id: row.get(0),
        agent_id: row.get(1),
        hostname: row.get(2),
        rule_set_id: row.get(3),
        rule_id: row.get(4),
        rule_version: row.get(5),
        severity: severity_from_db(row.get::<_, &str>(6)),
        confidence: row.get(7),
        message: row.get(8),
        evidence: row.get(9),
        scan_id: row.get(10),
        authenticated: row.get(11),
        origin: row.get(12),
        first_observed_at: row.get(13),
        last_observed_at: row.get(14),
        received_at: row.get(15),
    }
}

fn history_from_row(row: &Row) -> FindingEvent {
    FindingEvent {
        finding_id: row.get(0),
        observed_day: row.get(1),
        agent_id: row.get(2),
        rule_set_id: row.get(3),
        rule_id: row.get(4),
        rule_version: row.get(5),
        severity: severity_from_db(row.get::<_, &str>(6)),
        confidence: row.get(7),
        message: row.get(8),
        evidence: row.get(9),
        scan_id: row.get(10),
        authenticated: row.get(11),
        origin: row.get(12),
        observed_at: row.get(13),
        received_at: row.get(14),
    }
}

fn severity_from_db(value: &str) -> Severity {
    match value {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}
