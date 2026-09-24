//! Queries the ingest service runs, all within the `openvibes_ingest`
//! role's grants.

use chrono::{DateTime, Duration, Utc};

use crate::{Client, StoreError};

/// Heartbeats refresh `last_seen_at` at most this often.
const HEARTBEAT_WRITE_MINUTES: i64 = 5;

/// An enrollment token as ingest sees it; never the token itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenRow {
    /// Token id (UUID).
    pub token_id: String,
    /// End of validity.
    pub expires_at: DateTime<Utc>,
    /// Enrollments it allows.
    pub max_uses: i32,
    /// Whether it was revoked.
    pub revoked: bool,
}

/// An agent identity to hand back to the agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    /// Platform-assigned id.
    pub agent_id: String,
    /// Leaf, then the issuing CA.
    pub chain_pem: Vec<String>,
    /// Leaf expiry.
    pub not_after: DateTime<Utc>,
}

/// Outcome of [`enroll`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Enrolled {
    /// A new agent was created.
    New(Identity),
    /// The same token and key enrolled before: the protocol's retry rule.
    Existing(Identity),
    /// The token has no uses left.
    Exhausted,
    /// The token was revoked or has expired (checked under the token lock,
    /// so a revocation racing the request cannot slip through).
    TokenInvalid,
    /// A same-key retry whose agent has since been revoked; a revoked
    /// identity is never handed out again.
    AgentRevoked,
}

/// A certificate issued for an agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedCert {
    /// Serial as encoded in the certificate (16 bytes).
    pub serial: [u8; 16],
    /// SHA-256 of the certified key's SubjectPublicKeyInfo.
    pub spki_sha256: [u8; 32],
    /// Start of validity.
    pub not_before: DateTime<Utc>,
    /// End of validity.
    pub not_after: DateTime<Utc>,
    /// Leaf, then the issuing CA.
    pub chain_pem: Vec<String>,
}

/// Result of [`authenticate`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Authenticated {
    /// A recorded certificate of an active agent.
    Active(String),
    /// A recorded certificate of a revoked agent.
    Revoked,
    /// Not a recorded certificate (serial unknown or key different).
    Unknown,
}

/// A finding to store, attributed to the authenticated agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredFinding {
    /// Stable, idempotent id.
    pub finding_id: String,
    /// Scan that produced it.
    pub scan_id: String,
    /// Matching rule.
    pub rule_id: String,
    /// Rule version.
    pub rule_version: i64,
    /// Observation time on the agent.
    pub observed_at: DateTime<Utc>,
    /// Severity name.
    pub severity: String,
    /// Confidence 0 to 100.
    pub confidence: i16,
    /// Rule message.
    pub message: String,
    /// Evidence fact keys.
    pub evidence: Vec<String>,
}

fn chain_json(chain: &[String]) -> Result<String, StoreError> {
    serde_json::to_string(chain).map_err(|_| StoreError::Query)
}

fn chain_from_json(json: &str) -> Result<Vec<String>, StoreError> {
    serde_json::from_str(json).map_err(|_| StoreError::Query)
}

/// The token with this hash, if any.
pub async fn token_by_hash(
    client: &Client,
    sha256: [u8; 32],
) -> Result<Option<TokenRow>, StoreError> {
    let row = client
        .query_opt(
            "SELECT token_id::text, expires_at, max_uses, revoked_at IS NOT NULL
             FROM enrollment_tokens WHERE token_sha256 = $1",
            &[&sha256.as_slice()],
        )
        .await?;
    Ok(row.map(|row| TokenRow {
        token_id: row.get(0),
        expires_at: row.get(1),
        max_uses: row.get(2),
        revoked: row.get(3),
    }))
}

/// Enrolls with a token in one transaction, serialized per token so a
/// single-use token yields exactly one identity. A retry with the same token
/// and key returns the stored identity. Otherwise, if uses remain, `issue`
/// receives a fresh agent id, and the agent, its certificate, the token use,
/// and an audit entry are recorded together.
pub async fn enroll(
    client: &mut Client,
    token_id: &str,
    spki_sha256: [u8; 32],
    now: DateTime<Utc>,
    issue: impl FnOnce(&str) -> Result<IssuedCert, StoreError>,
) -> Result<Enrolled, StoreError> {
    let transaction = client.transaction().await?;
    transaction
        .execute("SELECT pg_advisory_xact_lock(hashtext($1))", &[&token_id])
        .await?;
    let existing = transaction
        .query_opt(
            "SELECT u.agent_id, c.chain_pem, c.not_after, a.status = 'revoked'
             FROM token_uses u JOIN certificates c ON c.serial = u.serial
             JOIN agents a ON a.agent_id = u.agent_id
             WHERE u.token_id = $1::text::uuid AND u.spki_sha256 = $2",
            &[&token_id, &spki_sha256.as_slice()],
        )
        .await?;
    if let Some(row) = existing {
        if row.get::<_, bool>(3) {
            transaction.commit().await?;
            return Ok(Enrolled::AgentRevoked);
        }
        let chain: String = row.get(1);
        let identity = Identity {
            agent_id: row.get(0),
            chain_pem: chain_from_json(&chain)?,
            not_after: row.get(2),
        };
        transaction.commit().await?;
        return Ok(Enrolled::Existing(identity));
    }
    let (uses, max_uses, valid): (i64, i32, bool) = {
        let row = transaction
            .query_one(
                "SELECT (SELECT count(*) FROM token_uses WHERE token_id = t.token_id), t.max_uses,
                        t.revoked_at IS NULL AND t.expires_at > $2
                 FROM enrollment_tokens t WHERE t.token_id = $1::text::uuid",
                &[&token_id, &now],
            )
            .await?;
        (row.get(0), row.get(1), row.get(2))
    };
    if !valid {
        transaction.commit().await?;
        return Ok(Enrolled::TokenInvalid);
    }
    if uses >= i64::from(max_uses) {
        transaction.commit().await?;
        return Ok(Enrolled::Exhausted);
    }
    let agent_id: String = transaction
        .query_one("SELECT 'agent.' || gen_random_uuid()::text", &[])
        .await?
        .get(0);
    let cert = issue(&agent_id)?;
    transaction
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', $2)",
            &[&agent_id, &now],
        )
        .await?;
    insert_certificate(&transaction, &agent_id, &cert, now).await?;
    transaction
        .execute(
            "INSERT INTO token_uses (token_id, spki_sha256, agent_id, serial, used_at)
             VALUES ($1::text::uuid, $2, $3, $4, $5)",
            &[
                &token_id,
                &spki_sha256.as_slice(),
                &agent_id,
                &cert.serial.as_slice(),
                &now,
            ],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO audit_log (actor, action, target, result)
             VALUES ('openvibes-ingest', 'enroll', $1, 'ok')",
            &[&agent_id],
        )
        .await?;
    transaction.commit().await?;
    Ok(Enrolled::New(Identity {
        agent_id,
        chain_pem: cert.chain_pem,
        not_after: cert.not_after,
    }))
}

async fn insert_certificate(
    client: &impl deadpool_postgres::GenericClient,
    agent_id: &str,
    cert: &IssuedCert,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    client
        .execute(
            "INSERT INTO certificates (serial, agent_id, spki_sha256, not_before, not_after, issued_at, chain_pem)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &cert.serial.as_slice(),
                &agent_id,
                &cert.spki_sha256.as_slice(),
                &cert.not_before,
                &cert.not_after,
                &now,
                &chain_json(&cert.chain_pem)?,
            ],
        )
        .await?;
    Ok(())
}

/// Records a renewed certificate for an existing agent.
pub async fn add_certificate(
    client: &Client,
    agent_id: &str,
    cert: &IssuedCert,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    insert_certificate(client, agent_id, cert, now).await
}

/// Matches a presented leaf: the serial must be recorded **and** its key
/// hash must match; then the agent's status decides.
pub async fn authenticate(
    client: &Client,
    serial: &[u8],
    spki_sha256: [u8; 32],
) -> Result<Authenticated, StoreError> {
    let row = client
        .query_opt(
            "SELECT a.agent_id, a.status, c.spki_sha256
             FROM certificates c JOIN agents a ON a.agent_id = c.agent_id
             WHERE c.serial = $1",
            &[&serial],
        )
        .await?;
    let Some(row) = row else {
        return Ok(Authenticated::Unknown);
    };
    let recorded: Vec<u8> = row.get(2);
    if recorded != spki_sha256 {
        return Ok(Authenticated::Unknown);
    }
    let status: String = row.get(1);
    Ok(if status == "active" {
        Authenticated::Active(row.get(0))
    } else {
        Authenticated::Revoked
    })
}

/// Records a heartbeat, writing at most once per 5 minutes per agent unless
/// the hostname changed. A present hostname replaces the stored one; an
/// absent one keeps it. Returns whether a write happened.
pub async fn heartbeat(
    client: &Client,
    agent_id: &str,
    version: &str,
    hostname: Option<&str>,
    capabilities: &[String],
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let stale_before = now - Duration::minutes(HEARTBEAT_WRITE_MINUTES);
    let changed = client
        .execute(
            "UPDATE agents SET last_seen_at = $2, scanner_version = $3, capabilities = $4,
                 hostname = COALESCE($6, hostname)
             WHERE agent_id = $1
               AND (last_seen_at IS NULL OR last_seen_at < $5
                    OR hostname IS DISTINCT FROM COALESCE($6, hostname))",
            &[
                &agent_id,
                &now,
                &version,
                &capabilities,
                &stale_before,
                &hostname,
            ],
        )
        .await?;
    Ok(changed == 1)
}

/// Stores a batch in one transaction; findings already stored are skipped.
/// Updates the current-state row per rule. Returns how many were new.
pub async fn store_findings(
    client: &mut Client,
    agent_id: &str,
    findings: &[StoredFinding],
    now: DateTime<Utc>,
) -> Result<u64, StoreError> {
    let transaction = client.transaction().await?;
    let mut stored = 0;
    for finding in findings {
        let day = finding.observed_at.date_naive();
        stored += transaction
            .execute(
                "INSERT INTO findings (finding_id, observed_day, observed_at, agent_id, scan_id,
                     rule_id, rule_version, severity, confidence, message, evidence, received_at,
                     origin, authenticated)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'online', true)
                 ON CONFLICT DO NOTHING",
                &[
                    &finding.finding_id,
                    &day,
                    &finding.observed_at,
                    &agent_id,
                    &finding.scan_id,
                    &finding.rule_id,
                    &finding.rule_version,
                    &finding.severity,
                    &finding.confidence,
                    &finding.message,
                    &finding.evidence,
                    &now,
                ],
            )
            .await?;
        transaction
            .execute(
                "INSERT INTO current_findings (agent_id, rule_id, last_finding_id, rule_version,
                     severity, first_observed_at, last_observed_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $6)
                 ON CONFLICT (agent_id, rule_id) DO UPDATE SET
                     last_finding_id = CASE WHEN EXCLUDED.last_observed_at > current_findings.last_observed_at
                         THEN EXCLUDED.last_finding_id ELSE current_findings.last_finding_id END,
                     rule_version = CASE WHEN EXCLUDED.last_observed_at > current_findings.last_observed_at
                         THEN EXCLUDED.rule_version ELSE current_findings.rule_version END,
                     severity = CASE WHEN EXCLUDED.last_observed_at > current_findings.last_observed_at
                         THEN EXCLUDED.severity ELSE current_findings.severity END,
                     first_observed_at = LEAST(current_findings.first_observed_at, EXCLUDED.first_observed_at),
                     last_observed_at = GREATEST(current_findings.last_observed_at, EXCLUDED.last_observed_at)",
                &[
                    &agent_id,
                    &finding.rule_id,
                    &finding.finding_id,
                    &finding.rule_version,
                    &finding.severity,
                    &finding.observed_at,
                ],
            )
            .await?;
    }
    transaction.commit().await?;
    Ok(stored)
}
