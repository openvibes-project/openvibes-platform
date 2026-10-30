//! SAML single sign-on storage: the sign-ins in progress, the assertions
//! already accepted, and the people who sign in through the identity
//! provider (spec 2026-10-29 §6). Nothing here decides who may sign in;
//! the console validates the response first.

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};

use crate::{Client, StoreError, console_auth::AuditContext};

/// Sign-ins that may be waiting at once; more are refused so an anonymous
/// caller cannot grow the table without bound.
const MAX_PENDING: i64 = 2_000;

/// A sign-in the console started.
#[derive(Clone, Debug)]
pub struct NewRequest<'a> {
    /// SHA-256 of the random relay token sent to the identity provider.
    pub relay_sha256: &'a [u8],
    /// The AuthnRequest ID the identity provider must answer.
    pub request_id: &'a str,
    /// SHA-256 of the cookie that ties the answer to this browser.
    pub browser_sha256: &'a [u8],
    /// Now.
    pub now: DateTime<Utc>,
    /// When it stops being accepted.
    pub expires_at: DateTime<Utc>,
}

/// Records a started sign-in and forgets the expired ones.
///
/// # Errors
/// The database could not be written.
pub async fn start_request(client: &Client, new: &NewRequest<'_>) -> Result<bool, StoreError> {
    client
        .execute(
            "DELETE FROM console_saml_requests WHERE expires_at < $1",
            &[&new.now],
        )
        .await?;
    client
        .execute(
            "DELETE FROM console_saml_seen WHERE expires_at < $1",
            &[&new.now],
        )
        .await?;
    let pending: i64 = client
        .query_one("SELECT count(*) FROM console_saml_requests", &[])
        .await?
        .get(0);
    if pending >= MAX_PENDING {
        return Ok(false);
    }
    client
        .execute(
            "INSERT INTO console_saml_requests
                (relay_sha256, request_id, browser_sha256, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &new.relay_sha256,
                &new.request_id,
                &new.browser_sha256,
                &new.now,
                &new.expires_at,
            ],
        )
        .await?;
    Ok(true)
}

/// Uses up the sign-in for this relay token and browser, once: returns the
/// request ID the response must answer, or `None` when there is no such
/// sign-in, it expired, it was already used or it started in another browser.
///
/// # Errors
/// The database could not be written.
pub async fn take_request(
    client: &Client,
    relay_sha256: &[u8],
    browser_sha256: &[u8],
    now: DateTime<Utc>,
) -> Result<Option<String>, StoreError> {
    let row = client
        .query_opt(
            "UPDATE console_saml_requests SET consumed_at = $3
             WHERE relay_sha256 = $1 AND browser_sha256 = $2
               AND consumed_at IS NULL AND expires_at > $3
             RETURNING request_id",
            &[&relay_sha256, &browser_sha256, &now],
        )
        .await?;
    Ok(row.map(|row| row.get(0)))
}

/// Who signed in and what the identity provider said about them.
#[derive(Clone, Debug)]
pub struct Person<'a> {
    /// The identity provider's entity ID.
    pub issuer: &'a str,
    /// The NameID: the person's stable identifier there.
    pub subject: &'a str,
    /// Shown name (already bounded by the caller).
    pub display_name: &'a str,
    /// Email, if the identity provider gave one.
    pub email: Option<&'a str>,
    /// The assertion's ID, for replay protection.
    pub assertion_id: &'a str,
    /// How long the assertion could still be valid.
    pub assertion_expires_at: DateTime<Utc>,
    /// The group names from the assertion, lower case.
    pub groups: &'a [String],
    /// Now.
    pub now: DateTime<Utc>,
}

/// What came of a sign-in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignIn {
    /// Signed in; the user's roles now match their groups.
    Allowed {
        /// The console user.
        user_id: String,
        /// The generation a session must carry.
        auth_generation: i64,
        /// Whether this created the user.
        created: bool,
    },
    /// The assertion was accepted before.
    Replay,
    /// None of the groups matches a role.
    NoRole,
    /// An administrator disabled this person.
    Disabled,
}

/// Finds or creates the person, replaces their identity-provider roles with
/// those their groups name, and remembers the assertion, all at once.
///
/// # Errors
/// The database could not be written.
pub async fn sign_in(client: &mut Client, person: &Person<'_>) -> Result<SignIn, StoreError> {
    let tx = client.transaction().await?;
    let fresh = tx
        .execute(
            "INSERT INTO console_saml_seen (assertion_sha256, expires_at) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
            &[
                &sha(&[person.issuer, person.assertion_id]).as_slice(),
                &person.assertion_expires_at,
            ],
        )
        .await?;
    if fresh == 0 {
        tx.rollback().await?;
        return Ok(SignIn::Replay);
    }
    let wanted: Vec<String> = tx
        .query(
            "SELECT role_id FROM console_roles WHERE lower(display_name) = ANY($1) ORDER BY role_id",
            &[&person.groups],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect();
    let existing = tx
        .query_opt(
            "SELECT u.user_id::text, u.enabled, u.auth_generation
             FROM console_sso_users s JOIN console_users u USING (user_id)
             WHERE s.issuer = $1 AND s.subject = $2 FOR UPDATE OF u",
            &[&person.issuer, &person.subject],
        )
        .await?;
    let (user_id, auth_generation, created) = match existing {
        Some(row) => {
            let enabled: bool = row.get(1);
            if !enabled {
                tx.rollback().await?;
                return Ok(SignIn::Disabled);
            }
            (row.get::<_, String>(0), row.get::<_, i64>(2), false)
        }
        None if wanted.is_empty() => {
            // Nobody is created without a role.
            tx.rollback().await?;
            return Ok(SignIn::NoRole);
        }
        None => {
            let username = format!("sso.{}", hex(&sha(&[person.issuer, person.subject])[..8]));
            let row = tx
                .query_one(
                    "INSERT INTO console_users
                        (user_id, username, display_name, created_at, auth_source, email)
                     VALUES (gen_random_uuid(), $1, $2, $3, 'sso', $4)
                     RETURNING user_id::text, auth_generation",
                    &[&username, &person.display_name, &person.now, &person.email],
                )
                .await?;
            let user_id: String = row.get(0);
            tx.execute(
                "INSERT INTO console_sso_users (user_id, issuer, subject, created_at)
                 VALUES ($1::text::uuid, $2, $3, $4)",
                &[&user_id, &person.issuer, &person.subject, &person.now],
            )
            .await?;
            audit(
                &tx,
                "user.created",
                &user_id,
                &username,
                serde_json::json!({"source": "sso"}),
                person.now,
            )
            .await?;
            (user_id, row.get(1), true)
        }
    };
    if !created {
        tx.execute(
            "UPDATE console_users SET display_name = $2, email = $3 WHERE user_id = $1::text::uuid",
            &[&user_id, &person.display_name, &person.email],
        )
        .await?;
    }
    // Roles from the identity provider follow its groups; roles granted by
    // hand are left alone.
    let current: Vec<(String, String)> = tx
        .query(
            "SELECT binding_id::text, role_id FROM console_role_bindings
             WHERE user_id = $1::text::uuid AND revoked_at IS NULL AND source = 'sso'",
            &[&user_id],
        )
        .await?
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    for (binding_id, role_id) in &current {
        if !wanted.contains(role_id) {
            tx.execute(
                "UPDATE console_role_bindings SET revoked_at = $2, revoked_by = 'console-sso'
                 WHERE binding_id = $1::text::uuid",
                &[binding_id, &person.now],
            )
            .await?;
            audit(
                &tx,
                "rbac.binding.revoked",
                binding_id,
                "role_binding",
                serde_json::json!({"role_id": role_id, "user_id": user_id, "source": "sso"}),
                person.now,
            )
            .await?;
        }
    }
    for role_id in &wanted {
        let held = tx
            .query_opt(
                "SELECT 1 FROM console_role_bindings
                 WHERE user_id = $1::text::uuid AND role_id = $2 AND revoked_at IS NULL",
                &[&user_id, role_id],
            )
            .await?
            .is_some();
        if !held {
            let binding_id: String = tx
                .query_one(
                    "INSERT INTO console_role_bindings
                        (binding_id, user_id, role_id, created_at, created_by, source)
                     VALUES (gen_random_uuid(), $1::text::uuid, $2, $3, 'console-sso', 'sso')
                     RETURNING binding_id::text",
                    &[&user_id, role_id, &person.now],
                )
                .await?
                .get(0);
            audit(
                &tx,
                "rbac.binding.created",
                &binding_id,
                "role_binding",
                serde_json::json!({"role_id": role_id, "user_id": user_id, "source": "sso"}),
                person.now,
            )
            .await?;
        }
    }
    // A person who still holds a role (even one granted by hand) may sign in.
    let remaining: i64 = tx
        .query_one(
            "SELECT count(*) FROM console_role_bindings
             WHERE user_id = $1::text::uuid AND revoked_at IS NULL",
            &[&user_id],
        )
        .await?
        .get(0);
    let outcome = if remaining == 0 {
        SignIn::NoRole
    } else {
        SignIn::Allowed {
            user_id,
            auth_generation,
            created,
        }
    };
    tx.commit().await?;
    Ok(outcome)
}

/// Records a refused sign-in. `reason` is a fixed word, never part of the
/// response the identity provider sent.
///
/// # Errors
/// The database could not be written.
pub async fn refuse(
    client: &Client,
    context: &AuditContext<'_>,
    reason: &str,
) -> Result<(), StoreError> {
    client
        .execute(
            "INSERT INTO audit_log
                (actor, action, result, detail, request_id, actor_kind, authentication_method,
                 reason_code, source_address, user_agent)
             VALUES ('console-sso', 'auth.saml.refused', 'failure',
                     jsonb_build_object('reason_code', $1::text), $2, 'anonymous', 'saml',
                     $1, $3::text::inet, $4)",
            &[
                &reason,
                &context.request_id,
                &context.source_address,
                &context.user_agent,
            ],
        )
        .await?;
    Ok(())
}

/// How long an assertion is remembered at least: an hour past its own end.
#[must_use]
pub fn remember_until(not_on_or_after: DateTime<Utc>) -> DateTime<Utc> {
    not_on_or_after + Duration::hours(1)
}

async fn audit(
    tx: &tokio_postgres::Transaction<'_>,
    action: &str,
    target_id: &str,
    target: &str,
    detail: serde_json::Value,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO audit_log (at, actor, action, target, result, detail, actor_kind,
             actor_id, actor_display, authentication_method, target_kind, target_id)
         VALUES ($1, 'console-sso', $2, $3, 'success', $4, 'system', 'console-sso',
                 'Single sign-on', 'saml', $5, $6)",
        &[
            &now,
            &action,
            &target,
            &detail,
            &if action.starts_with("user.") {
                "user"
            } else {
                "role_binding"
            },
            &target_id,
        ],
    )
    .await?;
    Ok(())
}

fn sha(parts: &[&str]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"openvibes-console-sso-v1\0");
    for part in parts {
        hash.update(part.as_bytes());
        hash.update([0]);
    }
    hash.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
