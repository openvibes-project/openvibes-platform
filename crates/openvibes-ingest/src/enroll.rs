use axum::{Json, body::Bytes, extract::State};
use chrono::Utc;
use openvibes_core::{
    EnrollmentRequest, EnrollmentResponse, Identifier, RenewalRequest, SchemaVersion,
};
use platform_pki::{CheckedCsr, IssuedClient};
use platform_store::{
    StoreError,
    ingest::{self, Enrolled, Identity, IssuedCert},
};

use crate::{auth::AuthenticatedAgent, error::ApiError, request::parse, server::AppState};

fn to_store(issued: IssuedClient) -> IssuedCert {
    IssuedCert {
        serial: issued.serial,
        spki_sha256: issued.spki_sha256,
        not_before: issued.not_before,
        not_after: issued.not_after,
        chain_pem: issued.chain_pem,
    }
}

fn respond(identity: Identity) -> Result<Json<EnrollmentResponse>, ApiError> {
    Ok(Json(EnrollmentResponse {
        schema_version: SchemaVersion::V1,
        agent_id: Identifier::new(identity.agent_id).map_err(|_| ApiError::Unavailable)?,
        certificate_chain_pem: identity.chain_pem,
        expires_at_unix_ms: identity.not_after.timestamp_millis(),
    }))
}

fn issue(state: &AppState, csr: &CheckedCsr, agent_id: &str) -> Result<IssuedCert, StoreError> {
    state
        .issuer
        .issue_client(csr, agent_id, Utc::now(), state.client_certificate_days)
        .map(to_store)
        .map_err(|_| StoreError::Query)
}

/// `POST /v1/enroll` (no client certificate): a token and a CSR for a new
/// identity. A retry with the same token and key returns the same identity.
pub(crate) async fn enroll(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<EnrollmentResponse>, ApiError> {
    let request: EnrollmentRequest = parse(&body)?;
    let hash = platform_pki::enrollment_token_sha256(request.token.expose_secret())
        .ok_or(ApiError::Unauthorized)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    let now = Utc::now();
    let token = ingest::token_by_hash(&client, hash)
        .await?
        .filter(|token| !token.revoked && token.expires_at > now)
        .ok_or(ApiError::Unauthorized)?;
    let csr = platform_pki::check_csr(&request.csr_pem).map_err(|_| ApiError::BadRequest)?;
    match ingest::enroll(
        &mut client,
        &token.token_id,
        csr.spki_sha256,
        now,
        |agent_id| issue(&state, &csr, agent_id),
    )
    .await?
    {
        Enrolled::New(identity) | Enrolled::Existing(identity) => respond(identity),
        Enrolled::Exhausted => Err(ApiError::Unauthorized),
    }
}

/// `POST /v1/renew`: a new certificate for the authenticated agent's own id.
pub(crate) async fn renew(
    State(state): State<AppState>,
    AuthenticatedAgent(agent_id): AuthenticatedAgent,
    body: Bytes,
) -> Result<Json<EnrollmentResponse>, ApiError> {
    let request: RenewalRequest = parse(&body)?;
    let csr = platform_pki::check_csr(&request.csr_pem).map_err(|_| ApiError::BadRequest)?;
    let cert = issue(&state, &csr, &agent_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    ingest::add_certificate(&client, &agent_id, &cert, Utc::now()).await?;
    respond(Identity {
        agent_id,
        chain_pem: cert.chain_pem,
        not_after: cert.not_after,
    })
}
