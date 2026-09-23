use axum::{extract::FromRequestParts, http::request::Parts};
use platform_store::ingest::{self, Authenticated};
use rustls::pki_types::CertificateDer;

use crate::{error::ApiError, server::AppState};

/// The client's leaf certificate, attached per connection.
#[derive(Clone)]
pub(crate) struct Peer(pub Option<CertificateDer<'static>>);

/// An agent authenticated by a recorded certificate (serial and key hash)
/// whose status is active.
pub(crate) struct AuthenticatedAgent(pub String);

impl FromRequestParts<AppState> for AuthenticatedAgent {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let Some(Peer(Some(leaf))) = parts.extensions.get::<Peer>().cloned() else {
            return Err(ApiError::Unauthorized);
        };
        let (serial, spki) =
            platform_pki::leaf_identity(&leaf).map_err(|_| ApiError::Unauthorized)?;
        let client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
        match ingest::authenticate(&client, &serial, spki).await? {
            Authenticated::Active(agent_id) => Ok(Self(agent_id)),
            Authenticated::Revoked => Err(ApiError::Revoked),
            Authenticated::Unknown => Err(ApiError::Unauthorized),
        }
    }
}
