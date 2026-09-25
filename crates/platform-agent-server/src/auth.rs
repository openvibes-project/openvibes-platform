use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use platform_store::{
    Pool,
    ingest::{self, Authenticated},
};
use rustls::pki_types::CertificateDer;

use crate::ApiError;

/// The client's leaf certificate, attached per connection.
#[derive(Clone)]
pub(crate) struct Peer(pub Option<CertificateDer<'static>>);

/// An agent authenticated by a recorded certificate (serial and key hash)
/// whose status is active.
pub struct AuthenticatedAgent(pub String);

impl<S: Send + Sync> FromRequestParts<S> for AuthenticatedAgent
where
    Pool: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let Some(Peer(Some(leaf))) = parts.extensions.get::<Peer>().cloned() else {
            return Err(ApiError::Unauthorized);
        };
        let (serial, spki) =
            platform_pki::leaf_identity(&leaf).map_err(|_| ApiError::Unauthorized)?;
        let client = Pool::from_ref(state)
            .get()
            .await
            .map_err(|_| ApiError::Unavailable)?;
        match ingest::authenticate(&client, &serial, spki).await? {
            // The handshake tolerates expiry so revoked agents still hear it;
            // an expired certificate of an active agent is refused here.
            Authenticated::Active(_) if !currently_valid(&leaf) => Err(ApiError::Unauthorized),
            Authenticated::Active(agent_id) => {
                tracing::Span::current().record("agent_id", agent_id.as_str());
                Ok(Self(agent_id))
            }
            Authenticated::Revoked => Err(ApiError::Revoked),
            Authenticated::Unknown => Err(ApiError::Unauthorized),
        }
    }
}

fn currently_valid(leaf: &CertificateDer<'_>) -> bool {
    let now = chrono::Utc::now();
    platform_pki::leaf_validity(leaf)
        .is_ok_and(|(not_before, not_after)| not_before <= now && now < not_after)
}
