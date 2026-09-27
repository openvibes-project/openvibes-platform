//! `GET /v1/ca` (contracts-v1): the platform's root certificate, public
//! data an installer checks by fingerprint before trusting the platform.

use axum::{
    extract::State,
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};

use crate::server::AppState;

pub(crate) async fn ca(State(state): State<AppState>) -> Response {
    match &state.root_pem {
        Some(pem) => ([(CONTENT_TYPE, "application/x-pem-file")], pem.to_string()).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "the platform has no CA yet: finish Setup first\n",
        )
            .into_response(),
    }
}
