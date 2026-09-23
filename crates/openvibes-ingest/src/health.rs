use axum::{Router, extract::State, http::StatusCode, routing::get};
use platform_store::Pool;

/// `/health`: the process answers. `/ready`: the database is reachable at
/// the expected schema version.
pub(crate) fn router(pool: Pool) -> Router {
    Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/ready", get(ready))
        .with_state(pool)
}

async fn ready(State(pool): State<Pool>) -> StatusCode {
    let Ok(client) = pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    match platform_store::schema_version(&client).await {
        Ok(Some(version)) if version == platform_store::SCHEMA_VERSION => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}
