//! The web app's files: hashed assets, public files and the SPA entry
//! document for each browser route, and their not-found answers.

use axum::{
    Router,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
#[cfg(feature = "embedded-ui")]
use axum::{extract::Path, routing::get};

#[cfg(feature = "embedded-ui")]
use super::assets::{self, CachePolicy};
#[cfg(feature = "embedded-ui")]
use super::frontend_contract::{BROWSER_ROUTES, PUBLIC_ASSETS};

#[cfg(feature = "embedded-ui")]
pub(super) fn asset_router() -> Router {
    Router::new()
        .route("/{*path}", get(hashed_asset))
        .fallback(asset_not_found)
}

#[cfg(not(feature = "embedded-ui"))]
pub(super) fn asset_router() -> Router {
    Router::new().fallback(asset_not_found)
}

#[cfg(feature = "embedded-ui")]
pub(super) fn frontend_router() -> Router {
    let mut router = Router::new();
    for (route, _) in PUBLIC_ASSETS {
        let public_route = *route;
        router = router.route(
            public_route,
            get(move || async move {
                assets::public_response(public_route).unwrap_or_else(asset_not_found_response)
            }),
        );
    }
    for route in BROWSER_ROUTES {
        router = router.route(route, get(spa_index));
    }
    router
}

async fn asset_not_found() -> Response {
    let mut response = StatusCode::NOT_FOUND.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(feature = "embedded-ui")]
async fn spa_index() -> Response {
    assets::response("index.html", CachePolicy::NoStore)
        .expect("build.rs validates the embedded SPA entry document")
}

#[cfg(feature = "embedded-ui")]
async fn hashed_asset(Path(path): Path<String>) -> Response {
    assets::manifest_response(&format!("assets/{path}")).unwrap_or_else(asset_not_found_response)
}

#[cfg(feature = "embedded-ui")]
fn asset_not_found_response() -> Response {
    let mut response = StatusCode::NOT_FOUND.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// An address no route answers: 404. A browser opening a page (a GET that
/// accepts HTML) gets the app with that status, so it shows "Page not
/// found" with the menu instead of a blank page; anything else gets no body.
pub(super) async fn browser_not_found(method: Method, headers: HeaderMap) -> Response {
    #[cfg(feature = "embedded-ui")]
    if method == Method::GET && accepts_html(&headers) {
        let mut response = spa_index().await;
        *response.status_mut() = StatusCode::NOT_FOUND;
        return response;
    }
    #[cfg(not(feature = "embedded-ui"))]
    let _ = (method, headers);
    let mut response = StatusCode::NOT_FOUND.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(feature = "embedded-ui")]
fn accepts_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"))
}
