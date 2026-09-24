//! Compile-time embedded frontend assets.

use std::{collections::BTreeSet, sync::LazyLock};

use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use include_dir::{Dir, include_dir};

use crate::frontend_contract::PUBLIC_ASSETS;

static FRONTEND: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/web/dist");
static MANIFEST_ASSETS: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let manifest = FRONTEND
        .get_file(".vite/manifest.json")
        .expect("build.rs validates the embedded Vite manifest");
    let manifest: serde_json::Value = serde_json::from_slice(manifest.contents())
        .expect("build.rs validates the embedded Vite manifest JSON");
    let mut paths = BTreeSet::new();
    for entry in manifest
        .as_object()
        .expect("build.rs validates the embedded Vite manifest object")
        .values()
    {
        let entry = entry
            .as_object()
            .expect("build.rs validates every Vite manifest entry");
        paths.insert(
            entry["file"]
                .as_str()
                .expect("build.rs validates manifest file paths")
                .to_owned(),
        );
        for field in ["css", "assets"] {
            if let Some(values) = entry.get(field) {
                for value in values
                    .as_array()
                    .expect("build.rs validates manifest path arrays")
                {
                    paths.insert(
                        value
                            .as_str()
                            .expect("build.rs validates manifest array paths")
                            .to_owned(),
                    );
                }
            }
        }
    }
    paths
});

pub(crate) enum CachePolicy {
    NoStore,
    Immutable,
    Revalidate,
}

pub(crate) fn response(path: &str, cache_policy: CachePolicy) -> Option<Response> {
    if !safe_relative_path(path) {
        return None;
    }
    let file = FRONTEND.get_file(path)?;
    let content_type = content_type(path);
    let cache_control = match cache_policy {
        CachePolicy::NoStore => "no-store",
        CachePolicy::Immutable => "public, max-age=31536000, immutable",
        CachePolicy::Revalidate => "public, max-age=0, must-revalidate",
    };

    let mut response = Response::new(Body::from(file.contents()));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    Some(response)
}

pub(crate) fn public_response(route: &str) -> Option<Response> {
    let (_, path) = PUBLIC_ASSETS
        .iter()
        .find(|(public_route, _)| *public_route == route)?;
    response(path, CachePolicy::Revalidate)
}

pub(crate) fn manifest_response(path: &str) -> Option<Response> {
    MANIFEST_ASSETS
        .contains(path)
        .then(|| response(path, CachePolicy::Immutable))?
}

fn safe_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("css") => "text/css; charset=utf-8",
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("webmanifest") => "application/manifest+json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CachePolicy, MANIFEST_ASSETS, content_type, manifest_response, public_response, response,
    };

    #[test]
    fn embedded_lookup_refuses_path_traversal() {
        for path in ["", "/index.html", "../index.html", "assets/../index.html"] {
            assert!(response(path, CachePolicy::NoStore).is_none(), "{path:?}");
        }
    }

    #[test]
    fn known_frontend_types_are_explicit() {
        assert_eq!(content_type("entry.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("entry.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("mark.svg"), "image/svg+xml");
        assert_eq!(
            content_type("app.webmanifest"),
            "application/manifest+json; charset=utf-8"
        );
    }

    #[test]
    fn public_asset_inventory_is_exact() {
        assert!(public_response("/app.webmanifest").is_some());
        assert!(public_response("/theme-bootstrap.js").is_some());
        assert!(public_response("/brand/openvibes-mark-placeholder.svg").is_some());
        assert!(public_response("/brand/not-built.svg").is_none());
    }

    #[test]
    fn manifest_asset_inventory_is_exact() {
        assert!(!MANIFEST_ASSETS.is_empty());
        for path in &*MANIFEST_ASSETS {
            assert!(manifest_response(path).is_some(), "{path}");
        }
        assert!(manifest_response("assets/not-built.js").is_none());
    }
}
