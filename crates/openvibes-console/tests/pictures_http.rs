//! Profile pictures over HTTP (spec §9.2): who may set whose, what the
//! helper refuses, and how the stored image is served.

use std::io::Cursor;

use axum::{body::to_bytes, http::StatusCode};
use openvibes_console::authenticated_router_with_picture;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::http::{ORIGIN, body, send_bytes};
use common::people::{Fx, uid};

fn png(width: u32, height: u32) -> Vec<u8> {
    let mut out = Cursor::new(Vec::new());
    image::RgbaImage::from_pixel(width, height, image::Rgba([200, 60, 90, 255]))
        .write_to(&mut out, image::ImageFormat::Png)
        .unwrap();
    out.into_inner()
}

/// The picture helper, in this process: one request per connection.
fn helper(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ov-pic-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("picture.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await.unwrap();
                let reply = openvibes_picture::wire::handle(&request);
                stream.write_all(&reply).await.unwrap();
            });
        }
    });
    path
}

async fn fixture(socket: std::path::PathBuf) -> Option<Fx> {
    let mut fx = Fx::new().await?;
    fx.router = authenticated_router_with_picture(fx.db.pool.clone(), ORIGIN, socket);
    Some(fx)
}

async fn put(
    fx: &Fx,
    who: &common::http::Session,
    user: &str,
    query: &str,
    bytes: Vec<u8>,
) -> (StatusCode, Value) {
    let uri = format!("/api/v1/users/{user}/picture?{query}");
    let response = send_bytes(&fx.router, "PUT", &uri, who, bytes).await;
    (response.status(), body(response).await)
}

const CROP: &str = "x=0&y=0&size=100";

#[tokio::test]
async fn a_person_sets_serves_and_removes_their_picture() {
    let Some(fx) = fixture(helper("own")).await else {
        return;
    };
    let me = uid(1);
    let (status, saved) = put(&fx, &fx.admin, &me, "x=10&y=0&size=100", png(300, 100)).await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    let version = saved["picture"].as_str().unwrap().to_owned();
    assert_eq!(version.len(), 64);

    let uri = format!("/api/v1/users/{me}/picture?size=64");
    let response = send_bytes(&fx.router, "GET", &uri, &fx.admin, Vec::new()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    assert_eq!(headers["content-type"], "image/webp");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    let etag = headers["etag"].to_str().unwrap().to_owned();
    let image = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    assert_eq!(&image[..4], b"RIFF");
    assert_eq!(&image[8..12], b"WEBP");

    // The same version is not sent twice, and the sizes differ.
    let mut cached = send_bytes(&fx.router, "GET", &uri, &fx.admin, Vec::new()).await;
    assert_eq!(cached.headers()["etag"], etag.as_str());
    cached = common::http::send_with(
        &fx.router,
        "GET",
        &uri,
        &fx.admin,
        &[("if-none-match", &etag)],
    )
    .await;
    assert_eq!(cached.status(), StatusCode::NOT_MODIFIED);
    let large = send_bytes(
        &fx.router,
        "GET",
        &format!("/api/v1/users/{me}/picture?size=256"),
        &fx.admin,
        Vec::new(),
    )
    .await;
    assert_ne!(large.headers()["etag"], etag.as_str());
    let odd_size = send_bytes(
        &fx.router,
        "GET",
        &format!("/api/v1/users/{me}/picture?size=100"),
        &fx.admin,
        Vec::new(),
    )
    .await;
    assert_eq!(odd_size.status(), StatusCode::BAD_REQUEST);

    // Their version appears in the session and the People lists.
    let (_, session) = fx.call(&fx.admin, "GET", "/api/v1/session", None).await;
    assert_eq!(session["principal"]["picture"], version.as_str());
    let (_, people) = fx.call(&fx.admin, "GET", "/api/v1/users", None).await;
    assert_eq!(people[0]["picture"], version.as_str());
    let (_, page) = fx
        .call(&fx.admin, "GET", &format!("/api/v1/users/{me}"), None)
        .await;
    assert_eq!(page["picture"], version.as_str());

    let removed = send_bytes(
        &fx.router,
        "DELETE",
        &format!("/api/v1/users/{me}/picture"),
        &fx.admin,
        Vec::new(),
    )
    .await;
    assert_eq!(removed.status(), StatusCode::NO_CONTENT);
    let gone = send_bytes(&fx.router, "GET", &uri, &fx.admin, Vec::new()).await;
    assert_eq!(gone.status(), StatusCode::NOT_FOUND);
    let (_, page) = fx
        .call(&fx.admin, "GET", &format!("/api/v1/users/{me}"), None)
        .await;
    assert_eq!(page["picture"], Value::Null);
    let actions = fx.db.audit_actions().await;
    assert!(
        actions.contains(&"user.picture.set".to_owned()),
        "{actions:?}"
    );
    assert!(
        actions.contains(&"user.picture.removed".to_owned()),
        "{actions:?}"
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn others_need_access_users_inside_their_share() {
    let Some(fx) = fixture(helper("share")).await else {
        return;
    };
    fx.db.user("bob", &fx.win_viewers, 3).await;
    let bob = common::http::sign_in(&fx.router, "bob").await;
    let wl = fx.windows_lead().await;
    let (alice, lead, bobs) = (uid(1), uid(2), uid(3));

    // Bob may set his own, not Alice's; people he cannot see are absent.
    assert_eq!(
        put(&fx, &bob, &bobs, CROP, png(120, 120)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        put(&fx, &bob, &alice, CROP, png(120, 120)).await.0,
        StatusCode::FORBIDDEN
    );
    let delete = format!("/api/v1/users/{alice}/picture");
    let response = send_bytes(&fx.router, "DELETE", &delete, &bob, Vec::new()).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // The Windows lead reaches Bob (a Win viewer) but not Alice.
    assert_eq!(
        put(&fx, &wl, &bobs, CROP, png(120, 120)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        put(&fx, &wl, &alice, CROP, png(120, 120)).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put(&fx, &wl, &lead, CROP, png(120, 120)).await.0,
        StatusCode::OK
    );
    // The administrator reaches everyone.
    assert_eq!(
        put(&fx, &fx.admin, &bobs, CROP, png(120, 120)).await.0,
        StatusCode::OK
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn the_helper_refuses_what_is_not_a_usable_picture() {
    let Some(fx) = fixture(helper("refuse")).await else {
        return;
    };
    let me = uid(1);
    let cases: [(&str, &str, Vec<u8>, StatusCode, &str); 5] = [
        (
            "svg",
            CROP,
            b"<svg xmlns='http://www.w3.org/2000/svg'/>".to_vec(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "picture_svg",
        ),
        (
            "text",
            CROP,
            b"hello".to_vec(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "picture_unsupported",
        ),
        (
            "crop",
            "x=50&y=0&size=100",
            png(120, 120),
            StatusCode::UNPROCESSABLE_ENTITY,
            "picture_crop",
        ),
        (
            "damaged",
            CROP,
            [&png(120, 120)[..40], &[0u8; 8]].concat(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "picture_decode",
        ),
        (
            "big",
            CROP,
            vec![0u8; openvibes_picture::MAX_BYTES + 100],
            StatusCode::PAYLOAD_TOO_LARGE,
            "picture_too_large",
        ),
    ];
    for (name, query, bytes, status, code) in cases {
        let (got, problem) = put(&fx, &fx.admin, &me, query, bytes).await;
        assert_eq!(
            (got, problem["code"].as_str()),
            (status, Some(code)),
            "{name}: {problem}"
        );
    }
    // Nothing was stored by any of them.
    let (_, page) = fx
        .call(&fx.admin, "GET", &format!("/api/v1/users/{me}"), None)
        .await;
    assert_eq!(page["picture"], Value::Null);
    fx.db.drop().await;
}

#[tokio::test]
async fn an_unreachable_helper_is_unavailable_not_a_crash() {
    let Some(fx) = fixture(std::env::temp_dir().join("ov-pic-nothing-here.sock")).await else {
        return;
    };
    let (status, problem) = put(&fx, &fx.admin, &uid(1), CROP, png(120, 120)).await;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("picture_unavailable"))
    );
    fx.db.drop().await;
}
