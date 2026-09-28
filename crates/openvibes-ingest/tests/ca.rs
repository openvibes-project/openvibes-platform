//! GET /v1/ca: the root certificate, public, for installers (contracts-v1).

mod support;

use support::{World, raw_request};

#[tokio::test]
async fn the_root_certificate_is_served_without_a_client_certificate() {
    let world = World::start().await;
    let (status, body) = raw_request(world.addr, &world.root.cert_pem, "GET", "/v1/ca", b"", None)
        .await
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(body, world.root.cert_pem);
    let (post, _) = raw_request(
        world.addr,
        &world.root.cert_pem,
        "POST",
        "/v1/ca",
        b"{}",
        None,
    )
    .await
    .unwrap();
    assert_eq!(post, 405);
    world.stop().await;
}

#[tokio::test]
async fn without_a_root_certificate_it_answers_503() {
    let world = World::start_with(|config| {
        config.root_certificate_file = "/nonexistent/openvibes/root.crt".into();
    })
    .await;
    let (status, body) = raw_request(world.addr, &world.root.cert_pem, "GET", "/v1/ca", b"", None)
        .await
        .unwrap();
    assert_eq!(status, 503);
    assert!(body.contains("finish Setup"), "{body}");
    world.stop().await;
}
