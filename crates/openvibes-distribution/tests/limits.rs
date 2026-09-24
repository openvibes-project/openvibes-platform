//! Load controls, database failure, and health, shared with ingest.

mod support;

use std::time::Duration as StdDuration;

use openvibes_distribution::DistributionConfig;
use support::{World, health_get, request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn an_oversized_body_is_a_bad_request() {
    let world = World::start().await;
    let agent = world.agent(1).await;
    let (chain, key) = agent.pem();
    let mut stream = world.connect(Some((&chain, key))).await.unwrap();
    stream
        .write_all(b"POST /v1/rule-bundle HTTP/1.1\r\nHost: x\r\nContent-Length: 1048577\r\nConnection: close\r\n\r\n{")
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ =
        tokio::time::timeout(StdDuration::from_secs(5), stream.read_to_end(&mut response)).await;
    let text = String::from_utf8_lossy(&response);
    assert_eq!(text.split_whitespace().nth(1), Some("400"), "{text}");
    world.stop().await;
}

#[tokio::test]
async fn a_database_outage_is_unavailable() {
    let world = World::start().await;
    let agent = world.agent(1).await;
    assert_eq!(health_get(world.health, "/ready").await, 200);
    world.drop_database().await;
    let status = world
        .raw(&request("baseline", None), Some(&agent))
        .await
        .map(|r| r.0);
    assert_eq!(status, Some(503));
    assert_eq!(health_get(world.health, "/ready").await, 503);
    assert_eq!(health_get(world.health, "/health").await, 200);
    world.stop().await;
}

#[tokio::test]
async fn the_in_flight_limit_answers_busy() {
    let world = World::start_with(|config| config.max_in_flight = 1).await;
    world.publish("baseline", 1, b"{}").await;
    let agent = world.agent(1).await;
    // Hold one authenticated request open: 10 bytes promised, 1 sent.
    let (chain, key) = agent.pem();
    let mut held = world.connect(Some((&chain, key))).await.unwrap();
    held.write_all(b"POST /v1/rule-bundle HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n{")
        .await
        .unwrap();
    held.flush().await.unwrap();
    tokio::time::sleep(StdDuration::from_millis(300)).await;
    let status = world
        .raw(&request("baseline", None), Some(&agent))
        .await
        .map(|r| r.0);
    assert_eq!(status, Some(503));
    drop(held);
    tokio::time::sleep(StdDuration::from_millis(300)).await;
    let status = world
        .raw(&request("baseline", None), Some(&agent))
        .await
        .map(|r| r.0);
    assert_eq!(status, Some(200), "the permit returns");
    world.stop().await;
}

#[test]
fn configuration_is_strict() {
    let base = |extra: &str| {
        format!(
            "listen = \"0.0.0.0:18424\"\nhealth_listen = \"127.0.0.1:18481\"\n\
             server_certificate_file = \"/etc/openvibes/tls/distribution.crt\"\n\
             server_key_file = \"/etc/openvibes/tls/distribution.key\"\n\
             client_ca_file = \"/etc/openvibes/pki/intermediate.crt\"\n\
             database_url = \"postgresql:///openvibes\"\n{extra}"
        )
    };
    let dir = std::env::temp_dir().join(format!("ov-dist-config-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let load = |text: String| {
        let path = dir.join("distribution.toml");
        std::fs::write(&path, text).unwrap();
        openvibes_distribution::load_config(&path)
    };
    let config: DistributionConfig = load(base("")).unwrap();
    assert_eq!(
        (config.max_in_flight, config.request_timeout_seconds),
        (4096, 10)
    );
    assert_eq!(
        (config.max_connections, config.database_pool_size),
        (1024, 16)
    );
    for bad in [
        base("unknown = 1\n"),
        base("").replace("127.0.0.1:18481", "0.0.0.0:18481"),
        base("").replace("/etc/openvibes/tls/distribution.key", "distribution.key"),
        base("max_in_flight = 0\n"),
        base("request_timeout_seconds = 301\n"),
    ] {
        let error = load(bad.clone()).expect_err(&bad);
        assert_eq!(error.to_string(), "invalid distribution configuration");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn local_files_are_checked_before_the_database() {
    // Both broken: the certificate file is missing and the database URL does
    // not parse. Local files are reported first, as ingest does.
    let config = DistributionConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        health_listen: "127.0.0.1:0".parse().unwrap(),
        server_certificate_file: "/nonexistent/distribution.crt".into(),
        server_key_file: "/nonexistent/distribution.key".into(),
        client_ca_file: "/nonexistent/intermediate.crt".into(),
        database_url: "not a database url ::".into(),
        max_in_flight: 64,
        request_timeout_seconds: 10,
        max_connections: 256,
        database_pool_size: 16,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let health = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let error = openvibes_distribution::run(config, listener, health, async {})
        .await
        .unwrap_err();
    assert_eq!(error, openvibes_distribution::DistributionError::Tls);
}
