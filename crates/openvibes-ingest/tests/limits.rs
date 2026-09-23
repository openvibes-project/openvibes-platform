//! Oversized bodies, silent clients, and the in-flight limit.

mod support;

use std::{sync::Arc, time::Duration as StdDuration};

use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use support::World;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

async fn tls(world: &World) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(world.root.cert_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = TcpStream::connect(world.addr).await.unwrap();
    TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await
        .unwrap()
}

#[tokio::test]
async fn oversized_bodies_are_400() {
    let world = World::start().await;
    // Just over the limit, sent in full.
    let body = vec![b' '; 1024 * 1024 + 1];
    assert_eq!(
        world.raw("/v1/enroll", &body, None).await.map(|r| r.0),
        Some(400)
    );
    // Declared far over the limit: refused from the header alone, without the
    // server waiting for (or reading) the body.
    let mut stream = tls(&world).await;
    stream
        .write_all(b"POST /v1/enroll HTTP/1.1\r\nHost: x\r\nContent-Length: 3145728\r\nConnection: close\r\n\r\n{")
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ =
        tokio::time::timeout(StdDuration::from_secs(5), stream.read_to_end(&mut response)).await;
    let status = String::from_utf8_lossy(&response)
        .split_whitespace()
        .nth(1)
        .map(str::to_owned);
    assert_eq!(status.as_deref(), Some("400"));
    world.stop().await;
}

#[tokio::test]
async fn silent_clients_are_dropped() {
    let world = World::start_with(|config| config.request_timeout_seconds = 1).await;
    let mut stream = tls(&world).await;
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(StdDuration::from_secs(5), stream.read(&mut byte)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "the server closes the idle connection"
    );
    let mut tcp = TcpStream::connect(world.addr).await.unwrap();
    let read = tokio::time::timeout(StdDuration::from_secs(5), tcp.read(&mut byte)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "no TLS handshake: dropped too"
    );
    world.stop().await;
}

#[tokio::test]
async fn requests_beyond_max_in_flight_get_503() {
    let world = World::start_with(|config| config.max_in_flight = 1).await;
    // Hold one request open: headers promise 10 bytes, only 1 arrives.
    let mut held = tls(&world).await;
    held.write_all(b"POST /v1/enroll HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n{")
        .await
        .unwrap();
    held.flush().await.unwrap();
    tokio::time::sleep(StdDuration::from_millis(300)).await;
    assert_eq!(
        world.raw("/v1/enroll", b"{}", None).await.map(|r| r.0),
        Some(503)
    );
    drop(held);
    tokio::time::sleep(StdDuration::from_millis(300)).await;
    assert_eq!(
        world.raw("/v1/enroll", b"{}", None).await.map(|r| r.0),
        Some(400),
        "the permit returns"
    );
    world.stop().await;
}

#[tokio::test]
async fn slow_bodies_do_not_hold_permits() {
    let world = World::start_with(|config| {
        config.max_in_flight = 1;
        config.request_timeout_seconds = 1;
    })
    .await;
    let mut slow = tls(&world).await;
    slow.write_all(b"POST /v1/enroll HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n{")
        .await
        .unwrap();
    slow.flush().await.unwrap();
    tokio::time::sleep(StdDuration::from_millis(2500)).await;
    assert_eq!(
        world.raw("/v1/enroll", b"{}", None).await.map(|r| r.0),
        Some(400),
        "the slow request was cut off at the request deadline"
    );
    world.stop().await;
}

#[tokio::test]
async fn connections_beyond_max_connections_wait_for_a_free_slot() {
    let world = World::start_with(|config| {
        config.max_connections = 1;
        config.request_timeout_seconds = 5;
    })
    .await;
    let held = TcpStream::connect(world.addr).await.unwrap();
    tokio::time::sleep(StdDuration::from_millis(200)).await;
    let blocked = tokio::time::timeout(
        StdDuration::from_millis(1500),
        world.raw("/v1/enroll", b"{}", None),
    )
    .await;
    assert!(
        blocked.is_err(),
        "a second connection is not served while the only slot is taken"
    );
    drop(held);
    assert_eq!(
        world.raw("/v1/enroll", b"{}", None).await.map(|r| r.0),
        Some(400)
    );
    world.stop().await;
}

#[tokio::test]
async fn shutdown_waits_for_requests_in_flight() {
    let world = World::start().await;
    let mut stream = tls(&world).await;
    // The handler is waiting for the rest of the body when shutdown starts.
    stream
        .write_all(b"POST /v1/enroll HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{")
        .await
        .unwrap();
    tokio::time::sleep(StdDuration::from_millis(200)).await;
    let stopping = tokio::spawn(world.stop());
    tokio::time::sleep(StdDuration::from_millis(500)).await;
    assert!(
        !stopping.is_finished(),
        "shutdown waits for the request in flight"
    );
    stream.write_all(b"}").await.unwrap();
    let mut response = Vec::new();
    let _ =
        tokio::time::timeout(StdDuration::from_secs(5), stream.read_to_end(&mut response)).await;
    let status = String::from_utf8_lossy(&response)
        .split_whitespace()
        .nth(1)
        .map(str::to_owned);
    assert_eq!(status.as_deref(), Some("400"), "the request is answered");
    tokio::time::timeout(StdDuration::from_secs(5), stopping)
        .await
        .expect("shutdown finishes once the connection is done")
        .unwrap();
}
