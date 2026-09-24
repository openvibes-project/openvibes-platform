//! A database failure is logged with the endpoint it broke. Its own test
//! binary, because a tracing subscriber is process-global.

mod support;

use std::sync::{Arc, Mutex};

use support::World;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn database_failures_are_logged_with_their_endpoint() {
    let capture = Capture::default();
    let writer = capture.clone();
    tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.clone())
        .init();
    let world = World::start().await;
    world.drop_database().await;
    let enroll = serde_json::json!({"schema_version": 1, "token": "A".repeat(43), "csr_pem": "x"});
    assert_eq!(
        world
            .raw("/v1/enroll", enroll.to_string().as_bytes(), None)
            .await
            .map(|r| r.0),
        Some(503)
    );
    world.stop().await;
    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.lines().any(|line| line.contains("\"WARN\"")
            && line.contains("database")
            && line.contains("/v1/enroll")),
        "no database warning for /v1/enroll in:\n{logs}"
    );
}
