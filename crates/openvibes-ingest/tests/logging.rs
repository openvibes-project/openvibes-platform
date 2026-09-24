//! Request logs carry endpoint, status, and latency, never secrets.

mod support;

use std::sync::{Arc, Mutex};

use chrono::Duration;
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
async fn a_failed_enrollment_is_logged_without_the_token_or_csr() {
    let capture = Capture::default();
    let writer = capture.clone();
    tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.clone())
        .init();
    let world = World::start().await;
    let token = world.token(1, Duration::days(1)).await;
    let csr = "-----BEGIN CERTIFICATE REQUEST-----\nnot-really-a-csr\n-----END CERTIFICATE REQUEST-----\n";
    let body = serde_json::json!({ "schema_version": 1, "token": token, "csr_pem": csr });
    assert_eq!(
        world
            .raw("/v1/enroll", body.to_string().as_bytes(), None)
            .await
            .map(|r| r.0),
        Some(400)
    );
    // An unknown path is logged as `other`, never copied: its length and
    // content are the client's.
    let long = format!("/{}", "x".repeat(4000));
    assert_eq!(world.raw(&long, b"{}", None).await.map(|r| r.0), Some(404));
    world.stop().await;
    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    let line = logs
        .lines()
        .find(|line| line.contains("/v1/enroll"))
        .expect("a request log line");
    for field in ["\"endpoint\"", "\"status\":400", "\"latency_ms\""] {
        assert!(line.contains(field), "{field} missing in {line}");
    }
    assert!(!logs.contains(&token) && !logs.contains("not-really-a-csr"));
    assert!(!logs.contains("xxxxxxxxxx"), "raw path copied into the log");
    assert!(logs.contains("\"endpoint\":\"other\""));
}
