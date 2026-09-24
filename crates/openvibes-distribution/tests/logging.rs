//! Request logs carry the route, status, latency, and agent id, never the
//! body or a raw path.

mod support;

use std::sync::{Arc, Mutex};

use support::{World, request};

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
async fn requests_are_logged_without_secrets() {
    let capture = Capture::default();
    let writer = capture.clone();
    tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.clone())
        .init();
    let world = World::start().await;
    world
        .publish("secret-set-name", 1, b"{\"payload\":\"envelope-body\"}")
        .await;
    let agent = world.agent(1).await;
    let status = world
        .raw(&request("secret-set-name", None), Some(&agent))
        .await
        .map(|r| r.0);
    assert_eq!(status, Some(200));
    world.stop().await;
    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    let line = logs
        .lines()
        .find(|line| line.contains("\"endpoint\":\"/v1/rule-bundle\""))
        .expect("a request log line");
    for field in ["\"status\":200", "\"latency_ms\"", &agent.id] {
        assert!(line.contains(field), "{field} missing in {line}");
    }
    assert!(!logs.contains("secret-set-name") && !logs.contains("envelope-body"));
}
