//! `openvibes-admin assistant check|eval` against a minimal model backend:
//! reports what the backend supports, applies the gate, and audits both.
// The tests start the CLI binary they verify; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::PathBuf,
    thread,
};

use common::{Fixture, row, stdout};

/// A backend that lists one model and answers every question with plain
/// text: it supports neither tool calls nor JSON-schema output.
fn plain_backend() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/v1", listener.local_addr().unwrap());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            thread::spawn(move || {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    return;
                }
                let get = line.starts_with("GET");
                let mut length = 0;
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                        break;
                    }
                    if let Some(value) = header.to_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0; length];
                let _ = reader.read_exact(&mut body);
                let reply = if get {
                    r#"{"data":[{"id":"test-model"}]}"#.to_owned()
                } else {
                    r#"{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"I do not know. 1 2 3"}}]}"#.to_owned()
                };
                let _ = reader.get_mut().write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                        reply.len()
                    )
                    .as_bytes(),
                );
            });
        }
    });
    url
}

fn console_config(fixture: &Fixture, name: &str, text: &str) -> PathBuf {
    let path = fixture.config.with_extension(format!("{name}.toml"));
    std::fs::write(&path, text).unwrap();
    path
}

fn assistant_toml(url: &str) -> String {
    // Other console settings are ignored; only [assistant] is read.
    format!(
        "listen = \"127.0.0.1:8443\"\n[assistant]\nenabled = true\n[assistant.backend]\nurl = \"{url}\"\nmodel = \"test-model\"\ndeadline_seconds = 5\n"
    )
}

#[tokio::test]
async fn check_reports_what_the_backend_supports() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let file = console_config(&fixture, "good", &assistant_toml(&plain_backend()));
    let out = stdout(&fixture.run(&["assistant", "check", "--file", file.to_str().unwrap()]));
    for line in [
        "model test-model",
        "models listed 1 (configured model listed)",
        "native tool calls no",
        "json schema output no",
        "lookup mode Prompted",
        "profile Small",
        "recommended models",
    ] {
        assert!(out.contains(line), "missing {line:?} in {out}");
    }
    assert!(out.contains("(local)"));
    assert!(out.contains("first token"));
    assert!(out.contains("not yet measured on OpenVIBES"));
    assert_eq!(
        fixture.audit().await,
        [row("migrate", "ok"), row("assistant check", "ok")]
    );
    fixture.drop().await;
}

#[tokio::test]
async fn eval_applies_the_gate_and_fails_a_backend_that_cannot_look_up() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let file = console_config(&fixture, "eval", &assistant_toml(&plain_backend()));
    let output = fixture.run(&["assistant", "eval", "--file", file.to_str().unwrap()]);
    assert!(
        !output.status.success(),
        "a model that never looks up fails the gate"
    );
    let report = String::from_utf8_lossy(&output.stderr);
    for line in [
        "questions 53",
        "lookup accuracy",
        "injections resisted",
        "gate FAILED",
    ] {
        assert!(report.contains(line), "missing {line:?} in {report}");
    }
    assert_eq!(
        fixture.audit().await,
        [row("migrate", "ok"), row("assistant eval", "error")]
    );
    fixture.drop().await;
}

#[tokio::test]
async fn configuration_problems_are_reported_and_audited() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let unreachable = {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        format!("http://127.0.0.1:{port}/v1")
    };
    for (name, text, expected) in [
        (
            "missing",
            "listen = \"x\"\n".to_owned(),
            "no [assistant] section",
        ),
        (
            "remote",
            assistant_toml("http://gpu.example:8000/v1"),
            "must use https unless it is a loopback address",
        ),
        (
            "down",
            assistant_toml(&unreachable),
            "did not answer a plain question",
        ),
    ] {
        let file = console_config(&fixture, name, &text);
        let output = fixture.run(&["assistant", "check", "--file", file.to_str().unwrap()]);
        assert!(!output.status.success(), "{name}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(expected), "{name}: {error}");
    }
    let audit = fixture.audit().await;
    assert_eq!(audit.len(), 4);
    assert!(
        audit[1..]
            .iter()
            .all(|entry| *entry == row("assistant check", "error"))
    );
    fixture.drop().await;
}
