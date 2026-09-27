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

fn model_dirs(fixture: &Fixture, name: &str) -> (PathBuf, PathBuf) {
    let dir = fixture.config.with_extension(format!("{name}.d"));
    let models = dir.join("models");
    std::fs::create_dir_all(&models).unwrap();
    // Absent until the first install creates it.
    (models, dir.join("model.conf"))
}

const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

#[tokio::test]
async fn model_install_verifies_installs_read_only_and_selects_the_model() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let (models, conf) = model_dirs(&fixture, "install");
    let download = models.parent().unwrap().join("Tiny-Model.Q4_K_M.gguf");
    std::fs::write(&download, b"abc").unwrap();
    let args = |sha: &str| {
        vec![
            "assistant".to_owned(),
            "model".into(),
            "install".into(),
            download.display().to_string(),
            "--sha256".into(),
            sha.into(),
            "--alias".into(),
            "tiny".into(),
            "--models-dir".into(),
            models.display().to_string(),
            "--model-config".into(),
            conf.display().to_string(),
        ]
    };
    let run = |sha: &str| {
        let args = args(sha);
        fixture.run(&args.iter().map(String::as_str).collect::<Vec<_>>())
    };

    // A wrong digest installs nothing and leaves no partial file.
    let output = run(&"0".repeat(64));
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("SHA-256 mismatch"), "{error}");
    assert_eq!(std::fs::read_dir(&models).unwrap().count(), 0);
    assert!(!conf.exists());

    let out = stdout(&run(&ABC_SHA256.to_uppercase()));
    assert!(
        out.contains("next: systemctl restart openvibes-llm"),
        "{out}"
    );
    let installed = models.join("Tiny-Model.Q4_K_M.gguf");
    assert_eq!(std::fs::read(&installed).unwrap(), b"abc");
    let mode = std::fs::metadata(&installed).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o444);
    assert_eq!(
        std::fs::read_to_string(&conf).unwrap(),
        format!(
            "OPENVIBES_LLM_MODEL={}\nOPENVIBES_LLM_MODEL_SHA256={ABC_SHA256}\nOPENVIBES_LLM_ALIAS=tiny\n",
            installed.display()
        )
    );
    // Installing the same file again is harmless; a different file under
    // the same name is refused.
    stdout(&run(ABC_SHA256));
    std::fs::write(&download, b"abcd").unwrap();
    let digest_abcd = "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589";
    let output = run(digest_abcd);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("already installed with different contents")
    );
    assert_eq!(std::fs::read(&installed).unwrap(), b"abc");

    let audit = fixture.audit().await;
    let actions: Vec<_> = audit
        .iter()
        .map(|(_, action, result)| (action.as_str(), result.as_str()))
        .collect();
    assert_eq!(
        actions,
        [
            ("migrate", "ok"),
            ("assistant model install", "error"),
            ("assistant model install", "ok"),
            ("assistant model install", "ok"),
            ("assistant model install", "error"),
        ]
    );
    fixture.drop().await;
}

#[tokio::test]
async fn model_install_refuses_bad_names_and_digests() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let (models, conf) = model_dirs(&fixture, "refuse");
    let download = models.parent().unwrap().join("model.gguf");
    std::fs::write(&download, b"abc").unwrap();
    let dir = models.display().to_string();
    let conf = conf.display().to_string();
    let file = download.display().to_string();
    for (extra, expected) in [
        (vec!["--sha256", "abc"], "--sha256 must be 64 hexadecimal"),
        (
            vec!["--sha256", ABC_SHA256, "--name", "../escape.gguf"],
            "must end in .gguf",
        ),
        (
            vec!["--sha256", ABC_SHA256, "--name", "model.bin"],
            "must end in .gguf",
        ),
        (
            vec!["--sha256", ABC_SHA256, "--alias", "bad alias"],
            "--alias must be",
        ),
    ] {
        let mut args = vec![
            "assistant",
            "model",
            "install",
            &file,
            "--models-dir",
            &dir,
            "--model-config",
            &conf,
        ];
        args.extend(extra);
        let output = fixture.run(&args);
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(expected), "{expected}: {error}");
    }
    assert_eq!(std::fs::read_dir(&models).unwrap().count(), 0);
    fixture.drop().await;
}
