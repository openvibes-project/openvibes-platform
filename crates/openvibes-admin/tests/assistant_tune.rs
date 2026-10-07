//! `openvibes-admin helper assistant-tune --root DIR` (debug builds only):
//! the whole flow against a fake model server and a temp root tree.
#![allow(clippy::disallowed_types)]

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
    time::Duration,
};

/// A model server on a free port: `/health` at once, chat after `delay`
/// (`None`: never answers).
fn server(delay: Option<Duration>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
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
                    if let Some(v) = header.to_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0; length];
                let _ = reader.read_exact(&mut body);
                let reply = if get {
                    r#"{"status":"ok"}"#
                } else {
                    match delay {
                        Some(d) => thread::sleep(d),
                        None => thread::sleep(Duration::from_secs(30)),
                    }
                    r#"{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}]}"#
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
    port
}

fn console(port: u16, deadline: u32) -> String {
    format!(
        "development_listen = \"127.0.0.1:8443\"\nhealth_listen = \"127.0.0.1:8444\"\n[assistant]\nenabled = true\n[assistant.backend]\nurl = \"http://127.0.0.1:{port}/v1\"\nmodel = \"test-model\"\ndeadline_seconds = {deadline}\n"
    )
}

/// A root tree with four CPUs on two cores.
fn tree(name: &str, port: u16, deadline: u32) -> PathBuf {
    let root = std::env::temp_dir().join(format!("ov-tune-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for (i, siblings) in ["0-1", "0-1", "2-3", "2-3"].iter().enumerate() {
        let dir = root.join(format!("sys/devices/system/cpu/cpu{i}/topology"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("core_cpus_list"), siblings).unwrap();
    }
    fs::create_dir_all(root.join("etc/openvibes")).unwrap();
    fs::create_dir_all(root.join("var/lib/openvibes-llm")).unwrap();
    fs::write(
        root.join("etc/openvibes/llm.conf"),
        format!("OPENVIBES_LLM_THREADS=4\nOPENVIBES_LLM_PORT={port}\n"),
    )
    .unwrap();
    fs::write(
        root.join("etc/openvibes/console.toml"),
        console(port, deadline),
    )
    .unwrap();
    root
}

fn tune(root: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openvibes-admin"))
        .args(["helper", "assistant-tune", "--root"])
        .arg(root)
        .args(extra)
        .output()
        .unwrap()
}

fn read(root: &Path, file: &str) -> String {
    fs::read_to_string(root.join(file)).unwrap()
}

const TUNING: &str = "var/lib/openvibes-llm/tuning.conf";
const CONSOLE: &str = "etc/openvibes/console.toml";

#[test]
fn fast_server_sets_threads_and_leaves_console_alone() {
    let port = server(Some(Duration::from_millis(100)));
    let root = tree("fast", port, 60);
    let before = read(&root, CONSOLE);
    let out = tune(&root, &["--cpu"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.starts_with("assistant: CPU (2 threads) · model test-model"),
        "{text}"
    );
    assert!(read(&root, TUNING).contains("OPENVIBES_LLM_THREADS=2\n"));
    assert_eq!(read(&root, CONSOLE), before);
    let json: serde_json::Value =
        serde_json::from_str(&read(&root, "var/lib/openvibes-llm/tune.json")).unwrap();
    assert_eq!(json["mode"], "cpu");
    assert_eq!(json["threads"], 2);
    assert_eq!(json["deadline_seconds"], 60);
    let out = tune(&root, &["--json"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"seconds_per_call\""));
}

#[test]
fn slow_server_raises_the_deadline() {
    let port = server(Some(Duration::from_millis(3500)));
    let root = tree("slow", port, 6);
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(read(&root, CONSOLE).contains("deadline_seconds = 8"));
    assert!(String::from_utf8_lossy(&out.stdout).contains("deadline raised to 8 s"));
}

#[test]
fn silent_server_fails_and_changes_nothing() {
    let port = server(None);
    let root = tree("silent", port, 2);
    let before = read(&root, CONSOLE);
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(read(&root, CONSOLE), before);
    assert!(!root.join(TUNING).exists());
    assert!(!root.join("var/lib/openvibes-llm/tune.json").exists());
}

#[test]
fn repeating_gives_identical_files() {
    let port = server(Some(Duration::from_millis(50)));
    let root = tree("twice", port, 60);
    assert_eq!(tune(&root, &[]).status.code(), Some(0));
    let (a, b) = (read(&root, TUNING), read(&root, CONSOLE));
    assert_eq!(tune(&root, &[]).status.code(), Some(0));
    assert_eq!((a, b), (read(&root, TUNING), read(&root, CONSOLE)));
}
