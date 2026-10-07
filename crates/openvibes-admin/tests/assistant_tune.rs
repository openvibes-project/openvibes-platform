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
    server_with(delay, "200 OK", "200 OK")
}

/// Like [`server`] with chosen status lines for `/health` and chat.
fn server_with(delay: Option<Duration>, health: &'static str, chat: &'static str) -> u16 {
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
                let status = if get { health } else { chat };
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
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
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
        .env("OPENVIBES_TUNE_HEALTH_SECS", "2")
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
const TUNE_JSON: &str = "var/lib/openvibes-llm/tune.json";
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
    let json: serde_json::Value = serde_json::from_str(&read(&root, TUNE_JSON)).unwrap();
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
fn failing_chat_fails_and_changes_nothing() {
    let port = server_with(Some(Duration::ZERO), "200 OK", "500 Internal Server Error");
    let root = tree("failing", port, 60);
    let before = read(&root, CONSOLE);
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(read(&root, CONSOLE), before);
    assert!(!root.join(TUNING).exists());
    assert!(!root.join(TUNE_JSON).exists());
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn never_healthy_fails_and_restores_the_previous_tuning() {
    let port = server_with(None, "503 Service Unavailable", "200 OK");
    let root = tree("unhealthy", port, 60);
    fs::write(root.join(TUNING), "OPENVIBES_LLM_THREADS=3\n").unwrap();
    let before = read(&root, CONSOLE);
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(read(&root, TUNING), "OPENVIBES_LLM_THREADS=3\n");
    assert_eq!(read(&root, CONSOLE), before);
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_call_slower_than_the_deadline_raises_it() {
    let port = server(Some(Duration::from_millis(2500)));
    let root = tree("overdue", port, 2);
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(read(&root, CONSOLE).contains("deadline_seconds = 6"));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("this host answers slowly (about 3 s per question)"),
        "{text}"
    );
    assert!(read(&root, TUNE_JSON).contains("deadline raised to 6 s"));
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn another_backend_is_not_measured() {
    let port = server(None);
    let root = tree("other", port, 60);
    fs::write(root.join(CONSOLE), console(port + 1, 60)).unwrap();
    let before = read(&root, CONSOLE);
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("speed not measured"));
    assert!(read(&root, TUNING).contains("THREADS=2"));
    assert_eq!(read(&root, CONSOLE), before);
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_planted_symlink_at_the_temp_path_is_not_followed() {
    let port = server(Some(Duration::from_millis(50)));
    let root = tree("symlink", port, 60);
    let victim = root.join("victim");
    fs::write(&victim, "precious").unwrap();
    for temp in ["tuning.new", "tune.new"] {
        std::os::unix::fs::symlink(&victim, root.join("var/lib/openvibes-llm").join(temp)).unwrap();
    }
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
    assert!(read(&root, TUNING).contains("THREADS=2"));
    fs::remove_dir_all(&root).unwrap();
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

#[test]
fn a_symlinked_tuning_conf_is_never_read_into_the_rollback() {
    let port = server_with(None, "503 Service Unavailable", "200 OK");
    let root = tree("secret", port, 60);
    let secret = root.join("secret");
    fs::write(&secret, "TOP-SECRET").unwrap();
    std::os::unix::fs::symlink(&secret, root.join(TUNING)).unwrap();
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        !fs::read_to_string(root.join(TUNING))
            .unwrap_or_default()
            .contains("TOP-SECRET")
    );
    assert_eq!(fs::read_to_string(&secret).unwrap(), "TOP-SECRET");
    fs::remove_dir_all(&root).unwrap();
}
