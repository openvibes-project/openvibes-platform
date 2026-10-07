//! `openvibes-admin helper assistant-tune --root DIR` (debug builds only):
//! the whole flow against a fake model server and a temp root tree.
#![allow(clippy::disallowed_types)]

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Arc, Mutex},
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
    recording(delay, health, chat).0
}

/// Like [`server_with`], also keeping every request header line it saw.
fn recording(
    delay: Option<Duration>,
    health: &'static str,
    chat: &'static str,
) -> (u16, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(String::new()));
    let headers = seen.clone();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let seen = seen.clone();
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
                    seen.lock().unwrap().push_str(&header);
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
    (port, headers)
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
    fs::write(root.join("etc/openvibes/llm-api-key"), "server-key\n").unwrap();
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

#[test]
fn a_fifo_at_tuning_conf_does_not_block_and_counts_as_absent() {
    let port = server_with(None, "503 Service Unavailable", "200 OK");
    let root = tree("fifo", port, 60);
    assert!(
        Command::new("mkfifo")
            .arg(root.join(TUNING))
            .status()
            .unwrap()
            .success()
    );
    let started = std::time::Instant::now();
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(started.elapsed() < Duration::from_secs(20));
    assert!(!root.join(TUNING).exists());
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_hard_linked_tuning_conf_is_ignored() {
    let port = server_with(None, "503 Service Unavailable", "200 OK");
    let root = tree("hardlink", port, 60);
    let secret = root.join("secret");
    fs::write(&secret, "TOP-SECRET").unwrap();
    fs::hard_link(&secret, root.join(TUNING)).unwrap();
    assert_eq!(tune(&root, &[]).status.code(), Some(1));
    assert!(
        !fs::read_to_string(root.join(TUNING))
            .unwrap_or_default()
            .contains("TOP-SECRET")
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn the_local_server_gets_its_own_key_never_the_configured_file() {
    use std::os::unix::fs::PermissionsExt;
    let (port, seen) = recording(Some(Duration::from_millis(50)), "200 OK", "200 OK");
    let root = tree("key", port, 60);
    let foreign = root.join("foreign");
    fs::write(&foreign, "FOREIGN-SECRET\n").unwrap();
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600)).unwrap();
    let console = console(port, 60).replace(
        "model = ",
        &format!("api_key_file = \"{}\"\nmodel = ", foreign.display()),
    );
    fs::write(root.join(CONSOLE), console).unwrap();
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let seen = seen.lock().unwrap().to_lowercase();
    assert!(!seen.contains("foreign-secret"), "{seen}");
    assert!(seen.contains("bearer server-key"), "{seen}");
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn keys_left_alone_are_named() {
    let port = server(Some(Duration::from_millis(50)));
    let root = tree("alone", port, 60);
    fs::write(
        root.join("etc/openvibes/llm.conf"),
        format!("OPENVIBES_LLM_THREADS=6\nOPENVIBES_LLM_PORT={port}\n"),
    )
    .unwrap();
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("CPU (6 threads)"), "{text}");
    assert!(
        text.contains("left alone (set in llm.conf): OPENVIBES_LLM_THREADS"),
        "{text}"
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn another_backend_only_try_restarts_and_skips_the_health_wait() {
    let port = server_with(None, "503 Service Unavailable", "200 OK");
    let root = tree("other-down", port, 60);
    fs::write(root.join(CONSOLE), console(port + 1, 60)).unwrap();
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("speed not measured"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("systemctl try-restart openvibes-llm"),
        "{stderr}"
    );
    assert!(!stderr.contains("systemctl restart"), "{stderr}");
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_second_run_fails_fast_while_one_is_running() {
    let port = server(Some(Duration::from_millis(50)));
    let root = tree("locked", port, 60);
    let lock = fs::File::create(root.join("var/lib/openvibes-llm/tune.lock")).unwrap();
    lock.lock().unwrap();
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("another assistant-tune is running"),
        "{stderr}"
    );
    assert!(!root.join(TUNING).exists());
    drop(lock);
    assert_eq!(tune(&root, &[]).status.code(), Some(0));
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn an_unsaved_summary_is_a_warning_once_tuned() {
    let port = server(Some(Duration::from_millis(50)));
    let root = tree("unsaved", port, 60);
    fs::create_dir_all(root.join(TUNE_JSON).join("x")).unwrap();
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("warning: the summary was not saved"));
    assert!(read(&root, TUNING).contains("THREADS=2"));
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn operator_values_tune_cannot_parse_are_shown_as_written() {
    let port = server(Some(Duration::from_millis(50)));
    let root = tree("raw", port, 60);
    fs::write(
        root.join("etc/openvibes/llm.conf"),
        format!(
            "OPENVIBES_LLM_THREADS=auto\nOPENVIBES_LLM_GPU_LAYERS=20\nOPENVIBES_LLM_PORT={port}\n"
        ),
    )
    .unwrap();
    let out = tune(&root, &[]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.starts_with("assistant: GPU layers set in llm.conf (auto threads)"),
        "{text}"
    );
    assert!(!read(&root, TUNING).contains("OPENVIBES_LLM"));
    fs::remove_dir_all(&root).unwrap();
}
