//! `openvibes-llm-check`: settings validation and the model file checks.
// The tests start the binary they verify; this is not shipped code.
#![allow(clippy::disallowed_types)]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use openvibes_llm::{
    CheckError, LLAMA_SOCKET, check_environment, check_model, idle_seconds, idle_setting,
    running_as_root, settings, sha256_hex, wait_ready,
};

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("openvibes-llm-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn env(models: &Path, file: &str, sha256: &str) -> BTreeMap<String, String> {
    [
        (
            "OPENVIBES_LLM_MODEL",
            models.join(file).display().to_string(),
        ),
        ("OPENVIBES_LLM_MODEL_SHA256", sha256.to_owned()),
        ("OPENVIBES_LLM_ALIAS", "qwen3-4b".to_owned()),
        ("OPENVIBES_LLM_PORT", "8091".to_owned()),
        ("OPENVIBES_LLM_CONTEXT", "8192".to_owned()),
        ("OPENVIBES_LLM_THREADS", "4".to_owned()),
        ("OPENVIBES_LLM_GPU_LAYERS", "0".to_owned()),
        ("OPENVIBES_LLM_PARALLEL", "1".to_owned()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect()
}

#[test]
fn valid_settings_are_accepted() {
    let models = Path::new("/var/lib/openvibes-llm/models");
    let checked = settings(&env(models, "model.Q4_K_M.gguf", EMPTY_SHA256), models).unwrap();
    assert_eq!(checked.port, 8091);
    assert_eq!(checked.alias, "qwen3-4b");
    assert_eq!(checked.model, models.join("model.Q4_K_M.gguf"));
    // Upper-case digests are normalised.
    let upper = env(models, "m.gguf", &EMPTY_SHA256.to_uppercase());
    assert_eq!(settings(&upper, models).unwrap().model_sha256, EMPTY_SHA256);
}

#[test]
fn models_outside_the_models_directory_are_refused() {
    let models = Path::new("/var/lib/openvibes-llm/models");
    for path in [
        "/etc/shadow",
        "/var/lib/openvibes-llm/models/../other.gguf",
        "/var/lib/openvibes-llm/models/sub/m.gguf",
        "/var/lib/openvibes-llm/models/model.bin",
        "/var/lib/openvibes-llm/models/.hidden.gguf",
        "/var/lib/openvibes-llm/models/a b.gguf",
        "models/m.gguf",
    ] {
        let mut vars = env(models, "m.gguf", EMPTY_SHA256);
        vars.insert("OPENVIBES_LLM_MODEL".into(), path.into());
        assert_eq!(
            settings(&vars, models),
            Err(CheckError::ModelPath),
            "{path}"
        );
    }
}

#[test]
fn missing_and_out_of_range_settings_are_named() {
    let models = Path::new("/var/lib/openvibes-llm/models");
    let base = env(models, "m.gguf", EMPTY_SHA256);
    for name in [
        "OPENVIBES_LLM_MODEL",
        "OPENVIBES_LLM_MODEL_SHA256",
        "OPENVIBES_LLM_ALIAS",
        "OPENVIBES_LLM_PORT",
        "OPENVIBES_LLM_PARALLEL",
    ] {
        let mut vars = base.clone();
        vars.remove(name);
        assert_eq!(settings(&vars, models), Err(CheckError::Missing(name)));
    }
    for (name, value) in [
        ("OPENVIBES_LLM_MODEL_SHA256", "abc"),
        ("OPENVIBES_LLM_MODEL_SHA256", &"g".repeat(64)),
        ("OPENVIBES_LLM_ALIAS", "bad alias"),
        ("OPENVIBES_LLM_ALIAS", &"a".repeat(65)),
        ("OPENVIBES_LLM_PORT", "80"),
        ("OPENVIBES_LLM_PORT", "70000"),
        ("OPENVIBES_LLM_CONTEXT", "100"),
        ("OPENVIBES_LLM_THREADS", "0"),
        ("OPENVIBES_LLM_GPU_LAYERS", "-1"),
        ("OPENVIBES_LLM_PARALLEL", "17"),
    ] {
        let mut vars = base.clone();
        vars.insert(name.into(), value.into());
        assert_eq!(
            settings(&vars, models),
            Err(CheckError::Invalid(name)),
            "{name}={value}"
        );
    }
}

#[test]
fn digest_is_streamed_and_bounded() {
    assert_eq!(sha256_hex(&b""[..], 0).unwrap(), EMPTY_SHA256);
    assert_eq!(
        sha256_hex(&b"abc"[..], 3).unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(sha256_hex(&b"abcd"[..], 3).is_err());
}

#[cfg(unix)]
#[test]
fn model_file_must_match_be_regular_and_read_only() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let models = scratch("model");
    let model = models.join("m.gguf");
    fs::write(&model, b"abc").unwrap();
    let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let checked =
        |file: &str, sha: &str| check_model(&settings(&env(&models, file, sha), &models).unwrap());

    // Writable by the service: refused before it is read.
    assert_eq!(checked("m.gguf", abc), Err(CheckError::ModelWritable));
    fs::set_permissions(&model, fs::Permissions::from_mode(0o444)).unwrap();
    if running_as_root() {
        // Root can open any file for writing; the unit never runs as root.
        assert_eq!(checked("m.gguf", abc), Err(CheckError::ModelWritable));
    } else {
        assert_eq!(checked("m.gguf", abc), Ok(3));
        assert_eq!(
            checked("m.gguf", EMPTY_SHA256),
            Err(CheckError::ModelDigest)
        );
    }
    symlink(&model, models.join("link.gguf")).unwrap();
    assert_eq!(checked("link.gguf", abc), Err(CheckError::ModelPath));
    fs::create_dir(models.join("dir.gguf")).unwrap();
    assert_eq!(checked("dir.gguf", abc), Err(CheckError::ModelPath));
    assert_eq!(
        checked("absent.gguf", abc),
        Err(CheckError::ModelUnreadable)
    );
    fs::set_permissions(&model, fs::Permissions::from_mode(0o644)).unwrap();
    fs::remove_dir_all(&models).unwrap();
}

#[test]
fn binary_refuses_without_settings_and_names_the_problem() {
    let output = Command::new(env!("CARGO_BIN_EXE_openvibes-llm-check"))
        .env_clear()
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    let expected = if running_as_root() {
        "must not run as root"
    } else {
        "OPENVIBES_LLM_MODEL is not set (install a model"
    };
    assert!(error.contains(expected), "{error}");
}

#[test]
fn variables_that_configure_llama_server_are_refused() {
    assert_eq!(
        check_environment([
            "PATH",
            "OPENVIBES_LLM_PORT",
            "GGML_NO_BACKTRACE",
            "CREDENTIALS_DIRECTORY"
        ]),
        Ok(())
    );
    for name in [
        "LLAMA_ARG_TOOLS",
        "LLAMA_ARG_MCP_SERVERS_JSON",
        "llama_arg_host",
        "GGML_VK_VISIBLE_DEVICES",
        "HF_TOKEN",
        "HUGGINGFACE_HUB_CACHE",
    ] {
        assert_eq!(
            check_environment(["PATH", name]),
            Err(CheckError::ForeignVariable(name.to_owned())),
            "{name}"
        );
    }
}

#[test]
fn binary_refuses_llama_variables_before_anything_else() {
    if running_as_root() {
        return; // covered by the root refusal above
    }
    let output = Command::new(env!("CARGO_BIN_EXE_openvibes-llm-check"))
        .env_clear()
        .env("LLAMA_ARG_TOOLS", "all")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("LLAMA_ARG_TOOLS is set"));
}

#[test]
fn idle_defaults_for_upgraded_settings_files() {
    let models = Path::new("/var/lib/openvibes-llm/models");
    let checked = settings(&env(models, "m.gguf", EMPTY_SHA256), models).unwrap();
    assert_eq!(checked.idle_seconds, Some(300));
    let mut vars = env(models, "m.gguf", EMPTY_SHA256);
    vars.insert("OPENVIBES_LLM_IDLE".into(), "infinity".into());
    assert_eq!(settings(&vars, models).unwrap().idle_seconds, None);
    vars.insert("OPENVIBES_LLM_IDLE".into(), "1s".into());
    assert_eq!(
        settings(&vars, models),
        Err(CheckError::Invalid("OPENVIBES_LLM_IDLE"))
    );
    assert_eq!(idle_setting(&BTreeMap::new()), Ok(Some(300)));
}

#[test]
fn idle_accepts_seconds_minutes_hours_within_30s_to_24h() {
    for (text, seconds) in [
        ("30", 30),
        ("30s", 30),
        ("5min", 300),
        (" 90s ", 90),
        ("2h", 7200),
        ("24h", 86_400),
        ("1440min", 86_400),
    ] {
        assert_eq!(idle_seconds(text), Ok(Some(seconds)), "{text}");
    }
    assert_eq!(idle_seconds("infinity"), Ok(None));
    for text in [
        "",
        "29s",
        "29",
        "0",
        "25h",
        "86401",
        "5m",
        "5 min",
        "-5min",
        "+5min",
        "1.5h",
        "min",
        "5min30s",
        "Infinity",
        "99999999999999999999h",
    ] {
        assert_eq!(
            idle_seconds(text),
            Err(CheckError::Invalid("OPENVIBES_LLM_IDLE")),
            "{text}"
        );
    }
}

/// A server on a Unix socket answering `/health` with each status in turn.
#[cfg(unix)]
fn health_server(name: &str, statuses: &'static [&'static str]) -> PathBuf {
    use std::io::{Read, Write};
    let path = scratch(name).join("llama.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        for (status, stream) in statuses.iter().cycle().zip(listener.incoming()) {
            let mut stream = stream.unwrap();
            let mut request = [0; 256];
            let read = stream.read(&mut request).unwrap();
            assert!(request[..read].starts_with(b"GET /health HTTP/1."));
            let _ = write!(stream, "HTTP/1.1 {status}\r\ncontent-length: 0\r\n\r\n");
        }
    });
    path
}

#[cfg(unix)]
#[test]
fn wait_ready_polls_the_unix_socket_until_health_answers_200() {
    let path = health_server(
        "ready",
        &[
            "503 Service Unavailable",
            "503 Service Unavailable",
            "200 OK",
        ],
    );
    let started = std::time::Instant::now();
    assert_eq!(
        wait_ready(&path, Duration::from_millis(50), Duration::from_secs(5)),
        Ok(())
    );
    assert!(started.elapsed() >= Duration::from_millis(100));
}

#[cfg(unix)]
#[test]
fn wait_ready_gives_up_after_the_timeout() {
    let path = health_server("busy", &["503 Service Unavailable"]);
    assert_eq!(
        wait_ready(&path, Duration::from_millis(50), Duration::from_millis(300)),
        Err(CheckError::NotReady)
    );
    // No socket yet: llama-server has not bound it.
    let absent = scratch("absent").join("llama.sock");
    assert_eq!(
        wait_ready(
            &absent,
            Duration::from_millis(50),
            Duration::from_millis(200)
        ),
        Err(CheckError::NotReady)
    );
    assert!(CheckError::NotReady.to_string().contains(LLAMA_SOCKET));
}

#[test]
fn binary_idle_only_checks_no_model() {
    if running_as_root() {
        return;
    }
    let run = |idle: &str| {
        Command::new(env!("CARGO_BIN_EXE_openvibes-llm-check"))
            .env_clear()
            .env("OPENVIBES_LLM_IDLE", idle)
            .arg("--idle-only")
            .output()
            .unwrap()
    };
    let ok = run("30s");
    assert!(ok.status.success(), "{ok:?}");
    let bad = run("5m");
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("OPENVIBES_LLM_IDLE is invalid"));
    let unknown = Command::new(env!("CARGO_BIN_EXE_openvibes-llm-check"))
        .env_clear()
        .arg("--bogus")
        .output()
        .unwrap();
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("usage"));
}
