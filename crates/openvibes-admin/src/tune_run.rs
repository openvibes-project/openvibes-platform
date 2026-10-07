//! `openvibes-admin helper assistant-tune`: measures the bundled model
//! server on this host and tunes it (CPU threads, console deadline). The
//! decisions are in [`crate::tune`]; this file does the IO as root. `root`
//! prefixes every absolute path (`/` in production).

use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{Duration, Instant},
};

use chrono::{SecondsFormat, Utc};
use platform_assistant::{
    AssistantConfig, BackendClient, BackendError,
    client::{ChatRequest, Message},
};
use platform_host::{
    Service,
    runner::{Program::Systemctl, Runner, SystemRunner},
};
use serde::Deserialize;
use toml_edit::{DocumentMut, value};

use crate::{
    assistant_setup::parse_env,
    config_file,
    tune::{self, Deadline},
};

const DATA_DIR: &str = "var/lib/openvibes-llm";
const DEFAULT_PORT: &str = "18430";

pub struct TuneOptions {
    pub cpu: bool,
    pub no_install: bool,
    pub json: bool,
}

/// The side effects that change the host's services.
pub trait Restarter {
    fn systemctl(&self, args: &[&str]) -> Result<(), String>;
}

pub struct Systemd;

impl Restarter for Systemd {
    fn systemctl(&self, args: &[&str]) -> Result<(), String> {
        let out = SystemRunner
            .run(Systemctl, args)
            .map_err(|error| error.to_string())?;
        if out.status == 0 {
            Ok(())
        } else {
            Err(format!(
                "systemctl {}: {}",
                args.join(" "),
                out.stderr.trim()
            ))
        }
    }
}

/// For tests under `--root`: the services are not the host's.
#[cfg(debug_assertions)]
pub struct NoRestart;

#[cfg(debug_assertions)]
impl Restarter for NoRestart {
    fn systemctl(&self, _: &[&str]) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Deserialize)]
struct ConsoleFile {
    assistant: Option<AssistantConfig>,
}

/// Physical-core lists and the logical CPU count from sysfs.
fn cpus(root: &Path) -> (Vec<String>, usize) {
    let mut lists = Vec::new();
    let mut logical = 0;
    for entry in fs::read_dir(root.join("sys/devices/system/cpu"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let name = entry.file_name();
        let digits = name
            .to_string_lossy()
            .strip_prefix("cpu")
            .map(str::to_owned);
        if digits.is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())) {
            logical += 1;
            if let Ok(list) = fs::read_to_string(entry.path().join("topology/core_cpus_list")) {
                lists.push(list.trim().to_owned());
            }
        }
    }
    if logical == 0 {
        logical = std::thread::available_parallelism().map_or(2, usize::from);
    }
    (lists, logical)
}

/// Largest file root reads from the data directory.
const MAX_READ: u64 = 64 * 1024;

/// A regular file's text; `None` for a missing file, a symlink, another
/// kind of file, or one over 64 KiB (the directory is writable by the
/// admin account, so root never follows what is planted there).
fn read_regular(path: &Path) -> Option<String> {
    let ignore = |why: &str| {
        eprintln!("openvibes-admin helper: ignoring {}: {why}", path.display());
        None
    };
    // O_NOFOLLOW refuses a symlink; O_NONBLOCK keeps a FIFO from blocking.
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return ignore("not a plain file"),
    };
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.nlink() != 1 {
        return ignore("not a plain file");
    }
    if meta.len() > MAX_READ {
        return ignore("larger than 64 KiB");
    }
    let mut text = String::new();
    file.take(MAX_READ).read_to_string(&mut text).ok()?;
    Some(text)
}

/// Writes `text` next to `path`, then renames it over (mode 0644). The
/// temp file is made with `create_new`, which refuses a planted symlink.
fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    let temp = path.with_extension("new");
    let _ = fs::remove_file(&temp);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temp)
        .map_err(err)?;
    let result = file
        .write_all(text.as_bytes())
        .and_then(|()| file.set_permissions(fs::Permissions::from_mode(0o644)))
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temp, path));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(err)
}

/// Seconds to wait for `/health`; debug builds can shorten it for tests.
fn health_seconds() -> u32 {
    #[cfg(debug_assertions)]
    if let Some(n) = std::env::var("OPENVIBES_TUNE_HEALTH_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return n;
    }
    120
}

/// Polls `/health` once a second for up to two minutes.
fn wait_health(port: &str) -> Result<(), String> {
    let port: u16 = port
        .parse()
        .map_err(|_| "OPENVIBES_LLM_PORT is not a port")?;
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    for attempt in 0..health_seconds() {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(1));
        }
        let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut head = [0; 12];
        if stream
            .write_all(b"GET /health HTTP/1.0\r\nhost: localhost\r\n\r\n")
            .is_ok()
            && stream.read_exact(&mut head).is_ok()
            && head.ends_with(b" 200")
        {
            return Ok(());
        }
    }
    Err(format!(
        "the model server did not become healthy within {} s",
        health_seconds()
    ))
}

/// Longest a timed call may take; a slower host counts as this (the
/// deadline raise is capped at 180 s anyway).
const MEASURE_LIMIT: u64 = 180;

/// Wall-clock seconds of one chat call; a timeout counts as the limit.
fn time_call(client: &BackendClient, limit: u64) -> Result<f64, String> {
    let request = ChatRequest {
        messages: vec![
            Message::System("You are a concise assistant.".into()),
            Message::User(format!(
                "Summarize the following notes in a few sentences.\n\n{}",
                tune::TUNE_PROMPT
            )),
        ],
        tools: Vec::new(),
        response_format: None,
        max_tokens: 200,
        temperature: 0.0,
    };
    let started = Instant::now();
    match client.chat(&request, |_| {}) {
        Ok(_) => Ok(started.elapsed().as_secs_f64()),
        Err(BackendError::Timeout) => Ok(limit as f64),
        Err(error) => Err(format!("timed call failed: {error}")),
    }
}

pub fn run(opts: &TuneOptions, root: &Path, restarter: &dyn Restarter) -> Result<String, String> {
    // --cpu is the only mode here; --no-install is for the GPU plan.
    let _ = (opts.cpu, opts.no_install);
    let etc = root.join("etc/openvibes");
    let data = root.join(DATA_DIR);
    let llm_conf = fs::read_to_string(etc.join("llm.conf")).unwrap_or_default();
    let env = parse_env(&llm_conf);
    let port = env
        .get("OPENVIBES_LLM_PORT")
        .map_or(DEFAULT_PORT, String::as_str);

    let console = config_file::read(&etc, Service::Console)?;
    let file: ConsoleFile = toml::from_str(&console).map_err(|e| format!("console.toml: {e}"))?;
    let mut config = file
        .assistant
        .ok_or("no [assistant] section in console.toml: run assistant-setup first")?;
    let local = config
        .backend
        .as_ref()
        .is_some_and(|b| is_local(&b.url, port));
    // Root sends the local server only its own key: console.toml's
    // api_key_file is operator-chosen (any root-readable secret), and
    // another local user may hold the port while openvibes-llm restarts.
    let server_key = if let (true, Some(b)) = (local, config.backend.as_mut()) {
        b.api_key_file = None;
        let key = read_regular(&etc.join("llm-api-key")).unwrap_or_default();
        let key = key.trim();
        if key.is_empty() {
            return Err("cannot read the model server's key /etc/openvibes/llm-api-key".into());
        }
        Some(key.to_owned())
    } else {
        None
    };
    let mut backend = config
        .validate()
        .map_err(|e| e.to_string())?
        .backend
        .ok_or("[assistant.backend] is not configured")?;
    if local {
        backend.set_api_key(server_key);
    }
    // The timed call may outlast the configured deadline: that is what the
    // raise is for.
    let current = u32::try_from(backend.deadline.as_secs()).unwrap_or(u32::MAX);
    let limit = u64::from(current).max(MEASURE_LIMIT);
    let mut timed = backend.clone();
    timed.deadline = Duration::from_secs(limit);
    let client = BackendClient::new(&timed).map_err(|e| e.to_string())?;

    let (lists, logical) = cpus(root);
    let threads = tune::threads_for(tune::physical_cores(&lists, logical));
    let plan = tune::plan(&env, threads);

    let tuning = data.join("tuning.conf");
    let old = read_regular(&tuning);
    write_atomic(&tuning, &tune::tuning_conf(&plan))?;
    let measured = restarter
        .systemctl(&["restart", "openvibes-llm"])
        .and_then(|()| wait_health(port))
        .and_then(|()| {
            if !local {
                return Ok(None);
            }
            let t = time_call(&client, limit)?;
            if t.is_finite() {
                Ok(Some(t))
            } else {
                Err("the timed call gave no usable time".into())
            }
        });
    let t = match measured {
        Ok(t) => t,
        Err(error) => {
            // Nothing changed: put the old tuning back and restart on it.
            let restored = match old {
                Some(old) => write_atomic(&tuning, &old),
                None => fs::remove_file(&tuning).map_err(|e| format!("{}: {e}", tuning.display())),
            };
            if let Err(why) = restored {
                eprintln!("openvibes-admin helper: could not restore the old tuning: {why}");
            }
            let _ = restarter.systemctl(&["restart", "openvibes-llm"]);
            return Err(error);
        }
    };

    let raised = match t.map(|t| tune::deadline(t, current)) {
        Some(Deadline::Raise(seconds)) => {
            let mut doc: DocumentMut = console.parse().map_err(|e| format!("console.toml: {e}"))?;
            doc["assistant"]["backend"]["deadline_seconds"] = value(i64::from(seconds));
            config_file::replace(&etc, Service::Console, &doc.to_string())?;
            restarter.systemctl(&["try-restart", "openvibes-console"])?;
            Some(seconds)
        }
        _ => None,
    };

    let alias = &backend.model;
    let used = plan
        .threads
        .or_else(|| {
            env.get("OPENVIBES_LLM_THREADS")
                .and_then(|v| tune::unquote(v).parse().ok())
        })
        .unwrap_or(threads);
    let mut text = match t {
        Some(t) if t >= limit as f64 => tune::summary(used, alias, t, raised).replace(
            &format!("~{limit} s per call"),
            &format!("more than {limit} s per call"),
        ),
        Some(t) => tune::summary(used, alias, t, raised),
        None => format!(
            "assistant: CPU ({used} threads) · console uses another backend; speed not measured"
        ),
    };
    let json = serde_json::json!({
        "mode": "cpu",
        "threads": used,
        "model": alias,
        "seconds_per_call": t,
        "deadline_seconds": raised.unwrap_or(current),
        "left_alone": plan.left_alone,
        "summary": text,
        "at": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    });
    write_atomic(&data.join("tune.json"), &format!("{json}\n"))?;
    if opts.json {
        return Ok(format!("{json}\n"));
    }
    if let (Some(t), Some(_)) = (t, raised) {
        text.push_str(&format!(
            "\nthis host answers slowly (about {} s per question)",
            t.round() as u64
        ));
    }
    if !plan.left_alone.is_empty() {
        text.push_str(&format!(
            "\nleft alone (set in llm.conf): {}",
            plan.left_alone.join(" ")
        ));
    }
    Ok(format!("{text}\n"))
}

/// The console's backend is the local `openvibes-llm` on its port.
fn is_local(base_url: &str, port: &str) -> bool {
    let rest = base_url.strip_prefix("http://").unwrap_or("");
    let authority = rest.split('/').next().unwrap_or("");
    [format!("127.0.0.1:{port}"), format!("localhost:{port}")].contains(&authority.to_owned())
}
