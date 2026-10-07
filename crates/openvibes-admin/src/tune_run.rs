//! `openvibes-admin helper assistant-tune`: measures the bundled model
//! server on this host and tunes it (CPU threads, console deadline). The
//! decisions are in [`crate::tune`]; this file does the IO as root. `root`
//! prefixes every absolute path (`/` in production).

use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{Duration, Instant},
};

use chrono::{SecondsFormat, Utc};
use platform_assistant::{
    AssistantConfig, BackendClient,
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

/// Writes `text` next to `path`, then renames it over (mode 0644).
fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    let temp = path.with_extension("new");
    let mut file = fs::File::create(&temp).map_err(err)?;
    file.write_all(text.as_bytes()).map_err(err)?;
    file.set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(err)?;
    file.sync_all().map_err(err)?;
    fs::rename(&temp, path).map_err(err)
}

/// Polls `/health` once a second for up to two minutes.
fn wait_health(port: &str) -> Result<(), String> {
    let port: u16 = port
        .parse()
        .map_err(|_| "OPENVIBES_LLM_PORT is not a port")?;
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    for attempt in 0..120 {
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
    Err("the model server did not become healthy within 120 s".into())
}

/// Wall-clock seconds of one chat call.
fn time_call(client: &BackendClient) -> Result<f64, String> {
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
    client
        .chat(&request, |_| {})
        .map_err(|error| format!("timed call failed: {error}"))?;
    Ok(started.elapsed().as_secs_f64())
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
    let backend = file
        .assistant
        .ok_or("no [assistant] section in console.toml: run assistant-setup first")?
        .validate()
        .map_err(|e| e.to_string())?
        .backend
        .ok_or("[assistant.backend] is not configured")?;
    let client = BackendClient::new(&backend).map_err(|e| e.to_string())?;

    let (lists, logical) = cpus(root);
    let threads = tune::threads_for(tune::physical_cores(&lists, logical));
    let plan = tune::plan(&env, threads);

    let tuning = data.join("tuning.conf");
    let old = fs::read_to_string(&tuning).ok();
    write_atomic(&tuning, &tune::tuning_conf(&plan))?;
    let measured = restarter
        .systemctl(&["restart", "openvibes-llm"])
        .and_then(|()| wait_health(port))
        .and_then(|()| time_call(&client))
        .and_then(|t| {
            if t.is_finite() {
                Ok(t)
            } else {
                Err("the timed call gave no usable time".into())
            }
        });
    let t = match measured {
        Ok(t) => t,
        Err(error) => {
            // Nothing changed: put the old tuning back and restart on it.
            match old {
                Some(old) => write_atomic(&tuning, &old)?,
                None => {
                    let _ = fs::remove_file(&tuning);
                }
            }
            let _ = restarter.systemctl(&["restart", "openvibes-llm"]);
            return Err(error);
        }
    };

    let current = u32::try_from(backend.deadline.as_secs()).unwrap_or(u32::MAX);
    let raised = match tune::deadline(t, current) {
        Deadline::Keep => None,
        Deadline::Raise(seconds) => {
            let mut doc: DocumentMut = console.parse().map_err(|e| format!("console.toml: {e}"))?;
            doc["assistant"]["backend"]["deadline_seconds"] = value(i64::from(seconds));
            config_file::replace(&etc, Service::Console, &doc.to_string())?;
            restarter.systemctl(&["try-restart", "openvibes-console"])?;
            Some(seconds)
        }
    };

    let alias = &backend.model;
    let used = plan
        .threads
        .or_else(|| env.get("OPENVIBES_LLM_THREADS")?.trim().parse().ok())
        .unwrap_or(threads);
    let json = serde_json::json!({
        "mode": "cpu",
        "threads": used,
        "model": alias,
        "seconds_per_call": t,
        "deadline_seconds": raised.unwrap_or(current),
        "left_alone": plan.left_alone,
        "at": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    });
    write_atomic(&data.join("tune.json"), &format!("{json}\n"))?;
    if opts.json {
        return Ok(format!("{json}\n"));
    }
    Ok(format!("{}\n", tune::summary(used, alias, t, raised)))
}
