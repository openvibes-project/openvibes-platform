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

/// Stops the model server; the next request through its socket starts it
/// with the new tuning (a stopped one stays stopped).
const STOP_LLM: [&str; 3] = [
    "stop",
    "openvibes-llm-proxy.service",
    "openvibes-llm.service",
];

/// Whether `systemctl show -p ActiveState -p Listen openvibes-llm.socket`
/// says systemd holds `127.0.0.1:port`. Only then can no other local user
/// listen there and receive the server's key.
pub fn socket_holds(show: &str, port: &str) -> Result<(), String> {
    if !show.lines().any(|line| line == "ActiveState=active") {
        return Err("openvibes-llm.socket is not active; turn the assistant on in Setup".into());
    }
    let listen = format!("Listen=127.0.0.1:{port} (Stream)");
    if !show.lines().any(|line| line == listen) {
        return Err(format!(
            "openvibes-llm.socket does not listen on 127.0.0.1:{port} (OPENVIBES_LLM_PORT); change both together (docs/components/openvibes-llm.md)"
        ));
    }
    Ok(())
}

/// The side effects that change the host's services.
pub trait Restarter {
    fn systemctl(&self, args: &[&str]) -> Result<(), String>;
    /// [`socket_holds`] for the host's `openvibes-llm.socket`.
    fn llm_socket_holds(&self, port: &str) -> Result<(), String>;
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

    fn llm_socket_holds(&self, port: &str) -> Result<(), String> {
        let args = [
            "show",
            "--property=ActiveState",
            "--property=Listen",
            "openvibes-llm.socket",
        ];
        let out = SystemRunner
            .run(Systemctl, &args)
            .map_err(|error| error.to_string())?;
        socket_holds(&out.stdout, port)
    }
}

/// For tests under `--root`: the services are not the host's.
#[cfg(debug_assertions)]
#[derive(Default)]
pub struct NoRestart {
    socket_checks: std::cell::Cell<usize>,
}

#[cfg(debug_assertions)]
impl Restarter for NoRestart {
    fn systemctl(&self, args: &[&str]) -> Result<(), String> {
        eprintln!("--root: not run: systemctl {}", args.join(" "));
        Ok(())
    }

    /// Active on the port unless `OPENVIBES_TUNE_SOCKET` says otherwise: a
    /// comma list, one state per check, the last one repeated.
    fn llm_socket_holds(&self, port: &str) -> Result<(), String> {
        let states = std::env::var("OPENVIBES_TUNE_SOCKET").unwrap_or_else(|_| "active".into());
        let states: Vec<&str> = states.split(',').collect();
        let check = self.socket_checks.replace(self.socket_checks.get() + 1);
        let state = states[check.min(states.len() - 1)];
        socket_holds(
            &format!("ActiveState={state}\nListen=127.0.0.1:{port} (Stream)\n"),
            port,
        )
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

/// Holds `tune.lock` in the data directory for the whole run; a second
/// run is refused. The directory is the admin account's: no symlink is
/// followed, a FIFO cannot block, and nothing is ever written to the file.
fn lock(data: &Path) -> Result<fs::File, String> {
    let path = data.join("tune.lock");
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(err)?;
    if !file.metadata().map_err(err)?.is_file() {
        return Err(format!("{}: not a plain file", path.display()));
    }
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => {
            Err("another assistant-tune is running; wait for it to finish".into())
        }
        Err(fs::TryLockError::Error(e)) => Err(err(e)),
    }
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
    // Nothing is sent to the port unless systemd's socket holds it: a
    // stopped socket would leave it to any local user.
    if local {
        restarter.llm_socket_holds(port)?;
    }
    // Root sends the local server only its own key: console.toml's
    // api_key_file is operator-chosen (any root-readable secret). The port
    // is checked to be systemd's socket (above), which keeps it while the
    // server stops and starts, so no other local user can listen there.
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
    if local {
        // The server listens on 127.0.0.1 only; `localhost` may resolve to
        // ::1 first, where another user could listen and take the key.
        timed.base_url = format!("http://127.0.0.1:{port}{}", url_path(&backend.base_url));
    }
    let client = BackendClient::new(&timed).map_err(|e| e.to_string())?;

    let _lock = lock(&data)?;
    let (lists, logical) = cpus(root);
    let threads = tune::threads_for(tune::physical_cores(&lists, logical));
    let plan = tune::plan(&env, threads);

    let tuning = data.join("tuning.conf");
    let old = read_regular(&tuning);
    write_atomic(&tuning, &tune::tuning_conf(&plan))?;
    // Stopped either way. Local: the health wait goes through the socket,
    // which starts the server on the new tuning. Another backend: nothing
    // starts it, waits for it, or measures it.
    let measured = restarter.systemctl(&STOP_LLM).and_then(|()| {
        if !local {
            return Ok(None);
        }
        restarter.llm_socket_holds(port)?;
        wait_health(port)?;
        // The socket may have gone during the wait: check right before the
        // key is sent.
        restarter.llm_socket_holds(port)?;
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
            let _ = restarter.systemctl(&STOP_LLM);
            return Err(error);
        }
    };

    // From here the tuning is in place: a failure is a warning, not exit 1.
    let warn = |what: &str| eprintln!("openvibes-admin helper: warning: {what}");
    let raised = match t.map(|t| tune::deadline(t, current)) {
        Some(Deadline::Raise(seconds)) => {
            let written = console
                .parse::<DocumentMut>()
                .map_err(|e| format!("console.toml: {e}"))
                .and_then(|mut doc| {
                    doc["assistant"]["backend"]["deadline_seconds"] = value(i64::from(seconds));
                    config_file::replace(&etc, Service::Console, &doc.to_string())
                });
            match written {
                Ok(()) => {
                    if let Err(e) = restarter.systemctl(&["try-restart", "openvibes-console"]) {
                        warn(&format!(
                            "{e}; restart openvibes-console to use the new deadline"
                        ));
                    }
                    Some(seconds)
                }
                Err(e) => {
                    warn(&format!("the deadline was not raised: {e}"));
                    None
                }
            }
        }
        _ => None,
    };

    let alias = &backend.model;
    // An operator's value is shown as written, even one tune cannot parse.
    let shown = match plan.threads {
        Some(n) => n.to_string(),
        None => env
            .get("OPENVIBES_LLM_THREADS")
            .map_or_else(|| threads.to_string(), |v| tune::unquote(v).to_owned()),
    };
    let mode = if plan.gpu_layers.is_some() {
        "CPU"
    } else {
        "GPU layers set in llm.conf"
    };
    let hardware = format!("{mode} ({shown} threads)");
    let timed_out = t.is_some_and(|t| t >= limit as f64);
    let mut text = match t {
        Some(t) if timed_out => tune::summary(&hardware, alias, t, raised).replace(
            &format!("~{limit} s per call"),
            &format!("more than {limit} s per call"),
        ),
        Some(t) => tune::summary(&hardware, alias, t, raised),
        None => format!("assistant: {hardware} · console uses another backend; speed not measured"),
    };
    let json = serde_json::json!({
        "mode": "cpu",
        "threads": shown.parse::<u32>().unwrap_or(threads),
        "model": alias,
        "seconds_per_call": t,
        "deadline_seconds": raised.unwrap_or(current),
        "left_alone": plan.left_alone,
        "summary": text,
        "at": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    });
    if let Err(e) = write_atomic(&data.join("tune.json"), &format!("{json}\n")) {
        warn(&format!("the summary was not saved: {e}"));
    }
    if opts.json {
        return Ok(format!("{json}\n"));
    }
    if timed_out {
        text.push_str(&format!(
            "\nthis host answers slowly (more than {limit} s per question): the assistant will time out on this host"
        ));
    } else if let (Some(t), Some(_)) = (t, raised) {
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

/// The path after `http://host:port`, e.g. `/v1`.
fn url_path(base_url: &str) -> &str {
    let rest = base_url.strip_prefix("http://").unwrap_or(base_url);
    rest.find('/').map_or("", |i| &rest[i..])
}

/// The console's backend is the local `openvibes-llm` on its port. Not
/// `[::1]`: the server listens on 127.0.0.1 only, so whoever holds the
/// IPv6 port is someone else.
fn is_local(base_url: &str, port: &str) -> bool {
    let rest = base_url.strip_prefix("http://").unwrap_or("");
    let authority = rest.split('/').next().unwrap_or("");
    [format!("127.0.0.1:{port}"), format!("localhost:{port}")].contains(&authority.to_owned())
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_an_active_socket_on_the_port_may_receive_the_key() {
        let show = "ActiveState=active\nListen=127.0.0.1:18430 (Stream)\n";
        assert_eq!(super::socket_holds(show, "18430"), Ok(()));
        let inactive = super::socket_holds(
            "ActiveState=inactive\nListen=127.0.0.1:18430 (Stream)\n",
            "18430",
        )
        .unwrap_err();
        assert!(
            inactive.contains("openvibes-llm.socket is not active; turn the assistant on in Setup"),
            "{inactive}"
        );
        // Not found, failed, another port, or a port that merely starts the same.
        for (show, port) in [
            ("", "18430"),
            (
                "ActiveState=failed\nListen=127.0.0.1:18430 (Stream)\n",
                "18430",
            ),
            (show, "18431"),
            (show, "1843"),
            (
                "ActiveState=active\nListen=127.0.0.1:184300 (Stream)\n",
                "18430",
            ),
            (
                "ActiveState=active\nListen=0.0.0.0:18430 (Stream)\n",
                "18430",
            ),
        ] {
            assert!(super::socket_holds(show, port).is_err(), "{show:?} {port}");
        }
    }

    #[test]
    fn local_means_loopback_on_the_server_port() {
        for url in ["http://127.0.0.1:18430/v1", "http://localhost:18430/v1"] {
            assert!(super::is_local(url, "18430"), "{url}");
        }
        for url in [
            "http://127.0.0.1:18431/v1",
            "https://127.0.0.1:18430/v1",
            "http://[::1]:18430/v1",
        ] {
            assert!(!super::is_local(url, "18430"), "{url}");
        }
        assert_eq!(super::url_path("http://localhost:18430/v1"), "/v1");
        assert_eq!(super::url_path("http://localhost:18430"), "");
    }
}
