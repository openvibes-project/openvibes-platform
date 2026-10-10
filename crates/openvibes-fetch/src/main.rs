#![forbid(unsafe_code)]

//! `openvibes-fetch [--config PATH]`: reads one JSON request (at most 8 KiB)
//! from stdin, writes one JSON response to stdout, logs one line to stderr.

use std::{io::Read, path::PathBuf, process::ExitCode};

use openvibes_fetch::{
    config::FetchConfig,
    http::Client,
    protocol::{Kind, Refusal, Request, Response},
    serve::handle,
};

const DEFAULT_CONFIG: &str = "/etc/openvibes/fetch.toml";
/// Longest wait for the request and for the whole answer.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);
const MAX_REQUEST: u64 = 8 * 1024;

fn fail(message: &str) -> ExitCode {
    eprintln!("openvibes-fetch: {message}");
    ExitCode::FAILURE
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = match args.as_slice() {
        [] => PathBuf::from(DEFAULT_CONFIG),
        [flag, path] if flag == "--config" => PathBuf::from(path),
        _ => {
            eprintln!("usage: openvibes-fetch [--config PATH]");
            return ExitCode::from(2);
        }
    };
    let config: FetchConfig = match platform_config::load(&path) {
        Ok(c) => c,
        Err(e) => return fail(&e.to_string()),
    };
    // A client that never half-closes must not hang us: the read runs on a
    // blocking task with its own deadline (the unit also sets RuntimeMaxSec).
    let read = tokio::task::spawn_blocking(|| {
        let mut raw = Vec::new();
        std::io::stdin()
            .take(MAX_REQUEST + 1)
            .read_to_end(&mut raw)
            .map(|_| raw)
    });
    let raw = match tokio::time::timeout(DEADLINE, read).await {
        Ok(Ok(Ok(raw))) => raw,
        Ok(_) => return fail("cannot read stdin"),
        Err(_) => {
            println!(r#"{{"result":"refused","code":"invalid"}}"#);
            eprintln!("openvibes-fetch: stdin timed out");
            // The blocked read cannot be cancelled; leave without waiting.
            std::process::exit(0);
        }
    };
    let request: Option<Request> = if raw.len() as u64 > MAX_REQUEST {
        None
    } else {
        serde_json::from_slice(&raw).ok()
    };
    let (who, what, response) = match request {
        None => (
            "-".to_owned(),
            "request".to_owned(),
            Response::Refused {
                code: Refusal::Invalid,
            },
        ),
        Some(req) => {
            let what = match &req.kind {
                Kind::Reference { id } => format!("reference {id}"),
                Kind::Search { query } => format!("search {query}"),
            };
            // ureq's own 10 s timeout bounds the blocking HTTP call.
            let response = tokio::time::timeout(DEADLINE, answer(&config, &req))
                .await
                .unwrap_or(Response::Refused {
                    code: Refusal::Unavailable,
                });
            (req.user, what, response)
        }
    };
    // One journal line: who, what, outcome. Never the response text.
    let result = match &response {
        Response::Ok { items, .. } => format!("ok {} items", items.len()),
        Response::Refused { code } => format!("refused {code:?}"),
    };
    eprintln!("openvibes-fetch: user={who:?} {what:?} -> {result}");
    match serde_json::to_string(&response) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(_) => fail("cannot encode the response"),
    }
}

/// Reads the setting and deny list, then handles the request. Any failure
/// is `Unavailable`.
async fn answer(config: &FetchConfig, req: &Request) -> Response {
    let unavailable = Response::Refused {
        code: Refusal::Unavailable,
    };
    let Ok(pool) = platform_store::connect_sized(&config.database_url, 1).await else {
        return unavailable;
    };
    let Ok(db) = pool.get().await else {
        return unavailable;
    };
    let (Ok(setting), Ok(deny)) = (
        platform_store::assistant_internet::get(&db).await,
        platform_store::assistant_internet::denylist(&db).await,
    ) else {
        return unavailable;
    };
    let Ok(http) = Client::new(config.proxy_url.as_deref()) else {
        return unavailable;
    };
    let http = http.with_searxng(setting.searxng_url.as_deref());
    // ureq blocks: fine, this process serves one request.
    handle(req, &setting, &deny, &http)
}
