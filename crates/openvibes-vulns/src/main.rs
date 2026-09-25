#![forbid(unsafe_code)]

//! `openvibes-vulns [--config PATH]`: the vulnerability feed and matching
//! service.

use std::{path::PathBuf, process::ExitCode};

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let path = match (args.next().as_deref(), args.next(), args.next()) {
        (None, None, None) => PathBuf::from("/etc/openvibes/vulns.toml"),
        (Some("--config"), Some(path), None) => PathBuf::from(path),
        _ => {
            eprintln!("usage: openvibes-vulns [--config PATH]");
            return ExitCode::from(2);
        }
    };
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .init();
    let config = match openvibes_vulns::config::load_config(&path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("openvibes-vulns: invalid vulns configuration: {error}");
            return ExitCode::FAILURE;
        }
    };
    let health = match tokio::net::TcpListener::bind(config.health_listen).await {
        Ok(listener) => listener,
        Err(_) => {
            eprintln!("openvibes-vulns: cannot bind the health listener");
            return ExitCode::FAILURE;
        }
    };
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    match openvibes_vulns::service::run(config, health, shutdown).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openvibes-vulns: {error}");
            ExitCode::FAILURE
        }
    }
}
