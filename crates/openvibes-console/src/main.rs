#![forbid(unsafe_code)]

//! `openvibes-console [--config PATH]`: loopback console server in C0 or C3 auth mode.

use std::{path::PathBuf, process::ExitCode};

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let config_path = match (args.next().as_deref(), args.next(), args.next()) {
        (None, None, None) => PathBuf::from("/etc/openvibes/console.toml"),
        (Some("--config"), Some(path), None) => PathBuf::from(path),
        _ => {
            eprintln!("usage: openvibes-console [--config PATH]");
            return ExitCode::from(2);
        }
    };

    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .init();
    let config = match openvibes_console::load_config(&config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("openvibes-console: {error}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        development_listen = %config.development_listen,
        health_listen = %config.health_listen,
        transport_mode = ?config.transport_mode,
        "openvibes-console starting"
    );
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    match openvibes_console::serve(config, shutdown).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openvibes-console: {error}");
            ExitCode::FAILURE
        }
    }
}
