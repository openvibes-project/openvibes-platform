#![forbid(unsafe_code)]

//! `openvibes-distribution [--config PATH]`: the rule distribution service.

use std::{path::PathBuf, process::ExitCode};

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let config = match (args.next().as_deref(), args.next(), args.next()) {
        (None, None, None) => PathBuf::from("/etc/openvibes/distribution.toml"),
        (Some("--config"), Some(path), None) => PathBuf::from(path),
        _ => {
            eprintln!("usage: openvibes-distribution [--config PATH]");
            return ExitCode::from(2);
        }
    };
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .init();
    let config = match openvibes_distribution::load_config(&config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("openvibes-distribution: {error}");
            return ExitCode::FAILURE;
        }
    };
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    match openvibes_distribution::serve(config, shutdown).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openvibes-distribution: {error}");
            ExitCode::FAILURE
        }
    }
}
