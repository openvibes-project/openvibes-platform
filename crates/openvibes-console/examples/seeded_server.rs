//! Loopback-only C1 read-model demo. Never package with production binaries.

use std::{net::SocketAddr, path::PathBuf, process::ExitCode};

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let config_path = match (args.next().as_deref(), args.next(), args.next()) {
        (None, None, None) => None,
        (Some("--config"), Some(path), None) => Some(PathBuf::from(path)),
        _ => {
            eprintln!("usage: seeded_server [--config PATH]");
            return ExitCode::from(2);
        }
    };

    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .init();
    let config = match config_path {
        None => openvibes_console::ConsoleConfig {
            development_listen: "127.0.0.1:18490"
                .parse::<SocketAddr>()
                .expect("valid address"),
            health_listen: "127.0.0.1:18491".parse().expect("valid address"),
        },
        Some(config_path) => match openvibes_console::load_config(&config_path) {
            Ok(config) => config,
            Err(error) => {
                eprintln!("seeded_server: {error}");
                return ExitCode::FAILURE;
            }
        },
    };
    tracing::info!(
        development_listen = %config.development_listen,
        health_listen = %config.health_listen,
        "openvibes seeded console starting; all data is synthetic"
    );
    match openvibes_console::serve(config, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("seeded_server: {error}");
            ExitCode::FAILURE
        }
    }
}
