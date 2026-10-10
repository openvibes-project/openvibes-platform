#![forbid(unsafe_code)]

//! `openvibes-netlog [--config PATH]`: network device events (UniFi
//! IPS/IDS over syslog) become alarms.

use std::{path::PathBuf, process::ExitCode};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let path = match (args.next().as_deref(), args.next(), args.next()) {
        (None, None, None) => PathBuf::from("/etc/openvibes/netlog.toml"),
        (Some("--config"), Some(path), None) => PathBuf::from(path),
        _ => {
            eprintln!("usage: openvibes-netlog [--config PATH]");
            return ExitCode::from(2);
        }
    };
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .init();
    let config = match openvibes_netlog::config::load_config(&path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("openvibes-netlog: invalid netlog configuration: {error}");
            return ExitCode::FAILURE;
        }
    };
    let socket = match tokio::net::UdpSocket::bind(config.listen).await {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("openvibes-netlog: cannot bind {}: {error}", config.listen);
            return ExitCode::FAILURE;
        }
    };
    let health = match tokio::net::TcpListener::bind(config.health_listen).await {
        Ok(listener) => listener,
        Err(_) => {
            eprintln!("openvibes-netlog: cannot bind the health listener");
            return ExitCode::FAILURE;
        }
    };
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    match openvibes_netlog::service::run(config, socket, health, shutdown).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openvibes-netlog: {error}");
            ExitCode::FAILURE
        }
    }
}
