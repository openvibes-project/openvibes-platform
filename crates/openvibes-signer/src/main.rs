#![forbid(unsafe_code)]

//! `openvibes-signer [--config PATH]`: the rule signer.
//! `openvibes-signer seed --min-version N [--config PATH]`: creates the
//! site key if missing and the version state, so the next version it
//! signs is N, and prints the agents' trust lines (Setup runs it as the
//! signer's user).

use std::{path::PathBuf, process::ExitCode, sync::Arc};

use openvibes_signer::{
    Signer, SignerConfig, request,
    state::{Seeded, State},
};

const DEFAULT_CONFIG: &str = "/etc/openvibes/signer.toml";
const USAGE: &str = "usage: openvibes-signer [--config PATH]\n       \
                     openvibes-signer seed --min-version N [--config PATH]";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (seed, rest) = match args.split_first() {
        Some((first, rest)) if first == "seed" => (true, rest),
        _ => (false, args.as_slice()),
    };
    let mut config = PathBuf::from(DEFAULT_CONFIG);
    let mut min_version = None;
    let mut rest = rest.iter();
    while let Some(arg) = rest.next() {
        match (arg.as_str(), rest.next()) {
            ("--config", Some(path)) => config = PathBuf::from(path),
            ("--min-version", Some(n)) if seed => min_version = n.parse::<u64>().ok(),
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let config: SignerConfig = match platform_config::load(&config) {
        Ok(config) => config,
        Err(error) => return fail(&error.to_string()),
    };
    if let Err(error) = config.check() {
        return fail(&error);
    }
    if seed {
        let Some(min_version) = min_version else {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        };
        let public = match openvibes_signer::sign::create_key(&config.key_file) {
            Ok(public) => public,
            Err(error) => return fail(&error),
        };
        return match State::seed(&config.state_dir, min_version) {
            Ok(seeded) => {
                match seeded {
                    Seeded::Created => {}
                    Seeded::Kept => {
                        eprintln!("openvibes-signer: version state already exists; kept");
                    }
                    Seeded::Replaced => eprintln!(
                        "openvibes-signer: the version state could not be read; replaced: \
                         the next version signed is {min_version}"
                    ),
                }
                // Stdout carries only the trust lines (Setup and B2 read them).
                for set in [request::SITE, request::SITE_ALARMS] {
                    println!("{set} {} {public}", config.issuer_key_id);
                }
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error),
        };
    }
    let pool = match platform_store::connect_sized(&config.database_url, 2).await {
        Ok(pool) => pool,
        Err(error) => return fail(&format!("database: {error}")),
    };
    let listener = match openvibes_signer::bind(&config.socket) {
        Ok(listener) => listener,
        Err(error) => {
            return fail(&format!(
                "cannot listen on {}: {error}",
                config.socket.display()
            ));
        }
    };
    let signer = match Signer::new(config, pool) {
        Ok(signer) => Arc::new(signer),
        Err(error) => return fail(&error),
    };
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    signer.serve(listener, shutdown).await;
    ExitCode::SUCCESS
}

fn fail(error: &str) -> ExitCode {
    eprintln!("openvibes-signer: {error}");
    ExitCode::FAILURE
}
