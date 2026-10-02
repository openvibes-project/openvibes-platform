#![forbid(unsafe_code)]

//! `openvibes-signer [--config PATH]`: the rule signer.
//! `openvibes-signer seed --min-version N [--config PATH]`: creates its
//! version state, so the next version it signs is N (Setup runs it).

use std::{path::PathBuf, process::ExitCode, sync::Arc};

use openvibes_signer::{
    Signer, SignerConfig,
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
        return match State::seed(&config.state_dir, min_version) {
            Ok(Seeded::Created) => {
                println!("the next version signed is {min_version}");
                ExitCode::SUCCESS
            }
            Ok(Seeded::Kept) => {
                println!("version state already exists; kept");
                ExitCode::SUCCESS
            }
            Ok(Seeded::Replaced) => {
                println!(
                    "the version state could not be read; replaced: the next version signed is {min_version}"
                );
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
