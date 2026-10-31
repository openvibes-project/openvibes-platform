#![forbid(unsafe_code)]

//! `openvibes-feed keygen | build | bundle`: see the crate documentation.

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use openvibes_feed::{build, config, key, pack};

#[derive(Parser)]
#[command(
    version,
    about = "Builds the signed vulnerability-data feed a site's platforms read"
)]
struct Cli {
    /// Settings file (missing: defaults).
    #[arg(long, global = true, default_value = "/etc/openvibes/feed.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make a signing key (mode 0600, never overwritten) and print what the
    /// platforms need to trust it.
    Keygen {
        /// New key file.
        key_file: PathBuf,
        /// Feed id the key signs for.
        #[arg(long)]
        feed_id: String,
        /// Key id named in `feed.json`.
        #[arg(long)]
        key_id: String,
    },
    /// Fetch the configured upstreams and publish a signed feed into DIR.
    Build {
        /// The tree to write and serve.
        #[arg(long)]
        out: PathBuf,
        /// Key file from `keygen`.
        #[arg(long)]
        key: PathBuf,
        /// Only these sources (comma separated); default all configured.
        #[arg(long, value_delimiter = ',')]
        sources: Vec<String>,
        /// Days the feed stays valid (default from the settings, 7).
        #[arg(long)]
        valid_days: Option<u32>,
    },
    /// Pack a built tree into one tar to carry into an air-gapped network.
    /// For a smaller bundle, `build --sources …` into another directory first.
    Bundle {
        /// A tree from `build`.
        dir: PathBuf,
        /// The new tar file.
        #[arg(long)]
        out: PathBuf,
    },
}

fn run(cli: &Cli) -> Result<(), String> {
    match &cli.command {
        Command::Keygen {
            key_file,
            feed_id,
            key_id,
        } => {
            let made = key::generate(key_file, feed_id, key_id)?;
            println!("feed id     {}", made.feed_id);
            println!("key id      {}", made.key_id);
            println!("public key  {}", made.public());
            println!("fingerprint {}", made.fingerprint());
            println!(
                "\nOn each platform: openvibes-admin feeds trust add {} {} {}",
                made.feed_id,
                made.key_id,
                made.public()
            );
            println!("and compare the fingerprint shown there.");
            Ok(())
        }
        Command::Build {
            out,
            key: key_file,
            sources,
            valid_days,
        } => {
            let settings = config::load(&cli.config)?;
            let signer = key::load(key_file)?;
            let report = build::run(
                &settings,
                &signer,
                &build::Options {
                    out,
                    only: sources,
                    valid_days: valid_days.unwrap_or(settings.valid_days),
                },
            )?;
            for line in &report.lines {
                println!("{line}");
            }
            println!(
                "published sequence {} in {}",
                report.sequence,
                out.display()
            );
            if report.failed > 0 {
                return Err(format!("{} source(s) could not be fetched", report.failed));
            }
            Ok(())
        }
        Command::Bundle { dir, out } => {
            let blobs = pack::bundle(dir, out)?;
            println!("wrote {} ({blobs} blobs)", out.display());
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    match run(&Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openvibes-feed: {error}");
            ExitCode::FAILURE
        }
    }
}
