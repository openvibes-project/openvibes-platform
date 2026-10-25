//! The CA verbs of `openvibes-admin helper`: `ca-request`, `ca-accept`,
//! `ca-replace` and `ca-import`, checked as the other verbs are (helper.rs).

use std::{path::PathBuf, process::ExitCode};

use clap::Subcommand;

#[derive(Subcommand)]
pub enum CaCommand {
    /// Makes the CA request before install, or reuses it; prints `request`
    /// or `signed<TAB>ISSUER`, the copy's line, then the request.
    #[command(name = "ca-request")]
    Request {
        /// Also write the request here (absolute), or beside it as `-2`,
        /// `-3`… when another file is there; prints `copy<TAB>PATH`.
        #[arg(long)]
        copy: Option<PathBuf>,
    },
    /// Checks the CA's certificate and root against the request and keeps
    /// them; prints `signed<TAB>ISSUER`, then the request.
    #[command(name = "ca-accept")]
    Accept {
        /// The certificate the CA signed for the request (PEM, which starts
        /// with dashes).
        #[arg(long, allow_hyphen_values = true)]
        cert: String,
        /// The CA's own self-signed certificate (PEM).
        #[arg(long, allow_hyphen_values = true)]
        root_cert: String,
    },
    /// Replaces the intermediate CA, trusting the old one beside it until
    /// agents have renewed; prints each stage, then
    /// `done<TAB>EXPIRES<TAB>PREVIOUS_UNTIL`.
    #[command(name = "ca-replace")]
    Replace {
        /// OpenVIBES' own CA: the root key kept at install (absolute).
        #[arg(long)]
        root_key: Option<PathBuf>,
    },
    /// Checks a company intermediate, the CAs above it and its key, read
    /// from standard input (the certificates, ours first, then one PRIVATE
    /// KEY; at most 1 MiB), and keeps them for the CA step; prints
    /// `imported<TAB>NAME<TAB>PATH<TAB>UNTIL`.
    #[command(name = "ca-import")]
    Import,
}

/// A CA verb whose arguments passed the checks.
pub enum CaVerb {
    Request(Option<PathBuf>),
    Accept(String, String),
    Replace(Option<PathBuf>),
    Import,
}

pub fn verb(command: &CaCommand) -> Result<CaVerb, String> {
    Ok(match command {
        CaCommand::Request { copy } => CaVerb::Request(absolute(copy)?),
        CaCommand::Accept { cert, root_cert } => CaVerb::Accept(cert.clone(), root_cert.clone()),
        CaCommand::Replace { root_key } => CaVerb::Replace(absolute(root_key)?),
        CaCommand::Import => CaVerb::Import,
    })
}

fn absolute(path: &Option<PathBuf>) -> Result<Option<PathBuf>, String> {
    if let Some(path) = path.as_ref().filter(|path| !path.is_absolute()) {
        return Err(format!("{}: not an absolute path", path.display()));
    }
    Ok(path.clone())
}

/// Runs a checked CA verb (as root).
pub fn run(verb: CaVerb) -> ExitCode {
    match verb {
        CaVerb::Request(copy) => crate::setup::request::run_request(copy.as_deref()),
        CaVerb::Accept(cert, root) => crate::setup::request::run_accept(&cert, &root),
        CaVerb::Replace(root_key) => crate::setup::ca_replace(root_key.as_deref()),
        CaVerb::Import => match crate::setup::import::read_bundle(&mut std::io::stdin()) {
            Ok(bundle) => crate::setup::import::run_import(&bundle),
            Err(error) => {
                eprintln!("openvibes-admin helper: {error}");
                ExitCode::FAILURE
            }
        },
    }
}
