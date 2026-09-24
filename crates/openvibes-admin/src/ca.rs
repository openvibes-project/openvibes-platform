//! `openvibes-admin ca …`: the built-in CA hierarchy.

use std::path::{Path, PathBuf};

use chrono::Utc;
use clap::Subcommand;
use platform_pki::Issuer;

use crate::files::{read_pem, write_new, write_pair};

const KEY_MODE: u32 = 0o600;
const CERT_MODE: u32 = 0o644;

#[derive(Subcommand)]
pub enum CaCommand {
    /// Create the root CA (run on an offline machine).
    InitRoot {
        /// Directory for root.crt and root.key.
        #[arg(long)]
        out: PathBuf,
    },
    /// Create the intermediate key and its CSR (run on the ingest host).
    IntermediateRequest {
        /// Directory for intermediate.csr and intermediate.key.
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign an intermediate CSR with the root (run on the offline machine).
    SignIntermediate {
        /// Directory holding root.crt and root.key.
        #[arg(long)]
        root: PathBuf,
        /// The intermediate CSR.
        #[arg(long)]
        csr: PathBuf,
        /// Where to write the intermediate certificate.
        #[arg(long)]
        out: PathBuf,
    },
    /// Check the intermediate against its key and root, then record both.
    ImportIntermediate {
        /// Intermediate certificate.
        #[arg(long)]
        cert: PathBuf,
        /// Intermediate private key.
        #[arg(long)]
        key: PathBuf,
        /// Root certificate that signed it.
        #[arg(long)]
        root_cert: PathBuf,
    },
    /// Issue a 90-day TLS server certificate from the intermediate.
    IssueServer {
        /// Primary DNS name (also the output file name).
        name: String,
        /// Additional DNS names or IP addresses.
        #[arg(long)]
        san: Vec<String>,
        /// Issuing (intermediate) certificate.
        #[arg(long)]
        issuer_cert: PathBuf,
        /// Issuing (intermediate) private key.
        #[arg(long)]
        issuer_key: PathBuf,
        /// Directory for NAME.crt and NAME.key.
        #[arg(long)]
        out: PathBuf,
    },
}

impl CaCommand {
    /// Offline commands need no config, no database, and are not audited.
    pub fn is_offline(&self) -> bool {
        matches!(
            self,
            Self::InitRoot { .. }
                | Self::IntermediateRequest { .. }
                | Self::SignIntermediate { .. }
        )
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::InitRoot { .. } => "ca init-root",
            Self::IntermediateRequest { .. } => "ca intermediate-request",
            Self::SignIntermediate { .. } => "ca sign-intermediate",
            Self::ImportIntermediate { .. } => "ca import-intermediate",
            Self::IssueServer { .. } => "ca issue-server",
        }
    }

    /// The audit target known from the arguments alone.
    pub fn target(&self) -> Option<String> {
        match self {
            Self::IssueServer { name, .. } => Some(name.clone()),
            _ => None,
        }
    }
}

fn pki(error: platform_pki::PkiError) -> String {
    error.to_string()
}

/// Runs an offline command.
pub fn run_offline(command: &CaCommand) -> Result<String, String> {
    match command {
        CaCommand::InitRoot { out } => {
            let root = platform_pki::generate_root(Utc::now()).map_err(pki)?;
            write_pair(
                (&out.join("root.key"), &root.key_pem),
                (&out.join("root.crt"), &root.cert_pem, CERT_MODE),
                KEY_MODE,
            )?;
            Ok(format!(
                "root CA written to {}; keep root.key offline\n",
                out.display()
            ))
        }
        CaCommand::IntermediateRequest { out } => {
            let (csr, key) = platform_pki::intermediate_request().map_err(pki)?;
            write_pair(
                (&out.join("intermediate.key"), &key),
                (&out.join("intermediate.csr"), &csr, CERT_MODE),
                KEY_MODE,
            )?;
            Ok(format!(
                "intermediate key and CSR written to {}; sign the CSR offline\n",
                out.display()
            ))
        }
        CaCommand::SignIntermediate { root, csr, out } => {
            let root = platform_pki::KeyAndCert {
                cert_pem: read_pem(&root.join("root.crt"))?,
                key_pem: read_pem(&root.join("root.key"))?,
            };
            let cert =
                platform_pki::sign_intermediate(&root, &read_pem(csr)?, Utc::now()).map_err(pki)?;
            write_new(out, &cert, CERT_MODE)?;
            Ok(format!(
                "intermediate certificate written to {}\n",
                out.display()
            ))
        }
        CaCommand::ImportIntermediate { .. } | CaCommand::IssueServer { .. } => {
            Err("not an offline command".into())
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Accepts a DNS name: letters, digits, dots, hyphens; used as a file name.
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

/// Runs a host command; returns the output and the audit target.
pub async fn run_host(
    command: &CaCommand,
    client: &platform_store::Client,
) -> (Result<String, String>, Option<String>) {
    match command {
        CaCommand::ImportIntermediate {
            cert,
            key,
            root_cert,
        } => {
            let loaded = (|| {
                let cert = read_pem(cert)?;
                let root = read_pem(root_cert)?;
                Issuer::load(&cert, &read_pem(key)?).map_err(pki)?;
                platform_pki::check_intermediate(&cert, &root, Utc::now()).map_err(pki)?;
                platform_pki::verify_signed_by(&root, &root).map_err(pki)?;
                let fingerprint = platform_pki::sha256_fingerprint(&cert).map_err(pki)?;
                Ok::<_, String>((cert, root, fingerprint))
            })();
            let (cert, root, fingerprint) = match loaded {
                Ok(loaded) => loaded,
                Err(error) => return (Err(error), None),
            };
            let target = Some(hex(&fingerprint));
            let recorded = async {
                for (role, pem) in [("root", &root), ("intermediate", &cert)] {
                    let fingerprint = platform_pki::sha256_fingerprint(pem).map_err(pki)?;
                    let not_after = platform_pki::not_after(pem).map_err(pki)?;
                    platform_store::ca::record(client, role, fingerprint, pem, not_after)
                        .await
                        .map_err(|error| error.to_string())?;
                }
                Ok(format!("intermediate {} recorded\n", hex(&fingerprint)))
            }
            .await;
            (recorded, target)
        }
        CaCommand::IssueServer {
            name,
            san,
            issuer_cert,
            issuer_key,
            out,
        } => {
            let target = Some(name.clone());
            if !safe_name(name) {
                return (Err("NAME must be a DNS name".into()), target);
            }
            let issued = (|| {
                let issuer =
                    Issuer::load(&read_pem(issuer_cert)?, &read_pem(issuer_key)?).map_err(pki)?;
                let mut names = vec![name.clone()];
                names.extend(san.iter().cloned());
                let server = issuer.issue_server(&names, Utc::now()).map_err(pki)?;
                write_server(out, name, &server)?;
                Ok(format!(
                    "server certificate for {name} written to {}\n",
                    out.display()
                ))
            })();
            (issued, target)
        }
        other => (run_offline(other), None),
    }
}

fn write_server(out: &Path, name: &str, server: &platform_pki::KeyAndCert) -> Result<(), String> {
    write_pair(
        (&out.join(format!("{name}.key")), &server.key_pem),
        (
            &out.join(format!("{name}.crt")),
            &server.cert_pem,
            CERT_MODE,
        ),
        KEY_MODE,
    )
}
