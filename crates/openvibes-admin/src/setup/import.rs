//! `helper ca-import` (sub-project 4b, Import from your PKI): a company
//! intermediate, the CAs above it and its key, sent on stdin by the TUI,
//! checked again here and staged in `IMPORT_DIR` (root, 0700) until the CA
//! step installs from it. The key never reaches argv, the journal or an
//! error message.

use std::{
    fs::{self, Permissions},
    io::Read,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::ExitCode,
};

use chrono::{DateTime, Utc};
use platform_host::runner::Runner;
use platform_pki::{Chain, ChainError, PkiError};
use zeroize::Zeroizing;

use super::{Ctx, request::REQUEST_DIR};

/// Where an import waits for the CA step.
pub const IMPORT_DIR: &str = "/etc/openvibes/pki/request/import";

/// The largest bundle read from stdin.
pub const MAX: usize = 1024 * 1024;

fn file(name: &str) -> String {
    format!("{IMPORT_DIR}/{name}")
}

/// The plain sentence for a refused chain or key; `name` is our
/// intermediate's common name, `file` the key's file when it came from one.
pub fn import_message(e: &ChainError, name: &str, file: Option<&str>) -> String {
    match e {
        ChainError::InvalidPem => {
            "This is not a certificate in PEM form (-----BEGIN CERTIFICATE-----).".into()
        }
        ChainError::NotCa(n) => format!("{n} is not a CA, so it cannot sign agent certificates."),
        ChainError::Missing(n) => format!("Signed by {n}, missing here: paste it below this one."),
        ChainError::IsRoot(n) => format!(
            "{n} is a root CA: paste the intermediate made for OpenVIBES first, then the CAs \
             above it."
        ),
        ChainError::NoCaBelow(n) => {
            format!("{n} allows no CA below it: ask for one more level.")
        }
        ChainError::NotYetValid(d) => format!("Valid from {}: not valid yet.", d.format("%F")),
        ChainError::Expiring(d) => format!(
            "Valid until {}: under the 90 days a server certificate lasts.",
            d.format("%F")
        ),
        ChainError::Pki(PkiError::WeakKey(b)) => {
            format!("A {b}-bit RSA key is too weak: 2048 bits or more.")
        }
        ChainError::Pki(PkiError::WrongPassword) => match file {
            Some(file) => format!("Wrong password for {file}."),
            None => "Wrong password.".into(),
        },
        ChainError::Pki(PkiError::KeyMismatch) => {
            format!("Not the key of {name}: paste the key it was made with.")
        }
        ChainError::Pki(PkiError::NameMismatch) => format!(
            "OpenVIBES cannot reproduce {name}'s name exactly, so its certificates would not \
             chain: ask for a certificate with a UTF-8 name."
        ),
        ChainError::Pki(PkiError::UnsupportedKey) => "This key type is not supported: use RSA \
                                                      (2048 to 4096 bits), EC P-256 or P-384, \
                                                      or Ed25519."
            .into(),
        ChainError::Pki(PkiError::KeyLocked) => "The key is locked: give its password.".into(),
        ChainError::Pki(PkiError::OldEncryption) => {
            "This key's encryption is too old to open here: ask for it with AES.".into()
        }
        ChainError::Pki(other) => format!("The certificate was refused: {other}."),
    }
}

/// Splits the bundle into its certificates (in order) and its one key,
/// which comes last. Sentences name labels only, never block contents.
fn split(bundle: &str) -> Result<(String, Zeroizing<String>), String> {
    let mut certs = String::new();
    let mut key: Option<Zeroizing<String>> = None;
    let mut lines = bundle.lines();
    while let Some(line) = lines.next() {
        // Text outside PEM blocks is ignored on purpose: e.g. the password
        // line sudo leaves unread under a NOPASSWD sudoers entry.
        let Some(label) = line
            .trim()
            .strip_prefix("-----BEGIN ")
            .and_then(|rest| rest.strip_suffix("-----"))
        else {
            continue;
        };
        let end = format!("-----END {label}-----");
        let mut block = Zeroizing::new(format!("{}\n", line.trim()));
        loop {
            let line = lines
                .next()
                .ok_or_else(|| format!("The {label} block has no END line."))?;
            block.push_str(line.trim());
            block.push('\n');
            if line.trim() == end {
                break;
            }
        }
        match label {
            "CERTIFICATE" if key.is_some() => {
                return Err("The certificates come first, then the key last.".into());
            }
            "CERTIFICATE" => certs.push_str(&block),
            "PRIVATE KEY" if key.is_some() => {
                return Err("Send one private key only, after the certificates.".into());
            }
            "PRIVATE KEY" => key = Some(block),
            other => {
                return Err(format!(
                    "A {other} block cannot be imported: send the certificates, then one \
                     PRIVATE KEY."
                ));
            }
        }
    }
    let key = key.ok_or("The bundle holds no private key (PRIVATE KEY).")?;
    Ok((certs, key))
}

/// Checks the bundle as the TUI did and stages it: the key first (0600),
/// then our intermediate, the CAs between it and the root (`chain.crt`,
/// only when there are any) and the root (0644). Nothing is written when
/// a check fails, and nothing stays staged when a write fails. With a CA installed (Replace), the root must be the one
/// agents already trust.
pub fn import<R: Runner>(ctx: &Ctx<R>, bundle: &str, now: DateTime<Utc>) -> Result<Chain, String> {
    let (certs, key) = split(bundle)?;
    let chain = platform_pki::check_chain(&certs, now).map_err(|e| import_message(&e, "", None))?;
    let message = |e: ChainError| import_message(&e, &chain.name, None);
    // PKCS#8 only (the TUI decrypts and converts); this checks it again.
    let key = platform_pki::pkcs8_pem(&key, None).map_err(|e| message(e.into()))?;
    platform_pki::check_key(&chain, &key, now).map_err(message)?;
    if super::pki::installed(ctx) {
        let installed = ctx.read(super::pki::ROOT_CERT)?;
        if installed.trim() != chain.root.trim() {
            let cn = |pem: &str| {
                platform_pki::issuer_common_name(pem)
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "an unnamed CA".into())
            };
            return Err(format!(
                "Replace: under {}, not {}, so agents would stop trusting this host. Ask for \
                 one under the same root.",
                cn(&chain.root),
                cn(&installed)
            ));
        }
    }
    let fail = |error: std::io::Error| format!("{IMPORT_DIR}: {error}");
    fs::create_dir_all(ctx.path(IMPORT_DIR)).map_err(fail)?;
    // Also folders left from before: only root ever reads the key.
    for dir in [REQUEST_DIR, IMPORT_DIR] {
        fs::set_permissions(ctx.path(dir), Permissions::from_mode(0o700)).map_err(fail)?;
    }
    // An earlier import never stays beside this one, and a write that
    // fails leaves nothing staged.
    clear(ctx)?;
    let middle = chain.middle.concat();
    let files = [
        ("intermediate.key", key.as_str(), 0o600),
        ("intermediate.crt", chain.ours.as_str(), 0o644),
        ("chain.crt", middle.as_str(), 0o644),
        ("root.crt", chain.root.as_str(), 0o644),
    ];
    for (name, text, mode) in files {
        if text.is_empty() {
            continue;
        }
        if let Err(error) = ctx.put(&file(name), text.as_bytes(), None, mode) {
            let _ = clear(ctx);
            return Err(error);
        }
    }
    Ok(chain)
}

/// Removes every staged file, the key first.
fn clear<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    for name in [
        "intermediate.key",
        "intermediate.crt",
        "chain.crt",
        "root.crt",
    ] {
        match fs::remove_file(ctx.path(&file(name))) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("{}: {error}", file(name)));
            }
            _ => {}
        }
    }
    Ok(())
}

/// `imported<TAB>NAME<TAB>PATH<TAB>UNTIL`, the path joined with " › ".
pub fn imported(chain: &Chain) -> String {
    format!(
        "imported\t{}\t{}\t{}\n",
        chain.name,
        chain.path.join(" › "),
        chain.not_after.format("%Y-%m-%d")
    )
}

/// At most `MAX` bytes of UTF-8 from `input`, held zeroed on drop.
pub fn read_bundle(input: &mut impl Read) -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    input
        .take(MAX as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("reading standard input: {error}"))?;
    if bytes.len() > MAX {
        return Err("The certificate and key are too large (over 1 MiB).".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "not UTF-8".to_owned())?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// `helper ca-import`: the bundle on stdin, under the Setup lock.
pub fn run_import(input: &str) -> ExitCode {
    let done = super::lock(Path::new("/")).and_then(|_lock| {
        let plan = super::plan::plan_of("components = []\nhostname = \"\"\nca = \"careful\"")?;
        import(&super::host_ctx(&plan, false), input, Utc::now())
    });
    match done {
        Ok(chain) => {
            print!("{}", imported(&chain));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("openvibes-admin helper: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
