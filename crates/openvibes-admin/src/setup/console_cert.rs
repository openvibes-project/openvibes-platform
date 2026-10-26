//! `helper console-cert-set` and `console-cert-reset` (4c): the admin's own
//! certificate for the console, sent on stdin by the TUI (the certificates,
//! the leaf first, then one PRIVATE KEY), checked again here and kept as
//! `OWN_CERT` + `OWN_KEY`; the certificates step then installs it. Reset
//! removes the pair and the step issues the platform's again. The key never
//! reaches argv, the journal or an error message.

use std::{fs, process::ExitCode};

use chrono::{DateTime, Utc};
use platform_host::{Step, runner::Runner};
use platform_pki::{ChainError, PkiError, ServerCertError};

use super::{
    Ctx, begin,
    import::{import_message, key_message, split},
    pki::certificate_names,
    pki_console::{OWN_CERT, OWN_KEY},
    run_step, setup_guard,
};

/// The plain sentence for a refused certificate or key; `file` is the
/// key's file when it came from one (a wrong password names it).
pub fn console_cert_message(e: &ServerCertError, file: Option<&str>) -> String {
    match e {
        ServerCertError::InvalidPem => import_message(&ChainError::InvalidPem, "", None),
        ServerCertError::IsCa => {
            "This is a CA certificate: pick the console's own certificate.".into()
        }
        ServerCertError::NotForServers => {
            "Not for servers (its extended key usage): ask for a server certificate.".into()
        }
        ServerCertError::Expired(d) => format!("Expired on {}: ask for a new one.", d.format("%F")),
        ServerCertError::NotYetValid(d) => format!("Valid from {}: not valid yet.", d.format("%F")),
        ServerCertError::CoversNone => {
            "Covers none of this console's names: add one under Names first.".into()
        }
        // The signature carries no name: the certificate is the one sent.
        ServerCertError::Pki(PkiError::KeyMismatch) => {
            "Not the key of this certificate: paste the key it was made with.".into()
        }
        ServerCertError::Pki(PkiError::WrongPassword) => {
            import_message(&ChainError::Pki(PkiError::WrongPassword), "", file)
        }
        ServerCertError::Pki(other) => key_message(*other),
    }
}

/// Checks the bundle as the TUI did and keeps it: the key first (0600),
/// then the certificates (0644). Nothing is written when a check fails, and
/// no half a pair stays when a write fails.
fn keep<R: Runner>(
    ctx: &Ctx<R>,
    bundle: &str,
    now: DateTime<Utc>,
) -> Result<platform_pki::ServerCert, String> {
    let (certs, key) = split(bundle)?;
    let say = |e: ServerCertError| console_cert_message(&e, None);
    let cert =
        platform_pki::check_server_cert(&certs, &certificate_names(ctx), now).map_err(say)?;
    // PKCS#8 only (the TUI decrypts and converts); this checks it again.
    let key = platform_pki::pkcs8_pem(&key, None).map_err(key_message)?;
    platform_pki::check_server_key(&cert, &key).map_err(say)?;
    let owner = Some(("root", "root"));
    let written = ctx
        .put(OWN_KEY, key.as_bytes(), owner, 0o600)
        .and_then(|()| ctx.put(OWN_CERT, cert.chain_pem.as_bytes(), owner, 0o644));
    if let Err(error) = written {
        let _ = remove(ctx);
        return Err(error);
    }
    Ok(cert)
}

/// Removes the pair, the key first; whether there was one.
fn remove<R: Runner>(ctx: &Ctx<R>) -> Result<bool, String> {
    let mut found = false;
    for abs in [OWN_KEY, OWN_CERT] {
        match fs::remove_file(ctx.path(abs)) {
            Ok(()) => found = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{abs}: {error}")),
        }
    }
    Ok(found)
}

/// Runs the certificates step; the pair stays whatever it says, since the
/// admin chose it.
fn install<R: Runner>(ctx: &Ctx<R>, kept: &str) -> Result<(), String> {
    let state = run_step(ctx, Step::Certificates);
    if state.finished() {
        return Ok(());
    }
    Err(format!(
        "{kept}, but installing it failed: {}",
        state.detail()
    ))
}

/// `set<TAB>NAME<TAB>UNTIL` once the console uses the certificate.
pub fn set<R: Runner>(ctx: &Ctx<R>, bundle: &str, now: DateTime<Utc>) -> Result<String, String> {
    let cert = keep(ctx, bundle, now)?;
    install(ctx, "The certificate is kept")?;
    Ok(format!(
        "set\t{}\t{}\n",
        cert.name,
        cert.not_after.format("%Y-%m-%d")
    ))
}

/// `reset` once the console has the platform's certificate again; nothing
/// to do (and nothing restarted) without an own pair.
pub fn reset<R: Runner>(ctx: &Ctx<R>) -> Result<String, String> {
    if remove(ctx)? {
        install(ctx, "Your own certificate is removed")?;
    }
    Ok("reset\n".into())
}

fn finish(done: Result<String, String>) -> ExitCode {
    match done {
        Ok(line) => {
            print!("{line}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("openvibes-admin helper: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `helper console-cert-set`: the bundle on stdin, under the Setup lock.
pub fn run_set(input: &str) -> ExitCode {
    let (_lock, plan) = match begin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    if let Err(code) = setup_guard() {
        return code;
    }
    finish(set(&super::host_ctx(&plan, false), input, Utc::now()))
}

/// `helper console-cert-reset`, under the Setup lock.
pub fn run_reset() -> ExitCode {
    let (_lock, plan) = match begin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    if let Err(code) = setup_guard() {
        return code;
    }
    finish(reset(&super::host_ctx(&plan, false)))
}

#[cfg(test)]
#[path = "console_cert_tests.rs"]
mod tests;
