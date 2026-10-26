//! `helper console-cert-set` and `console-cert-reset` (4c): the admin's own
//! certificate for the console, sent on stdin by the TUI (the certificates,
//! the leaf first, then one PRIVATE KEY), checked again here and kept as
//! `OWN_CERT` + `OWN_KEY`; the certificates step then installs it. Reset
//! removes the pair and the step issues the platform's again. The key never
//! reaches argv, the journal or an error message.

use std::{fs, process::ExitCode};

use chrono::{DateTime, Utc};
use platform_host::{
    Step,
    runner::{Runner, SystemRunner},
};
use platform_pki::{ChainError, PkiError, ServerCertError};

use super::{
    Ctx, begin,
    import::{import_message, key_message, split},
    pki::certificate_names,
    pki_console::{OWN_CERT, OWN_KEY},
    run_step, setup_guard,
};

/// The plain sentence for a refused certificate or key; `name` is the
/// certificate's name, `file` the key's file when it came from one (a wrong
/// password names it).
pub fn console_cert_message(e: &ServerCertError, name: &str, file: Option<&str>) -> String {
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
        ServerCertError::Pki(PkiError::KeyMismatch) => {
            format!("Not the key of {name}: paste the key it was made with.")
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
    let cert = platform_pki::check_server_cert(&certs, &certificate_names(ctx), now)
        .map_err(|e| console_cert_message(&e, "", None))?;
    let say = |e: ServerCertError| console_cert_message(&e, &cert.name, None);
    // PKCS#8 only (the TUI decrypts and converts); this checks it again.
    let key = platform_pki::pkcs8_pem(&key, None).map_err(key_message)?;
    platform_pki::check_server_key(&cert, &key).map_err(say)?;
    let owner = Some(("root", "root"));
    // A pair already there is copied aside first, and put back when a
    // write fails: never half old, half new. A copy that fails stops here,
    // with the pair untouched.
    // ponytail: a crash between the writes and the removal of the copies,
    // or a second failure while putting back, can leave a stale or mixed
    // pair; the certificates step refuses it with a sentence (use your
    // certificate again, or go back to the platform's).
    let mut aside: Vec<(&str, String)> = Vec::new();
    for (abs, mode) in pair() {
        if !ctx.exists(abs) {
            continue;
        }
        let copy = old(abs);
        if let Err(error) = ctx.copy(abs, &copy, owner, mode) {
            for (_, copy) in aside {
                let _ = fs::remove_file(ctx.path(&copy));
            }
            return Err(error);
        }
        aside.push((abs, copy));
    }
    let written = ctx
        .put(OWN_KEY, key.as_bytes(), owner, 0o600)
        .and_then(|()| ctx.put(OWN_CERT, cert.chain_pem.as_bytes(), owner, 0o644));
    if let Err(error) = written {
        // What was aside comes back; a file with none aside goes.
        for (abs, _) in pair() {
            match aside.iter().find(|(had, _)| *had == abs) {
                Some((_, copy)) => {
                    let _ = fs::rename(ctx.path(copy), ctx.path(abs));
                }
                None => {
                    let _ = fs::remove_file(ctx.path(abs));
                }
            }
        }
        return Err(error);
    }
    for (_, copy) in &aside {
        let _ = fs::remove_file(ctx.path(copy));
    }
    Ok(cert)
}

/// The pair with its modes, the key first.
fn pair() -> [(&'static str, u32); 2] {
    [(OWN_KEY, 0o600), (OWN_CERT, 0o644)]
}

fn old(abs: &str) -> String {
    format!("{abs}.old")
}

/// Puts back the copies a run cut short left aside (nothing without any).
fn put_back<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    for (abs, _) in pair() {
        match fs::rename(ctx.path(&old(abs)), ctx.path(abs)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("{abs}: {error}"));
            }
            _ => {}
        }
    }
    Ok(())
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
    put_back(ctx)?;
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
    put_back(ctx)?;
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

/// Takes the Setup lock, then runs `verb` on this host.
fn locked(verb: impl FnOnce(&Ctx<SystemRunner>) -> Result<String, String>) -> ExitCode {
    let (_lock, plan) = match begin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    if let Err(code) = setup_guard() {
        return code;
    }
    finish(verb(&super::host_ctx(&plan, false)))
}

/// `helper console-cert-set`: the bundle on stdin, under the Setup lock.
pub fn run_set(input: &str) -> ExitCode {
    locked(|ctx| set(ctx, input, Utc::now()))
}

/// `helper console-cert-reset`, under the Setup lock.
pub fn run_reset() -> ExitCode {
    locked(reset)
}

#[cfg(test)]
#[path = "console_cert_tests.rs"]
mod tests;
