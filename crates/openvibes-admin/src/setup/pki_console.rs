//! The console's own certificate (4c): kept as `OWN_CERT` + `OWN_KEY`, the
//! certificates step installs it as the console's instead of issuing one,
//! and never renews it or asks it to come from the intermediate.

use std::fs;

use platform_host::{StepState, runner::Runner};
use zeroize::Zeroizing;

use super::Ctx;

/// The admin's own certificate for the console: the leaf, then the CAs above it.
pub(crate) const OWN_CERT: &str = platform_host::OWN_CONSOLE_CERT;
/// Its key, 0600 root.
pub(crate) const OWN_KEY: &str = "/etc/openvibes/tls/console-own.key";

const AGAIN: &str = "use your own certificate again in Maintenance › Certificates, or go back \
                     to the platform's";

/// The console uses your own certificate. Either file is enough: half a
/// pair fails `checked` with a sentence instead of being replaced quietly.
pub(super) fn own<R: Runner>(ctx: &Ctx<R>) -> bool {
    ctx.exists(OWN_CERT) || ctx.exists(OWN_KEY)
}

/// Your pair cannot be used (and nothing then touches the console's).
pub(super) const MISMATCH: &str = "The console's own certificate and key do not match: use your \
                                   own certificate again in Maintenance › Certificates, or go \
                                   back to the platform's.";

/// Your pair can be installed: both files there and the key the
/// certificate's. Its dates and names are not checked: you renew it, and
/// Status says when it ends or no longer covers the console's names.
pub(super) fn checked<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    for abs in [OWN_CERT, OWN_KEY] {
        if !ctx.exists(abs) {
            return Err(format!("{abs} is missing: {AGAIN}"));
        }
    }
    let cert = platform_pki::ServerCert {
        name: String::new(),
        covers: Vec::new(),
        chain_pem: ctx.read(OWN_CERT)?,
        not_after: chrono::Utc::now(),
    };
    let key = Zeroizing::new(ctx.read(OWN_KEY)?);
    platform_pki::check_server_key(&cert, &key).map_err(|_| MISMATCH.to_owned())?;
    Ok(())
}

/// `cert` holds your certificate (compared as DER) and `key` your key.
fn installed<R: Runner>(ctx: &Ctx<R>, cert: &str, key: &str) -> bool {
    let der = |abs: &str| {
        ctx.read(abs)
            .ok()
            .and_then(|pem| platform_pki::certificates(&pem).ok())
            .filter(|ders| !ders.is_empty())
    };
    let bytes = |abs: &str| fs::read(ctx.path(abs)).ok().map(Zeroizing::new);
    let ours = bytes(OWN_KEY);
    der(cert).is_some() && der(cert) == der(OWN_CERT) && ours.is_some() && bytes(key) == ours
}

/// The check for a console on your own: Failed when your pair cannot be
/// used, Todo until it is the console's, else nothing to do.
pub(super) fn check<R: Runner>(ctx: &Ctx<R>, cert: &str, key: &str) -> Option<StepState> {
    if let Err(error) = checked(ctx) {
        return Some(StepState::Failed(error));
    }
    (!installed(ctx, cert, key)).then_some(StepState::Todo)
}

/// Copies your pair (`checked` first) to the console's `cert` (0644) and
/// `key` (0640), root:`group`, as an issued pair is installed; the unit to
/// restart, none when they already were (not restarted for nothing).
pub(super) fn install<R: Runner>(
    ctx: &Ctx<R>,
    cert: &str,
    key: &str,
    group: &str,
) -> Result<Option<String>, String> {
    if installed(ctx, cert, key) {
        return Ok(None);
    }
    let owner = Some(("root", group));
    ctx.copy(OWN_CERT, cert, owner, 0o644)?;
    ctx.copy(OWN_KEY, key, owner, 0o640)?;
    Ok(Some("openvibes-console".into()))
}

/// The certificates step's Done line: what it issued, and whether the
/// console keeps yours.
pub(super) fn done(names: &[String], issued: bool, yours: bool) -> String {
    let issued = issued.then(|| {
        format!(
            "server certificates for {} (valid 90 days)",
            names.join(", ")
        )
    });
    let yours = yours.then(|| "the console keeps your own certificate".to_owned());
    [issued, yours]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
#[path = "pki_console_tests.rs"]
mod tests;
