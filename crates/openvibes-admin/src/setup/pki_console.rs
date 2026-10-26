//! The console's own certificate (4c): kept as `OWN_CERT` + `OWN_KEY`, the
//! certificates step installs it as the console's instead of issuing one,
//! and never renews it or asks it to come from the intermediate.

use std::fs;

use platform_host::runner::Runner;
use zeroize::Zeroizing;

use super::{Ctx, system::Owner};

/// The admin's own certificate for the console: the leaf, then the CAs above it.
pub(crate) const OWN_CERT: &str = "/etc/openvibes/tls/console-own.crt";
/// Its key, 0600 root.
pub(crate) const OWN_KEY: &str = "/etc/openvibes/tls/console-own.key";

const AGAIN: &str = "use your own certificate again in Maintenance › Certificates, or go back \
                     to the platform's";

/// The console uses your own certificate. Either file is enough: half a
/// pair fails `install` with a sentence instead of being replaced quietly.
pub(super) fn own<R: Runner>(ctx: &Ctx<R>) -> bool {
    ctx.exists(OWN_CERT) || ctx.exists(OWN_KEY)
}

/// `cert` holds your certificate (compared as DER) and `key` your key.
pub(super) fn installed<R: Runner>(ctx: &Ctx<R>, cert: &str, key: &str) -> bool {
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

/// Copies your pair to the console's `cert` (0644) and `key` (0640), as an
/// issued pair is installed.
pub(super) fn install<R: Runner>(
    ctx: &Ctx<R>,
    cert: &str,
    key: &str,
    owner: Owner<'_>,
) -> Result<(), String> {
    for abs in [OWN_CERT, OWN_KEY] {
        if !ctx.exists(abs) {
            return Err(format!("{abs} is missing: {AGAIN}"));
        }
    }
    if !platform_pki::certificates(&ctx.read(OWN_CERT)?).is_ok_and(|ders| !ders.is_empty()) {
        return Err(format!("{OWN_CERT} holds no certificate: {AGAIN}"));
    }
    ctx.copy(OWN_CERT, cert, owner, 0o644)?;
    ctx.copy(OWN_KEY, key, owner, 0o640)
}

#[cfg(test)]
#[path = "pki_console_tests.rs"]
mod tests;
