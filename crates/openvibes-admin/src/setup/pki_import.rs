//! The CA step for Import from your PKI (sub-project 4b): installs what
//! `helper ca-import` staged in `IMPORT_DIR`. The CAs between our
//! intermediate and the root go in `CHAIN`, which every server certificate
//! ends with; never in `intermediate.crt`, which distribution trusts for
//! agent client certificates.

use std::fs;

use platform_host::{StepState, runner::Runner};

use super::{
    Ctx,
    import::IMPORT_DIR,
    pki::{
        ADMIN_OWNER, INT, INTERMEDIATE, INTERMEDIATE_KEY, ROOT_CERT, installed, remove_request,
        remove_stage, root_summary, stage_from,
    },
};

/// The CAs between our intermediate and the root, nearest first.
pub const CHAIN: &str = "/etc/openvibes/pki/chain.crt";

pub(super) const HELP: &str =
    "add the certificate and its key from your PKI: Install › Certificates";

/// Installs the staged import; waits until `ca-import` staged one. An
/// installed CA is never imported over (Replace does that).
pub(super) fn import<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if installed(ctx) {
        return Ok(StepState::Done(root_summary(ctx)?));
    }
    let staged = |name: &str| format!("{IMPORT_DIR}/{name}");
    let names = ["intermediate.key", "intermediate.crt", "root.crt"];
    if !names.iter().all(|name| ctx.exists(&staged(name))) {
        return Ok(StepState::Waiting(HELP.into()));
    }
    stage_from(ctx, IMPORT_DIR, &names)?;
    // Empty for a two-level PKI: `--chain` still checks the path.
    let chain = staged("chain.crt");
    let middle = if ctx.exists(&chain) {
        fs::read(ctx.path(&chain)).map_err(|error| format!("{chain}: {error}"))?
    } else {
        Vec::new()
    };
    ctx.put(&format!("{INT}/chain.crt"), &middle, ADMIN_OWNER, 0o644)?;
    import_and_install(ctx)?;
    remove_stage(ctx)?;
    remove_request(ctx)?;
    Ok(StepState::Done(root_summary(ctx)?))
}

/// Imports the signed intermediate and installs the CA files; the staging
/// directory is left for the caller to remove. A staged `chain.crt` is
/// checked with the rest and installed as `CHAIN` when not empty; a stale
/// `CHAIN` is removed otherwise.
pub(super) fn import_and_install<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    for file in ["intermediate.crt", "root.crt"] {
        ctx.chown(&format!("{INT}/{file}"), ADMIN_OWNER)?;
    }
    let (cert, key, root, chain) = (
        format!("{INT}/intermediate.crt"),
        format!("{INT}/intermediate.key"),
        format!("{INT}/root.crt"),
        format!("{INT}/chain.crt"),
    );
    let mut args = vec![
        "ca",
        "import-intermediate",
        "--cert",
        &cert,
        "--key",
        &key,
        "--root-cert",
        &root,
    ];
    let chained = ctx.exists(&chain);
    if chained {
        args.extend(["--chain", &chain]);
    }
    ctx.as_admin(&args)?;
    ctx.copy(&cert, INTERMEDIATE, None, 0o644)?;
    ctx.copy(&root, ROOT_CERT, None, 0o644)?;
    if chained && !ctx.read(&chain)?.trim().is_empty() {
        ctx.copy(&chain, CHAIN, None, 0o644)?;
    } else {
        match fs::remove_file(ctx.path(CHAIN)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("{CHAIN}: {error}"));
            }
            _ => {}
        }
    }
    ctx.copy(
        &key,
        INTERMEDIATE_KEY,
        Some(("openvibes-ingest", "openvibes-ingest")),
        0o600,
    )
}

/// Whether a server certificate (leaf, our intermediate, then the rest)
/// ends with exactly `CHAIN`'s CAs, compared as DER (a `chain.crt` written
/// by hand may carry openssl's attribute lines or CRLF); always true
/// without a `CHAIN`.
pub(super) fn ends_in_chain<R: Runner>(ctx: &Ctx<R>, cert_pem: &str) -> bool {
    let Ok(chain) = ctx.read(CHAIN) else {
        return true;
    };
    match (
        platform_pki::certificates(cert_pem),
        platform_pki::certificates(&chain),
    ) {
        (Ok(cert), Ok(chain)) => cert.get(2..) == Some(&chain[..]),
        _ => false,
    }
}

#[cfg(test)]
#[path = "pki_import_tests.rs"]
mod tests;
