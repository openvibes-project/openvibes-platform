//! Replace for an imported intermediate (sub-project 4b): the next one
//! from the same PKI, staged by `ca-import`, checked again here up to this
//! host's root; and the files `swap` uses for its `CHAIN`.

use std::fs;

use chrono::Utc;
use platform_host::runner::Runner;
use platform_pki::Chain;

use super::super::{
    Ctx,
    import::{IN_USE, import_message, same_root},
    pki::{INT, certificate_names},
    pki_import::{CHAIN, stage_import},
};

/// The import staged in `INT`, under the root agents trust.
pub(super) fn stage<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    if !stage_import(ctx)? {
        return Err("There is nothing imported: add the certificate and its key first.".into());
    }
    same_root(ctx, &ctx.read(&format!("{INT}/root.crt"))?)
}

/// `CHAIN` as it was before a swap, kept until it is final; empty when
/// there was none (a `CHAIN` in use is never empty).
pub(super) const CHAIN_OLD: &str = "/etc/openvibes/pki/chain.crt.old";

/// The CAs between the new intermediate and `root`, nearest first: the
/// path and the key are checked again, and the one in use (`previous`) is
/// not new.
pub(super) fn chain<R: Runner>(
    ctx: &Ctx<R>,
    root: &str,
    (new, key): (&str, &str),
    previous: &str,
) -> Result<String, String> {
    let der = |pem: &str| platform_pki::certificates(pem).ok();
    if der(new).is_some() && der(new) == der(previous) {
        return Err(IN_USE.into());
    }
    let middle = ctx.read(&format!("{INT}/chain.crt"))?;
    Ok(checked(ctx, &format!("{new}{middle}{root}"), key)?
        .middle
        .concat())
}

/// The new intermediate's path (ours, the CAs between, the root) and its
/// key, checked as an import's, with this host's names: agents must accept
/// the server certificates it signs.
pub(super) fn checked<R: Runner>(ctx: &Ctx<R>, path: &str, key: &str) -> Result<Chain, String> {
    let now = Utc::now();
    let chain = platform_pki::check_chain(path, now).map_err(|e| import_message(&e, "", None))?;
    same_root(ctx, &chain.root)?;
    platform_pki::check_key(&chain, key, &certificate_names(ctx), now)
        .map_err(|e| import_message(&e, &chain.name, None))?;
    Ok(chain)
}

/// Copies `CHAIN` to `CHAIN_OLD` (empty without one); a `CHAIN` that
/// cannot be read stops the swap before anything changes.
pub(super) fn back_up_chain<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    let old = match fs::read(ctx.path(CHAIN)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        read => read.map_err(|error| format!("{CHAIN}: {error}"))?,
    };
    ctx.put(CHAIN_OLD, &old, None, 0o644)
}

/// Puts `CHAIN` back from `CHAIN_OLD`: removed when there was none.
pub(super) fn restore_chain<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    let old = fs::read(ctx.path(CHAIN_OLD)).map_err(|error| format!("{CHAIN_OLD}: {error}"))?;
    if old.is_empty() {
        remove(ctx, CHAIN)
    } else {
        ctx.put(CHAIN, &old, None, 0o644)
    }
}

/// An empty `CHAIN` stood for "no CAs between": it goes.
pub(super) fn drop_empty_chain<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    if ctx.read(CHAIN).is_ok_and(|text| text.trim().is_empty()) {
        remove(ctx, CHAIN)?;
    }
    Ok(())
}

/// Removes `path`; already gone is fine.
pub(super) fn remove<R: Runner>(ctx: &Ctx<R>, path: &str) -> Result<(), String> {
    match fs::remove_file(ctx.path(path)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("{path}: {error}"))
        }
        _ => Ok(()),
    }
}
