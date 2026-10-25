//! Replace for an imported intermediate (sub-project 4b): the next one
//! from the same PKI, staged by `ca-import`, checked again here up to this
//! host's root; and the files `swap` uses for its `CHAIN`.

use std::fs;

use chrono::Utc;
use platform_host::runner::Runner;

use super::super::{
    Ctx,
    import::{import_message, same_root},
    pki::INT,
    pki_import::{CHAIN, stage_import},
};

/// The import staged in `INT`, under the root agents trust.
pub(super) fn stage<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    if !stage_import(ctx)? {
        return Err("There is nothing imported: add the certificate and its key first.".into());
    }
    same_root(ctx, &ctx.read(&format!("{INT}/root.crt"))?)
}

/// The CAs between the new intermediate and `root`, nearest first: the
/// path and the key are checked again.
pub(super) fn chain<R: Runner>(
    ctx: &Ctx<R>,
    root: &str,
    new: &str,
    key: &str,
) -> Result<String, String> {
    let middle = ctx.read(&format!("{INT}/chain.crt"))?;
    let now = Utc::now();
    let chain = platform_pki::check_chain(&format!("{new}{middle}{root}"), now)
        .map_err(|e| import_message(&e, "", None))?;
    same_root(ctx, &chain.root)?;
    platform_pki::check_key(&chain, key, now).map_err(|e| import_message(&e, &chain.name, None))?;
    Ok(chain.middle.concat())
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
