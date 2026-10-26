//! The swap of `ca-replace`: the new pair (and an import's chain) put in
//! place of the old one by renames, put back on failure, and finished or
//! undone after a crash by `finish_interrupted`.

use std::fs;

use platform_host::runner::Runner;
use platform_pki::Issuer;

use super::{PREVIOUS, PREVIOUS_UNTIL, import};
use crate::setup::{
    Ctx,
    pki::{INTERMEDIATE, INTERMEDIATE_KEY},
    pki_import::CHAIN,
};

/// Puts the new key and the bundle (new + old) in place of the old pair;
/// with `chain` (Import), also the CAs above the new one as `CHAIN`, empty
/// for none.
///
/// `previous.*` go first: while they are there Replace refuses and they
/// name the old one. The new files are then written whole beside their
/// targets (`.new`), so only renames are left to change what is in use:
/// the bundle first, then the chain, the key last. A failure at any point
/// puts back what was renamed and removes the rest, so the old pair (and
/// its chain, from the copy `import::back_up_chain` keeps) is in use
/// again. A crash part way is ended by `finish_interrupted`.
pub(super) fn swap<R: Runner>(
    ctx: &Ctx<R>,
    previous: &str,
    until: &str,
    (new, new_key): (&str, &str),
    chain: Option<&str>,
) -> Result<(), String> {
    let old = ctx.read(INTERMEDIATE)?;
    if chain.is_some() {
        import::back_up_chain(ctx)?;
    } else {
        // A copy left from before would make an undo put an old chain back.
        import::remove(ctx, import::CHAIN_OLD)?;
    }
    let (bundle, key, chain_new) = staged();
    let mut restored = true;
    let result = (|| {
        ctx.put(PREVIOUS, previous.as_bytes(), None, 0o644)?;
        ctx.put(PREVIOUS_UNTIL, format!("{until}\n").as_bytes(), None, 0o644)?;
        let ingest = Some(("openvibes-ingest", "openvibes-ingest"));
        ctx.put(&key, new_key.as_bytes(), ingest, 0o600)?;
        ctx.put(&bundle, format!("{new}{previous}").as_bytes(), None, 0o644)?;
        if let Some(chain) = chain {
            ctx.put(&chain_new, chain.as_bytes(), None, 0o644)?;
        }
        rename(ctx, &bundle, INTERMEDIATE)?;
        let rest = match chain {
            Some(_) => rename(ctx, &chain_new, CHAIN),
            None => Ok(()),
        }
        .and_then(|()| rename(ctx, &key, INTERMEDIATE_KEY));
        rest.map_err(|error| {
            // The bundle first: if it cannot go back, the chain stays the
            // new one's too.
            let back =
                ctx.put(INTERMEDIATE, old.as_bytes(), None, 0o644)
                    .and_then(|()| match chain {
                        Some(_) => import::restore_chain(ctx),
                        None => Ok(()),
                    });
            match back {
                Ok(()) => error,
                Err(again) => {
                    restored = false;
                    format!("{error}; the old intermediate could not be put back: {again}")
                }
            }
        })
    })();
    // When the old bundle is not back, all stay: `finish_interrupted`
    // renames the key next time.
    if result.is_err() && restored {
        let backup = import::CHAIN_OLD;
        for path in [
            bundle.as_str(),
            &key,
            &chain_new,
            backup,
            PREVIOUS,
            PREVIOUS_UNTIL,
        ] {
            let _ = fs::remove_file(ctx.path(path));
        }
    }
    result?;
    // Done: the copy only helps undo, best effort.
    let _ = fs::remove_file(ctx.path(import::CHAIN_OLD));
    Ok(())
}

/// Renames `from` over `to`, then syncs the folder so the rename itself
/// survives a crash. Only the rename decides: once it is done the file is
/// in place, and a failed sync must not make the caller undo half a swap.
fn rename<R: Runner>(ctx: &Ctx<R>, from: &str, to: &str) -> Result<(), String> {
    #[cfg(test)]
    if FAIL_RENAME.get() == Some(to) {
        return Err(format!("{to}: refused by the test"));
    }
    let target = ctx.path(to);
    fs::rename(ctx.path(from), &target).map_err(|error| format!("{to}: {error}"))?;
    if let Some(dir) = target.parent() {
        let _ = fs::File::open(dir).and_then(|dir| dir.sync_all());
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// A rename target that fails, for the rollback tests.
    pub(super) static FAIL_RENAME: std::cell::Cell<Option<&'static str>> =
        const { std::cell::Cell::new(None) };
}

/// Where `swap` writes the new bundle, key and chain before renaming them.
fn staged() -> (String, String, String) {
    (
        format!("{INTERMEDIATE}.new"),
        format!("{INTERMEDIATE_KEY}.new"),
        format!("{CHAIN}.new"),
    )
}

/// A crash cut a Replace short inside `swap`: its staged files are left.
/// The files in use are judged once `finish_interrupted` has ended it.
pub(crate) fn interrupted<R: Runner>(ctx: &Ctx<R>) -> bool {
    let (bundle, key, chain) = staged();
    [bundle, key, chain].iter().any(|path| ctx.exists(path))
}

/// Ends a Replace a crash cut short inside `swap` (callers hold the Setup
/// lock): the bundle renamed but not the key is finished; a swap whose
/// bundle still has the old one first is undone, so Replace does not
/// refuse for a month. The line saying which, when it did.
pub(crate) fn finish_interrupted<R: Runner>(ctx: &Ctx<R>) -> Result<Option<String>, String> {
    let (bundle, key, chain) = staged();
    let left = interrupted(ctx);
    if !left && !ctx.exists(PREVIOUS) {
        return Ok(None);
    }
    let first = platform_pki::first_certificate(&ctx.read(INTERMEDIATE)?)
        .map_err(|error| format!("{INTERMEDIATE}: {error:?}"))?;
    if ctx
        .read(&key)
        .is_ok_and(|pem| Issuer::load(&first, &pem).is_ok())
    {
        if ctx.exists(&chain) {
            rename(ctx, &chain, CHAIN)?;
        }
        rename(ctx, &key, INTERMEDIATE_KEY)?;
        let _ = fs::remove_file(ctx.path(import::CHAIN_OLD));
        let _ = import::drop_empty_chain(ctx);
        return Ok(Some("finished an interrupted replacement".into()));
    }
    // previous.crt is the old first certificate: still first, nothing took.
    let never = match ctx.read(PREVIOUS) {
        Ok(previous) => previous == first,
        Err(_) => left,
    };
    if !never {
        return Ok(None);
    }
    // The chain as it was before the swap, when it kept a copy.
    if ctx.exists(import::CHAIN_OLD) {
        import::restore_chain(ctx)?;
    }
    for path in [
        bundle.as_str(),
        &key,
        &chain,
        import::CHAIN_OLD,
        PREVIOUS,
        PREVIOUS_UNTIL,
    ] {
        import::remove(ctx, path)?;
    }
    Ok(Some(
        "removed an interrupted replacement that never took effect".into(),
    ))
}
