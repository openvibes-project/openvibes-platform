//! `helper ca-replace [--root-key PATH]`: a new intermediate, signed by the
//! same root. `intermediate.crt` then holds the new one first (it issues
//! everything from now on) and the old one second, so agents keep
//! connecting with what the old one signed until they renew onto the new
//! one; the daily renewal drops the old one after `PREVIOUS_UNTIL`
//! (`drop_previous`).

use std::{fs, os::unix::fs::DirBuilderExt, path::Path, process::ExitCode};

use chrono::{DateTime, Utc};
use platform_host::{
    CONFIG_DIR,
    runner::{
        Program::{Admin, Systemctl},
        Runner,
    },
};
use platform_pki::Issuer;

use super::{
    Ctx, begin, host_ctx,
    pki::{
        self, ADMIN_OWNER, INT, INTERMEDIATE, INTERMEDIATE_KEY, ROOT_CERT, ROOT_DIR, STAGE,
        certificates_apply,
    },
    plan::{CaMode, Component},
    request::{REQUEST_DIR, message},
    setup_guard,
};

/// The old intermediate while agents still hold certificates it signed
/// (0644 root:root, for the TUI).
pub(crate) const PREVIOUS: &str = "/etc/openvibes/pki/previous.crt";
/// When the old one stops being trusted: one RFC 3339 instant.
pub(crate) const PREVIOUS_UNTIL: &str = "/etc/openvibes/pki/previous-until";
/// Ingest's own certificate: from the new intermediate once ingest issues
/// from it.
const INGEST_CERT: &str = "/etc/openvibes/tls/ingest.crt";

/// A root key file that is not this root's (the TUI checks it first too).
pub(crate) const NOT_THE_KEY: &str =
    "Not the key of this host's root: pick the root key kept at install.";

/// The stages finished so far, one line each, for the TUI's step list
/// (under the root; 0644, replaced whole; emptied when a run starts and
/// removed when one succeeds).
pub(crate) const PROGRESS: &str = "run/openvibes-admin/ca-replace-progress";

/// Says `stage` is done: on standard output and in `PROGRESS`. The
/// progress file is only a display: failing to write it fails nothing.
fn finished<R: Runner>(ctx: &Ctx<R>, done: &mut String, stage: &str) {
    use std::os::unix::fs::PermissionsExt;
    println!("{stage}");
    done.push_str(stage);
    done.push('\n');
    let file = ctx.path(PROGRESS);
    if let Some(dir) = file.parent() {
        let _ = fs::create_dir_all(dir);
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
    }
    let _ = crate::model_progress::replace_file(&file, done);
}

/// The agents' certificate lifetime, `client_certificate_days` (default 30).
fn client_days<R: Runner>(ctx: &Ctx<R>) -> i64 {
    ctx.read(&format!("{CONFIG_DIR}/ingest.toml"))
        .ok()
        .and_then(|text| text.parse::<toml::Table>().ok())
        .and_then(|table| table.get("client_certificate_days")?.as_integer())
        .unwrap_or(30)
}

/// The new intermediate and its key, staged in `INT` for openvibes-admin.
fn careful<R: Runner>(ctx: &Ctx<R>, root: &str) -> Result<(), String> {
    let request = |name: &str| format!("{REQUEST_DIR}/{name}");
    let names = [
        "intermediate.key",
        "intermediate.csr",
        "intermediate.crt",
        "root.crt",
    ];
    if !names.iter().all(|name| ctx.exists(&request(name))) {
        let missing =
            "There is no signed request: make the request and add both certificates first.";
        return Err(missing.into());
    }
    if ctx.read(&request("root.crt"))?.trim() != root.trim() {
        return Err(
            "Your CA's certificate is not this host's root: agents trust only that one.".into(),
        );
    }
    pki::fresh_stage(ctx)?;
    pki::stage_dir(ctx, INT)?;
    for name in ["intermediate.key", "intermediate.crt"] {
        let mode = if name.ends_with(".key") { 0o600 } else { 0o644 };
        ctx.copy(&request(name), &format!("{INT}/{name}"), ADMIN_OWNER, mode)?;
    }
    Ok(())
}

/// Signs a new intermediate with the root key, as at install; the key's
/// copy lives in tmpfs and the caller removes the stage.
fn quick<R: Runner>(ctx: &Ctx<R>, root: &str, root_key: Option<&str>) -> Result<(), String> {
    let mismatch = || NOT_THE_KEY;
    let key = ctx.read(root_key.ok_or_else(mismatch)?)?;
    Issuer::load(root, &key).map_err(|_| mismatch())?;
    pki::fresh_stage(ctx)?;
    // Root's, as `ca init-root` makes it at install: only root reads the key.
    fs::DirBuilder::new()
        .mode(0o700)
        .create(ctx.path(ROOT_DIR))
        .map_err(|error| format!("{ROOT_DIR}: {error}"))?;
    ctx.put(
        &format!("{ROOT_DIR}/root.crt"),
        root.as_bytes(),
        None,
        0o644,
    )?;
    ctx.put(&format!("{ROOT_DIR}/root.key"), key.as_bytes(), None, 0o600)?;
    ctx.as_admin(&["ca", "intermediate-request", "--out", INT])?;
    ctx.ok(
        Admin,
        &[
            "ca",
            "sign-intermediate",
            "--root",
            ROOT_DIR,
            "--csr",
            &format!("{INT}/intermediate.csr"),
            "--out",
            &format!("{INT}/intermediate.crt"),
        ],
    )?;
    fs::remove_dir_all(ctx.path(ROOT_DIR)).map_err(|error| format!("{ROOT_DIR}: {error}"))
}

/// Puts the new key and the bundle (new + old) in place of the old pair.
///
/// `previous.*` go first: while they are there Replace refuses and they
/// name the old one. The new key and bundle are then written whole beside
/// their targets (`.new`), so only two renames are left to change what is
/// in use: the bundle first, the key last. A failure at any point puts back
/// what was renamed and removes the rest, so the old pair is in use again.
/// A crash part way is ended by `finish_interrupted`.
fn swap<R: Runner>(
    ctx: &Ctx<R>,
    previous: &str,
    until: &str,
    new: &str,
    new_key: &str,
) -> Result<(), String> {
    let old = ctx.read(INTERMEDIATE)?;
    let (bundle, key) = staged();
    let mut restored = true;
    let result = (|| {
        ctx.put(PREVIOUS, previous.as_bytes(), None, 0o644)?;
        ctx.put(PREVIOUS_UNTIL, format!("{until}\n").as_bytes(), None, 0o644)?;
        let ingest = Some(("openvibes-ingest", "openvibes-ingest"));
        ctx.put(&key, new_key.as_bytes(), ingest, 0o600)?;
        ctx.put(&bundle, format!("{new}{previous}").as_bytes(), None, 0o644)?;
        rename(ctx, &bundle, INTERMEDIATE)?;
        rename(ctx, &key, INTERMEDIATE_KEY).map_err(|error| {
            match ctx.put(INTERMEDIATE, old.as_bytes(), None, 0o644) {
                Ok(()) => error,
                Err(again) => {
                    restored = false;
                    format!("{error}; the old {INTERMEDIATE} could not be put back: {again}")
                }
            }
        })
    })();
    // When the old bundle is not back, all stay: `finish_interrupted`
    // renames the key next time.
    if result.is_err() && restored {
        for path in [bundle.as_str(), &key, PREVIOUS, PREVIOUS_UNTIL] {
            let _ = fs::remove_file(ctx.path(path));
        }
    }
    result
}

/// The new intermediate staged and checked, then trusted beside the old
/// one; the server certificates are reissued from it. Prints each finished
/// stage; the new one's expiry and the old one's end, `YYYY-MM-DD<TAB>…`.
fn run<R: Runner>(ctx: &Ctx<R>, root_key: Option<&str>) -> Result<String, String> {
    let mut done = String::new();
    let _ = crate::model_progress::replace_file(&ctx.path(PROGRESS), "");
    let root = ctx.read(ROOT_CERT)?;
    let previous = platform_pki::first_certificate(&ctx.read(INTERMEDIATE)?)
        .map_err(|error| format!("{INTERMEDIATE}: {error:?}"))?;
    match ctx.plan.ca {
        CaMode::Careful => careful(ctx, &root)?,
        CaMode::Quick => quick(ctx, &root, root_key)?,
    }
    let (cert, key) = (
        format!("{INT}/intermediate.crt"),
        format!("{INT}/intermediate.key"),
    );
    let new = platform_pki::first_certificate(&ctx.read(&cert)?).map_err(|e| message(&e))?;
    let new_key = ctx.read(&key)?;
    Issuer::load(&new, &new_key).map_err(|e| message(&e))?;
    platform_pki::check_intermediate(&new, &root, Utc::now()).map_err(|e| message(&e))?;
    let expires = platform_pki::not_after(&new).map_err(|e| message(&e))?;
    finished(ctx, &mut done, "Making the new intermediate");

    // Recorded first: the import checks it once more before anything on
    // disk changes.
    ctx.as_admin(&[
        "ca",
        "import-intermediate",
        "--cert",
        &cert,
        "--key",
        &key,
        "--root-cert",
        ROOT_CERT,
    ])?;
    let until = Utc::now() + chrono::Duration::days(client_days(ctx) + 1);
    let until_text = until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    swap(ctx, &previous, &until_text, &new, &new_key)?;
    if ctx.plan.ca == CaMode::Careful {
        pki::remove_request(ctx)?;
    }
    pki::remove_stage(ctx)?;
    finished(ctx, &mut done, "Trusting the old and the new one");

    certificates_apply(ctx).map_err(|error| {
        format!(
            "The intermediate was replaced, but the server certificates were not reissued: run \
             Repair in Maintenance (they stay valid until then). {error}"
        )
    })?;
    finished(ctx, &mut done, "Issuing the server certificates");
    finished(ctx, &mut done, "Restarting the services");
    Ok(format!(
        "{}\t{}",
        expires.format("%Y-%m-%d"),
        until.format("%Y-%m-%d")
    ))
}

/// Removes the previous intermediate once nothing it signed is left (after
/// `PREVIOUS_UNTIL`, and `client_certificate_days` + 1 after ingest moved
/// to the new one); the log line when it did.
pub(crate) fn drop_previous<R: Runner>(ctx: &Ctx<R>) -> Result<Option<String>, String> {
    let Ok(until) = ctx.read(PREVIOUS_UNTIL) else {
        return Ok(None);
    };
    let until = chrono::DateTime::parse_from_rfc3339(until.trim())
        .map_err(|error| format!("{PREVIOUS_UNTIL}: {error}"))?;
    if chrono::Utc::now() < until {
        return Ok(None);
    }
    let first = platform_pki::first_certificate(&ctx.read(INTERMEDIATE)?)
        .map_err(|error| format!("{INTERMEDIATE}: {error:?}"))?;
    // A running ingest issues from the intermediate it read at start: the
    // new one only once it restarted on its certificate reissued from it.
    // Agents' certificates from the old one last `client_certificate_days`
    // from then.
    if ctx.plan.has(Component::Ingest) {
        let moved = ctx
            .read(INGEST_CERT)
            .ok()
            .filter(|pem| platform_pki::verify_signed_by(pem, &first).is_ok())
            .and_then(|pem| platform_pki::not_before(&pem).ok());
        let Some(moved) = moved else {
            return Ok(None);
        };
        if chrono::Utc::now() < moved + chrono::Duration::days(client_days(ctx) + 1) {
            return Ok(None);
        }
    }
    ctx.put(INTERMEDIATE, first.as_bytes(), None, 0o644)?;
    // The services read the bundle at start. The date goes last: a failed
    // restart is tried again tomorrow.
    let units = [Component::Ingest, Component::Distribution]
        .into_iter()
        .filter(|component| ctx.plan.has(*component))
        .map(|component| format!("openvibes-{}", component.name()));
    let mut args = vec!["try-restart".to_owned()];
    args.extend(units);
    ctx.ok(
        Systemctl,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    for path in [PREVIOUS, PREVIOUS_UNTIL] {
        match fs::remove_file(ctx.path(path)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("{path}: {error}"));
            }
            _ => {}
        }
    }
    Ok(Some("previous intermediate no longer trusted".into()))
}

/// Renames `from` over `to`, then syncs the folder so the rename itself
/// survives a crash. Only the rename decides: once it is done the file is
/// in place, and a failed sync must not make the caller undo half a swap.
fn rename<R: Runner>(ctx: &Ctx<R>, from: &str, to: &str) -> Result<(), String> {
    let target = ctx.path(to);
    fs::rename(ctx.path(from), &target).map_err(|error| format!("{to}: {error}"))?;
    if let Some(dir) = target.parent() {
        let _ = fs::File::open(dir).and_then(|dir| dir.sync_all());
    }
    Ok(())
}

/// Where `swap` writes the new bundle and key before renaming them.
fn staged() -> (String, String) {
    (
        format!("{INTERMEDIATE}.new"),
        format!("{INTERMEDIATE_KEY}.new"),
    )
}

/// Ends a Replace a crash cut short inside `swap` (callers hold the Setup
/// lock): the bundle renamed but not the key is finished; a swap whose
/// bundle still has the old one first is undone, so Replace does not
/// refuse for a month. The line saying which, when it did.
pub(crate) fn finish_interrupted<R: Runner>(ctx: &Ctx<R>) -> Result<Option<String>, String> {
    let (bundle, key) = staged();
    let left = ctx.exists(&bundle) || ctx.exists(&key);
    if !left && !ctx.exists(PREVIOUS) {
        return Ok(None);
    }
    let first = platform_pki::first_certificate(&ctx.read(INTERMEDIATE)?)
        .map_err(|error| format!("{INTERMEDIATE}: {error:?}"))?;
    if ctx
        .read(&key)
        .is_ok_and(|pem| Issuer::load(&first, &pem).is_ok())
    {
        rename(ctx, &key, INTERMEDIATE_KEY)?;
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
    for path in [bundle.as_str(), &key, PREVIOUS, PREVIOUS_UNTIL] {
        match fs::remove_file(ctx.path(path)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("{path}: {error}"));
            }
            _ => {}
        }
    }
    Ok(Some(
        "removed an interrupted replacement that never took effect".into(),
    ))
}

/// Why another replacement waits (the TUI says it before asking).
pub(crate) fn still_trusted(until: &str) -> String {
    format!(
        "The previous intermediate is still trusted until {until}, while agents move over: \
         replace it again after that."
    )
}

/// Replaces the intermediate; the stage (with any root key copy) is gone
/// whatever happened.
pub fn replace<R: Runner>(ctx: &Ctx<R>, root_key: Option<&str>) -> Result<String, String> {
    if let Some(line) = finish_interrupted(ctx)? {
        println!("{line}");
    }
    // Another replacement now would drop the intermediate most agents
    // still hold certificates from.
    if ctx.exists(PREVIOUS) {
        let until = ctx.read(PREVIOUS_UNTIL)?;
        let until = DateTime::parse_from_rfc3339(until.trim())
            .map_err(|error| format!("{PREVIOUS_UNTIL}: {error}"))?;
        return Err(still_trusted(&until.format("%Y-%m-%d").to_string()));
    }
    let result = run(ctx, root_key);
    if result.is_ok() {
        let _ = fs::remove_file(ctx.path(PROGRESS));
    }
    let stage = ctx.path(STAGE);
    if stage.exists()
        && let Err(error) = fs::remove_dir_all(&stage)
    {
        let left = format!("{STAGE} is left, remove it: {error}");
        return Err(match result {
            Ok(_) => left,
            Err(failed) => format!("{failed}; {left}"),
        });
    }
    result
}

/// `helper ca-replace [--root-key PATH]`: the stages, then
/// `done<TAB>EXPIRES<TAB>PREVIOUS_UNTIL`.
pub fn ca_replace(root_key: Option<&Path>) -> ExitCode {
    let (_lock, plan) = match begin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    if let Err(code) = setup_guard() {
        return code;
    }
    let replaced = root_key
        .map(|path| path.to_str().ok_or("the root key path is not UTF-8"))
        .transpose()
        .map_err(str::to_owned)
        .and_then(|key| replace(&host_ctx(&plan, false), key));
    match replaced {
        Ok(detail) => {
            println!("done\t{detail}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("openvibes-admin helper: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[path = "replace_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "replace_interrupted_tests.rs"]
mod interrupted_tests;
