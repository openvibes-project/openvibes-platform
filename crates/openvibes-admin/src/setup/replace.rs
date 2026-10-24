//! `helper ca-replace [--root-key PATH]`: a new intermediate, signed by the
//! same root. `intermediate.crt` then holds the new one first (it issues
//! everything from now on) and the old one second, so agents keep
//! connecting with what the old one signed until they renew onto the new
//! one; the daily renewal drops the old one after `PREVIOUS_UNTIL`
//! (`pki::drop_previous`).

use std::{fs, os::unix::fs::DirBuilderExt, path::Path, process::ExitCode};

use chrono::{DateTime, Utc};
use platform_host::{
    CONFIG_DIR,
    runner::{Program::Admin, Runner},
};
use platform_pki::Issuer;

use super::{
    Ctx, begin, host_ctx,
    pki::{
        self, ADMIN_OWNER, INT, INTERMEDIATE, INTERMEDIATE_KEY, ROOT_CERT, ROOT_DIR, STAGE,
        certificates_apply,
    },
    plan::CaMode,
    request::{REQUEST_DIR, message},
    setup_guard,
};

/// The old intermediate while agents still hold certificates it signed
/// (0644 root:root, for the TUI).
pub(crate) const PREVIOUS: &str = "/etc/openvibes/pki/previous.crt";
/// When the old one stops being trusted: one RFC 3339 instant.
pub(crate) const PREVIOUS_UNTIL: &str = "/etc/openvibes/pki/previous-until";

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
    let mismatch = || "Not the key of this host's root: pick the root key kept at install.";
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

/// The new intermediate staged and checked, then trusted beside the old
/// one; the server certificates are reissued from it. Prints each finished
/// stage; the new one's expiry and the old one's end, `YYYY-MM-DD<TAB>…`.
fn run<R: Runner>(ctx: &Ctx<R>, root_key: Option<&str>) -> Result<String, String> {
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
    println!("Making the new intermediate");

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
    ctx.put(PREVIOUS, previous.as_bytes(), None, 0o644)?;
    ctx.put(
        PREVIOUS_UNTIL,
        format!("{until_text}\n").as_bytes(),
        None,
        0o644,
    )?;
    ctx.put(
        INTERMEDIATE_KEY,
        new_key.as_bytes(),
        Some(("openvibes-ingest", "openvibes-ingest")),
        0o600,
    )?;
    ctx.put(
        INTERMEDIATE,
        format!("{new}{previous}").as_bytes(),
        None,
        0o644,
    )?;
    if ctx.plan.ca == CaMode::Careful {
        pki::remove_request(ctx)?;
    }
    pki::remove_stage(ctx)?;
    println!("Trusting the old and the new one");

    certificates_apply(ctx).map_err(|error| {
        format!(
            "The intermediate was replaced, but the server certificates were not reissued: run \
             Repair in Maintenance (they stay valid until then). {error}"
        )
    })?;
    println!("Issuing the server certificates");
    println!("Restarting the services");
    Ok(format!(
        "{}\t{}",
        expires.format("%Y-%m-%d"),
        until.format("%Y-%m-%d")
    ))
}

/// Replaces the intermediate; the stage (with any root key copy) is gone
/// whatever happened.
pub fn replace<R: Runner>(ctx: &Ctx<R>, root_key: Option<&str>) -> Result<String, String> {
    // Another replacement now would drop the intermediate most agents
    // still hold certificates from.
    if ctx.exists(PREVIOUS) {
        let until = ctx.read(PREVIOUS_UNTIL)?;
        let until = DateTime::parse_from_rfc3339(until.trim())
            .map_err(|error| format!("{PREVIOUS_UNTIL}: {error}"))?;
        return Err(format!(
            "The previous intermediate is still trusted until {}, while agents move over: \
             replace it again after that.",
            until.format("%Y-%m-%d")
        ));
    }
    let result = run(ctx, root_key);
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
