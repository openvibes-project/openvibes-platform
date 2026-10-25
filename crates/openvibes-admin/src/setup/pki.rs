//! Steps 6–7: the CA (quick, careful or imported) and the server
//! certificates, staged in `/run/openvibes-ca` (tmpfs, so key copies never
//! reach disk) and installed where the services read them (packaging.md
//! "First install").

use std::fs;

use platform_host::{
    StepState,
    runner::{
        Program::{Admin, Ip, Systemctl},
        Runner,
    },
};

use super::{
    Ctx,
    pki_import::{CHAIN, ends_in_chain, import_and_install},
    plan::{CaMode, Component},
    request::REQUEST_DIR,
};

pub(super) const STAGE: &str = "/run/openvibes-ca";
pub(super) const INT: &str = "/run/openvibes-ca/int";
pub(super) const ROOT_DIR: &str = "/run/openvibes-ca/root";
pub(crate) const INTERMEDIATE: &str = "/etc/openvibes/pki/intermediate.crt";
/// The root certificate agents trust.
pub const ROOT_CERT: &str = "/etc/openvibes/pki/root.crt";
pub(crate) const INTERMEDIATE_KEY: &str = "/var/lib/openvibes-ingest/intermediate.key";
pub(super) const ADMIN_OWNER: Option<(&str, &str)> = Some(("openvibes-admin", "openvibes-admin"));

/// `AB:CD:…`, the SHA-256 of a certificate.
pub fn fingerprint(pem: &str) -> Result<String, String> {
    let digest = platform_pki::sha256_fingerprint(pem)
        .map_err(|error| format!("root certificate: {error:?}"))?;
    Ok(digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

pub(super) fn root_summary<R: Runner>(ctx: &Ctx<R>) -> Result<String, String> {
    Ok(format!(
        "root certificate {ROOT_CERT}, SHA-256 {}",
        fingerprint(&ctx.read(ROOT_CERT)?)?
    ))
}

fn careful_help() -> String {
    format!(
        "sign {INT}/intermediate.csr on the offline machine (openvibes-admin ca sign-intermediate \
         --root ROOT_DIR --csr intermediate.csr --out intermediate.crt), then copy intermediate.crt \
         and root.crt into {INT} and run this step again; the request is lost on reboot"
    )
}

/// The CA files are where the services read them.
pub(super) fn installed<R: Runner>(ctx: &Ctx<R>) -> bool {
    ctx.exists(INTERMEDIATE) && ctx.exists(ROOT_CERT) && ctx.exists(INTERMEDIATE_KEY)
}

/// A quick CA installed whose root key is still staged: writing it to
/// `root_key_out` failed, so the step is not done until it is kept.
fn key_staged<R: Runner>(ctx: &Ctx<R>) -> bool {
    ctx.plan.root_key_out.is_some() && ctx.exists(&format!("{ROOT_DIR}/root.key"))
}

pub fn ca_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if installed(ctx) && !key_staged(ctx) {
        return Ok(StepState::Done(root_summary(ctx)?));
    }
    if ctx.plan.ca == CaMode::Import {
        return Ok(StepState::Waiting(super::pki_import::HELP.into()));
    }
    let signed =
        ctx.exists(&format!("{INT}/intermediate.crt")) && ctx.exists(&format!("{INT}/root.crt"));
    if ctx.plan.ca == CaMode::Careful && ctx.exists(&format!("{INT}/intermediate.csr")) && !signed {
        return Ok(StepState::Waiting(careful_help()));
    }
    Ok(StepState::Todo)
}

/// A fresh staging directory, 0700 openvibes-admin (a stale one from a
/// failed run is removed: it is in tmpfs and only ever ours).
pub(super) fn fresh_stage<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    let path = ctx.path(STAGE);
    if path.exists() {
        fs::remove_dir_all(&path).map_err(|error| format!("{STAGE}: {error}"))?;
    }
    stage_dir(ctx, STAGE)
}

/// Creates `abs` (0700, openvibes-admin) for a command run as that user.
pub(super) fn stage_dir<R: Runner>(ctx: &Ctx<R>, abs: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let path = ctx.path(abs);
    fs::create_dir_all(&path).map_err(|error| format!("{abs}: {error}"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("{abs}: {error}"))?;
    ctx.chown(abs, ADMIN_OWNER)
}

/// Copies `names` from the root-only `dir` into a fresh `INT` for
/// openvibes-admin, which cannot read that folder: keys 0600, the rest 0644.
pub(super) fn stage_from<R: Runner>(ctx: &Ctx<R>, dir: &str, names: &[&str]) -> Result<(), String> {
    fresh_stage(ctx)?;
    stage_dir(ctx, INT)?;
    for name in names {
        let mode = if name.ends_with(".key") { 0o600 } else { 0o644 };
        ctx.copy(
            &format!("{dir}/{name}"),
            &format!("{INT}/{name}"),
            ADMIN_OWNER,
            mode,
        )?;
    }
    Ok(())
}

pub(super) fn remove_stage<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    fs::remove_dir_all(ctx.path(STAGE)).map_err(|error| format!("{STAGE}: {error}"))
}

/// Writes the root key once to `root_key_out` (never over an existing
/// file); what happened to it.
fn keep_root_key<R: Runner>(ctx: &Ctx<R>) -> Result<String, String> {
    let Some(out) = &ctx.plan.root_key_out else {
        return Ok("root key deleted (a new intermediate will need a new root)".into());
    };
    let shown = out.display().to_string();
    let mut key = fs::File::open(ctx.path(&format!("{ROOT_DIR}/root.key")))
        .map_err(|error| format!("root key: {error}"))?;
    let note = ctx.write_new(&shown, &mut key)?;
    Ok(format!("root key saved to {shown}: keep it offline{note}"))
}

/// `root_key_out` is new (a dangling link counts as there) in an existing
/// folder, so the key can be written once the CA is installed.
fn check_root_key_out<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    let Some(out) = &ctx.plan.root_key_out else {
        return Ok(());
    };
    let again = "set another Root key file (Esc opens the form, or --root-key-out)";
    if fs::symlink_metadata(ctx.path(&out.display().to_string())).is_ok() {
        return Err(format!(
            "{} already exists (a root key kept from an earlier install?); {again}",
            out.display()
        ));
    }
    let folder = out.parent().map_or("/".into(), |p| p.display().to_string());
    let path = ctx.path(&folder);
    if !path.exists() {
        return Err(format!("the folder {folder} does not exist; {again}"));
    }
    if !path.is_dir() {
        return Err(format!("{folder} is not a folder; {again}"));
    }
    Ok(())
}

fn quick<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    check_root_key_out(ctx)?;
    if installed(ctx) && key_staged(ctx) {
        // A retry after the key could not be written: keep it now.
        let kept = keep_root_key(ctx)?;
        remove_stage(ctx)?;
        remove_request(ctx)?;
        return Ok(StepState::Done(format!("{kept}; {}", root_summary(ctx)?)));
    }
    fresh_stage(ctx)?;
    ctx.ok(Admin, &["ca", "init-root", "--out", ROOT_DIR])?;
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
    ctx.copy(
        &format!("{ROOT_DIR}/root.crt"),
        &format!("{INT}/root.crt"),
        ADMIN_OWNER,
        0o644,
    )?;
    // The key is written only once the root is installed, so a failed
    // import leaves no key file to block the retry.
    import_and_install(ctx)?;
    let kept = keep_root_key(ctx)?;
    remove_stage(ctx)?;
    remove_request(ctx)?;
    Ok(StepState::Done(format!("{kept}; {}", root_summary(ctx)?)))
}

/// Removes the request made before install, if any (R2), and the
/// operator's copy of it.
pub(super) fn remove_request<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    super::request::remove_copy(ctx);
    match fs::remove_dir_all(ctx.path(REQUEST_DIR)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("{REQUEST_DIR}: {error}"))
        }
        _ => Ok(()),
    }
}

fn careful<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    // A request beside an installed CA is `ca-replace`'s: installing it
    // here would drop the intermediate enrolled agents hold (ruling 8).
    if installed(ctx) {
        return Ok(StepState::Done(root_summary(ctx)?));
    }
    let request = |name: &str| format!("{REQUEST_DIR}/{name}");
    let names = [
        "intermediate.key",
        "intermediate.csr",
        "intermediate.crt",
        "root.crt",
    ];
    if names.iter().all(|name| ctx.exists(&request(name))) {
        stage_from(ctx, REQUEST_DIR, &names)?;
        import_and_install(ctx)?;
        remove_stage(ctx)?;
        remove_request(ctx)?;
        return Ok(StepState::Done(root_summary(ctx)?));
    }
    if ctx.exists(&format!("{INT}/intermediate.crt")) && ctx.exists(&format!("{INT}/root.crt")) {
        import_and_install(ctx)?;
        remove_stage(ctx)?;
        return Ok(StepState::Done(root_summary(ctx)?));
    }
    if !ctx.exists(&format!("{INT}/intermediate.csr")) {
        fresh_stage(ctx)?;
        ctx.as_admin(&["ca", "intermediate-request", "--out", INT])?;
    }
    Ok(StepState::Waiting(careful_help()))
}

pub fn ca_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    // Keeping a staged root key (installed CA) is no new CA.
    if ctx.repair && !installed(ctx) {
        return Err("the CA files are missing; Repair never makes a new CA (enrolled agents trust \
                    the old one): restore /etc/openvibes/pki and /var/lib/openvibes-ingest/\
                    intermediate.key from a backup, or uninstall with Remove everything and set up again"
            .into());
    }
    match ctx.plan.ca {
        CaMode::Quick => quick(ctx),
        CaMode::Careful => careful(ctx),
        CaMode::Import => super::pki_import::import(ctx),
    }
}

/// Where one service's certificate goes.
struct Tls {
    component: Component,
    stem: &'static str,
    cert: &'static str,
    key: &'static str,
    /// Console: certificate then intermediate in one file (0644) and the
    /// key (0640), root:openvibes-console; otherwise the key belongs to
    /// the service.
    console: bool,
    owner: &'static str,
}

static TLS: [Tls; 3] = [
    Tls {
        component: Component::Ingest,
        stem: "ingest",
        cert: "/etc/openvibes/tls/ingest.crt",
        key: "/etc/openvibes/tls/ingest.key",
        console: false,
        owner: "openvibes-ingest",
    },
    Tls {
        component: Component::Distribution,
        stem: "distribution",
        cert: "/etc/openvibes/tls/distribution.crt",
        key: "/etc/openvibes/tls/distribution.key",
        console: false,
        owner: "openvibes-distribution",
    },
    Tls {
        component: Component::Console,
        stem: "console",
        cert: "/etc/openvibes/tls/console-chain.pem",
        key: "/etc/openvibes/tls/console-key.pem",
        console: true,
        owner: "openvibes-console",
    },
];

fn chosen<'a, R: Runner>(ctx: &'a Ctx<'a, R>) -> impl Iterator<Item = &'static Tls> + 'a {
    TLS.iter().filter(|tls| ctx.plan.has(tls.component))
}

const TLS_NAMES: &str = "/etc/openvibes/tls/setup-names";
/// The renewal timer reissues a server certificate this close to expiry.
pub(crate) const RENEW_AT_DAYS: i64 = 30;
/// Health reports a server certificate this close to expiry: the timer
/// should have renewed it by now.
pub(crate) const RENEW_DAYS: i64 = 14;
/// Health asks for a new intermediate this close to its expiry: nothing
/// renews it by itself.
pub(crate) const INTERMEDIATE_WARN_DAYS: i64 = 60;

/// The plan's names, then the host's own addresses (board #71: the console
/// opens by IP over a VPN). An address that changes (DHCP) makes the check
/// Todo, so Check shows it and Repair reissues; Health says so too. Without
/// `ip`, just the plan's names.
pub(crate) fn certificate_names<R: Runner>(ctx: &Ctx<R>) -> Vec<String> {
    let mut names = ctx.plan.names();
    let listing = ctx.ok(Ip, &platform_host::IP_ADDRESSES).unwrap_or_default();
    for address in platform_host::host_addresses(&listing) {
        if !names.contains(&address) {
            names.push(address);
        }
    }
    names
}

pub fn certificates_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let names = certificate_names(ctx);
    let wanted = format!("{}\n", names.join("\n"));
    let present = chosen(ctx).all(|tls| ctx.exists(tls.cert) && ctx.exists(tls.key));
    if !present || ctx.read(TLS_NAMES).ok().as_deref() != Some(wanted.as_str()) {
        return Ok(StepState::Todo);
    }
    for tls in chosen(ctx) {
        let pem = ctx.read(tls.cert)?;
        let expires =
            platform_pki::not_after(&pem).map_err(|error| format!("{}: {error:?}", tls.cert))?;
        if expires - chrono::Utc::now() < chrono::Duration::days(RENEW_AT_DAYS) {
            return Ok(StepState::Todo);
        }
    }
    // After a replaced intermediate, until they are issued again from it.
    if let Some(issuer) = ctx
        .read(INTERMEDIATE)
        .ok()
        .and_then(|bundle| platform_pki::first_certificate(&bundle).ok())
    {
        let signed = |tls: &Tls| {
            ctx.read(tls.cert)
                .is_ok_and(|pem| platform_pki::verify_signed_by(&pem, &issuer).is_ok())
        };
        if !chosen(ctx).all(signed) {
            return Ok(StepState::Todo);
        }
    }
    // After `CHAIN` was installed or changed (Import).
    if !chosen(ctx).all(|tls| ctx.read(tls.cert).is_ok_and(|pem| ends_in_chain(ctx, &pem))) {
        return Ok(StepState::Todo);
    }
    // The console's chain is public (browsers get it anyway) and the TUI,
    // which is not root, reads its expiry: an older install wrote it 0640.
    let world_readable = |path: &str| {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(ctx.path(path)).is_ok_and(|m| m.permissions().mode() & 0o777 == 0o644)
    };
    if chosen(ctx).any(|tls| tls.console && !world_readable(tls.cert)) {
        return Ok(StepState::Todo);
    }
    Ok(StepState::Done(format!(
        "server certificates for {}",
        names.join(", ")
    )))
}

pub fn certificates_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    // Repair's way out of a Replace a crash cut short (key and bundle apart).
    let recovered = super::replace::finish_interrupted(ctx)?.map_or(String::new(), |l| l + "; ");
    let names = certificate_names(ctx);
    fresh_stage(ctx)?;
    ctx.copy(
        INTERMEDIATE,
        &format!("{STAGE}/issuer.crt"),
        ADMIN_OWNER,
        0o644,
    )?;
    ctx.copy(
        INTERMEDIATE_KEY,
        &format!("{STAGE}/issuer.key"),
        ADMIN_OWNER,
        0o600,
    )?;
    for tls in chosen(ctx) {
        let out = format!("{STAGE}/{}", tls.stem);
        stage_dir(ctx, &out)?;
        let mut args = vec!["ca", "issue-server", names[0].as_str()];
        for san in &names[1..] {
            args.extend(["--san", san.as_str()]);
        }
        let issuer_cert = format!("{STAGE}/issuer.crt");
        let issuer_key = format!("{STAGE}/issuer.key");
        args.extend([
            "--issuer-cert",
            &issuer_cert,
            "--issuer-key",
            &issuer_key,
            "--out",
            &out,
        ]);
        if ctx.exists(CHAIN) {
            args.extend(["--chain", CHAIN]);
        }
        ctx.as_admin(&args)?;
        let crt = format!("{out}/{}.crt", names[0]);
        let key = format!("{out}/{}.key", names[0]);
        if tls.console {
            // Already the chain: the leaf, then its issuer (the bundle's
            // first certificate only), then `CHAIN`'s CAs.
            let owner = Some(("root", tls.owner));
            ctx.copy(&crt, tls.cert, owner, 0o644)?;
            ctx.copy(&key, tls.key, owner, 0o640)?;
        } else {
            ctx.copy(&crt, tls.cert, None, 0o644)?;
            ctx.copy(&key, tls.key, Some((tls.owner, tls.owner)), 0o600)?;
        }
    }
    remove_stage(ctx)?;
    // The services read their certificate at start (none reloads it).
    // try-restart leaves a stopped service alone, so a first install is
    // not started early. Before the names are written: a failed restart
    // leaves the check Todo, so the next Repair tries again.
    let units: Vec<String> = chosen(ctx)
        .map(|tls| format!("openvibes-{}", tls.stem))
        .collect();
    let mut args = vec!["try-restart"];
    args.extend(units.iter().map(String::as_str));
    ctx.ok(Systemctl, &args)?;
    ctx.put(
        TLS_NAMES,
        format!("{}\n", names.join("\n")).as_bytes(),
        None,
        0o644,
    )?;
    Ok(StepState::Done(format!(
        "{recovered}server certificates for {} (valid 90 days)",
        names.join(", ")
    )))
}

#[cfg(test)]
#[path = "pki_root_key_tests.rs"]
mod root_key_tests;

#[cfg(test)]
#[path = "pki_renew_tests.rs"]
mod renew_tests;
