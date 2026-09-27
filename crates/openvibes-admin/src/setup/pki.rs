//! Steps 6–7: the CA (quick or careful) and the server certificates, staged
//! in `/run/openvibes-ca` (tmpfs, so key copies never reach disk) and
//! installed where the services read them (packaging.md "First install").

use std::{fs, io::Write, os::unix::fs::OpenOptionsExt};

use platform_host::{
    StepState,
    runner::{Program::Admin, Runner},
};

use super::{
    Ctx,
    plan::{CaMode, Component},
};

const STAGE: &str = "/run/openvibes-ca";
const INT: &str = "/run/openvibes-ca/int";
const ROOT_DIR: &str = "/run/openvibes-ca/root";
const INTERMEDIATE: &str = "/etc/openvibes/pki/intermediate.crt";
/// The root certificate agents trust.
pub const ROOT_CERT: &str = "/etc/openvibes/pki/root.crt";
const INTERMEDIATE_KEY: &str = "/var/lib/openvibes-ingest/intermediate.key";
const ADMIN_OWNER: Option<(&str, &str)> = Some(("openvibes-admin", "openvibes-admin"));

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

fn root_summary<R: Runner>(ctx: &Ctx<R>) -> Result<String, String> {
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

pub fn ca_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if ctx.exists(INTERMEDIATE) && ctx.exists(ROOT_CERT) && ctx.exists(INTERMEDIATE_KEY) {
        return Ok(StepState::Done(root_summary(ctx)?));
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
fn fresh_stage<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    let path = ctx.path(STAGE);
    if path.exists() {
        fs::remove_dir_all(&path).map_err(|error| format!("{STAGE}: {error}"))?;
    }
    stage_dir(ctx, STAGE)
}

/// Creates `abs` (0700, openvibes-admin) for a command run as that user.
fn stage_dir<R: Runner>(ctx: &Ctx<R>, abs: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let path = ctx.path(abs);
    fs::create_dir_all(&path).map_err(|error| format!("{abs}: {error}"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("{abs}: {error}"))?;
    ctx.chown(abs, ADMIN_OWNER)
}

fn remove_stage<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    fs::remove_dir_all(ctx.path(STAGE)).map_err(|error| format!("{STAGE}: {error}"))
}

/// Imports the signed intermediate and installs the CA files; the staging
/// directory is left for the caller to remove.
fn import_and_install<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    for file in ["intermediate.crt", "root.crt"] {
        ctx.chown(&format!("{INT}/{file}"), ADMIN_OWNER)?;
    }
    ctx.as_admin(&[
        "ca",
        "import-intermediate",
        "--cert",
        &format!("{INT}/intermediate.crt"),
        "--key",
        &format!("{INT}/intermediate.key"),
        "--root-cert",
        &format!("{INT}/root.crt"),
    ])?;
    ctx.copy(
        &format!("{INT}/intermediate.crt"),
        INTERMEDIATE,
        None,
        0o644,
    )?;
    ctx.copy(&format!("{INT}/root.crt"), ROOT_CERT, None, 0o644)?;
    ctx.copy(
        &format!("{INT}/intermediate.key"),
        INTERMEDIATE_KEY,
        Some(("openvibes-ingest", "openvibes-ingest")),
        0o600,
    )
}

/// Writes the root key once to `root_key_out` (never over an existing
/// file); what happened to it.
fn keep_root_key<R: Runner>(ctx: &Ctx<R>) -> Result<String, String> {
    let Some(out) = &ctx.plan.root_key_out else {
        return Ok("root key deleted (a new intermediate will need a new root)".into());
    };
    let key = fs::read(ctx.path(&format!("{ROOT_DIR}/root.key")))
        .map_err(|error| format!("root key: {error}"))?;
    let shown = out.display().to_string();
    let path = ctx.path(&shown);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("{shown}: {error}"))?;
    file.write_all(&key)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{shown}: {error}"))?;
    // Through the open file, never the path (the directory may be the
    // user's); a stick that cannot change owners keeps it root's.
    let owner = ctx.plan.operator.as_deref().map(|user| {
        ctx.ids(Some((user, user))).and_then(|(uid, gid)| {
            std::os::unix::fs::fchown(&file, Some(uid), Some(gid))
                .map_err(|error| format!("{shown}: {error}"))
        })
    });
    let note = match owner {
        Some(Err(error)) => format!(" (still owned by root: {error})"),
        _ => String::new(),
    };
    Ok(format!("root key saved to {shown}: keep it offline{note}"))
}

fn quick<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if let Some(out) = &ctx.plan.root_key_out
        && ctx.path(&out.display().to_string()).exists()
    {
        return Err(format!(
            "{} already exists; choose another file for the root key",
            out.display()
        ));
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
    Ok(StepState::Done(format!("{kept}; {}", root_summary(ctx)?)))
}

fn careful<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
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
    if ctx.repair {
        return Err("the CA files are missing; Repair never makes a new CA (enrolled agents trust \
                    the old one): restore /etc/openvibes/pki and /var/lib/openvibes-ingest/\
                    intermediate.key from a backup, or uninstall with Remove everything and set up again"
            .into());
    }
    match ctx.plan.ca {
        CaMode::Quick => quick(ctx),
        CaMode::Careful => careful(ctx),
    }
}

/// Where one service's certificate goes.
struct Tls {
    component: Component,
    stem: &'static str,
    cert: &'static str,
    key: &'static str,
    /// Console: certificate then intermediate in one file, both 0640
    /// root:openvibes-console; otherwise the key belongs to the service.
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
const RENEW_DAYS: i64 = 14;

pub fn certificates_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let names = ctx.plan.names();
    let wanted = format!("{}\n", names.join("\n"));
    let present = chosen(ctx).all(|tls| ctx.exists(tls.cert) && ctx.exists(tls.key));
    if !present || ctx.read(TLS_NAMES).ok().as_deref() != Some(wanted.as_str()) {
        return Ok(StepState::Todo);
    }
    for tls in chosen(ctx) {
        let pem = ctx.read(tls.cert)?;
        let expires =
            platform_pki::not_after(&pem).map_err(|error| format!("{}: {error:?}", tls.cert))?;
        if expires - chrono::Utc::now() < chrono::Duration::days(RENEW_DAYS) {
            return Ok(StepState::Failed(format!(
                "{} expires on {}: renew it (docs/components/packaging.md, \"Renewing the server certificate\")",
                tls.cert,
                expires.format("%Y-%m-%d")
            )));
        }
    }
    Ok(StepState::Done(format!(
        "server certificates for {}",
        names.join(", ")
    )))
}

pub fn certificates_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let names = ctx.plan.names();
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
        ctx.as_admin(&args)?;
        let crt = format!("{out}/{}.crt", names[0]);
        let key = format!("{out}/{}.key", names[0]);
        if tls.console {
            let chain = format!("{}{}", ctx.read(&crt)?, ctx.read(INTERMEDIATE)?);
            let owner = Some(("root", tls.owner));
            ctx.put(tls.cert, chain.as_bytes(), owner, 0o640)?;
            ctx.copy(&key, tls.key, owner, 0o640)?;
        } else {
            ctx.copy(&crt, tls.cert, None, 0o644)?;
            ctx.copy(&key, tls.key, Some((tls.owner, tls.owner)), 0o600)?;
        }
    }
    ctx.put(
        TLS_NAMES,
        format!("{}\n", names.join("\n")).as_bytes(),
        None,
        0o644,
    )?;
    remove_stage(ctx)?;
    Ok(StepState::Done(format!(
        "server certificates for {} (valid 90 days)",
        names.join(", ")
    )))
}
