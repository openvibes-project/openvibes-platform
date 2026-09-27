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

pub fn certificates_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    Ok(
        if chosen(ctx).all(|tls| ctx.exists(tls.cert) && ctx.exists(tls.key)) {
            StepState::Done(format!(
                "server certificates for {}",
                ctx.plan.names().join(", ")
            ))
        } else {
            StepState::Todo
        },
    )
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
    remove_stage(ctx)?;
    Ok(StepState::Done(format!(
        "server certificates for {} (valid 90 days)",
        names.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use platform_host::{Step, StepState};

    use crate::setup::{
        fake::{Fake, plan},
        plan::{CaMode, Component::*},
        run_step,
    };

    const ADMIN: [&str; 5] = [
        "/usr/sbin/runuser",
        "-u",
        "openvibes-admin",
        "--",
        "/usr/bin/openvibes-admin",
    ];

    fn with(prefix: &[&str], rest: &[&str]) -> Vec<&'static str> {
        prefix
            .iter()
            .chain(rest)
            .map(|s| &*Box::leak((*s).to_owned().into_boxed_str()))
            .collect()
    }

    /// The CA commands as fakes that write what the real ones write.
    fn ca_commands(fake: &Fake) {
        fake.effect(&["/usr/bin/openvibes-admin", "ca", "init-root"], |root| {
            let dir = root.join("run/openvibes-ca/root");
            std::fs::create_dir_all(&dir).unwrap();
            let ca = platform_pki::generate_root(chrono::Utc::now()).unwrap();
            std::fs::write(dir.join("root.crt"), &ca.cert_pem).unwrap();
            std::fs::write(dir.join("root.key"), &ca.key_pem).unwrap();
        });
        fake.effect(&with(&ADMIN, &["ca", "intermediate-request"]), |root| {
            let dir = root.join("run/openvibes-ca/int");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("intermediate.csr"), "CSR").unwrap();
            std::fs::write(dir.join("intermediate.key"), "INTERMEDIATE KEY").unwrap();
        });
        fake.effect(
            &["/usr/bin/openvibes-admin", "ca", "sign-intermediate"],
            |root| {
                std::fs::write(
                    root.join("run/openvibes-ca/int/intermediate.crt"),
                    "INTERMEDIATE",
                )
                .unwrap();
            },
        );
        fake.answer(&with(&ADMIN, &["ca", "import-intermediate"]), 0, "");
    }

    #[test]
    fn quick_ca_keeps_only_the_root_certificate_and_the_chosen_key_copy() {
        let fake = Fake::new("ca-quick");
        ca_commands(&fake);
        fake.file("/run/openvibes-ca/stale", "left by a failed run");
        let mut plan = plan(&[Ingest]);
        plan.root_key_out = Some("/media/usb/openvibes-root.key".into());
        std::fs::create_dir_all(fake.root.join("media/usb")).unwrap();
        let state = run_step(&fake.ctx(&plan), Step::Ca);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(
            state.detail().contains("/media/usb/openvibes-root.key"),
            "{state:?}"
        );
        assert!(state.detail().contains("SHA-256 "), "{state:?}");
        assert!(
            fake.text("/etc/openvibes/pki/root.crt")
                .contains("BEGIN CERTIFICATE")
        );
        assert_eq!(
            fake.text("/etc/openvibes/pki/intermediate.crt"),
            "INTERMEDIATE"
        );
        assert_eq!(
            fake.text("/var/lib/openvibes-ingest/intermediate.key"),
            "INTERMEDIATE KEY"
        );
        assert!(
            fake.text("/media/usb/openvibes-root.key")
                .contains("PRIVATE KEY")
        );
        assert!(
            !fake.root.join("run/openvibes-ca").exists(),
            "staging removed"
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = |abs: &str| {
            std::fs::metadata(fake.root.join(abs.trim_start_matches('/')))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("/var/lib/openvibes-ingest/intermediate.key"), 0o600);
        assert_eq!(mode("/media/usb/openvibes-root.key"), 0o600);
        assert_eq!(mode("/etc/openvibes/pki/root.crt"), 0o644);
        // Done now: a second run changes nothing.
        let calls = fake.calls.borrow().len();
        assert!(matches!(
            run_step(&fake.ctx(&plan), Step::Ca),
            StepState::Done(_)
        ));
        assert_eq!(fake.calls.borrow().len(), calls);
    }

    #[test]
    fn a_stale_staging_directory_is_replaced() {
        let fake = Fake::new("ca-stale");
        ca_commands(&fake);
        fake.file(
            "/run/openvibes-ca/root/root.crt",
            "half-written by a failed run",
        );
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Ca);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(state.detail().contains("root key deleted"), "{state:?}");
    }

    #[test]
    fn a_failed_import_leaves_no_root_key_file_to_block_the_retry() {
        let fake = Fake::new("ca-import-fails");
        fake.answer(&with(&ADMIN, &["ca", "import-intermediate"]), 1, "");
        ca_commands(&fake);
        std::fs::create_dir_all(fake.root.join("media/usb")).unwrap();
        let mut plan = plan(&[Ingest]);
        plan.root_key_out = Some("/media/usb/openvibes-root.key".into());
        let state = run_step(&fake.ctx(&plan), Step::Ca);
        assert!(matches!(state, StepState::Failed(_)), "{state:?}");
        assert!(
            !fake.root.join("media/usb/openvibes-root.key").exists(),
            "a key for a root that was never installed would block every retry"
        );
    }

    #[test]
    fn an_existing_root_key_file_is_not_overwritten() {
        let fake = Fake::new("ca-existing-key");
        ca_commands(&fake);
        fake.file("/media/usb/openvibes-root.key", "an older root key");
        let mut plan = plan(&[Ingest]);
        plan.root_key_out = Some("/media/usb/openvibes-root.key".into());
        let state = run_step(&fake.ctx(&plan), Step::Ca);
        assert!(state.detail().contains("already exists"), "{state:?}");
        assert_eq!(
            fake.text("/media/usb/openvibes-root.key"),
            "an older root key"
        );
        assert!(
            !fake.called(&["/usr/bin/openvibes-admin", "ca", "init-root"]),
            "checked before any CA material"
        );
    }

    #[test]
    fn careful_ca_waits_for_the_signed_certificate() {
        let fake = Fake::new("ca-careful");
        ca_commands(&fake);
        let mut plan = plan(&[Ingest]);
        plan.ca = CaMode::Careful;
        let state = run_step(&fake.ctx(&plan), Step::Ca);
        assert!(matches!(state, StepState::Waiting(_)), "{state:?}");
        assert!(state.detail().contains("sign-intermediate"), "{state:?}");
        assert!(!fake.called(&["/usr/bin/openvibes-admin", "ca", "init-root"]));
        assert!(matches!(
            run_step(&fake.ctx(&plan), Step::Ca),
            StepState::Waiting(_)
        ));
        let root = platform_pki::generate_root(chrono::Utc::now()).unwrap();
        fake.file("/run/openvibes-ca/int/intermediate.crt", "INTERMEDIATE");
        fake.file("/run/openvibes-ca/int/root.crt", &root.cert_pem);
        let state = run_step(&fake.ctx(&plan), Step::Ca);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(fake.called(&with(&ADMIN, &["ca", "import-intermediate"])));
    }

    #[test]
    fn certificates_are_issued_for_every_name_and_installed() {
        let fake = Fake::new("certificates");
        fake.file("/etc/openvibes/pki/intermediate.crt", "INTERMEDIATE\n");
        fake.file(
            "/var/lib/openvibes-ingest/intermediate.key",
            "INTERMEDIATE KEY",
        );
        fake.effect(&with(&ADMIN, &["ca", "issue-server"]), |root| {
            for service in ["ingest", "distribution", "console"] {
                let dir = root.join(format!("run/openvibes-ca/{service}"));
                if dir.exists() && !dir.join("platform.example.com.crt").exists() {
                    std::fs::write(
                        dir.join("platform.example.com.crt"),
                        format!("{service} CERT\n"),
                    )
                    .unwrap();
                    std::fs::write(
                        dir.join("platform.example.com.key"),
                        format!("{service} KEY"),
                    )
                    .unwrap();
                    return;
                }
            }
            panic!("no output directory");
        });
        let state = run_step(
            &fake.ctx(&plan(&[Ingest, Console, Distribution])),
            Step::Certificates,
        );
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        let issue = fake.call(&with(&ADMIN, &["ca", "issue-server"]));
        assert_eq!(
            issue[7..],
            [
                "platform.example.com",
                "--san",
                "10.0.0.5",
                "--san",
                "localhost",
                "--san",
                "127.0.0.1",
                "--issuer-cert",
                "/run/openvibes-ca/issuer.crt",
                "--issuer-key",
                "/run/openvibes-ca/issuer.key",
                "--out",
                "/run/openvibes-ca/ingest"
            ]
        );
        assert_eq!(fake.text("/etc/openvibes/tls/ingest.crt"), "ingest CERT\n");
        assert_eq!(
            fake.text("/etc/openvibes/tls/console-chain.pem"),
            "console CERT\nINTERMEDIATE\n"
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = |abs: &str| {
            std::fs::metadata(fake.root.join(abs.trim_start_matches('/')))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("/etc/openvibes/tls/ingest.key"), 0o600);
        assert_eq!(mode("/etc/openvibes/tls/distribution.key"), 0o600);
        assert_eq!(mode("/etc/openvibes/tls/console-key.pem"), 0o640);
        assert_eq!(mode("/etc/openvibes/tls/console-chain.pem"), 0o640);
        assert!(!fake.root.join("run/openvibes-ca").exists());
    }
}
