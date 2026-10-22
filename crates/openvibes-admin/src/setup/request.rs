//! `helper ca-request` and `helper ca-accept` (sub-project 3, Install): the
//! intermediate's request made before install for "Your own CA", kept in
//! `REQUEST_DIR` (root, 0700) across reboots until the CA step installs
//! from it. Reusing the key keeps a request already sent valid.

use std::{
    fs::{self, OpenOptions, Permissions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::ExitCode,
};

use platform_host::runner::Runner;
use platform_pki::{PkiError, Signed};

use super::Ctx;

/// The request folder; the CA step and Quick remove it.
pub const REQUEST_DIR: &str = "/etc/openvibes/pki/request";

fn file(name: &str) -> String {
    format!("{REQUEST_DIR}/{name}")
}

/// What the request folder holds.
#[derive(Debug, Eq, PartialEq)]
pub enum RequestState {
    /// The request, waiting for the CA's signature.
    Request { csr: String },
    /// The request and its accepted certificate, signed by `issuer`.
    Signed { csr: String, issuer: String },
}

/// The plain sentence for a refused certificate.
pub fn message(e: &PkiError) -> String {
    match e {
        PkiError::NotForRequest => {
            "This certificate was signed for a different request: sign the request shown here."
                .into()
        }
        PkiError::NotCa | PkiError::NotIntermediate => {
            "This is not a CA certificate: sign the request as an intermediate (CA:TRUE, pathlen 0)."
                .into()
        }
        PkiError::IssuerExpired => {
            "This certificate is not valid today (expired or not yet valid): check its dates."
                .into()
        }
        PkiError::NotSignedBy => "Your CA's certificate must be the root that signed this \
                                  certificate directly: paste that root, not another CA."
            .into(),
        PkiError::NotRoot => "This is not a root CA (self-signed): OpenVIBES needs the root that \
                              signed the request directly, with no CA in between."
            .into(),
        PkiError::RootPathLen0 => "Your CA's certificate does not allow it to sign another CA \
                                   (path length 0): it cannot sign the intermediate."
            .into(),
        PkiError::Several(n) => {
            format!("That is {n} certificates: paste only the one signed for OpenVIBES.")
        }
        PkiError::InvalidPem => {
            "This is not a certificate in PEM form (-----BEGIN CERTIFICATE-----).".into()
        }
        PkiError::InvalidCsr => "The stored request is damaged: make a new one.".into(),
        other => format!("The certificate was refused: {other}."),
    }
}

/// Makes the key and request, or reuses them.
pub fn request<R: Runner>(ctx: &Ctx<R>) -> Result<RequestState, String> {
    let (key, csr) = (file("intermediate.key"), file("intermediate.csr"));
    let dir = ctx.path(REQUEST_DIR);
    let fail = |error: std::io::Error| format!("{REQUEST_DIR}: {error}");
    fs::create_dir_all(&dir).map_err(fail)?;
    // Also a folder left from before: only root ever reads the key.
    fs::set_permissions(&dir, Permissions::from_mode(0o700)).map_err(fail)?;
    if !(ctx.exists(&key) && ctx.exists(&csr)) {
        let (csr_pem, key_pem) = platform_pki::intermediate_request()
            .map_err(|error| format!("intermediate request: {error}"))?;
        // The key first: a CSR on disk always has its key.
        ctx.put(&key, key_pem.as_bytes(), None, 0o600)?;
        ctx.put(&csr, csr_pem.as_bytes(), None, 0o644)?;
    }
    let csr = ctx.read(&csr)?;
    let (crt, root) = (file("intermediate.crt"), file("root.crt"));
    if !(ctx.exists(&crt) && ctx.exists(&root)) {
        return Ok(RequestState::Request { csr });
    }
    let signed = platform_pki::check_signed_request(&csr, &ctx.read(&crt)?, chrono::Utc::now())
        .map_err(|error| message(&error))?;
    Ok(RequestState::Signed {
        csr,
        issuer: signed.issuer,
    })
}

/// The names a copy may take: `base`, then `-2`, `-3`… before the extension
/// (as `maint::backup::free_path`).
const COPY_NAMES: usize = 100;

/// Writes `csr` (0644, the operator's) to `base` (absolute), or beside it
/// as `-2`, `-3`… when another file is there; the same request already at
/// one of those names is taken as it is. The path used.
pub fn save_copy<R: Runner>(ctx: &Ctx<R>, base: &Path, csr: &str) -> Result<String, String> {
    let abs = base
        .to_str()
        .filter(|path| path.starts_with('/'))
        .ok_or_else(|| format!("{}: not an absolute path", base.display()))?;
    let (stem, ext) = match base.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => (&abs[..abs.len() - ext.len() - 1], format!(".{ext}")),
        None => (abs, String::new()),
    };
    let names =
        std::iter::once(abs.to_owned()).chain((2..=COPY_NAMES).map(|n| format!("{stem}-{n}{ext}")));
    for path in names {
        if write_copy(ctx, &path, csr)? {
            return Ok(path);
        }
    }
    Err(format!(
        "That file already exists: {abs}. Choose another name."
    ))
}

/// Creates `abs` with the request, 0644, owned by the operator; false when
/// another file is there (never overwritten), true when it holds this
/// request already.
fn write_copy<R: Runner>(ctx: &Ctx<R>, abs: &str, csr: &str) -> Result<bool, String> {
    let fail = |error: std::io::Error| format!("{abs}: {error}");
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(ctx.path(abs))
    {
        Ok(file) => file,
        // The same request written earlier is fine; anything else is the
        // operator's and stays as it is.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Ok(fs::read(ctx.path(abs)).is_ok_and(|old| old == csr.as_bytes()));
        }
        Err(error) => return Err(fail(error)),
    };
    file.write_all(csr.as_bytes())
        .and_then(|()| file.set_permissions(Permissions::from_mode(0o644)))
        .and_then(|()| file.sync_all())
        .map_err(fail)?;
    // Best effort: a root-owned copy is still readable, and removable from
    // the operator's own home.
    if let Some(Ok((uid, gid))) = ctx.plan.operator.as_deref().map(|u| ctx.ids(Some((u, u)))) {
        let _ = std::os::unix::fs::fchown(&file, Some(uid), Some(gid));
    }
    Ok(true)
}

/// Checks the CA's certificate and root against the stored request, then
/// writes both; nothing is written when a check fails.
pub fn accept<R: Runner>(ctx: &Ctx<R>, cert_pem: &str, root_pem: &str) -> Result<Signed, String> {
    let csr = ctx
        .read(&file("intermediate.csr"))
        .map_err(|_| "There is no request here: make one first.".to_owned())?;
    let now = chrono::Utc::now();
    let signed =
        platform_pki::check_signed_request(&csr, cert_pem, now).map_err(|e| message(&e))?;
    platform_pki::check_root_signed(root_pem, cert_pem, now).map_err(|e| match e {
        PkiError::Several(n) => {
            format!("That is {n} certificates: paste only your root CA's certificate.")
        }
        e => message(&e),
    })?;
    for (name, pem) in [("intermediate.crt", cert_pem), ("root.crt", root_pem)] {
        ctx.put(
            &file(name),
            format!("{}\n", pem.trim()).as_bytes(),
            None,
            0o644,
        )?;
    }
    Ok(signed)
}

/// Line 1 `request` or `signed<TAB>ISSUER`, then `copy<TAB>PATH` when a
/// copy was written, then the request.
fn output(state: &RequestState, copy: Option<&str>) -> String {
    let copy = copy.map_or(String::new(), |path| format!("copy\t{path}\n"));
    match state {
        RequestState::Request { csr } => format!("request\n{copy}{csr}"),
        RequestState::Signed { csr, issuer } => format!("signed\t{issuer}\n{copy}{csr}"),
    }
}

/// Runs `work` under the Setup lock on the host, with a plan holding only
/// the operator (the request comes before `setup-plan`).
fn on_host(
    work: impl FnOnce(
        &Ctx<platform_host::runner::SystemRunner>,
    ) -> Result<(RequestState, Option<String>), String>,
) -> ExitCode {
    let done = super::lock(Path::new("/")).and_then(|_lock| {
        let mut plan = super::plan::plan_of("components = []\nhostname = \"\"\nca = \"careful\"")?;
        plan.operator = super::plan::operator_from_env();
        work(&super::host_ctx(&plan, false))
    });
    match done {
        Ok((state, copy)) => {
            print!("{}", output(&state, copy.as_deref()));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("openvibes-admin helper: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `helper ca-request [--copy PATH]`.
pub fn run_request(copy: Option<&Path>) -> ExitCode {
    on_host(|ctx| {
        let state = request(ctx)?;
        let copy = match (copy, &state) {
            (Some(base), RequestState::Request { csr } | RequestState::Signed { csr, .. }) => {
                Some(save_copy(ctx, base, csr)?)
            }
            (None, _) => None,
        };
        Ok((state, copy))
    })
}

/// `helper ca-accept --cert PEM --root-cert PEM`.
pub fn run_accept(cert_pem: &str, root_pem: &str) -> ExitCode {
    on_host(|ctx| {
        let signed = accept(ctx, cert_pem, root_pem)?;
        let csr = ctx.read(&file("intermediate.csr"))?;
        let state = RequestState::Signed {
            csr,
            issuer: signed.issuer,
        };
        Ok((state, None))
    })
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;
