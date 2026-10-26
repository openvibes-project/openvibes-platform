//! The Certificate and Private key rows' checks for the console's own
//! certificate (certs4c.py #3-#5): a server certificate for one of the
//! console's names, and its key. The sentences are the helper's
//! (`console_cert_message`); the helper checks everything again.

use chrono::{DateTime, Utc};
use platform_pki::{KeyInfo, ServerCert, ServerCertError};

use super::Added;
use crate::setup::console_cert::console_cert_message;

pub(super) fn cert_of(text: &str, names: &[String], file: Option<&str>) -> Result<Added, String> {
    platform_pki::check_server_cert(text, names, Utc::now())
        .map(Added::Server)
        .map_err(|e| console_cert_message(&e, "", file))
}

pub(super) fn key_fits(
    cert: &ServerCert,
    pkcs8: &str,
    file: Option<&str>,
) -> Result<KeyInfo, String> {
    platform_pki::check_server_key(cert, pkcs8)
        .map_err(|e| console_cert_message(&e, &cert.name, file))
}

fn server_line(name: &str, until: DateTime<Utc>) -> String {
    format!(
        "{name} · for server use · valid until {}",
        until.format("%F")
    )
}

/// What the certificate is, and the first of the console's names it covers.
pub(super) fn lines(cert: &ServerCert) -> Vec<String> {
    let mut said = vec![server_line(&cert.name, cert.not_after)];
    if let Some(name) = cert.covers.first() {
        said.push(format!("Covers {name}, one of this console's names."));
    }
    said
}

/// The certificate's line when it is right but covers none of the names.
pub(super) fn partial(text: &str, names: &[String]) -> Option<String> {
    match platform_pki::check_server_cert(text, names, Utc::now()) {
        Err(ServerCertError::CoversNone) => {
            let name = name_of(text)?;
            Some(server_line(&name, platform_pki::not_after(text).ok()?))
        }
        _ => None,
    }
}

/// What `check_server_cert` calls the first certificate in `pem` (its
/// first DNS name, else its first address, else its common name), whatever
/// its dates and names: it is checked for its own names on its last day.
pub fn name_of(pem: &str) -> Option<String> {
    let names = platform_pki::subject_alt_names(pem).ok()?;
    let names = if names.is_empty() {
        vec![platform_pki::common_name(pem).ok()?]
    } else {
        names
    };
    let last = platform_pki::not_after(pem).ok()?;
    platform_pki::check_server_cert(pem, &names, last)
        .ok()
        .map(|c| c.name)
}
