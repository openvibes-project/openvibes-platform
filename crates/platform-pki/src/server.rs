//! The console's own certificate: a server certificate the admin brings, with
//! the CAs above it. Agents never see it; they keep the platform's.

use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use rcgen::{KeyPair, PublicKeyData};
use x509_parser::{certificate::X509Certificate, extensions::GeneralName};

use crate::ca::parse;
use crate::chain::for_servers;
use crate::keys::pem;
use crate::{KeyInfo, PkiError, certificates, key_info};

/// A checked console certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerCert {
    /// What to call it: the first DNS name, else the first IP address, else
    /// the common name.
    pub name: String,
    /// Which of the console's names it covers.
    pub covers: Vec<String>,
    /// Ours first, then the rest as given, as canonical PEM.
    pub chain_pem: String,
    /// End of validity of ours.
    pub not_after: DateTime<Utc>,
}

/// Why a certificate cannot be the console's.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerCertError {
    /// No certificate, or a block that does not parse.
    InvalidPem,
    /// The first certificate is a CA.
    IsCa,
    /// Its extended key usage does not allow serverAuth.
    NotForServers,
    /// It ended at this time.
    Expired(DateTime<Utc>),
    /// It starts at this time.
    NotYetValid(DateTime<Utc>),
    /// It covers none of the console's names.
    CoversNone,
    /// The key, or its match with the certificate.
    Pki(PkiError),
}

impl fmt::Display for ServerCertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPem => f.write_str("no certificate found"),
            Self::IsCa => f.write_str("the first certificate is a CA, not a server certificate"),
            Self::NotForServers => f.write_str("the certificate is not for servers"),
            Self::Expired(at) => write!(f, "the certificate ended {}", at.format("%Y-%m-%d")),
            Self::NotYetValid(at) => {
                write!(f, "the certificate starts {}", at.format("%Y-%m-%d"))
            }
            Self::CoversNone => f.write_str("the certificate covers none of this console's names"),
            Self::Pki(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ServerCertError {}

impl From<PkiError> for ServerCertError {
    fn from(error: PkiError) -> Self {
        Self::Pki(error)
    }
}

/// Checks `certs_pem`: the first block is ours (not a CA, serverAuth or no
/// extended key usage, valid at `now`, covering at least one of `names`);
/// the blocks after it must only be certificates and are kept as given.
pub fn check_server_cert(
    certs_pem: &str,
    names: &[String],
    now: DateTime<Utc>,
) -> Result<ServerCert, ServerCertError> {
    let ders = certificates(certs_pem).map_err(|_| ServerCertError::InvalidPem)?;
    let der = ders.first().ok_or(ServerCertError::InvalidPem)?;
    let cert = parse(der)?;
    if cert
        .basic_constraints()
        .map_err(|_| PkiError::InvalidPem)?
        .is_some_and(|c| c.value.ca)
    {
        return Err(ServerCertError::IsCa);
    }
    if !for_servers(&cert) {
        return Err(ServerCertError::NotForServers);
    }
    let not_before = time_of(cert.validity().not_before.timestamp())?;
    let not_after = time_of(cert.validity().not_after.timestamp())?;
    if now < not_before {
        return Err(ServerCertError::NotYetValid(not_before));
    }
    if now > not_after {
        return Err(ServerCertError::Expired(not_after));
    }
    let wanted: Vec<String> = names
        .iter()
        .filter(|name| covered(&cert, name))
        .cloned()
        .collect();
    if wanted.is_empty() {
        return Err(ServerCertError::CoversNone);
    }
    Ok(ServerCert {
        name: display_name(&cert),
        covers: wanted,
        chain_pem: ders.iter().map(|der| pem("CERTIFICATE", der)).collect(),
        not_after,
    })
}

/// Checks the PKCS#8 key (kinds and sizes as `key_info`) belongs to the
/// certificate (`KeyMismatch`).
pub fn check_server_key(cert: &ServerCert, pkcs8_pem: &str) -> Result<KeyInfo, ServerCertError> {
    let info = key_info(pkcs8_pem)?;
    let ders = certificates(&cert.chain_pem)?;
    let der = ders.first().ok_or(ServerCertError::InvalidPem)?;
    let key = KeyPair::from_pem(pkcs8_pem).map_err(|_| PkiError::InvalidPem)?;
    if key.subject_public_key_info() != parse(der)?.tbs_certificate.subject_pki.raw {
        return Err(PkiError::KeyMismatch.into());
    }
    Ok(info)
}

/// Whether the first certificate in `cert_pem` covers `name`.
pub fn covers(cert_pem: &str, name: &str) -> bool {
    certificates(cert_pem)
        .ok()
        .and_then(|ders| {
            ders.first()
                .map(|der| parse(der).is_ok_and(|c| covered(&c, name)))
        })
        .unwrap_or(false)
}

fn time_of(seconds: i64) -> Result<DateTime<Utc>, PkiError> {
    DateTime::from_timestamp(seconds, 0).ok_or(PkiError::InvalidPem)
}

/// DNS names and IP addresses of the subject alternative name extension.
fn sans(cert: &X509Certificate<'_>) -> Vec<(bool, String)> {
    let Ok(Some(ext)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    ext.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some((false, (*dns).to_owned())),
            GeneralName::IPAddress(bytes) => Some((true, ip(bytes)?.to_string())),
            _ => None,
        })
        .collect()
}

fn ip(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => None,
    }
}

fn common(cert: &X509Certificate<'_>) -> Option<String> {
    let cn = cert.subject().iter_common_name().next()?;
    cn.as_str().ok().map(str::to_owned)
}

fn display_name(cert: &X509Certificate<'_>) -> String {
    let sans = sans(cert);
    sans.iter()
        .find(|(is_ip, _)| !is_ip)
        .or_else(|| sans.first())
        .map(|(_, name)| name.clone())
        .or_else(|| common(cert))
        .unwrap_or_default()
}

/// SANs when present, else the common name. A `*.x.y` name covers `a.x.y`
/// only; an IP name matches the same address however it is written.
fn covered(cert: &X509Certificate<'_>, name: &str) -> bool {
    let sans = sans(cert);
    let candidates = if sans.is_empty() {
        common(cert).map(|cn| (false, cn)).into_iter().collect()
    } else {
        sans
    };
    let wanted_ip = name.parse::<IpAddr>().ok();
    candidates
        .iter()
        .any(|(is_ip, have)| match (is_ip, wanted_ip) {
            (true, Some(wanted)) => have.parse::<IpAddr>().ok() == Some(wanted),
            (true, None) | (false, Some(_)) => false,
            (false, None) => dns_covers(have, name),
        })
}

fn dns_covers(have: &str, name: &str) -> bool {
    let (have, name) = (have.to_ascii_lowercase(), name.to_ascii_lowercase());
    match have.strip_prefix("*.") {
        Some(rest) => name
            .split_once('.')
            .is_some_and(|(label, tail)| !label.is_empty() && tail == rest),
        None => have == name,
    }
}
