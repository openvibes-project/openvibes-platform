//! A company CA chain and its key, checked before import: the path from our
//! intermediate up to a self-signed root, built by signature.

use chrono::{DateTime, Duration, Utc};
use x509_parser::{certificate::X509Certificate, pem::Pem, x509::X509Name};

use crate::ca::{SERVER_DAYS, parse};
use crate::{Issuer, KeyInfo, PkiError, key_info, keys::pem};

/// A checked chain: our intermediate, the CAs above it, and the root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Chain {
    /// Our intermediate's certificate, PEM.
    pub ours: String,
    /// The CAs between ours and the root, nearest first, PEM.
    pub middle: Vec<String>,
    /// The self-signed root, PEM.
    pub root: String,
    /// Our intermediate's common name.
    pub name: String,
    /// The common names above ours, root last.
    pub path: Vec<String>,
    /// The earliest end of validity on the path.
    pub not_after: DateTime<Utc>,
}

/// Why a chain or key cannot be imported. Names are common names, or
/// "an unnamed CA".
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainError {
    /// No certificate, or a block that does not parse.
    InvalidPem,
    /// This certificate on the path is not a CA that may sign certificates.
    NotCa(String),
    /// The CA that signed the last certificate found is not in the bundle.
    Missing(String),
    /// The first certificate is a self-signed root, not an intermediate.
    IsRoot(String),
    /// This CA's path length allows no more CAs below it.
    NoCaBelow(String),
    /// A certificate on the path is not valid yet; when it starts.
    NotYetValid(DateTime<Utc>),
    /// A certificate on the path is not valid now or for 90 days more; the
    /// earliest end of validity.
    Expiring(DateTime<Utc>),
    /// The key, or issuing with it.
    Pki(PkiError),
}

impl From<PkiError> for ChainError {
    fn from(error: PkiError) -> Self {
        Self::Pki(error)
    }
}

/// The DER of every `CERTIFICATE` block in `pem`, each parsed once; none
/// for blank text.
pub fn certificates(pem: &str) -> Result<Vec<Vec<u8>>, PkiError> {
    let ders = Pem::iter_from_buffer(pem.replace("\r\n", "\n").as_bytes())
        .map(|block| {
            let block = block.map_err(|_| PkiError::InvalidPem)?;
            if block.label != "CERTIFICATE" {
                return Err(PkiError::InvalidPem);
            }
            parse(&block.contents)?;
            Ok(block.contents)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if ders.is_empty() && !pem.trim().is_empty() {
        return Err(PkiError::InvalidPem);
    }
    Ok(ders)
}

fn cn(name: &X509Name<'_>) -> String {
    name.iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map_or_else(|| "an unnamed CA".to_owned(), str::to_owned)
}

/// CA:TRUE, and keyCertSign when key usage is present.
fn can_sign(cert: &X509Certificate<'_>) -> bool {
    let ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|constraints| constraints.value.ca);
    let usage = match cert.key_usage() {
        Ok(Some(usage)) => usage.value.key_cert_sign(),
        Ok(None) => true,
        Err(_) => false,
    };
    ca && usage
}

fn self_signed(cert: &X509Certificate<'_>) -> bool {
    cert.subject().as_raw() == cert.issuer().as_raw() && cert.verify_signature(None).is_ok()
}

/// Checks a pasted or imported bundle: the first certificate is ours, the
/// rest (in any order) must hold every CA up to a self-signed root.
/// Certificates not on the path are ignored. Every CA on the path must
/// allow the CAs below it (ours included), and be valid at `now` and for
/// 90 days more.
pub fn check_chain(certs_pem: &str, now: DateTime<Utc>) -> Result<Chain, ChainError> {
    let ders = certificates(certs_pem).map_err(|_| ChainError::InvalidPem)?;
    if ders.is_empty() {
        return Err(ChainError::InvalidPem);
    }
    let certs = ders
        .iter()
        .map(|der| parse(der))
        .collect::<Result<Vec<_>, _>>()?;
    // Indexes into `certs`, ours first, root last.
    let mut path = vec![0];
    loop {
        let current = &certs[path[path.len() - 1]];
        if !can_sign(current) {
            return Err(ChainError::NotCa(cn(current.subject())));
        }
        if self_signed(current) {
            if path.len() == 1 {
                return Err(ChainError::IsRoot(cn(current.subject())));
            }
            break;
        }
        let issuer = (1..certs.len()).find(|&i| {
            // Agents chain by name, so the names must match as well.
            !path.contains(&i)
                && current.issuer().as_raw() == certs[i].subject().as_raw()
                && current
                    .verify_signature(Some(certs[i].public_key()))
                    .is_ok()
        });
        match issuer {
            Some(i) => path.push(i),
            None => return Err(ChainError::Missing(cn(current.issuer()))),
        }
    }
    // A CA with path length N may have at most N CAs below it.
    for (below, &i) in path.iter().enumerate().skip(1) {
        let limit = certs[i]
            .basic_constraints()
            .ok()
            .flatten()
            .and_then(|constraints| constraints.value.path_len_constraint);
        if limit.is_some_and(|limit| (below as u64) > u64::from(limit)) {
            return Err(ChainError::NoCaBelow(cn(certs[i].subject())));
        }
    }
    let at = |seconds| DateTime::from_timestamp(seconds, 0).ok_or(ChainError::InvalidPem);
    let mut not_before = DateTime::<Utc>::MIN_UTC;
    let mut not_after = DateTime::<Utc>::MAX_UTC;
    for &i in &path {
        let validity = certs[i].validity();
        not_before = not_before.max(at(validity.not_before.timestamp())?);
        not_after = not_after.min(at(validity.not_after.timestamp())?);
    }
    if not_before > now {
        return Err(ChainError::NotYetValid(not_before));
    }
    if not_after < now + Duration::days(SERVER_DAYS) {
        return Err(ChainError::Expiring(not_after));
    }
    let pem_of = |i: usize| pem("CERTIFICATE", &ders[i]);
    let root = path[path.len() - 1];
    Ok(Chain {
        ours: pem_of(0),
        middle: path[1..path.len() - 1].iter().map(|&i| pem_of(i)).collect(),
        root: pem_of(root),
        name: cn(certs[0].subject()),
        path: path[1..].iter().map(|&i| cn(certs[i].subject())).collect(),
        not_after,
    })
}

/// Checks the key for a checked chain: an accepted kind, our intermediate's
/// own key, and a name OpenVIBES reproduces exactly as the issuer of what it
/// signs (`NameMismatch`), so its certificates chain.
pub fn check_key(
    chain: &Chain,
    pkcs8_pem: &str,
    now: DateTime<Utc>,
) -> Result<KeyInfo, ChainError> {
    let info = key_info(pkcs8_pem)?;
    let issuer = Issuer::load(&chain.ours, pkcs8_pem)?;
    let leaf = issuer.issue_server(&["openvibes.invalid".into()], now)?;
    let leaf_der = &certificates(&leaf.cert_pem)?[0];
    let ours_der = &certificates(&chain.ours)?[0];
    if parse(leaf_der)?.issuer().as_raw() != parse(ours_der)?.subject().as_raw() {
        return Err(ChainError::Pki(PkiError::NameMismatch));
    }
    Ok(info)
}
