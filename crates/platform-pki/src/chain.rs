//! A company CA chain and its key, checked before import: the path from our
//! intermediate up to a self-signed root, built by signature.

use chrono::{DateTime, Duration, Utc};
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};
use webpki::ring as algs;
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
    /// Agents would refuse the server certificates issued under this CA,
    /// and why.
    NotForServers(String, ServerLimit),
    /// The key, or issuing with it.
    Pki(PkiError),
}

/// Why agents would refuse a server certificate under a CA on the path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerLimit {
    /// Its extended key usage leaves out serverAuth.
    KeyUsage,
    /// Its name constraints leave out the host's names.
    NameConstraints,
    /// A signature algorithm agents no longer accept (e.g. SHA-1).
    OldSignature,
    /// A critical extension agents cannot read.
    UnknownExtension,
    /// Another check agents make.
    Other,
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

/// The common name of the first certificate in `pem` ("an unnamed CA"
/// without one): the TUI names ours while the chain above it is not whole.
pub fn common_name(pem: &str) -> Result<String, PkiError> {
    let ders = certificates(pem)?;
    let der = ders.first().ok_or(PkiError::InvalidPem)?;
    Ok(cn(parse(der)?.subject()))
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

/// No extended key usage, or one naming serverAuth. Agents (rustls-webpki)
/// do not take anyExtendedKeyUsage for it, so neither does this.
fn for_servers(cert: &X509Certificate<'_>) -> bool {
    match cert.extended_key_usage() {
        Ok(Some(eku)) => eku.value.server_auth,
        Ok(None) => true,
        Err(_) => false,
    }
}

fn self_signed(cert: &X509Certificate<'_>) -> bool {
    cert.subject().as_raw() == cert.issuer().as_raw() && cert.verify_signature(None).is_ok()
}

/// Agents chain by name, so the names must match as well as the signature.
fn signed_by(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
    cert.issuer().as_raw() == issuer.subject().as_raw()
        && cert.verify_signature(Some(issuer.public_key())).is_ok()
}

/// Ours in a bundle pasted root first: the one CA that is not self-signed
/// and signed no other certificate in it.
fn lowest_ca(certs: &[X509Certificate<'_>]) -> Option<usize> {
    let lowest: Vec<usize> = (0..certs.len())
        .filter(|&i| {
            can_sign(&certs[i])
                && !self_signed(&certs[i])
                && !(0..certs.len()).any(|j| j != i && signed_by(&certs[j], &certs[i]))
        })
        .collect();
    match lowest[..] {
        [i] => Some(i),
        _ => None,
    }
}

/// Checks a pasted or imported bundle: the first certificate is ours (or,
/// when the root comes first, the CA lowest in the bundle), the rest (in
/// any order) must hold every CA up to a self-signed root.
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
    let ours = if self_signed(&certs[0]) {
        lowest_ca(&certs).unwrap_or(0)
    } else {
        0
    };
    // Indexes into `certs`, ours first, root last.
    let mut path = vec![ours];
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
        let issuer =
            (0..certs.len()).find(|&i| !path.contains(&i) && signed_by(current, &certs[i]));
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
    // Refused at once, before the key: the self-check would refuse it too.
    for &i in &path[..path.len() - 1] {
        if !for_servers(&certs[i]) {
            return Err(ChainError::NotForServers(
                cn(certs[i].subject()),
                ServerLimit::KeyUsage,
            ));
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
        ours: pem_of(ours),
        middle: path[1..path.len() - 1].iter().map(|&i| pem_of(i)).collect(),
        root: pem_of(root),
        name: cn(certs[ours].subject()),
        path: path[1..].iter().map(|&i| cn(certs[i].subject())).collect(),
        not_after,
    })
}

/// Checks the key for a checked chain: an accepted kind, our intermediate's
/// own key, a name OpenVIBES reproduces exactly as the issuer of what it
/// signs (`NameMismatch`), so its certificates chain, and a throwaway server
/// certificate for `names` that agents would accept (`NotForServers`).
/// Without names, `openvibes.invalid` stands in and name constraints are
/// not checked (they would refuse the stand-in, not the host).
pub fn check_key(
    chain: &Chain,
    pkcs8_pem: &str,
    names: &[String],
    now: DateTime<Utc>,
) -> Result<KeyInfo, ChainError> {
    let info = key_info(pkcs8_pem)?;
    let issuer = Issuer::load(&chain.ours, pkcs8_pem)?;
    let leaf = match names {
        [] => issuer.issue_server(&["openvibes.invalid".into()], now)?,
        names => issuer.issue_server(names, now)?,
    };
    let leaf_der = &certificates(&leaf.cert_pem)?[0];
    let ours_der = &certificates(&chain.ours)?[0];
    if parse(leaf_der)?.issuer().as_raw() != parse(ours_der)?.subject().as_raw() {
        return Err(ChainError::Pki(PkiError::NameMismatch));
    }
    agents_accept(chain, leaf_der, !names.is_empty(), now)?;
    Ok(info)
}

/// The algorithms agents verify with (rustls' ring provider).
static ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    algs::ECDSA_P256_SHA256,
    algs::ECDSA_P256_SHA384,
    algs::ECDSA_P384_SHA256,
    algs::ECDSA_P384_SHA384,
    algs::ED25519,
    algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    algs::RSA_PKCS1_2048_8192_SHA256,
    algs::RSA_PKCS1_2048_8192_SHA384,
    algs::RSA_PKCS1_2048_8192_SHA512,
];

/// Verifies `leaf` as agents verify a server certificate (rustls-webpki,
/// ServerAuth). Each CA is the trust anchor in turn, ours first, so the
/// first refusal is about the CA just moved below the anchor, or about the
/// anchor itself for its name constraints. webpki checks those last, so
/// without `names` such a refusal passes and the next anchor is tried.
fn agents_accept(
    chain: &Chain,
    leaf: &[u8],
    names: bool,
    now: DateTime<Utc>,
) -> Result<(), ChainError> {
    let pems = std::iter::once(&chain.ours)
        .chain(&chain.middle)
        .chain(std::iter::once(&chain.root));
    let ders = pems
        .map(|pem| {
            let der = certificates(pem)?.into_iter().next();
            der.map(CertificateDer::from).ok_or(PkiError::InvalidPem)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cas: Vec<&String> = std::iter::once(&chain.name).chain(&chain.path).collect();
    let leaf = CertificateDer::from(leaf);
    let leaf = webpki::EndEntityCert::try_from(&leaf).map_err(|_| PkiError::InvalidPem)?;
    let seconds = u64::try_from(now.timestamp()).map_err(|_| PkiError::InvalidValidity)?;
    let time = UnixTime::since_unix_epoch(std::time::Duration::from_secs(seconds));
    let refused =
        |at: usize, error: &webpki::Error| ChainError::NotForServers(cas[at].clone(), limit(error));
    for k in 0..ders.len() {
        let anchor = webpki::anchor_from_trusted_cert(&ders[k]).map_err(|e| refused(k, &e))?;
        let usage = webpki::KeyUsage::server_auth();
        if let Err(error) =
            leaf.verify_for_usage(ALGS, &[anchor], &ders[..k], time, usage, None, None)
        {
            let at = match limit(&error) {
                ServerLimit::NameConstraints if !names => continue,
                ServerLimit::NameConstraints => k,
                _ => k.saturating_sub(1),
            };
            return Err(refused(at, &error));
        }
    }
    Ok(())
}

fn limit(error: &webpki::Error) -> ServerLimit {
    use webpki::Error as E;
    match error {
        E::RequiredEkuNotFoundContext(_) | E::EmptyEkuExtension => ServerLimit::KeyUsage,
        E::NameConstraintViolation
        | E::MalformedNameConstraint
        | E::InvalidNetworkMaskConstraint => ServerLimit::NameConstraints,
        E::UnsupportedSignatureAlgorithmContext(_)
        | E::UnsupportedSignatureAlgorithmForPublicKeyContext(_) => ServerLimit::OldSignature,
        E::UnsupportedCriticalExtension => ServerLimit::UnknownExtension,
        _ => ServerLimit::Other,
    }
}
