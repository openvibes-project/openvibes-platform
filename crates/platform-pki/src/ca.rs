use chrono::{DateTime, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, CertifiedIssuer,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PublicKeyData, SerialNumber,
};
use ring::rand::{SecureRandom, SystemRandom};
use time::OffsetDateTime;
use x509_parser::{
    certificate::X509Certificate,
    pem::{Pem, parse_x509_pem},
    x509::X509Name,
};

use crate::PkiError;

const ROOT_DAYS: i64 = 3652;
const INTERMEDIATE_DAYS: i64 = 730;
pub(crate) const SERVER_DAYS: i64 = 90;

/// A certificate and its private key, both PEM.
#[derive(Clone)]
pub struct KeyAndCert {
    /// Certificate (for server certificates: leaf then intermediate).
    pub cert_pem: String,
    /// PKCS#8 private key.
    pub key_pem: String,
}

impl std::fmt::Debug for KeyAndCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyAndCert")
            .field("cert_pem", &self.cert_pem)
            .field("key_pem", &"[REDACTED]")
            .finish()
    }
}

pub(crate) fn offset(now: DateTime<Utc>, days: i64) -> Result<OffsetDateTime, PkiError> {
    OffsetDateTime::from_unix_timestamp(now.timestamp() + days * 86_400)
        .map_err(|_| PkiError::Generation)
}

/// 16 bytes whose DER INTEGER encoding is exactly these 16 bytes: the top
/// bit is clear (positive) and the next bit set (no leading zero byte that
/// DER would strip), leaving 126 random bits.
pub(crate) fn random_serial() -> Result<[u8; 16], PkiError> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| PkiError::Generation)?;
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    Ok(bytes)
}

fn named(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

fn ca_params(
    common_name: &str,
    path_len: u8,
    now: DateTime<Utc>,
    days: i64,
) -> Result<CertificateParams, PkiError> {
    let mut params = CertificateParams::default();
    params.distinguished_name = named(common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = offset(now, 0)?;
    params.not_after = offset(now, days)?;
    params.serial_number = Some(SerialNumber::from(random_serial()?.to_vec()));
    Ok(params)
}

/// A new offline root CA: P-256, 10 years, path length 1.
pub fn generate_root(now: DateTime<Utc>) -> Result<KeyAndCert, PkiError> {
    let key = KeyPair::generate().map_err(|_| PkiError::Generation)?;
    let key_pem = key.serialize_pem();
    let params = ca_params("OpenVIBES Root CA", 1, now, ROOT_DAYS)?;
    let issuer = CertifiedIssuer::self_signed(params, key).map_err(|_| PkiError::Generation)?;
    Ok(KeyAndCert {
        cert_pem: issuer.pem(),
        key_pem,
    })
}

/// A new intermediate key and a CSR for it, generated where the key will
/// live (the ingest host). Returns `(csr_pem, key_pem)`.
pub fn intermediate_request() -> Result<(String, String), PkiError> {
    let key = KeyPair::generate().map_err(|_| PkiError::Generation)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = named("OpenVIBES Intermediate CA");
    let csr = params
        .serialize_request(&key)
        .and_then(|csr| csr.pem())
        .map_err(|_| PkiError::Generation)?;
    Ok((csr, key.serialize_pem()))
}

/// Signs an intermediate CSR with the root: 2 years (never past the root's
/// own expiry; `IssuerExpired` once the root has expired), path length 0. The root
/// key must match the root certificate (`KeyMismatch`). The CSR's signature
/// is verified; only its public key is taken from it.
pub fn sign_intermediate(
    root: &KeyAndCert,
    csr_pem: &str,
    now: DateTime<Utc>,
) -> Result<String, PkiError> {
    let csr =
        CertificateSigningRequestParams::from_pem(csr_pem).map_err(|_| PkiError::InvalidCsr)?;
    // Checks that the root is a CA and that the key is the root's own.
    let root = Issuer::load(&root.cert_pem, &root.key_pem)?;
    if now >= root.not_after {
        return Err(PkiError::IssuerExpired);
    }
    let mut params = ca_params("OpenVIBES Intermediate CA", 0, now, INTERMEDIATE_DAYS)?;
    // Never outlive the root: clients would reject the chain after it.
    if now + chrono::Duration::days(INTERMEDIATE_DAYS) > root.not_after {
        params.not_after = OffsetDateTime::from_unix_timestamp(root.not_after.timestamp())
            .map_err(|_| PkiError::Generation)?;
    }
    params
        .signed_by(&csr.public_key, &root.issuer)
        .map(|cert| cert.pem())
        .map_err(|_| PkiError::Generation)
}

/// The first `CERTIFICATE` block of a PEM bundle, as its own PEM. An issuer
/// file may hold the new intermediate followed by the old one.
pub fn first_certificate(pem: &str) -> Result<String, PkiError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem.find(BEGIN).ok_or(PkiError::InvalidPem)?;
    let len = pem[start..].find(END).ok_or(PkiError::InvalidPem)? + END.len();
    let block = &pem[start..start + len];
    parse_x509_pem(block.as_bytes()).map_err(|_| PkiError::InvalidPem)?;
    Ok(format!("{}\n", block.replace("\r\n", "\n")))
}

pub(crate) fn der_of(pem: &str) -> Result<Vec<u8>, PkiError> {
    let (_, pem) = parse_x509_pem(pem.as_bytes()).map_err(|_| PkiError::InvalidPem)?;
    Ok(pem.contents)
}

pub(crate) fn parse(der: &[u8]) -> Result<X509Certificate<'_>, PkiError> {
    x509_parser::parse_x509_certificate(der)
        .map(|(_, cert)| cert)
        .map_err(|_| PkiError::InvalidPem)
}

/// A CA certificate and its key, loaded for issuing.
pub struct Issuer {
    pub(crate) issuer: rcgen::Issuer<'static, KeyPair>,
    cert_pem: String,
    chain_pem: String,
    pub(crate) not_after: DateTime<Utc>,
}

impl Issuer {
    /// Loads an issuing CA from the first certificate of `cert_pem`. The key must match the certificate and the
    /// certificate must be a CA.
    pub fn load(cert_pem: &str, key_pem: &str) -> Result<Self, PkiError> {
        let cert_pem = &first_certificate(cert_pem)?;
        let der = der_of(cert_pem)?;
        let cert = parse(&der)?;
        let is_ca = cert
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|constraints| constraints.value.ca);
        if !is_ca {
            return Err(PkiError::NotCa);
        }
        let key = KeyPair::from_pem(key_pem).map_err(|_| PkiError::InvalidPem)?;
        if key.subject_public_key_info() != cert.tbs_certificate.subject_pki.raw {
            return Err(PkiError::KeyMismatch);
        }
        let not_after = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .ok_or(PkiError::InvalidPem)?;
        let issuer =
            rcgen::Issuer::from_ca_cert_pem(cert_pem, key).map_err(|_| PkiError::InvalidPem)?;
        Ok(Self {
            issuer,
            cert_pem: cert_pem.to_owned(),
            chain_pem: String::new(),
            not_after,
        })
    }

    /// Adds the CAs between this one and the root (PEM, nearest first) to
    /// every server certificate. They are not checked against this CA.
    pub fn with_chain(mut self, middle_pem: &str) -> Result<Self, PkiError> {
        self.chain_pem = crate::chain::certificates(middle_pem)?
            .iter()
            .map(|der| crate::keys::pem("CERTIFICATE", der))
            .collect();
        Ok(self)
    }

    /// The issuing CA's certificate.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// A TLS server certificate for `names` (DNS names or IP addresses),
    /// valid 90 days, with a fresh key. `cert_pem` holds the leaf, this CA's
    /// certificate, then the chain from [`Issuer::with_chain`].
    pub fn issue_server(
        &self,
        names: &[String],
        now: DateTime<Utc>,
    ) -> Result<KeyAndCert, PkiError> {
        let key = KeyPair::generate().map_err(|_| PkiError::Generation)?;
        let mut params =
            CertificateParams::new(names.to_vec()).map_err(|_| PkiError::Generation)?;
        params.distinguished_name = names
            .first()
            .map_or_else(DistinguishedName::new, |name| named(name));
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before = offset(now, 0)?;
        params.not_after = offset(now, SERVER_DAYS)?;
        params.serial_number = Some(SerialNumber::from(random_serial()?.to_vec()));
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(|_| PkiError::Generation)?;
        Ok(KeyAndCert {
            cert_pem: format!("{}{}{}", cert.pem(), self.cert_pem, self.chain_pem),
            key_pem: key.serialize_pem(),
        })
    }
}

/// Whether `cert_pem`'s first certificate is signed by `issuer_cert_pem`'s key.
pub fn verify_signed_by(cert_pem: &str, issuer_cert_pem: &str) -> Result<(), PkiError> {
    let cert_der = der_of(cert_pem)?;
    let issuer_der = der_of(issuer_cert_pem)?;
    let cert = parse(&cert_der)?;
    let issuer = parse(&issuer_der)?;
    cert.verify_signature(Some(issuer.public_key()))
        .map_err(|_| PkiError::NotSignedBy)
}

/// Whether `cert_pem` is a usable intermediate of `root_cert_pem` at `now`:
/// a CA with path length 0 (so not a leaf and not the root itself), signed
/// by the root, and currently valid.
pub fn check_intermediate(
    cert_pem: &str,
    root_cert_pem: &str,
    now: DateTime<Utc>,
) -> Result<(), PkiError> {
    let der = der_of(cert_pem)?;
    let cert = parse(&der)?;
    let constraints = cert
        .basic_constraints()
        .map_err(|_| PkiError::InvalidPem)?
        .map(|extension| (extension.value.ca, extension.value.path_len_constraint));
    let self_signed = cert.subject() == cert.issuer();
    if constraints != Some((true, Some(0))) || self_signed {
        return Err(PkiError::NotIntermediate);
    }
    verify_signed_by(cert_pem, root_cert_pem)?;
    valid_at(&cert, now)
}

fn valid_at(cert: &X509Certificate<'_>, now: DateTime<Utc>) -> Result<(), PkiError> {
    let validity = cert.validity();
    let now = now.timestamp();
    if now < validity.not_before.timestamp() || now > validity.not_after.timestamp() {
        return Err(PkiError::IssuerExpired);
    }
    Ok(())
}

/// Exactly one PEM block (a pasted chain is refused, not half read).
fn single(pem: &str) -> Result<(), PkiError> {
    match Pem::iter_from_buffer(pem.as_bytes()).count() {
        0 => Err(PkiError::InvalidPem),
        1 => Ok(()),
        n => Err(PkiError::Several(n)),
    }
}

/// The common name, else the whole distinguished name.
fn name_of(name: &X509Name<'_>) -> String {
    name.iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map_or_else(|| name.to_string(), str::to_owned)
}

/// A signed intermediate request, as [`check_signed_request`] read it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signed {
    /// The certificate's subject (common name, else the whole name).
    pub subject: String,
    /// Its issuer, the same way.
    pub issuer: String,
    /// End of validity, `YYYY-MM-DD`.
    pub not_after: String,
}

/// Whether `cert_pem` is the CA's answer to `csr_pem`: one certificate, for
/// the request's own key, a CA with path length 0, and valid at `now`.
pub fn check_signed_request(
    csr_pem: &str,
    cert_pem: &str,
    now: DateTime<Utc>,
) -> Result<Signed, PkiError> {
    single(cert_pem)?;
    let der = der_of(cert_pem)?;
    let cert = parse(&der)?;
    // The request first: another CA pasted by mistake (the root, say) is
    // for a different request, not "not a CA".
    let csr =
        CertificateSigningRequestParams::from_pem(csr_pem).map_err(|_| PkiError::InvalidCsr)?;
    if csr.public_key.subject_public_key_info() != cert.tbs_certificate.subject_pki.raw {
        return Err(PkiError::NotForRequest);
    }
    let constraints = cert
        .basic_constraints()
        .map_err(|_| PkiError::InvalidPem)?
        .map(|extension| (extension.value.ca, extension.value.path_len_constraint));
    if constraints != Some((true, Some(0))) {
        return Err(PkiError::NotCa);
    }
    valid_at(&cert, now)?;
    let not_after = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
        .ok_or(PkiError::InvalidPem)?;
    Ok(Signed {
        subject: name_of(cert.subject()),
        issuer: name_of(cert.issuer()),
        not_after: not_after.format("%Y-%m-%d").to_string(),
    })
}

/// Whether `root_pem` is one self-signed CA certificate, valid at `now`,
/// that signed `cert_pem` and may sign a CA (no path length 0); the
/// root's common name.
pub fn check_root_signed(
    root_pem: &str,
    cert_pem: &str,
    now: DateTime<Utc>,
) -> Result<String, PkiError> {
    single(root_pem)?;
    let der = der_of(root_pem)?;
    let root = parse(&der)?;
    let constraints = root.basic_constraints().ok().flatten().map(|c| c.value);
    let is_ca = constraints.is_some_and(|constraints| constraints.ca);
    if !is_ca || root.subject() != root.issuer() || root.verify_signature(None).is_err() {
        return Err(PkiError::NotRoot);
    }
    valid_at(&root, now)?;
    verify_signed_by(cert_pem, root_pem)?;
    // Path length 0 allows no CA below it: every agent's TLS would fail.
    if constraints.and_then(|c| c.path_len_constraint) == Some(0) {
        return Err(PkiError::RootPathLen0);
    }
    Ok(name_of(root.subject()))
}

/// SHA-256 of the first certificate's DER encoding.
pub fn sha256_fingerprint(cert_pem: &str) -> Result<[u8; 32], PkiError> {
    let der = der_of(cert_pem)?;
    parse(&der)?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &der);
    digest.as_ref().try_into().map_err(|_| PkiError::Generation)
}

/// The DNS names and IP addresses the first certificate covers.
pub fn subject_alt_names(cert_pem: &str) -> Result<Vec<String>, PkiError> {
    use x509_parser::extensions::GeneralName;
    let der = der_of(cert_pem)?;
    let cert = parse(&der)?;
    let Ok(Some(names)) = cert.subject_alternative_name() else {
        return Ok(Vec::new());
    };
    Ok(names
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some((*dns).to_owned()),
            GeneralName::IPAddress(bytes) => match bytes.len() {
                4 => Some(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(*bytes).ok()?).to_string()),
                16 => {
                    Some(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*bytes).ok()?).to_string())
                }
                _ => None,
            },
            _ => None,
        })
        .collect())
}

/// Whether the first certificate is a CA (basicConstraints CA:TRUE).
pub fn is_ca(cert_pem: &str) -> Result<bool, PkiError> {
    let der = der_of(cert_pem)?;
    let cert = parse(&der)?;
    let constraints = cert.basic_constraints().map_err(|_| PkiError::InvalidPem)?;
    Ok(constraints.is_some_and(|extension| extension.value.ca))
}

/// Start of validity of the first certificate.
pub fn not_before(cert_pem: &str) -> Result<DateTime<Utc>, PkiError> {
    let der = der_of(cert_pem)?;
    let seconds = parse(&der)?.validity().not_before.timestamp();
    DateTime::from_timestamp(seconds, 0).ok_or(PkiError::InvalidPem)
}

/// End of validity of the first certificate.
pub fn not_after(cert_pem: &str) -> Result<DateTime<Utc>, PkiError> {
    let der = der_of(cert_pem)?;
    let seconds = parse(&der)?.validity().not_after.timestamp();
    DateTime::from_timestamp(seconds, 0).ok_or(PkiError::InvalidPem)
}

/// The common name of the first certificate's issuer, if it has one.
pub fn issuer_common_name(cert_pem: &str) -> Result<Option<String>, PkiError> {
    let der = der_of(cert_pem)?;
    let cert = parse(&der)?;
    Ok(cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned))
}
