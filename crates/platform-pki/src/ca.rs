use chrono::{DateTime, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, CertifiedIssuer,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PublicKeyData, SerialNumber,
};
use ring::rand::{SecureRandom, SystemRandom};
use time::OffsetDateTime;
use x509_parser::{certificate::X509Certificate, pem::parse_x509_pem};

use crate::PkiError;

const ROOT_DAYS: i64 = 3652;
const INTERMEDIATE_DAYS: i64 = 730;
const SERVER_DAYS: i64 = 90;

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

/// 16 random bytes with the top bit cleared, so the serial is positive.
pub(crate) fn random_serial() -> Result<[u8; 16], PkiError> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| PkiError::Generation)?;
    bytes[0] &= 0x7f;
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

/// Signs an intermediate CSR with the root: 2 years, path length 0. The CSR's
/// signature is verified; only its public key is taken from it.
pub fn sign_intermediate(
    root: &KeyAndCert,
    csr_pem: &str,
    now: DateTime<Utc>,
) -> Result<String, PkiError> {
    let csr =
        CertificateSigningRequestParams::from_pem(csr_pem).map_err(|_| PkiError::InvalidCsr)?;
    let root_key = KeyPair::from_pem(&root.key_pem).map_err(|_| PkiError::InvalidPem)?;
    let issuer = rcgen::Issuer::from_ca_cert_pem(&root.cert_pem, root_key)
        .map_err(|_| PkiError::InvalidPem)?;
    let params = ca_params("OpenVIBES Intermediate CA", 0, now, INTERMEDIATE_DAYS)?;
    params
        .signed_by(&csr.public_key, &issuer)
        .map(|cert| cert.pem())
        .map_err(|_| PkiError::Generation)
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
}

impl Issuer {
    /// Loads an issuing CA. The key must match the certificate and the
    /// certificate must be a CA.
    pub fn load(cert_pem: &str, key_pem: &str) -> Result<Self, PkiError> {
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
        let issuer =
            rcgen::Issuer::from_ca_cert_pem(cert_pem, key).map_err(|_| PkiError::InvalidPem)?;
        Ok(Self {
            issuer,
            cert_pem: cert_pem.to_owned(),
        })
    }

    /// The issuing CA's certificate.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// A TLS server certificate for `names` (DNS names or IP addresses),
    /// valid 90 days, with a fresh key. `cert_pem` holds the leaf then this
    /// CA's certificate.
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
            cert_pem: format!("{}{}", cert.pem(), self.cert_pem),
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

/// SHA-256 of the first certificate's DER encoding.
pub fn sha256_fingerprint(cert_pem: &str) -> Result<[u8; 32], PkiError> {
    let der = der_of(cert_pem)?;
    parse(&der)?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &der);
    digest.as_ref().try_into().map_err(|_| PkiError::Generation)
}

/// End of validity of the first certificate.
pub fn not_after(cert_pem: &str) -> Result<DateTime<Utc>, PkiError> {
    let der = der_of(cert_pem)?;
    let seconds = parse(&der)?.validity().not_after.timestamp();
    DateTime::from_timestamp(seconds, 0).ok_or(PkiError::InvalidPem)
}
