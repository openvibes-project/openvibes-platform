use chrono::{DateTime, Duration, Utc};
use rcgen::{
    CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose, SanType,
    SerialNumber,
};
use x509_parser::{
    certification_request::X509CertificationRequest,
    oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY},
    pem::parse_x509_pem,
    prelude::FromDer,
    x509::SubjectPublicKeyInfo,
};

use crate::{
    Issuer, PkiError,
    ca::{der_of, offset, parse, random_serial},
};

/// Largest CSR accepted, matching the V1 document limit.
const MAX_CSR_BYTES: usize = 1024 * 1024;

/// Longest client certificate validity.
const MAX_CLIENT_DAYS: u32 = 365;

/// A CSR that passed [`check_csr`]: signature verified, P-256, empty subject.
pub struct CheckedCsr {
    /// The requested key exactly as the CSR's key info states it (algorithm
    /// included); nothing else from the CSR reaches the certificate.
    public_key: rcgen::SubjectPublicKeyInfo,
    /// SHA-256 of the requested key's SubjectPublicKeyInfo DER.
    pub spki_sha256: [u8; 32],
}

/// An issued agent client certificate.
#[derive(Clone, Debug)]
pub struct IssuedClient {
    /// Certificate serial: exactly the 16 bytes encoded in the certificate.
    pub serial: [u8; 16],
    /// SHA-256 of the certified key's SubjectPublicKeyInfo DER.
    pub spki_sha256: [u8; 32],
    /// Start of validity.
    pub not_before: DateTime<Utc>,
    /// End of validity.
    pub not_after: DateTime<Utc>,
    /// Leaf, then the issuing CA.
    pub chain_pem: Vec<String>,
}

fn spki_sha256(spki: &SubjectPublicKeyInfo<'_>) -> Result<[u8; 32], PkiError> {
    ring::digest::digest(&ring::digest::SHA256, spki.raw)
        .as_ref()
        .try_into()
        .map_err(|_| PkiError::Generation)
}

fn is_p256(spki: &SubjectPublicKeyInfo<'_>) -> bool {
    spki.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY
        && spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.as_oid().ok())
            .is_some_and(|curve| curve == OID_EC_P256)
}

/// Checks an agent CSR: at most 1 MiB, a signature that verifies, an ECDSA
/// P-256 key, and an empty subject. Requested extensions are ignored.
pub fn check_csr(csr_pem: &str) -> Result<CheckedCsr, PkiError> {
    if csr_pem.len() > MAX_CSR_BYTES {
        return Err(PkiError::InvalidCsr);
    }
    let (_, pem) = parse_x509_pem(csr_pem.as_bytes()).map_err(|_| PkiError::InvalidCsr)?;
    let (_, request) =
        X509CertificationRequest::from_der(&pem.contents).map_err(|_| PkiError::InvalidCsr)?;
    request
        .verify_signature()
        .map_err(|_| PkiError::InvalidCsr)?;
    let info = &request.certification_request_info;
    if !is_p256(&info.subject_pki) {
        return Err(PkiError::UnsupportedKey);
    }
    if info.subject.iter().count() != 0 {
        return Err(PkiError::NonEmptySubject);
    }
    // The certified key's algorithm comes from the key info itself, never
    // from the CSR's signature algorithm.
    let public_key = rcgen::SubjectPublicKeyInfo::from_der(info.subject_pki.raw)
        .map_err(|_| PkiError::UnsupportedKey)?;
    Ok(CheckedCsr {
        spki_sha256: spki_sha256(&info.subject_pki)?,
        public_key,
    })
}

/// SHA-256 of a certificate's SubjectPublicKeyInfo DER, as recorded for
/// agents at issuance.
pub fn spki_sha256_of_cert(cert_pem: &str) -> Result<[u8; 32], PkiError> {
    let der = der_of(cert_pem)?;
    spki_sha256(&parse(&der)?.tbs_certificate.subject_pki)
}

impl Issuer {
    /// Issues an agent client certificate for a checked CSR: empty subject,
    /// SAN URI `openvibes:agent:<agent_id>`, client auth only, not a CA,
    /// valid `days` (1 to 365) from `now`, never beyond the issuer's own
    /// expiry. Every extension is set here; nothing is copied from the CSR
    /// except its public key, and the result is refused if the certified key
    /// differs from the CSR's.
    pub fn issue_client(
        &self,
        csr: &CheckedCsr,
        agent_id: &str,
        now: DateTime<Utc>,
        days: u32,
    ) -> Result<IssuedClient, PkiError> {
        if !(1..=MAX_CLIENT_DAYS).contains(&days) {
            return Err(PkiError::InvalidValidity);
        }
        if now >= self.not_after {
            return Err(PkiError::IssuerExpired);
        }
        let serial = random_serial()?;
        let uri = format!("openvibes:agent:{agent_id}")
            .try_into()
            .map_err(|_| PkiError::Generation)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = vec![SanType::URI(uri)];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.is_ca = IsCa::NoCa;
        params.serial_number = Some(SerialNumber::from(serial.to_vec()));
        let not_before =
            DateTime::from_timestamp(now.timestamp(), 0).ok_or(PkiError::Generation)?;
        let not_after = (not_before + Duration::days(i64::from(days))).min(self.not_after);
        params.not_before = offset(not_before, 0)?;
        params.not_after = offset(not_after, 0)?;
        let leaf = params
            .signed_by(&csr.public_key, &self.issuer)
            .map_err(|_| PkiError::Generation)?
            .pem();
        if spki_sha256_of_cert(&leaf)? != csr.spki_sha256 {
            return Err(PkiError::Generation);
        }
        Ok(IssuedClient {
            serial,
            spki_sha256: csr.spki_sha256,
            not_before,
            not_after,
            chain_pem: vec![leaf, self.cert_pem().to_owned()],
        })
    }
}
