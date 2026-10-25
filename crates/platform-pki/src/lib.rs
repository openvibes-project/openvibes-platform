#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Certificate issuing for the platform: the built-in CA hierarchy, server
//! certificates, and (for ingest) agent client certificates. No I/O and no
//! network: PEM strings in, PEM strings out.

mod ca;
mod chain;
mod client;
mod keys;
mod token;

use std::fmt;

pub use ca::{
    Issuer, KeyAndCert, Signed, check_intermediate, check_root_signed, check_signed_request,
    first_certificate, generate_root, intermediate_request, is_ca, issuer_common_name, not_after,
    not_before, sha256_fingerprint, sign_intermediate, subject_alt_names, verify_signed_by,
};
pub use chain::{Chain, ChainError, certificates, check_chain, check_key};
pub use client::{
    CheckedCsr, IssuedClient, check_csr, leaf_identity, leaf_validity, spki_sha256_of_cert,
};
pub use keys::{KeyInfo, KeyKind, P12, is_locked, is_p12, key_info, pkcs8_pem, read_p12};
pub use token::{enrollment_token_sha256, is_agent_id};

/// Fixed failure categories; no key or certificate material is included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PkiError {
    /// Not a parseable PEM certificate or key.
    InvalidPem,
    /// Not a parseable CSR, or its signature does not verify.
    InvalidCsr,
    /// The CSR's key is not ECDSA P-256.
    UnsupportedKey,
    /// The CSR has a subject; the platform assigns identity itself.
    NonEmptySubject,
    /// The private key does not belong to the certificate.
    KeyMismatch,
    /// The certificate is not a CA and cannot issue.
    NotCa,
    /// The certificate is not signed by the given issuer.
    NotSignedBy,
    /// Key or certificate generation failed.
    Generation,
    /// Requested validity is outside 1 to 365 days.
    InvalidValidity,
    /// The issuing CA has expired.
    IssuerExpired,
    /// Not an agent id the platform assigns (`agent.<lowercase uuid>`).
    InvalidAgentId,
    /// Not an intermediate: a leaf, a self-signed root, or a CA without path
    /// length 0.
    NotIntermediate,
    /// The certificate was signed for another request (another key).
    NotForRequest,
    /// Several PEM blocks where one certificate was expected.
    Several(usize),
    /// Not a self-signed CA certificate.
    NotRoot,
    /// A root with path length 0: it cannot validly sign an intermediate.
    RootPathLen0,
    /// The private key is encrypted and no password was given.
    KeyLocked,
    /// The password does not open the key or file.
    WrongPassword,
    /// An RSA key below 2048 bits; the payload is its size.
    WeakKey(u32),
    /// The key is locked with an encryption OpenVIBES no longer opens
    /// (PBES1, or a traditional `DEK-Info` cipher other than AES or 3DES).
    OldEncryption,
    /// The CA's name cannot be written back byte for byte as the issuer of
    /// the certificates it signs, so they would not chain.
    NameMismatch,
}

impl fmt::Display for PkiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPem => "invalid certificate or key",
            Self::InvalidCsr => "invalid certificate signing request",
            Self::UnsupportedKey => "unsupported key type; P-256 is required",
            Self::NonEmptySubject => "certificate signing request must have an empty subject",
            Self::KeyMismatch => "private key does not match the certificate",
            Self::NotCa => "certificate is not a CA",
            Self::NotSignedBy => "certificate is not signed by the given issuer",
            Self::Generation => "key or certificate generation failed",
            Self::InvalidValidity => "certificate validity must be 1 to 365 days",
            Self::IssuerExpired => "the issuing CA has expired",
            Self::NotIntermediate => "not an intermediate CA certificate (path length 0)",
            Self::InvalidAgentId => "invalid agent id",
            Self::NotForRequest => "certificate was signed for another request",
            Self::NotRoot => "not a self-signed CA certificate",
            Self::RootPathLen0 => "the root CA has path length 0 and cannot sign an intermediate",
            Self::KeyLocked => "the private key is locked with a password",
            Self::WrongPassword => "wrong password",
            Self::OldEncryption => "the key's encryption is too old",
            Self::NameMismatch => "the CA's name cannot be reproduced",
            Self::WeakKey(bits) => return write!(f, "an RSA key of {bits} bits is too weak"),
            Self::Several(n) => {
                return write!(f, "{n} PEM blocks where one certificate was expected");
            }
        })
    }
}

impl std::error::Error for PkiError {}
