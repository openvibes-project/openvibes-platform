#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Certificate issuing for the platform: the built-in CA hierarchy, server
//! certificates, and (for ingest) agent client certificates. No I/O and no
//! network: PEM strings in, PEM strings out.

mod ca;
mod client;

use std::fmt;

pub use ca::{
    Issuer, KeyAndCert, generate_root, intermediate_request, sha256_fingerprint, sign_intermediate,
    verify_signed_by,
};
pub use client::{CheckedCsr, IssuedClient, check_csr, spki_sha256_of_cert};

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
        })
    }
}

impl std::error::Error for PkiError {}
