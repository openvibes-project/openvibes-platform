//! Company keys and `.p12`/`.pfx` files, turned into the plain PKCS#8 that
//! rcgen loads. Every key returned here has already loaded once.

use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};
use der::asn1::{AnyRef, BitStringRef, ObjectIdentifier, OctetStringRef, UintRef};
use der::{Any, Decode, Encode, Reader, Sequence, SliceReader};
use p12_keystore::Pkcs12Archive;
use pkcs5::EncryptionScheme;
use rcgen::KeyPair;
use zeroize::Zeroizing;

use crate::PkiError;

const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// The kind of an accepted private key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyKind {
    /// RSA, 2048 to 8192 bits.
    Rsa,
    /// ECDSA on P-256.
    P256,
    /// ECDSA on P-384.
    P384,
    /// Ed25519.
    Ed25519,
}

/// What a private key is, for the screen ("an RSA key (3072 bits)").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyInfo {
    /// The key's kind.
    pub kind: KeyKind,
    /// Its size in bits (the curve size for EC and Ed25519).
    pub bits: u32,
}

impl fmt::Display for KeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            KeyKind::Rsa => write!(f, "an RSA key ({} bits)", self.bits),
            KeyKind::P256 => f.write_str("an EC P-256 key"),
            KeyKind::P384 => f.write_str("an EC P-384 key"),
            KeyKind::Ed25519 => f.write_str("an Ed25519 key"),
        }
    }
}

/// The certificates and key read from a `.p12`/`.pfx` file.
pub struct P12 {
    /// Every certificate in the file as PEM, the key's own one first.
    pub certs_pem: String,
    /// The first private key, as PKCS#8 PEM.
    pub key_pem: Zeroizing<String>,
}

impl fmt::Debug for P12 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("P12")
            .field("certs_pem", &self.certs_pem)
            .field("key_pem", &"[REDACTED]")
            .finish()
    }
}

/// The PKCS#8 encoding, used to wrap PKCS#1 and SEC1 keys.
#[derive(Sequence)]
struct PrivateKeyInfo<'a> {
    version: u8,
    algorithm: AlgorithmIdentifier,
    private_key: &'a OctetStringRef,
}

#[derive(Sequence)]
struct AlgorithmIdentifier {
    oid: ObjectIdentifier,
    parameters: Any,
}

/// SEC1 `ECPrivateKey`.
#[derive(Sequence)]
struct EcPrivateKey<'a> {
    version: u8,
    private_key: &'a OctetStringRef,
    #[asn1(context_specific = "0", optional = "true")]
    parameters: Option<ObjectIdentifier>,
    #[asn1(context_specific = "1", optional = "true")]
    public_key: Option<BitStringRef<'a>>,
}

/// Converts the first key in `key_pem` (PEM `PRIVATE KEY`, `RSA PRIVATE
/// KEY`, `EC PRIVATE KEY` or `ENCRYPTED PRIVATE KEY`) to PKCS#8 PEM.
pub fn pkcs8_pem(key_pem: &str, password: Option<&str>) -> Result<Zeroizing<String>, PkiError> {
    let (label, der) = first_key_block(key_pem)?;
    let pkcs8 = match label.as_str() {
        "PRIVATE KEY" => der,
        "RSA PRIVATE KEY" => wrap(RSA, Any::null(), &der)?,
        "EC PRIVATE KEY" => from_sec1(&der)?,
        "ENCRYPTED PRIVATE KEY" => decrypt(&der, password.ok_or(PkiError::KeyLocked)?)?,
        _ => return Err(PkiError::InvalidPem),
    };
    checked_pem(&pkcs8)
}

/// Whether the first key in `key_pem` is an `ENCRYPTED PRIVATE KEY`.
pub fn is_locked(key_pem: &str) -> bool {
    first_key_block(key_pem).is_ok_and(|(label, _)| label == "ENCRYPTED PRIVATE KEY")
}

/// Names the key in a PKCS#8 PEM and refuses the ones OpenVIBES cannot sign
/// with: RSA below 2048 bits is weak; P-521, DSA and RSA above 8192 bits
/// are unsupported.
pub fn key_info(pkcs8_pem: &str) -> Result<KeyInfo, PkiError> {
    let (label, der) = first_key_block(pkcs8_pem)?;
    if label != "PRIVATE KEY" {
        return Err(PkiError::InvalidPem);
    }
    classify(&der)
}

/// Whether `bytes` look like a `.p12`/`.pfx` file: DER, not PEM text.
pub fn is_p12(bytes: &[u8]) -> bool {
    bytes.first() == Some(&0x30) && !bytes.starts_with(b"-----")
}

/// Opens a `.p12`/`.pfx` file (PBES2 with AES, or legacy 3DES/RC2) and
/// returns its first private key and every certificate in it.
pub fn read_p12(bytes: &[u8], password: &str) -> Result<P12, PkiError> {
    let archive = Pkcs12Archive::from_pkcs12(bytes, password).map_err(|error| match error {
        p12_keystore::error::Error::MacError(_) | p12_keystore::error::Error::UnpadError => {
            PkiError::WrongPassword
        }
        _ => PkiError::InvalidPem,
    })?;
    let key = archive.keys.first().ok_or(PkiError::InvalidPem)?;
    let key_pem = checked_pem(key.key.as_der())?;
    let key_id = key.local_key_id.as_ref().map(|id| id.0.as_slice());
    let mut certs: Vec<_> = archive.certs.iter().collect();
    certs.sort_by_key(|bag| key_id.is_none() || bag.local_key_id.as_deref() != key_id);
    let certs_pem = certs
        .iter()
        .map(|bag| pem("CERTIFICATE", bag.cert.as_der()))
        .collect();
    Ok(P12 { certs_pem, key_pem })
}

/// The label and DER of the first PEM block, skipping `EC PARAMETERS`
/// (which `openssl ecparam -genkey` writes before the key).
fn first_key_block(text: &str) -> Result<(String, Zeroizing<Vec<u8>>), PkiError> {
    x509_parser::pem::Pem::iter_from_buffer(text.as_bytes())
        .find(|block| block.as_ref().map_or(true, |b| b.label != "EC PARAMETERS"))
        .and_then(Result::ok)
        .map(|block| (block.label, Zeroizing::new(block.contents)))
        .ok_or(PkiError::InvalidPem)
}

/// Checks a PKCS#8 key and returns it as PEM, as rcgen writes it.
fn checked_pem(pkcs8: &[u8]) -> Result<Zeroizing<String>, PkiError> {
    classify(pkcs8)?;
    let key = KeyPair::try_from(pkcs8).map_err(|_| PkiError::InvalidPem)?;
    Ok(Zeroizing::new(key.serialize_pem()))
}

fn classify(pkcs8: &[u8]) -> Result<KeyInfo, PkiError> {
    let (oid, parameters, key) = parse_pkcs8(pkcs8).map_err(|_| PkiError::InvalidPem)?;
    let curve = || parameters.and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
    let (kind, bits) = match oid {
        RSA => (
            KeyKind::Rsa,
            rsa_bits(key).map_err(|_| PkiError::InvalidPem)?,
        ),
        EC if curve() == Some(P256) => (KeyKind::P256, 256),
        EC if curve() == Some(P384) => (KeyKind::P384, 384),
        ED25519 => (KeyKind::Ed25519, 256),
        _ => return Err(PkiError::UnsupportedKey),
    };
    match bits {
        ..2048 if kind == KeyKind::Rsa => Err(PkiError::WeakKey(bits)),
        8193.. => Err(PkiError::UnsupportedKey),
        _ => Ok(KeyInfo { kind, bits }),
    }
}

/// The algorithm, its parameters and the inner key of a PKCS#8 key. Trailing
/// attributes and the version 2 public key are skipped.
fn parse_pkcs8(der: &[u8]) -> der::Result<(ObjectIdentifier, Option<AnyRef<'_>>, &[u8])> {
    let mut reader = SliceReader::new(der)?;
    let parsed = reader.sequence(|r| {
        let _version: u8 = r.decode()?;
        let (oid, parameters) = r.sequence(|alg| {
            let oid: ObjectIdentifier = alg.decode()?;
            let parameters: Option<AnyRef<'_>> = alg.decode()?;
            Ok::<_, der::Error>((oid, parameters))
        })?;
        let key: &OctetStringRef = r.decode()?;
        r.drain(r.remaining_len())?;
        Ok::<_, der::Error>((oid, parameters, key.as_bytes()))
    })?;
    reader.finish()?;
    Ok(parsed)
}

/// The modulus size of a PKCS#1 `RSAPrivateKey`.
fn rsa_bits(der: &[u8]) -> der::Result<u32> {
    let mut reader = SliceReader::new(der)?;
    let modulus = reader.sequence(|r| {
        let _version: u8 = r.decode()?;
        let modulus: UintRef<'_> = r.decode()?;
        r.drain(r.remaining_len())?;
        Ok::<_, der::Error>(modulus)
    })?;
    reader.finish()?;
    let bytes = modulus.as_bytes();
    let top = bytes.first().map_or(0, |b| 8 - b.leading_zeros());
    Ok((bytes.len().saturating_sub(1) * 8) as u32 + top)
}

fn wrap(
    oid: ObjectIdentifier,
    parameters: Any,
    key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PkiError> {
    let info = PrivateKeyInfo {
        version: 0,
        algorithm: AlgorithmIdentifier { oid, parameters },
        private_key: OctetStringRef::new(key).map_err(|_| PkiError::InvalidPem)?,
    };
    info.to_der()
        .map(Zeroizing::new)
        .map_err(|_| PkiError::InvalidPem)
}

/// SEC1 to PKCS#8: the curve moves from the key to the algorithm.
fn from_sec1(der: &[u8]) -> Result<Zeroizing<Vec<u8>>, PkiError> {
    let mut key = EcPrivateKey::from_der(der).map_err(|_| PkiError::InvalidPem)?;
    let curve = key.parameters.take().ok_or(PkiError::UnsupportedKey)?;
    let inner = Zeroizing::new(key.to_der().map_err(|_| PkiError::InvalidPem)?);
    let curve = Any::encode_from(&curve).map_err(|_| PkiError::InvalidPem)?;
    wrap(EC, curve, &inner)
}

/// Decrypts an `EncryptedPrivateKeyInfo`. Anything that does not come out as
/// PKCS#8 is a wrong password.
fn decrypt(der: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>, PkiError> {
    let mut reader = SliceReader::new(der).map_err(|_| PkiError::InvalidPem)?;
    let (scheme, data) = reader
        .sequence(|r| {
            let scheme: EncryptionScheme = r.decode()?;
            let data: &OctetStringRef = r.decode()?;
            Ok::<_, der::Error>((scheme, data))
        })
        .map_err(|_| PkiError::InvalidPem)?;
    let plain = scheme
        .decrypt(password, data.as_bytes())
        .map(Zeroizing::new)
        .map_err(|error| match error {
            pkcs5::Error::DecryptFailed => PkiError::WrongPassword,
            _ => PkiError::InvalidPem,
        })?;
    parse_pkcs8(&plain).map_err(|_| PkiError::WrongPassword)?;
    Ok(plain)
}

fn pem(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).unwrap_or_default())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}
