//! Company keys and `.p12`/`.pfx` files, turned into the plain PKCS#8 that
//! rcgen loads. Every key returned here has already loaded once.

use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};
use cbc::cipher::{BlockCipherDecrypt, BlockModeDecrypt, KeyInit, KeyIvInit, block_padding::Pkcs7};
use der::asn1::{AnyRef, BitStringRef, ObjectIdentifier, OctetStringRef, UintRef};
use der::{Any, Decode, Encode, Reader, Sequence, SliceReader};
use md5::{Digest, Md5};
use p12_keystore::Pkcs12Archive;
use pkcs5::EncryptionScheme;
use rcgen::{KeyPair, PublicKeyData};
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
    /// RSA, 2048 to 4096 bits.
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

/// One PEM block: its label, its `DEK-Info` header (OpenSSL's traditional
/// encryption) and its DER.
struct Block {
    label: String,
    dek_info: Option<String>,
    der: Zeroizing<Vec<u8>>,
}

/// Converts the first key in `key_pem` (PEM `PRIVATE KEY`, `RSA PRIVATE
/// KEY`, `EC PRIVATE KEY` or `ENCRYPTED PRIVATE KEY`) to PKCS#8 PEM. The
/// traditional forms may carry OpenSSL's `Proc-Type: 4,ENCRYPTED` headers.
pub fn pkcs8_pem(key_pem: &str, password: Option<&str>) -> Result<Zeroizing<String>, PkiError> {
    let Block {
        label,
        dek_info,
        der,
    } = first_key_block(key_pem)?;
    let der = match dek_info {
        Some(dek_info) => traditional(&dek_info, &der, password.ok_or(PkiError::KeyLocked)?)?,
        None => der,
    };
    let pkcs8 = match label.as_str() {
        "PRIVATE KEY" => der,
        "RSA PRIVATE KEY" => wrap(RSA, Any::null(), &der)?,
        "EC PRIVATE KEY" => from_sec1(&der)?,
        "ENCRYPTED PRIVATE KEY" => decrypt(&der, password.ok_or(PkiError::KeyLocked)?)?,
        _ => return Err(PkiError::InvalidPem),
    };
    checked_pem(&pkcs8)
}

/// Whether the first key in `key_pem` is an `ENCRYPTED PRIVATE KEY` or
/// carries OpenSSL's traditional encryption headers.
pub fn is_locked(key_pem: &str) -> bool {
    first_key_block(key_pem)
        .is_ok_and(|block| block.label == "ENCRYPTED PRIVATE KEY" || block.dek_info.is_some())
}

/// Names the key in a PKCS#8 PEM and refuses the ones OpenVIBES cannot sign
/// with: RSA below 2048 bits is weak; P-521, DSA and RSA above 4096 bits
/// (ring's limit) are unsupported.
pub fn key_info(pkcs8_pem: &str) -> Result<KeyInfo, PkiError> {
    let block = first_key_block(pkcs8_pem)?;
    if block.label != "PRIVATE KEY" || block.dek_info.is_some() {
        return Err(PkiError::InvalidPem);
    }
    classify(&block.der)
}

/// Whether `bytes` look like a `.p12`/`.pfx` file: DER, not PEM text.
pub fn is_p12(bytes: &[u8]) -> bool {
    bytes.first() == Some(&0x30) && !bytes.starts_with(b"-----")
}

/// Opens a `.p12`/`.pfx` file (PBES2 with AES, or legacy 3DES/RC2) and
/// returns its first private key and every certificate in it, the one for
/// that key first (found by its public key, not the file's key ids).
pub fn read_p12(bytes: &[u8], password: &str) -> Result<P12, PkiError> {
    let archive = Pkcs12Archive::from_pkcs12(bytes, password).map_err(|error| match error {
        p12_keystore::error::Error::MacError(_) | p12_keystore::error::Error::UnpadError => {
            PkiError::WrongPassword
        }
        _ => PkiError::InvalidPem,
    })?;
    let key = archive.keys.first().ok_or(PkiError::InvalidPem)?;
    let key_pem = checked_pem(key.key.as_der())?;
    let spki = KeyPair::try_from(key.key.as_der())
        .map_err(|_| PkiError::InvalidPem)?
        .subject_public_key_info();
    let mut certs: Vec<_> = archive.certs.iter().collect();
    certs.sort_by_key(|bag| {
        crate::ca::parse(bag.cert.as_der()).map_or(true, |cert| cert.public_key().raw != spki)
    });
    let certs_pem = certs
        .iter()
        .map(|bag| pem("CERTIFICATE", bag.cert.as_der()))
        .collect();
    Ok(P12 { certs_pem, key_pem })
}

/// The first PEM block, skipping `EC PARAMETERS` (which `openssl ecparam
/// -genkey` writes before the key) and certificates (a file may hold the
/// certificate, then its key). Header lines (`Name: value`) are kept
/// out of the base64; only `DEK-Info` is used.
fn first_key_block(text: &str) -> Result<Block, PkiError> {
    let mut lines = text.lines().map(str::trim);
    loop {
        let label = lines
            .find_map(|line| line.strip_prefix("-----BEGIN ")?.strip_suffix("-----"))
            .ok_or(PkiError::InvalidPem)?;
        let mut dek_info = None;
        let mut body = Zeroizing::new(String::new());
        loop {
            let line = lines.next().ok_or(PkiError::InvalidPem)?;
            if line.starts_with("-----END ") {
                break;
            }
            match line.split_once(':') {
                Some(("DEK-Info", value)) => dek_info = Some(value.trim().to_owned()),
                Some(_) => {}
                None => body.push_str(line),
            }
        }
        if label == "EC PARAMETERS" || label == "CERTIFICATE" {
            continue;
        }
        let der = STANDARD
            .decode(body.as_bytes())
            .map_err(|_| PkiError::InvalidPem)?;
        return Ok(Block {
            label: label.to_owned(),
            dek_info,
            der: Zeroizing::new(der),
        });
    }
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
        4097.. => Err(PkiError::UnsupportedKey),
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

/// Decrypts an `EncryptedPrivateKeyInfo` (PBES2, with SHA-1 or SHA-2 and
/// AES or 3DES). PBES1 is too old. Anything that does not come out as PKCS#8
/// is a wrong password.
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
            pkcs5::Error::NoPbes1CryptSupport | pkcs5::Error::UnsupportedAlgorithm { .. } => {
                PkiError::OldEncryption
            }
            _ => PkiError::InvalidPem,
        })?;
    parse_pkcs8(&plain).map_err(|_| PkiError::WrongPassword)?;
    Ok(plain)
}

/// Decrypts OpenSSL's traditional encryption (`DEK-Info: <cipher>,<iv hex>`):
/// the key is EVP_BytesToKey with MD5, one round, salted with the first 8
/// bytes of the IV. Other ciphers are too old.
fn traditional(
    dek_info: &str,
    data: &[u8],
    password: &str,
) -> Result<Zeroizing<Vec<u8>>, PkiError> {
    let (cipher, iv) = dek_info.split_once(',').ok_or(PkiError::InvalidPem)?;
    let key_len = match cipher {
        "AES-128-CBC" => 16,
        "AES-192-CBC" | "DES-EDE3-CBC" => 24,
        "AES-256-CBC" => 32,
        _ => return Err(PkiError::OldEncryption),
    };
    let iv = hex(iv.trim()).ok_or(PkiError::InvalidPem)?;
    let salt = iv.get(..8).ok_or(PkiError::InvalidPem)?;
    // Sized up front and refilled in place: no copy is left unwiped.
    let mut key = Zeroizing::new(Vec::with_capacity(key_len + 16));
    let mut round = Zeroizing::new(Vec::with_capacity(16));
    while key.len() < key_len {
        let mut digest = Zeroizing::new([0u8; 16]);
        Md5::new()
            .chain_update(&*round)
            .chain_update(password)
            .chain_update(salt)
            .finalize_into((&mut *digest).into());
        round.clear();
        round.extend_from_slice(&*digest);
        key.extend_from_slice(&round);
    }
    key.truncate(key_len);
    let plain = match cipher {
        "AES-128-CBC" => cbc_decrypt::<aes::Aes128>(&key, &iv, data),
        "AES-192-CBC" => cbc_decrypt::<aes::Aes192>(&key, &iv, data),
        "AES-256-CBC" => cbc_decrypt::<aes::Aes256>(&key, &iv, data),
        _ => cbc_decrypt::<des::TdesEde3>(&key, &iv, data),
    }?;
    // Garbage that happens to unpad is a wrong password too.
    let whole_sequence = SliceReader::new(&plain).and_then(|mut reader| {
        reader.sequence(|r| r.drain(r.remaining_len()))?;
        reader.finish()
    });
    whole_sequence.map_err(|_| PkiError::WrongPassword)?;
    Ok(plain)
}

fn cbc_decrypt<C: BlockCipherDecrypt + KeyInit>(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PkiError> {
    cbc::Decryptor::<C>::new_from_slices(key, iv)
        .map_err(|_| PkiError::InvalidPem)?
        .decrypt_padded_vec::<Pkcs7>(data)
        .map(Zeroizing::new)
        .map_err(|_| PkiError::WrongPassword)
}

fn hex(text: &str) -> Option<Vec<u8>> {
    let digits = text.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

pub(crate) fn pem(label: &str, der: &[u8]) -> String {
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
