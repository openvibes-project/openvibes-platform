//! Company keys and `.p12` files: every accepted form becomes plain PKCS#8.

use platform_pki::{Issuer, PkiError, is_locked, is_p12, key_info, pkcs8_pem, read_p12};

const PASS: &str = "correct horse";
const EC_PKCS8: &str = include_str!("fixtures/ours-ec.pkcs8.pem");
const EC_SEC1: &str = include_str!("fixtures/ours-ec.sec1.pem");
const EC_ENC: &str = include_str!("fixtures/ours-ec.enc.pem");
const RSA_KEY: &str = include_str!("fixtures/ours-rsa.key");
const RSA_PKCS1: &str = include_str!("fixtures/ours-rsa.pkcs1.pem");
const RSA_CRT: &str = include_str!("fixtures/ours-rsa.crt");
const MODERN: &[u8] = include_bytes!("fixtures/modern.pfx");
const LEGACY: &[u8] = include_bytes!("fixtures/legacy.pfx");

#[test]
fn every_pem_form_gives_the_same_pkcs8() {
    let plain = pkcs8_pem(EC_PKCS8, None).unwrap();
    assert!(plain.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert_eq!(*pkcs8_pem(EC_SEC1, None).unwrap(), *plain);
    assert_eq!(*pkcs8_pem(EC_ENC, Some(PASS)).unwrap(), *plain);
    assert_eq!(
        *pkcs8_pem(RSA_PKCS1, None).unwrap(),
        *pkcs8_pem(RSA_KEY, None).unwrap()
    );
}

#[test]
fn a_locked_key_needs_its_password() {
    assert_eq!(pkcs8_pem(EC_ENC, None), Err(PkiError::KeyLocked));
    assert!(is_locked(EC_ENC));
    assert!(!is_locked(EC_SEC1));
    assert!(!is_locked(EC_PKCS8));
}

#[test]
fn a_wrong_password_is_said() {
    assert_eq!(
        pkcs8_pem(EC_ENC, Some("wrong")),
        Err(PkiError::WrongPassword)
    );
}

#[test]
fn key_info_names_the_key() {
    let rsa = pkcs8_pem(RSA_KEY, None).unwrap();
    assert_eq!(
        key_info(&rsa).unwrap().to_string(),
        "an RSA key (3072 bits)"
    );
    assert_eq!(key_info(EC_PKCS8).unwrap().to_string(), "an EC P-256 key");
    let p384 = include_str!("fixtures/issuing.key");
    assert_eq!(key_info(p384).unwrap().to_string(), "an EC P-384 key");
    let ed = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ed = pkcs8_pem(&ed.serialize_pem(), None).unwrap();
    assert_eq!(key_info(&ed).unwrap().to_string(), "an Ed25519 key");
}

#[test]
fn weak_and_unknown_keys_are_refused() {
    let weak = include_str!("fixtures/weak.key");
    assert_eq!(key_info(weak), Err(PkiError::WeakKey(1024)));
    assert_eq!(pkcs8_pem(weak, None), Err(PkiError::WeakKey(1024)));
    let p521 = include_str!("fixtures/p521.key");
    assert_eq!(key_info(p521), Err(PkiError::UnsupportedKey));
    assert_eq!(pkcs8_pem(p521, None), Err(PkiError::UnsupportedKey));
    assert_eq!(
        pkcs8_pem(
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            None
        ),
        Err(PkiError::InvalidPem)
    );
}

#[test]
fn modern_and_legacy_pfx_open() {
    let key = pkcs8_pem(EC_PKCS8, None).unwrap();
    for (pfx, extra) in [(MODERN, false), (LEGACY, true)] {
        let p12 = read_p12(pfx, PASS).unwrap();
        assert_eq!(*p12.key_pem, *key);
        for name in [
            "Lime Lab OpenVIBES CA",
            "Lime Lab Issuing CA",
            "Lime Lab Root CA",
        ] {
            assert!(names(&p12.certs_pem).contains(&name.to_owned()), "{name}");
        }
        assert_eq!(
            names(&p12.certs_pem).contains(&"Lime Lab Web".into()),
            extra
        );
        assert_eq!(names(&p12.certs_pem)[0], "Lime Lab OpenVIBES CA");
        assert!(!format!("{p12:?}").contains("PRIVATE KEY"));
    }
}

#[test]
fn a_pfx_with_the_wrong_password_is_said() {
    assert_eq!(
        read_p12(MODERN, "wrong").unwrap_err(),
        PkiError::WrongPassword
    );
    assert_eq!(
        read_p12(LEGACY, "wrong").unwrap_err(),
        PkiError::WrongPassword
    );
}

#[test]
fn is_p12_tells_der_from_pem() {
    assert!(is_p12(MODERN));
    assert!(is_p12(LEGACY));
    assert!(!is_p12(EC_PKCS8.as_bytes()));
    assert!(!is_p12(RSA_CRT.as_bytes()));
    assert!(!is_p12(b""));
}

#[test]
fn an_imported_rsa_key_loads_as_issuer() {
    let key = pkcs8_pem(RSA_PKCS1, None).unwrap();
    Issuer::load(RSA_CRT, &key).unwrap();
}

/// Common names of every certificate in a PEM bundle, in order.
fn names(pem: &str) -> Vec<String> {
    x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes())
        .map(|block| {
            let block = block.unwrap();
            let cert = block.parse_x509().unwrap();
            let cn = cert.subject().iter_common_name().next().unwrap();
            cn.as_str().unwrap().to_owned()
        })
        .collect()
}
