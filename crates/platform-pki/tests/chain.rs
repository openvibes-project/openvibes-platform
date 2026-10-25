//! A company chain and key: the path to the root, and what server
//! certificates carry.

use chrono::{DateTime, TimeZone, Utc};
use platform_pki::{
    ChainError, Issuer, KeyInfo, KeyKind, PkiError, check_chain, check_key, common_name,
    generate_root, intermediate_request, sign_intermediate, verify_signed_by,
};

const ROOT: &str = include_str!("fixtures/root.crt");
const ISSUING: &str = include_str!("fixtures/issuing.crt");
const OURS_EC: &str = include_str!("fixtures/ours-ec.crt");
const OURS_EC_KEY: &str = include_str!("fixtures/ours-ec.pkcs8.pem");
const OURS_RSA: &str = include_str!("fixtures/ours-rsa.crt");
const RSA_KEY: &str = include_str!("fixtures/ours-rsa.key");
const LEAF: &str = include_str!("fixtures/leaf-not-ca.crt");
const STRICT: &str = include_str!("fixtures/strict.crt");
const UNDER_STRICT: &str = include_str!("fixtures/under-strict.crt");
const SHORT: &str = include_str!("fixtures/short.crt");
const TWIN_DC: &str = include_str!("fixtures/twin-dc.crt");
const TWIN_DC_KEY: &str = include_str!("fixtures/twin-dc.key");

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 6, 1, 0, 0, 0).unwrap()
}

fn missing(name: &str) -> Result<platform_pki::Chain, ChainError> {
    Err(ChainError::Missing(name.into()))
}

#[test]
fn a_full_chain_is_accepted() {
    let chain = check_chain(&format!("{OURS_EC}{ISSUING}{ROOT}"), now()).unwrap();
    assert_eq!(chain.ours, OURS_EC);
    assert_eq!(chain.middle, [ISSUING]);
    assert_eq!(chain.root, ROOT);
    assert_eq!(chain.name, "Lime Lab OpenVIBES CA");
    assert_eq!(chain.path, ["Lime Lab Issuing CA", "Lime Lab Root CA"]);
    assert_eq!(
        chain.not_after,
        Utc.with_ymd_and_hms(2046, 1, 1, 0, 0, 0).unwrap()
    );
}

#[test]
fn order_and_crlf_do_not_matter() {
    let mixed = format!("{OURS_EC}{ROOT}{ISSUING}").replace('\n', "\r\n");
    assert_eq!(
        check_chain(&mixed, now()),
        check_chain(&format!("{OURS_EC}{ISSUING}{ROOT}"), now())
    );
}

#[test]
fn the_root_may_come_first() {
    assert_eq!(
        check_chain(&format!("{ROOT}{ISSUING}{OURS_EC}"), now()),
        check_chain(&format!("{OURS_EC}{ISSUING}{ROOT}"), now())
    );
    // A lone root, or one with only CAs it signed, is still a root.
    assert_eq!(
        check_chain(&format!("{ROOT}{ISSUING}{STRICT}"), now()),
        Err(ChainError::IsRoot("Lime Lab Root CA".into()))
    );
}

#[test]
fn extra_certificates_are_ignored() {
    let chain = check_chain(&format!("{OURS_EC}{LEAF}{ROOT}{STRICT}{ISSUING}"), now()).unwrap();
    assert_eq!(chain.middle, [ISSUING]);
}

#[test]
fn a_gap_names_the_missing_ca() {
    assert_eq!(
        check_chain(&format!("{OURS_EC}{ROOT}"), now()),
        missing("Lime Lab Issuing CA")
    );
    assert_eq!(check_chain(OURS_EC, now()), missing("Lime Lab Issuing CA"));
}

#[test]
fn the_root_must_be_there() {
    assert_eq!(
        check_chain(&format!("{OURS_EC}{ISSUING}"), now()),
        missing("Lime Lab Root CA")
    );
}

#[test]
fn a_leaf_is_not_a_ca() {
    assert_eq!(
        check_chain(&format!("{LEAF}{ISSUING}{ROOT}"), now()),
        Err(ChainError::NotCa("Lime Lab Web".into()))
    );
}

#[test]
fn a_root_is_not_ours() {
    assert_eq!(
        check_chain(ROOT, now()),
        Err(ChainError::IsRoot("Lime Lab Root CA".into()))
    );
}

#[test]
fn a_chain_not_valid_yet_is_refused() {
    let early = Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap();
    assert_eq!(
        check_chain(&format!("{OURS_EC}{ISSUING}{ROOT}"), early),
        Err(ChainError::NotYetValid(
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
        ))
    );
}

#[test]
fn not_pem_is_refused() {
    assert_eq!(check_chain("", now()), Err(ChainError::InvalidPem));
    assert_eq!(check_chain("hello", now()), Err(ChainError::InvalidPem));
}

#[test]
fn path_length_zero_allows_no_ca_below() {
    assert_eq!(
        check_chain(&format!("{UNDER_STRICT}{STRICT}{ROOT}"), now()),
        Err(ChainError::NoCaBelow("Lime Lab Strict CA".into()))
    );
}

#[test]
fn ninety_days_are_needed() {
    let now = Utc.with_ymd_and_hms(2026, 10, 25, 0, 0, 0).unwrap();
    assert_eq!(
        check_chain(&format!("{SHORT}{ISSUING}{ROOT}"), now),
        Err(ChainError::Expiring(
            Utc.with_ymd_and_hms(2026, 12, 1, 0, 0, 0).unwrap()
        ))
    );
    // The same chain is fine when the 90 days fit.
    let early = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap();
    check_chain(&format!("{SHORT}{ISSUING}{ROOT}"), early).unwrap();
}

#[test]
fn the_key_must_match() {
    let chain = check_chain(&format!("{OURS_EC}{ISSUING}{ROOT}"), now()).unwrap();
    let rsa = platform_pki::pkcs8_pem(RSA_KEY, None).unwrap();
    assert_eq!(
        check_key(&chain, &rsa, &[], now()),
        Err(ChainError::Pki(PkiError::KeyMismatch))
    );
    assert_eq!(
        check_key(&chain, OURS_EC_KEY, &[], now()),
        Ok(KeyInfo {
            kind: KeyKind::P256,
            bits: 256
        })
    );
}

#[test]
fn an_rsa_key_is_accepted() {
    let chain = check_chain(&format!("{OURS_RSA}{ISSUING}{ROOT}"), now()).unwrap();
    let key = platform_pki::pkcs8_pem(RSA_KEY, None).unwrap();
    assert_eq!(
        check_key(&chain, &key, &[], now()),
        Ok(KeyInfo {
            kind: KeyKind::Rsa,
            bits: 3072
        })
    );
}

#[test]
fn a_name_rcgen_cannot_reproduce_is_refused() {
    let chain = check_chain(&format!("{TWIN_DC}{ISSUING}{ROOT}"), now()).unwrap();
    assert_eq!(
        check_key(&chain, TWIN_DC_KEY, &[], now()),
        Err(ChainError::Pki(PkiError::NameMismatch))
    );
}

fn blocks(pem: &str) -> Vec<String> {
    pem.split_inclusive("-----END CERTIFICATE-----\n")
        .map(str::to_owned)
        .collect()
}

#[test]
fn server_certificates_carry_the_chain() {
    let issuer = Issuer::load(OURS_EC, OURS_EC_KEY)
        .unwrap()
        .with_chain(ISSUING)
        .unwrap();
    let server = issuer.issue_server(&["limebox.lan".into()], now()).unwrap();
    let parts = blocks(&server.cert_pem);
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[1], OURS_EC);
    assert_eq!(parts[2], ISSUING);
    verify_signed_by(&parts[0], OURS_EC).unwrap();
    verify_signed_by(OURS_EC, ISSUING).unwrap();
    verify_signed_by(ISSUING, ROOT).unwrap();

    // No chain: leaf and our CA, as before.
    let plain = Issuer::load(OURS_EC, OURS_EC_KEY).unwrap();
    let server = plain.issue_server(&["limebox.lan".into()], now()).unwrap();
    assert_eq!(blocks(&server.cert_pem).len(), 2);
    // An empty middle (a two-tier PKI) is no chain either.
    for empty in ["", " \n"] {
        let server = Issuer::load(OURS_EC, OURS_EC_KEY)
            .unwrap()
            .with_chain(empty)
            .unwrap()
            .issue_server(&["limebox.lan".into()], now())
            .unwrap();
        assert_eq!(blocks(&server.cert_pem).len(), 2);
    }
    assert!(
        Issuer::load(OURS_EC, OURS_EC_KEY)
            .unwrap()
            .with_chain("not a certificate")
            .is_err()
    );
}

#[test]
fn openvibes_made_cas_still_pass() {
    let now = Utc::now();
    let root = generate_root(now).unwrap();
    let (csr, key) = intermediate_request().unwrap();
    let cert = sign_intermediate(&root, &csr, now).unwrap();
    let chain = check_chain(&format!("{cert}{}", root.cert_pem), now).unwrap();
    assert!(chain.middle.is_empty());
    assert_eq!(chain.path, ["OpenVIBES Root CA"]);
    check_key(&chain, &key, &[], now).unwrap();
}

#[test]
fn common_name_names_the_first_certificate() {
    assert_eq!(
        common_name(&format!("{OURS_EC}{ROOT}")).unwrap(),
        "Lime Lab OpenVIBES CA"
    );
    assert_eq!(common_name(""), Err(PkiError::InvalidPem));
}
