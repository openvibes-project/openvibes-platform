//! The throwaway leaf of `check_key`, verified as agents verify a server
//! certificate (rustls-webpki, ServerAuth) up to the root.

use chrono::{DateTime, TimeZone, Utc};
use platform_pki::{Chain, ChainError, ServerLimit, check_chain, check_key};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, GeneralSubtree, IsCa, Issuer, KeyPair,
    NameConstraints,
};

const ROOT: &str = include_str!("fixtures/root.crt");
const ISSUING: &str = include_str!("fixtures/issuing.crt");
const OURS_EC: &str = include_str!("fixtures/ours-ec.crt");
const OURS_EC_KEY: &str = include_str!("fixtures/ours-ec.pkcs8.pem");
const CLIENT_ONLY: &str = include_str!("fixtures/client-only.crt");
const CLIENT_ONLY_KEY: &str = include_str!("fixtures/client-only.key");
const ANY_USAGE: &str = include_str!("fixtures/any-usage.crt");
const ANY_USAGE_KEY: &str = include_str!("fixtures/any-usage.key");

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 6, 1, 0, 0, 0).unwrap()
}

#[test]
fn a_ca_for_client_certificates_only_is_refused_with_its_chain() {
    let refused = Err(ChainError::NotForServers(
        "Lime Lab Client Only CA".into(),
        ServerLimit::KeyUsage,
    ));
    assert_eq!(check_chain(&format!("{CLIENT_ONLY}{ROOT}"), now()), refused);
}

/// Agents (rustls-webpki) do not read anyExtendedKeyUsage as serverAuth:
/// such a CA is refused at once, as the self-check refuses it.
#[test]
fn any_extended_key_usage_alone_is_refused_as_agents_refuse_it() {
    let refused = ChainError::NotForServers("Lime Lab Any Usage CA".into(), ServerLimit::KeyUsage);
    assert_eq!(
        check_chain(&format!("{ANY_USAGE}{ROOT}"), now()),
        Err(refused.clone())
    );
    let chain = Chain {
        ours: ANY_USAGE.into(),
        middle: Vec::new(),
        root: ROOT.into(),
        name: "Lime Lab Any Usage CA".into(),
        path: vec!["Lime Lab Root CA".into()],
        not_after: platform_pki::not_after(ANY_USAGE).unwrap(),
    };
    assert_eq!(check_key(&chain, ANY_USAGE_KEY, &[], now()), Err(refused));
}

#[test]
fn the_self_check_refuses_it_too() {
    // The chain as check_chain would have built it without its own check.
    let chain = Chain {
        ours: CLIENT_ONLY.into(),
        middle: Vec::new(),
        root: ROOT.into(),
        name: "Lime Lab Client Only CA".into(),
        path: vec!["Lime Lab Root CA".into()],
        not_after: platform_pki::not_after(CLIENT_ONLY).unwrap(),
    };
    assert_eq!(
        check_key(&chain, CLIENT_ONLY_KEY, &[], now()),
        Err(ChainError::NotForServers(
            "Lime Lab Client Only CA".into(),
            ServerLimit::KeyUsage
        ))
    );
}

#[test]
fn the_fixture_chain_passes_with_names() {
    let chain = check_chain(&format!("{OURS_EC}{ISSUING}{ROOT}"), now()).unwrap();
    let names = ["limebox.lan".to_owned(), "10.0.0.5".to_owned()];
    check_key(&chain, OURS_EC_KEY, &names, now()).unwrap();
}

fn ca(name: &str, constraints: Option<NameConstraints>) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.name_constraints = constraints;
    params
}

/// A root, a middle CA limited to `example.org`, and ours under it, with
/// ours' key.
fn constrained() -> (String, String) {
    let root_key = KeyPair::generate().unwrap();
    let root_params = ca("NC Root", None);
    let root = root_params.self_signed(&root_key).unwrap();
    let middle_key = KeyPair::generate().unwrap();
    let only = NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName("example.org".into())],
        excluded_subtrees: vec![],
    };
    let middle_params = ca("NC Middle", Some(only));
    let middle = middle_params
        .signed_by(&middle_key, &Issuer::from_params(&root_params, &root_key))
        .unwrap();
    let ours_key = KeyPair::generate().unwrap();
    let ours = ca("NC Ours", None)
        .signed_by(&ours_key, &Issuer::from_params(&middle_params, &middle_key))
        .unwrap();
    let pem = format!("{}{}{}", ours.pem(), middle.pem(), root.pem());
    (pem, ours_key.serialize_pem())
}

#[test]
fn name_constraints_name_the_ca_that_sets_them() {
    let (pem, key) = constrained();
    let now = Utc::now();
    let chain = check_chain(&pem, now).unwrap();
    assert_eq!(
        check_key(&chain, &key, &["limebox.lan".into()], now),
        Err(ChainError::NotForServers(
            "NC Middle".into(),
            ServerLimit::NameConstraints
        ))
    );
    check_key(&chain, &key, &["host.example.org".into()], now).unwrap();
    // Without the host's names there is nothing to check them against.
    check_key(&chain, &key, &[], now).unwrap();
}
