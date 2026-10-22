//! The built-in hierarchy: offline root, intermediate, server certificates.

use chrono::Utc;
use platform_pki::{
    Issuer, KeyAndCert, PkiError, generate_root, intermediate_request, sign_intermediate,
    verify_signed_by,
};

fn hierarchy() -> (KeyAndCert, Issuer) {
    let now = Utc::now();
    let root = generate_root(now).unwrap();
    let (csr, key) = intermediate_request().unwrap();
    let cert = sign_intermediate(&root, &csr, now).unwrap();
    (root, Issuer::load(&cert, &key).unwrap())
}

#[test]
fn root_signs_intermediate_signs_server() {
    let (root, intermediate) = hierarchy();
    verify_signed_by(intermediate.cert_pem(), &root.cert_pem).unwrap();
    let server = intermediate
        .issue_server(&["ingest.example".into()], Utc::now())
        .unwrap();
    verify_signed_by(&server.cert_pem, intermediate.cert_pem()).unwrap();
    assert_eq!(
        verify_signed_by(&server.cert_pem, &root.cert_pem),
        Err(PkiError::NotSignedBy)
    );
}

#[test]
fn lifetimes_and_constraints_follow_the_spec() {
    let (root, intermediate) = hierarchy();
    let parse = |pem: &str| {
        let der = x509_parser::pem::parse_x509_pem(pem.as_bytes())
            .unwrap()
            .1
            .contents;
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        let days = (cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp())
            / 86_400;
        let constraints = cert
            .basic_constraints()
            .unwrap()
            .map(|c| (c.value.ca, c.value.path_len_constraint));
        (days, constraints)
    };
    assert_eq!(parse(&root.cert_pem), (3652, Some((true, Some(1)))));
    assert_eq!(parse(intermediate.cert_pem()), (730, Some((true, Some(0)))));
    let server = intermediate
        .issue_server(&["ingest.example".into()], Utc::now())
        .unwrap();
    assert_eq!(parse(&server.cert_pem).0, 90);
}

#[test]
fn a_mismatched_key_or_a_non_ca_certificate_cannot_issue() {
    let (root, intermediate) = hierarchy();
    let (_, other_key) = intermediate_request().unwrap();
    assert_eq!(
        Issuer::load(intermediate.cert_pem(), &other_key).err(),
        Some(PkiError::KeyMismatch)
    );
    let server = intermediate
        .issue_server(&["x.example".into()], Utc::now())
        .unwrap();
    assert_eq!(
        Issuer::load(&server.cert_pem, &server.key_pem).err(),
        Some(PkiError::NotCa)
    );
    assert_eq!(
        Issuer::load("garbage", &root.key_pem).err(),
        Some(PkiError::InvalidPem)
    );
}

#[test]
fn only_a_current_intermediate_of_that_root_imports() {
    let now = Utc::now();
    let (root, intermediate) = hierarchy();
    platform_pki::check_intermediate(intermediate.cert_pem(), &root.cert_pem, now).unwrap();
    assert_eq!(
        platform_pki::check_intermediate(&root.cert_pem, &root.cert_pem, now),
        Err(PkiError::NotIntermediate),
        "the root is not its own intermediate"
    );
    let server = intermediate
        .issue_server(&["ingest.example".into()], now)
        .unwrap();
    assert_eq!(
        platform_pki::check_intermediate(&server.cert_pem, intermediate.cert_pem(), now),
        Err(PkiError::NotIntermediate),
        "a leaf is not an intermediate"
    );
    let (other_root, _) = hierarchy();
    assert_eq!(
        platform_pki::check_intermediate(intermediate.cert_pem(), &other_root.cert_pem, now),
        Err(PkiError::NotSignedBy)
    );
    let later = now + chrono::Duration::days(3 * 365);
    assert_eq!(
        platform_pki::check_intermediate(intermediate.cert_pem(), &root.cert_pem, later),
        Err(PkiError::IssuerExpired)
    );
}

#[test]
fn the_root_key_must_match_the_root_certificate() {
    let now = Utc::now();
    let root = generate_root(now).unwrap();
    let other = generate_root(now).unwrap();
    let mixed = KeyAndCert {
        cert_pem: root.cert_pem.clone(),
        key_pem: other.key_pem.clone(),
    };
    let (csr, _) = intermediate_request().unwrap();
    assert_eq!(
        sign_intermediate(&mixed, &csr, now).map(drop),
        Err(PkiError::KeyMismatch)
    );
}

#[test]
fn an_intermediate_never_outlives_its_root() {
    let issued = Utc::now();
    let root = generate_root(issued).unwrap();
    let (csr, _) = intermediate_request().unwrap();
    // Signed in the root's last year: 2 years would run past the root.
    let late = issued + chrono::Duration::days(9 * 365);
    let cert = sign_intermediate(&root, &csr, late).unwrap();
    assert!(
        platform_pki::not_after(&cert).unwrap() <= platform_pki::not_after(&root.cert_pem).unwrap()
    );
    let after_root = issued + chrono::Duration::days(11 * 365);
    assert_eq!(
        sign_intermediate(&root, &csr, after_root).map(drop),
        Err(PkiError::IssuerExpired)
    );
}

#[test]
fn issuer_common_name_reads_the_signer() {
    let now = Utc::now();
    let root = generate_root(now).unwrap();
    let (csr, _) = intermediate_request().unwrap();
    let cert = sign_intermediate(&root, &csr, now).unwrap();
    assert_eq!(
        platform_pki::issuer_common_name(&cert).unwrap().as_deref(),
        Some("OpenVIBES Root CA")
    );
    assert_eq!(
        platform_pki::issuer_common_name("nope"),
        Err(PkiError::InvalidPem)
    );
}

/// A root, a request and the root's signature of it.
fn signed_request() -> (KeyAndCert, String, String) {
    let now = Utc::now();
    let root = generate_root(now).unwrap();
    let (csr, _) = intermediate_request().unwrap();
    let cert = sign_intermediate(&root, &csr, now).unwrap();
    (root, csr, cert)
}

#[test]
fn signed_request_matches_its_csr() {
    let (root, csr, cert) = signed_request();
    let signed = platform_pki::check_signed_request(&csr, &cert, Utc::now()).unwrap();
    assert_eq!(signed.subject, "OpenVIBES Intermediate CA");
    assert_eq!(signed.issuer, "OpenVIBES Root CA");
    assert_eq!(
        signed.not_after,
        platform_pki::not_after(&cert)
            .unwrap()
            .format("%Y-%m-%d")
            .to_string()
    );
    assert_eq!(
        platform_pki::check_root_signed(&root.cert_pem, &cert, Utc::now()).as_deref(),
        Ok("OpenVIBES Root CA")
    );
}

#[test]
fn certificate_for_another_request_is_refused() {
    let (_, _, cert) = signed_request();
    let (other_csr, _) = intermediate_request().unwrap();
    assert_eq!(
        platform_pki::check_signed_request(&other_csr, &cert, Utc::now()).err(),
        Some(PkiError::NotForRequest)
    );
}

#[test]
fn end_entity_certificate_is_refused() {
    let (_, csr, _) = signed_request();
    let (_, intermediate) = hierarchy();
    let server = intermediate
        .issue_server(&["x.example".into()], Utc::now())
        .unwrap();
    // The leaf alone, without the intermediate after it.
    let leaf = server
        .cert_pem
        .split_inclusive("-----END CERTIFICATE-----\n")
        .next()
        .unwrap();
    assert_eq!(
        platform_pki::check_signed_request(&csr, leaf, Utc::now()).err(),
        Some(PkiError::NotCa)
    );
}

#[test]
fn expired_certificate_is_refused() {
    let (_, csr, cert) = signed_request();
    let later = Utc::now() + chrono::Duration::days(3 * 365);
    assert_eq!(
        platform_pki::check_signed_request(&csr, &cert, later).err(),
        Some(PkiError::IssuerExpired)
    );
}

#[test]
fn wrong_root_is_refused() {
    let (root, _, cert) = signed_request();
    let other = generate_root(Utc::now()).unwrap();
    let now = Utc::now();
    assert_eq!(
        platform_pki::check_root_signed(&other.cert_pem, &cert, now).err(),
        Some(PkiError::NotSignedBy)
    );
    // The intermediate itself is no root.
    assert_eq!(
        platform_pki::check_root_signed(&cert, &cert, now).err(),
        Some(PkiError::NotRoot)
    );
    let later = now + chrono::Duration::days(11 * 365);
    assert_eq!(
        platform_pki::check_root_signed(&root.cert_pem, &cert, later).err(),
        Some(PkiError::IssuerExpired)
    );
}

#[test]
fn two_pem_blocks_are_refused() {
    let (root, csr, cert) = signed_request();
    let both = format!("{cert}{}", root.cert_pem);
    let now = Utc::now();
    assert_eq!(
        platform_pki::check_signed_request(&csr, &both, now).err(),
        Some(PkiError::Several(2))
    );
    assert_eq!(
        platform_pki::check_root_signed(&both, &cert, now).err(),
        Some(PkiError::Several(2))
    );
    assert_eq!(
        platform_pki::check_signed_request(&csr, "no certificate", now).err(),
        Some(PkiError::InvalidPem)
    );
}

#[test]
fn a_root_with_path_length_0_is_refused() {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
    let now = Utc::now();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "Tight Root");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root = KeyAndCert {
        cert_pem: params.self_signed(&key).unwrap().pem(),
        key_pem: key.serialize_pem(),
    };
    let (csr, _) = intermediate_request().unwrap();
    let cert = sign_intermediate(&root, &csr, now).unwrap();
    assert_eq!(
        platform_pki::check_root_signed(&root.cert_pem, &cert, now).err(),
        Some(PkiError::RootPathLen0)
    );
}
