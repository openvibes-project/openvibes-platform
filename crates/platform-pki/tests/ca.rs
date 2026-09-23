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
