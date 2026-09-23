//! Agent CSR checks and client certificate issuing (consumed by ingest).

use chrono::{Duration, Utc};
use platform_pki::{
    Issuer, PkiError, check_csr, generate_root, intermediate_request, sign_intermediate,
    spki_sha256_of_cert, verify_signed_by,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PublicKeyData};
use x509_parser::extensions::GeneralName;

const AGENT: &str = "agent.00000000-0000-4000-8000-000000000001";

fn intermediate() -> Issuer {
    let now = Utc::now();
    let root = generate_root(now).unwrap();
    let (csr, key) = intermediate_request().unwrap();
    Issuer::load(&sign_intermediate(&root, &csr, now).unwrap(), &key).unwrap()
}

fn csr(key: &KeyPair, subject: Option<&str>) -> String {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    if let Some(name) = subject {
        params.distinguished_name.push(DnType::CommonName, name);
    }
    params.serialize_request(key).unwrap().pem().unwrap()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .try_into()
        .unwrap()
}

#[test]
fn only_empty_subject_p256_csrs_with_valid_signatures_pass() {
    let key = KeyPair::generate().unwrap();
    let good = check_csr(&csr(&key, None)).unwrap();
    assert_eq!(good.spki_sha256, sha256(&key.subject_public_key_info()));

    assert_eq!(
        check_csr(&csr(&key, Some("evil"))).err(),
        Some(PkiError::NonEmptySubject)
    );
    let p384 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    assert_eq!(
        check_csr(&csr(&p384, None)).err(),
        Some(PkiError::UnsupportedKey)
    );
    // Corrupt one base64 character in the last body line (the signature).
    let pem = csr(&key, None);
    let mut lines: Vec<String> = pem.lines().map(str::to_owned).collect();
    let last_body = lines.len() - 2;
    let middle = lines[last_body].len() / 2;
    let swapped = if &lines[last_body][middle..=middle] == "A" {
        "B"
    } else {
        "A"
    };
    lines[last_body].replace_range(middle..=middle, swapped);
    assert_eq!(
        check_csr(&lines.join("\n")).err(),
        Some(PkiError::InvalidCsr)
    );
    assert_eq!(check_csr("not a csr").err(), Some(PkiError::InvalidCsr));
    assert_eq!(
        check_csr(&"x".repeat(1024 * 1024 + 1)).err(),
        Some(PkiError::InvalidCsr)
    );
}

#[test]
fn client_certificates_follow_the_profile() {
    let issuer = intermediate();
    let key = KeyPair::generate().unwrap();
    let checked = check_csr(&csr(&key, None)).unwrap();
    let now = Utc::now();
    let issued = issuer.issue_client(&checked, AGENT, now, 30).unwrap();
    assert_eq!(issued.chain_pem.len(), 2);
    assert_eq!(issued.chain_pem[1], issuer.cert_pem());
    let leaf = &issued.chain_pem[0];
    verify_signed_by(leaf, issuer.cert_pem()).unwrap();
    assert_eq!(spki_sha256_of_cert(leaf).unwrap(), checked.spki_sha256);
    assert_eq!(issued.spki_sha256, checked.spki_sha256);
    assert_eq!(issued.not_after - issued.not_before, Duration::days(30));

    let der = x509_parser::pem::parse_x509_pem(leaf.as_bytes())
        .unwrap()
        .1
        .contents;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    assert_eq!(cert.subject().iter().count(), 0, "subject must be empty");
    let san = cert.subject_alternative_name().unwrap().unwrap();
    let names: Vec<_> = san.value.general_names.iter().collect();
    assert_eq!(
        names,
        [&GeneralName::URI(
            "openvibes:agent:agent.00000000-0000-4000-8000-000000000001"
        )]
    );
    let eku = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.client_auth && !eku.server_auth);
    let is_ca = cert
        .basic_constraints()
        .unwrap()
        .is_some_and(|constraints| constraints.value.ca);
    assert!(!is_ca);
    assert_eq!(cert.raw_serial().len(), 16);
    assert_eq!(cert.raw_serial()[0] & 0x80, 0);
    assert_eq!(cert.raw_serial(), issued.serial);

    let again = issuer.issue_client(&checked, AGENT, now, 30).unwrap();
    assert_ne!(again.serial, issued.serial);
}
