//! Enrollment token hashing (shared by admin and ingest) and agent ids.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use platform_pki::{
    Issuer, PkiError, check_csr, enrollment_token_sha256, generate_root, intermediate_request,
    is_agent_id, sign_intermediate,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};

#[test]
fn tokens_hash_as_their_decoded_bytes() {
    let bytes = [7u8; 32];
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let expected: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .try_into()
        .unwrap();
    assert_eq!(enrollment_token_sha256(&token), Some(expected));
    let padded = base64::engine::general_purpose::URL_SAFE.encode(bytes);
    let standard = base64::engine::general_purpose::STANDARD_NO_PAD.encode([0xfbu8; 32]);
    for bad in [
        padded.as_str(),
        &token[..42],
        &format!("{token}A"),
        standard.as_str(),
        &format!(" {token}"),
        &format!("{token}\n"),
        "",
    ] {
        assert_eq!(enrollment_token_sha256(bad), None, "{bad:?}");
    }
}

#[test]
fn agent_ids_are_agent_dot_lowercase_uuid() {
    assert!(is_agent_id("agent.00000000-0000-4000-8000-000000000001"));
    for bad in [
        "agent.00000000-0000-4000-8000-00000000000A",
        "00000000-0000-4000-8000-000000000001",
        "agent.a/b?c#d",
        &"a".repeat(1024),
        "agent.00000000-0000-4000-8000-0000000000011",
    ] {
        assert!(!is_agent_id(bad), "{bad:?}");
    }
}

#[test]
fn issue_client_refuses_a_malformed_agent_id() {
    let now = Utc::now();
    let root = generate_root(now).unwrap();
    let (request, key) = intermediate_request().unwrap();
    let issuer = Issuer::load(&sign_intermediate(&root, &request, now).unwrap(), &key).unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    let csr = params
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    let checked = check_csr(&csr).unwrap();
    assert_eq!(
        issuer
            .issue_client(&checked, "agent.a/b?c#d", now, 30)
            .err(),
        Some(PkiError::InvalidAgentId)
    );
}
