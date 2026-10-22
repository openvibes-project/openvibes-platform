//! The CA request before install (sub-project 3) on a temp root.

use std::os::unix::fs::PermissionsExt;

use platform_host::{Step, StepState};

use super::{REQUEST_DIR, RequestState, accept, output, request};
use crate::setup::{
    fake::{Fake, plan},
    pki_tests::{ADMIN, ca_commands, with},
    plan::{CaMode, Component::Ingest},
    run_step,
};

fn mode(fake: &Fake, abs: &str) -> u32 {
    std::fs::metadata(fake.root.join(abs.trim_start_matches('/')))
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

fn csr_of(state: RequestState) -> String {
    match state {
        RequestState::Request { csr } | RequestState::Signed { csr, .. } => csr,
    }
}

/// A root and its signature of the stored request.
fn signed(fake: &Fake) -> (String, String) {
    let root = platform_pki::generate_root(chrono::Utc::now()).unwrap();
    let csr = fake.text(&format!("{REQUEST_DIR}/intermediate.csr"));
    let cert = platform_pki::sign_intermediate(&root, &csr, chrono::Utc::now()).unwrap();
    (cert, root.cert_pem)
}

#[test]
fn request_is_reused() {
    let fake = Fake::new("request-reused");
    let plan = plan(&[Ingest]);
    let first = request(&fake.ctx(&plan), None).unwrap();
    assert!(matches!(first, RequestState::Request { .. }), "{first:?}");
    let key = fake.text(&format!("{REQUEST_DIR}/intermediate.key"));
    let csr = csr_of(first);
    assert!(csr.contains("BEGIN CERTIFICATE REQUEST"), "{csr}");
    assert_eq!(csr_of(request(&fake.ctx(&plan), None).unwrap()), csr);
    assert_eq!(fake.text(&format!("{REQUEST_DIR}/intermediate.key")), key);
    assert_eq!(fake.text(&format!("{REQUEST_DIR}/intermediate.csr")), csr);
    assert_eq!(mode(&fake, REQUEST_DIR), 0o700);
    assert_eq!(
        mode(&fake, &format!("{REQUEST_DIR}/intermediate.key")),
        0o600
    );
}

#[test]
fn request_copy_is_written_once() {
    let fake = Fake::new("request-copy");
    std::fs::create_dir_all(fake.root.join("home/alice")).unwrap();
    let plan = plan(&[Ingest]);
    let copy = std::path::Path::new("/home/alice/openvibes-request.csr");
    let csr = csr_of(request(&fake.ctx(&plan), Some(copy)).unwrap());
    assert_eq!(fake.text("/home/alice/openvibes-request.csr"), csr);
    assert_eq!(mode(&fake, "/home/alice/openvibes-request.csr"), 0o644);
    fake.file(
        "/home/alice/openvibes-request.csr",
        "the operator's own file",
    );
    request(&fake.ctx(&plan), Some(copy)).unwrap();
    assert_eq!(
        fake.text("/home/alice/openvibes-request.csr"),
        "the operator's own file"
    );
    assert!(
        request(&fake.ctx(&plan), Some(std::path::Path::new("relative.csr"))).is_err(),
        "only an absolute path"
    );
}

#[test]
fn accept_writes_both_and_state_is_signed() {
    let fake = Fake::new("request-accept");
    let plan = plan(&[Ingest]);
    let csr = csr_of(request(&fake.ctx(&plan), None).unwrap());
    let (cert, root) = signed(&fake);
    let accepted = accept(&fake.ctx(&plan), &cert, &root).unwrap();
    assert_eq!(accepted.issuer, "OpenVIBES Root CA");
    assert_eq!(fake.text(&format!("{REQUEST_DIR}/intermediate.crt")), cert);
    assert_eq!(fake.text(&format!("{REQUEST_DIR}/root.crt")), root);
    let state = request(&fake.ctx(&plan), None).unwrap();
    assert_eq!(
        state,
        RequestState::Signed {
            csr,
            issuer: "OpenVIBES Root CA".into()
        }
    );
}

#[test]
fn accept_refuses_other_request_and_writes_nothing() {
    let fake = Fake::new("request-other");
    let plan = plan(&[Ingest]);
    request(&fake.ctx(&plan), None).unwrap();
    let root = platform_pki::generate_root(chrono::Utc::now()).unwrap();
    let (other, _) = platform_pki::intermediate_request().unwrap();
    let cert = platform_pki::sign_intermediate(&root, &other, chrono::Utc::now()).unwrap();
    let error = accept(&fake.ctx(&plan), &cert, &root.cert_pem).unwrap_err();
    assert_eq!(
        error,
        "This certificate was signed for a different request: sign the request shown here."
    );
    let (cert, _) = signed(&fake);
    let wrong = platform_pki::generate_root(chrono::Utc::now()).unwrap();
    let error = accept(&fake.ctx(&plan), &cert, &wrong.cert_pem).unwrap_err();
    assert!(error.contains("add your root CA's certificate"), "{error}");
    let both = format!("{cert}{}", root.cert_pem);
    assert_eq!(
        accept(&fake.ctx(&plan), &both, &root.cert_pem).unwrap_err(),
        "That is 2 certificates: paste only the one signed for OpenVIBES."
    );
    for file in ["intermediate.crt", "root.crt"] {
        assert!(!fake.root.join(&REQUEST_DIR[1..]).join(file).exists());
    }
}

#[test]
fn careful_installs_from_request_dir_and_removes_it() {
    let fake = Fake::new("request-careful");
    ca_commands(&fake);
    let mut plan = plan(&[Ingest]);
    plan.ca = CaMode::Careful;
    request(&fake.ctx(&plan), None).unwrap();
    let key = fake.text(&format!("{REQUEST_DIR}/intermediate.key"));
    let (cert, root) = signed(&fake);
    accept(&fake.ctx(&plan), &cert, &root).unwrap();
    let state = run_step(&fake.ctx(&plan), Step::Ca);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    let import = fake.call(&with(&ADMIN, &["ca", "import-intermediate"]));
    assert!(
        import.contains(&"/run/openvibes-ca/int/intermediate.key".to_owned()),
        "{import:?}"
    );
    assert!(!fake.called(&with(&ADMIN, &["ca", "intermediate-request"])));
    assert_eq!(fake.text("/etc/openvibes/pki/intermediate.crt"), cert);
    assert_eq!(fake.text("/etc/openvibes/pki/root.crt"), root);
    assert_eq!(fake.text("/var/lib/openvibes-ingest/intermediate.key"), key);
    assert!(
        !fake.root.join(&REQUEST_DIR[1..]).exists(),
        "request removed"
    );
    assert!(
        !fake.root.join("run/openvibes-ca").exists(),
        "staging removed"
    );
}

#[test]
fn quick_removes_a_leftover_request_dir() {
    let fake = Fake::new("request-quick");
    ca_commands(&fake);
    let plan = plan(&[Ingest]);
    request(&fake.ctx(&plan), None).unwrap();
    let state = run_step(&fake.ctx(&plan), Step::Ca);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(!fake.root.join(&REQUEST_DIR[1..]).exists());
}

#[test]
fn output_names_the_state_then_the_request() {
    let csr = "-----BEGIN CERTIFICATE REQUEST-----\n…\n".to_owned();
    assert_eq!(
        output(&RequestState::Request { csr: csr.clone() }),
        format!("request\n{csr}")
    );
    let signed = RequestState::Signed {
        csr: csr.clone(),
        issuer: "Example Root".into(),
    };
    assert_eq!(output(&signed), format!("signed\tExample Root\n{csr}"));
}
