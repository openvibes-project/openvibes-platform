//! The CA request before install (sub-project 3) on a temp root.

use std::os::unix::fs::PermissionsExt;

use platform_host::{Step, StepState};

use super::{REQUEST_DIR, RequestState, accept, output, request, save_copy};
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
    let first = request(&fake.ctx(&plan)).unwrap();
    assert!(matches!(first, RequestState::Request { .. }), "{first:?}");
    let key = fake.text(&format!("{REQUEST_DIR}/intermediate.key"));
    let csr = csr_of(first);
    assert!(csr.contains("BEGIN CERTIFICATE REQUEST"), "{csr}");
    assert_eq!(csr_of(request(&fake.ctx(&plan)).unwrap()), csr);
    assert_eq!(fake.text(&format!("{REQUEST_DIR}/intermediate.key")), key);
    assert_eq!(fake.text(&format!("{REQUEST_DIR}/intermediate.csr")), csr);
    assert_eq!(mode(&fake, REQUEST_DIR), 0o700);
    assert_eq!(
        mode(&fake, &format!("{REQUEST_DIR}/intermediate.key")),
        0o600
    );
}

#[test]
fn a_reused_request_dir_is_tightened_again() {
    let fake = Fake::new("request-tighten");
    let plan = plan(&[Ingest]);
    request(&fake.ctx(&plan)).unwrap();
    let dir = fake.root.join(&REQUEST_DIR[1..]);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    request(&fake.ctx(&plan)).unwrap();
    assert_eq!(mode(&fake, REQUEST_DIR), 0o700);
}

#[test]
fn the_copy_is_reused_or_written_beside_another_file() {
    let fake = Fake::new("request-copy");
    std::fs::create_dir_all(fake.root.join("home/alice")).unwrap();
    let plan = plan(&[Ingest]);
    let ctx = fake.ctx(&plan);
    let csr = csr_of(request(&ctx).unwrap());
    let base = std::path::Path::new("/home/alice/openvibes-request.csr");
    let copy = save_copy(&ctx, base, &csr).unwrap();
    assert_eq!(copy, "/home/alice/openvibes-request.csr");
    assert_eq!(fake.text(&copy), csr);
    assert_eq!(mode(&fake, &copy), 0o644);
    // The same request again (a new session): the same file, nothing new.
    assert_eq!(save_copy(&ctx, base, &csr).unwrap(), copy);
    assert!(
        !fake
            .root
            .join("home/alice/openvibes-request-2.csr")
            .exists()
    );
    // The operator's own file there: kept, the copy goes beside it.
    fake.file(&copy, "the operator's own file");
    let beside = save_copy(&ctx, base, &csr).unwrap();
    assert_eq!(beside, "/home/alice/openvibes-request-2.csr");
    assert_eq!(fake.text(&beside), csr);
    assert_eq!(fake.text(&copy), "the operator's own file");
    assert_eq!(save_copy(&ctx, base, &csr).unwrap(), beside);
    assert!(
        save_copy(&ctx, std::path::Path::new("relative.csr"), &csr).is_err(),
        "only an absolute path"
    );
}

#[test]
fn every_copy_name_taken_is_refused() {
    let fake = Fake::new("request-copy-full");
    let plan = plan(&[Ingest]);
    fake.file("/h/r.csr", "taken");
    for n in 2..=100 {
        fake.file(&format!("/h/r-{n}.csr"), "taken");
    }
    assert_eq!(
        save_copy(&fake.ctx(&plan), std::path::Path::new("/h/r.csr"), "CSR").unwrap_err(),
        "That file already exists: /h/r.csr. Choose another name."
    );
}

#[test]
fn accept_writes_both_and_state_is_signed() {
    let fake = Fake::new("request-accept");
    let plan = plan(&[Ingest]);
    let csr = csr_of(request(&fake.ctx(&plan)).unwrap());
    let (cert, root) = signed(&fake);
    let accepted = accept(&fake.ctx(&plan), &cert, &root).unwrap();
    assert_eq!(accepted.issuer, "OpenVIBES Root CA");
    assert_eq!(fake.text(&format!("{REQUEST_DIR}/intermediate.crt")), cert);
    assert_eq!(fake.text(&format!("{REQUEST_DIR}/root.crt")), root);
    let state = request(&fake.ctx(&plan)).unwrap();
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
    request(&fake.ctx(&plan)).unwrap();
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
    assert_eq!(
        error,
        "Your CA's certificate must be the root that signed this certificate directly: \
         paste that root, not another CA."
    );
    // The certificate itself as the root: not self-signed.
    assert_eq!(
        accept(&fake.ctx(&plan), &cert, &cert).unwrap_err(),
        "This is not a root CA (self-signed): OpenVIBES needs the root that signed the \
         request directly, with no CA in between."
    );
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
    request(&fake.ctx(&plan)).unwrap();
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
    request(&fake.ctx(&plan)).unwrap();
    let state = run_step(&fake.ctx(&plan), Step::Ca);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(!fake.root.join(&REQUEST_DIR[1..]).exists());
}

#[test]
fn output_names_the_state_the_copy_then_the_request() {
    let csr = "-----BEGIN CERTIFICATE REQUEST-----\n…\n".to_owned();
    assert_eq!(
        output(&RequestState::Request { csr: csr.clone() }, None),
        format!("request\n{csr}")
    );
    let signed = RequestState::Signed {
        csr: csr.clone(),
        issuer: "Example Root".into(),
    };
    assert_eq!(
        output(&signed, Some("/home/a/r-2.csr")),
        format!("signed\tExample Root\ncopy\t/home/a/r-2.csr\n{csr}")
    );
}

#[test]
fn a_root_with_path_length_0_has_its_own_sentence() {
    assert_eq!(
        super::message(&platform_pki::PkiError::RootPathLen0),
        "Your CA's certificate does not allow it to sign another CA (path length 0): it \
         cannot sign the intermediate."
    );
}
