//! "Your CA signs our request" through a sub-CA (sub-project 4b): the CAs
//! between the root and our intermediate go in `chain.crt`, at accept,
//! install and Replace. The platform-pki fixtures' issuing CA signs.

use chrono::Utc;
use platform_host::{Step, StepState};
use platform_pki::KeyAndCert;

use super::{REQUEST_DIR, accept, request};
use crate::setup::{
    fake::{Fake, plan},
    pki::{INTERMEDIATE, INTERMEDIATE_KEY, ROOT_CERT},
    pki_import::CHAIN,
    pki_tests::{ADMIN, ca_commands, issuing, with},
    plan::{CaMode, Component::*, Plan},
    replace::replace,
    run_step,
};

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!("../../../platform-pki/tests/fixtures/", $name))
    };
}
const ROOT: &str = fixture!("root.crt");
const ISSUING: &str = fixture!("issuing.crt");
const ISSUING_KEY: &str = fixture!("issuing.key");

fn careful() -> Plan {
    Plan {
        ca: CaMode::Careful,
        ..plan(&[Ingest])
    }
}

fn der(pem: &str) -> Vec<Vec<u8>> {
    platform_pki::certificates(pem).unwrap()
}

fn exists(fake: &Fake, abs: &str) -> bool {
    fake.root.join(abs.trim_start_matches('/')).exists()
}

/// The stored request signed by the fixtures' issuing CA, as an
/// intermediate with path length 0.
fn signed_by_issuing(fake: &Fake) -> String {
    let issuing = KeyAndCert {
        cert_pem: ISSUING.into(),
        key_pem: ISSUING_KEY.into(),
    };
    let csr = fake.text(&format!("{REQUEST_DIR}/intermediate.csr"));
    platform_pki::sign_intermediate(&issuing, &csr, Utc::now()).unwrap()
}

#[test]
fn accept_takes_a_sub_ca_chain() {
    let fake = Fake::new("request-chain-accept");
    let plan = careful();
    request(&fake.ctx(&plan)).unwrap();
    let cert = signed_by_issuing(&fake);
    // The CA that signed us, then the root; any order is fine.
    let accepted = accept(&fake.ctx(&plan), &cert, &format!("{ROOT}{ISSUING}")).unwrap();
    assert_eq!(accepted.issuer, "Lime Lab Issuing CA");
    assert_eq!(
        der(&fake.text(&format!("{REQUEST_DIR}/root.crt"))),
        der(ROOT)
    );
    assert_eq!(
        der(&fake.text(&format!("{REQUEST_DIR}/chain.crt"))),
        der(ISSUING)
    );
    // Signed again by the root directly: no chain.crt is left.
    let root = KeyAndCert {
        cert_pem: ROOT.into(),
        key_pem: fixture!("root.key").into(),
    };
    let csr = fake.text(&format!("{REQUEST_DIR}/intermediate.csr"));
    let direct = platform_pki::sign_intermediate(&root, &csr, Utc::now()).unwrap();
    accept(&fake.ctx(&plan), &direct, ROOT).unwrap();
    assert!(!exists(&fake, &format!("{REQUEST_DIR}/chain.crt")));
}

#[test]
fn accept_still_refuses_a_gap() {
    let fake = Fake::new("request-chain-gap");
    let plan = careful();
    request(&fake.ctx(&plan)).unwrap();
    let cert = signed_by_issuing(&fake);
    assert_eq!(
        accept(&fake.ctx(&plan), &cert, ROOT).unwrap_err(),
        "Signed by Lime Lab Issuing CA, missing here: paste it below this one."
    );
    assert_eq!(
        accept(&fake.ctx(&plan), &cert, ISSUING).unwrap_err(),
        "Signed by Lime Lab Root CA, missing here: paste it below this one."
    );
    for file in ["intermediate.crt", "root.crt", "chain.crt"] {
        assert!(!exists(&fake, &format!("{REQUEST_DIR}/{file}")), "{file}");
    }
}

#[test]
fn install_from_request_writes_chain() {
    let fake = Fake::new("request-chain-install");
    ca_commands(&fake);
    let plan = careful();
    request(&fake.ctx(&plan)).unwrap();
    let cert = signed_by_issuing(&fake);
    accept(&fake.ctx(&plan), &cert, &format!("{ISSUING}{ROOT}")).unwrap();
    let state = run_step(&fake.ctx(&plan), Step::Ca);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    let call = fake.call(&with(&ADMIN, &["ca", "import-intermediate"]));
    assert_eq!(
        call[call.len() - 2..],
        ["--chain", "/run/openvibes-ca/int/chain.crt"]
    );
    assert_eq!(fake.text(INTERMEDIATE), cert);
    assert_eq!(der(&fake.text(ROOT_CERT)), der(ROOT));
    assert_eq!(der(&fake.text(CHAIN)), der(ISSUING));
    assert!(!exists(&fake, REQUEST_DIR));
}

#[test]
fn own_ca_replace_compares_roots_not_parents() {
    let fake = issuing("request-chain-replace");
    let plan = careful();
    request(&fake.ctx(&plan)).unwrap();
    let old = signed_by_issuing(&fake);
    let old_key = fake.text(&format!("{REQUEST_DIR}/intermediate.key"));
    std::fs::remove_dir_all(fake.root.join(&REQUEST_DIR[1..])).unwrap();
    // Installed as openssl writes it: CRLF, so only the DER is the same.
    fake.file(ROOT_CERT, &ROOT.replace('\n', "\r\n"));
    fake.file(INTERMEDIATE, &old);
    fake.file(INTERMEDIATE_KEY, &old_key);
    fake.file(CHAIN, ISSUING);
    fake.answer(&with(&ADMIN, &["ca", "import-intermediate"]), 0, "");
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");

    request(&fake.ctx(&plan)).unwrap();
    let new = signed_by_issuing(&fake);
    accept(&fake.ctx(&plan), &new, &format!("{ISSUING}{ROOT}")).unwrap();
    replace(&fake.ctx(&plan), None).unwrap();
    let bundle = der(&fake.text(INTERMEDIATE));
    assert_eq!(bundle, [der(&new), der(&old)].concat());
    assert_eq!(der(&fake.text(CHAIN)), der(ISSUING), "the chain follows");
    let call = fake.call(&with(&ADMIN, &["ca", "import-intermediate"]));
    assert_eq!(
        call[call.len() - 2..],
        ["--chain", "/run/openvibes-ca/int/chain.crt"]
    );
    assert!(!exists(&fake, REQUEST_DIR));
}

#[test]
fn own_ca_replace_under_the_root_directly_drops_the_chain() {
    let fake = issuing("request-chain-replace-direct");
    let plan = careful();
    request(&fake.ctx(&plan)).unwrap();
    let old = signed_by_issuing(&fake);
    let old_key = fake.text(&format!("{REQUEST_DIR}/intermediate.key"));
    std::fs::remove_dir_all(fake.root.join(&REQUEST_DIR[1..])).unwrap();
    fake.file(ROOT_CERT, ROOT);
    fake.file(INTERMEDIATE, &old);
    fake.file(INTERMEDIATE_KEY, &old_key);
    fake.file(CHAIN, ISSUING);
    fake.answer(&with(&ADMIN, &["ca", "import-intermediate"]), 0, "");
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");

    request(&fake.ctx(&plan)).unwrap();
    let root = KeyAndCert {
        cert_pem: ROOT.into(),
        key_pem: fixture!("root.key").into(),
    };
    let csr = fake.text(&format!("{REQUEST_DIR}/intermediate.csr"));
    let new = platform_pki::sign_intermediate(&root, &csr, Utc::now()).unwrap();
    accept(&fake.ctx(&plan), &new, ROOT).unwrap();
    replace(&fake.ctx(&plan), None).unwrap();
    assert!(
        !exists(&fake, CHAIN),
        "a stale chain would end every server certificate"
    );
}
