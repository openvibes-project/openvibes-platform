//! Step 3 with your own CA signing through a sub-CA (sub-project 4b):
//! "Your CA's certificate" takes the CA that signed us, then each CA
//! above it up to the root.

use platform_pki::KeyAndCert;

use super::{
    Which,
    certs_tests::{Pki, paste, pki, requested},
    steps_tests::{answer, calls},
};
use crate::tui::{
    app::Key,
    script_host::{screen, type_text},
};

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!("../../../../platform-pki/tests/fixtures/", $name))
    };
}
const ROOT: &str = fixture!("root.crt");
const ISSUING: &str = fixture!("issuing.crt");

const NOTE: &str = "Your CA's certificate, then each CA above it up to the root.";

/// A request signed by the fixtures' issuing CA, under its root.
fn sub_ca() -> Pki {
    let (csr, _key) = platform_pki::intermediate_request().unwrap();
    let issuing = KeyAndCert {
        cert_pem: ISSUING.into(),
        key_pem: fixture!("issuing.key").into(),
    };
    let cert = platform_pki::sign_intermediate(&issuing, &csr, chrono::Utc::now()).unwrap();
    Pki {
        csr,
        root: ROOT.into(),
        cert,
    }
}

#[test]
fn the_box_takes_the_chain_up_to_the_root() {
    let pki = sub_ca();
    let mut app = requested(&pki);
    // Before the signed certificate: the CAs are checked on their own.
    paste(&mut app, Which::Root, &format!("{ISSUING}{ROOT}"));
    let text = screen(&app);
    for want in [
        NOTE,
        "✓ Lime Lab Root CA · a root CA (self-signed)",
        "✓ Chain: Lime Lab Issuing CA › Lime Lab Root CA",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    assert!(!text.contains("Signed "), "{text}");
    app.key(Key::Esc);
    app.key(Key::Esc);

    paste(&mut app, Which::Signed, &pki.cert);
    app.key(Key::Enter);
    paste(&mut app, Which::Root, ISSUING);
    assert!(
        screen(&app).contains("Signed by Lime Lab Root CA, missing here: paste it below this one."),
        "{}",
        screen(&app)
    );
    app.key(Key::Paste(ROOT.into()));
    let text = screen(&app);
    for want in [
        "✓ Lime Lab Root CA · a root CA (self-signed)",
        "✓ Signed through Lime Lab Issuing CA › Lime Lab Root CA",
        "Enter  Use it",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    answer(
        &app,
        Ok(format!("signed\tLime Lab Issuing CA\n{}", pki.csr)),
    );
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(app.install.root_added.as_deref(), Some("Lime Lab Root CA"));
    let sent = &calls(&app)[1];
    assert!(
        sent.contains(ISSUING.trim()) && sent.ends_with(ROOT.trim()),
        "{sent}"
    );
}

#[test]
fn a_root_that_signed_directly_has_no_chain_line() {
    let pki = pki();
    let mut app = requested(&pki);
    paste(&mut app, Which::Signed, &pki.cert);
    app.key(Key::Enter);
    paste(&mut app, Which::Root, &pki.root);
    let text = screen(&app);
    for want in [
        NOTE,
        "✓ OpenVIBES Root CA · a root CA (self-signed)",
        "✓ Signed the intermediate directly",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    assert!(!text.contains("Chain:"), "{text}");
}
