//! Step 3 with your own CA: a refused `ca-accept`, and Esc back to the
//! choice, forget the certificates added (the rows never claim "✓ added"
//! for certificates the helper did not keep).

use platform_host::HostError;

use super::{
    Stage, Which,
    certs_tests::{paste, pki, requested},
    steps_tests::{answer, calls},
};
use crate::tui::{
    app::Key,
    nav::Screen,
    script_host::{screen, type_text},
};

#[test]
fn a_refused_accept_says_why_and_next_stays_disabled() {
    let pki = pki();
    let mut app = requested(&pki);
    paste(&mut app, Which::Signed, &pki.cert);
    app.key(Key::Enter);
    answer(
        &app,
        Err(HostError::Failed(
            "openvibes-admin helper: There is no request here: make one first.".into(),
        )),
    );
    paste(&mut app, Which::Root, &pki.root);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("There is no request here"), "{text}");
    assert!(app.install.signed.is_none());
    // Both rows can be added again: neither claims what was refused.
    assert!(!text.contains("✓ added"), "{text}");
    assert!(app.install.cert.is_none() && app.install.root_pem.is_none());
    assert!(app.install.root_added.is_none());
    app.nav.row = 3;
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
}

#[test]
fn esc_to_the_choice_forgets_the_certificates_added() {
    let pki = pki();
    let mut app = requested(&pki);
    paste(&mut app, Which::Signed, &pki.cert);
    app.key(Key::Enter);
    assert!(app.install.cert.is_some());
    app.key(Key::Esc);
    assert!(app.install.cert.is_none() && app.install.root_pem.is_none());
    assert!(app.install.root_added.is_none());
    // Next asks the helper again: the request, nothing added.
    answer(&app, Ok(format!("request\n{}", pki.csr)));
    app.nav.row = 3;
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(calls(&app).len(), 2, "{:?}", calls(&app));
    let text = screen(&app);
    assert!(!text.contains("✓ added"), "{text}");
}
