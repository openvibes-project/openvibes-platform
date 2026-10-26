//! Step 3, Import from your PKI (certs4b.py): the third choice, the
//! certificate chain and its key pasted and checked at once, and Next
//! sending both to the helper on stdin.

use platform_host::HostError;

use super::{
    Ca, Stage, Which,
    steps_tests::{answer, calls, down, steps},
};
use crate::tui::{
    app::{App, Key},
    nav::Screen,
    script_host::{SetupHost, screen, type_text},
};

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!("../../../../platform-pki/tests/fixtures/", $name))
    };
}
pub(super) const ROOT: &str = fixture!("root.crt");
pub(super) const ISSUING: &str = fixture!("issuing.crt");
pub(super) const OURS: &str = fixture!("ours-ec.crt");
pub(super) const OURS_KEY: &str = fixture!("ours-ec.pkcs8.pem");
const LOCKED_KEY: &str = fixture!("ours-ec.enc.pem");
const OTHER_KEY: &str = fixture!("ours-rsa.key");
pub(super) const PASSWORD: &str = "correct horse";

pub(super) fn chain() -> String {
    format!("{OURS}{ISSUING}{ROOT}")
}

/// Step 3 with Import from your PKI chosen.
pub(super) fn import() -> App<SetupHost> {
    let mut app = steps(2);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    assert_eq!(app.install.ca, Ca::Import);
    app
}

/// From step 3: open `which`'s row, Paste it, and paste `text`.
pub(super) fn paste(app: &mut App<SetupHost>, which: Which, text: &str) {
    app.nav.row = if which == Which::Cert { 3 } else { 4 };
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Add(which)));
    app.key(Key::Enter);
    app.key(Key::Paste(text.to_owned()));
}

/// Import chosen, the chain pasted and used.
pub(super) fn with_chain() -> App<SetupHost> {
    let mut app = import();
    paste(&mut app, Which::Cert, &chain());
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
    app
}

pub(super) const IMPORTED: &str =
    "imported\tLime Lab OpenVIBES CA\tLime Lab Issuing CA › Lime Lab Root CA\t2046-01-01\n";

/// Both rows added: `ca-import` runs at once and asks the password.
fn with_both(reply: Result<String, HostError>) -> App<SetupHost> {
    let mut app = with_chain();
    answer(&app, reply);
    paste(&mut app, Which::Key, OURS_KEY);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
    assert!(screen(&app).contains("Your password (sudo)"));
    app
}

#[test]
fn import_is_the_second_choice() {
    let mut app = steps(2);
    let text = screen(&app);
    let at = |s: &str| text.find(s).unwrap_or_else(|| panic!("{s}\n{text}"));
    assert!(at("(•) Your own CA") < at("( ) Import from your PKI"));
    assert!(at("( ) Import from your PKI") < at("( ) OpenVIBES makes one"));
    assert!(
        text.contains("a finished intermediate and its key"),
        "{text}"
    );
    app.key(Key::Down);
    let text = screen(&app);
    assert!(
        text.contains("Paste or pick the certificate and its key, or a .p12 with its password."),
        "{text}"
    );
    app.key(Key::Char(' '));
    assert_eq!(app.install.ca, Ca::Import);
    let text = screen(&app);
    assert!(text.contains("(•) Import from your PKI"), "{text}");
    assert!(text.contains("Certificate"), "{text}");
    assert!(text.contains("not added yet"), "{text}");
    down(&mut app, 4);
    let text = screen(&app);
    assert!(text.contains("once both are added"), "{text}");
    let args = app.install.plan_args();
    let ca = args.iter().position(|a| a == "--ca").unwrap();
    assert_eq!(args[ca + 1], "import");
    assert!(!args.contains(&"--root-key-out".to_owned()));
}

#[test]
fn pasting_the_chain_fills_the_certificate_row() {
    let mut app = import();
    paste(&mut app, Which::Cert, &chain());
    let text = screen(&app);
    for line in [
        "· Install › Certificates › Certificate",
        "Paste the certificate",
        "Our intermediate first, then each CA above it, ending with the root.",
        "✓ Lime Lab OpenVIBES CA · may sign certificates · valid until 2046-01-01",
        "✓ Chain: Lime Lab Issuing CA › Lime Lab Root CA (root, also added)",
        "Enter  Use it",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
    let text = screen(&app);
    assert!(text.contains("✓ added · Lime Lab OpenVIBES CA"), "{text}");
    assert!(calls(&app).is_empty(), "nothing is sent before Next");
}

#[test]
fn a_gap_shows_the_missing_ca_and_use_it_does_nothing() {
    let mut app = import();
    // The root without the CA between: P1, the root must be there too.
    paste(&mut app, Which::Cert, &format!("{OURS}{ROOT}"));
    let text = screen(&app);
    assert!(
        text.contains("✓ Lime Lab OpenVIBES CA · may sign certificates · valid until 2046-01-01"),
        "{text}"
    );
    assert!(
        text.contains("✗ Signed by Lime Lab Issuing CA, missing here: paste it below this one."),
        "{text}"
    );
    assert!(!text.contains("Use it"), "{text}");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Add(Which::Cert)));
    assert!(app.install.imported.is_none());
    // No root at all: the same line for the root.
    app.key(Key::ClearLine);
    app.key(Key::Paste(format!("{OURS}{ISSUING}")));
    assert!(
        screen(&app).contains("✗ Signed by Lime Lab Root CA, missing here"),
        "{}",
        screen(&app)
    );
}

#[test]
fn a_locked_key_asks_its_password_in_the_bar() {
    let mut app = with_chain();
    paste(&mut app, Which::Key, LOCKED_KEY);
    let text = screen(&app);
    for line in [
        "· Install › Certificates › Private key",
        "Paste the private key",
        "It stays on this host, readable by root only.",
        "Its password:",
        "Enter  Unlock",
        "✓ A private key, locked with a password",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
    type_text(&mut app, "wrong");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Wrong password."), "{text}");
    assert!(text.contains("Its password:"), "still asked\n{text}");
    app.key(Key::ClearLine);
    type_text(&mut app, PASSWORD);
    assert!(!screen(&app).contains(PASSWORD));
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        text.contains("✓ An EC P-256 key, locked with a password"),
        "{text}"
    );
    assert!(text.contains("Enter  Use it"), "{text}");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
    assert!(
        screen(&app).contains("✓ added · matches the certificate"),
        "{}",
        screen(&app)
    );
}

/// Esc in the bar forgets the password and the key's text.
#[test]
fn esc_in_the_bar_forgets_the_locked_key() {
    let mut app = with_chain();
    paste(&mut app, Which::Key, LOCKED_KEY);
    type_text(&mut app, "corr");
    app.key(Key::Esc);
    assert!(app.install.secret.is_none());
    assert!(app.install.locked.is_none());
    assert!(app.install.paste.is_none());
    assert_eq!(app.nav.screen, Screen::Install(Stage::Add(Which::Key)));
}

#[test]
fn a_wrong_key_is_red() {
    let mut app = with_chain();
    paste(&mut app, Which::Key, OTHER_KEY);
    let text = screen(&app);
    assert!(
        text.contains("✗ Not the key of Lime Lab OpenVIBES CA: paste the key it was made with."),
        "{text}"
    );
    assert!(!text.contains("Use it"), "{text}");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Add(Which::Key)));
    assert!(app.install.imported.as_ref().unwrap().key.is_none());
}

#[test]
fn both_added_sends_the_bundle_on_stdin_at_once_and_next_moves_on() {
    let mut app = with_both(Ok(IMPORTED.into()));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(calls(&app), vec!["ca-import"]);
    assert!(app.install.import_done.is_some());
    // The helper has the key now: no copy is kept here.
    assert!(app.install.imported.as_ref().unwrap().key.is_none());
    let text = screen(&app);
    assert!(text.contains("✓ added · Lime Lab OpenVIBES CA"), "{text}");
    assert!(text.contains("✓ added · matches the certificate"), "{text}");
    assert!(
        text.contains("▸ Next                       ports"),
        "{text}"
    );
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(3)));
    assert_eq!(calls(&app).len(), 1);
}

#[test]
fn a_refused_import_keeps_both_rows() {
    let mut app = with_both(Err(HostError::Failed(
        "openvibes-admin helper: Valid until 2026-12-01: under the 90 days a server \
         certificate lasts."
            .into(),
    )));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        text.contains("✗ Valid until 2026-12-01: under the 90 days a server certificate"),
        "{text}"
    );
    assert!(app.install.import_done.is_none());
    assert!(text.contains("✓ added · Lime Lab OpenVIBES CA"), "{text}");
    assert!(text.contains("✓ added · matches the certificate"), "{text}");
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
}

/// A wrong sudo password, then Esc: the run stops and keeps no key; Next
/// asks again.
#[test]
fn a_cancelled_sudo_ask_wipes_the_bundle() {
    let mut app = with_both(Err(HostError::WrongPassword));
    type_text(&mut app, "bad");
    app.key(Key::Enter);
    assert!(screen(&app).contains("Wrong password, 2 tries left."));
    app.key(Key::Esc);
    let run = app.run.as_ref().unwrap();
    match &run.work.calls[0] {
        crate::tui::run::Call::CaImport(bundle) => assert!(bundle.0.is_empty()),
        call => panic!("{call:?}"),
    }
    assert!(app.install.import_done.is_none());
    answer(&app, Ok(IMPORTED.into()));
    app.nav.row = 5;
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(app.install.import_done.is_some());
}

#[test]
fn review_wants_both() {
    let mut app = import();
    assert_eq!(
        app.install.not_ready().as_deref(),
        Some("✗ Certificates: add the certificate and its key first.")
    );
    app.install.import_done = Some(
        "imported\tLime Lab OpenVIBES CA\tLime Lab Issuing CA › Lime Lab Root CA\t2046-01-01"
            .into(),
    );
    assert_eq!(app.install.not_ready(), None);
}

/// Leaving Import, or step 3, before the helper has the key forgets it.
#[test]
fn leaving_import_forgets_the_key() {
    let mut app = with_both(Ok(IMPORTED.into()));
    app.key(Key::Esc);
    assert!(app.install.imported.as_ref().unwrap().key.is_some());
    app.nav.row = 0;
    app.key(Key::Char(' '));
    assert_eq!(app.install.ca, Ca::Own);
    assert!(app.install.imported.is_none());
    let mut app = with_both(Ok(IMPORTED.into()));
    app.key(Key::Esc);
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(1)));
    // The certificate stays; its key is added again.
    assert!(app.install.imported.as_ref().unwrap().key.is_none());
}

#[test]
fn choosing_openvibes_still_edits_the_root_key_row() {
    let mut app = steps(2);
    down(&mut app, 2);
    app.key(Key::Char(' '));
    assert_eq!(app.install.ca, Ca::OpenVibes);
    app.key(Key::Down);
    assert!(screen(&app).contains("Root key file"));
    app.key(Key::Enter);
    assert!(app.install.editing.is_some(), "the root key file is typed");
    app.key(Key::Esc);
    app.key(Key::Down);
    app.key(Key::Down);
    assert_eq!(app.nav.row, 4, "Next is the last of five rows");
}

#[test]
fn the_key_is_checked_again_only_when_something_changes() {
    let mut app = with_chain();
    paste(&mut app, Which::Key, OURS_KEY);
    let text = app.install.paste.clone().unwrap();
    assert!(screen(&app).contains("An EC P-256 key"));
    // Another draw takes the last check: a stand-in shows it is not redone.
    let seen = app.install.seen(Which::Key, &text);
    *app.install.checked.borrow_mut() = Some((seen, Some(Ok(vec!["kept".into()]))));
    assert!(screen(&app).contains("kept"), "{}", screen(&app));
    // Another text, or another chain, is checked again.
    assert!(matches!(
        app.install.check(Which::Key, OTHER_KEY),
        Some(Err(_))
    ));
    assert_ne!(app.install.seen(Which::Cert, &text), seen);
}
