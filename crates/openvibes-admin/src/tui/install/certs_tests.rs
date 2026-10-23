//! Step 3, Certificates (ca.py, ca2.py, full_advanced.py): the two CA
//! modes, the request made before install, and the two certificates
//! added by paste, typed lines or a file, checked at once.

use platform_host::HostError;

use super::{
    Ca, Stage, Which,
    steps_tests::{answer, at, calls, down, folder, steps},
};
use crate::{
    setup::request::RequestState,
    tui::{
        app::{App, Key},
        nav::Screen,
        script_host::{PLAN, SetupHost, app_with_plan, screen, type_text},
    },
};

/// A request, the root that signs it, and its answer.
pub(super) struct Pki {
    pub(super) csr: String,
    pub(super) root: String,
    pub(super) cert: String,
}

pub(super) fn pki() -> Pki {
    let now = chrono::Utc::now();
    let (csr, _key) = platform_pki::intermediate_request().unwrap();
    let root = platform_pki::generate_root(now).unwrap();
    let cert = platform_pki::sign_intermediate(&root, &csr, now).unwrap();
    Pki {
        csr,
        root: root.cert_pem,
        cert,
    }
}

/// Step 3 with your own CA: Next, the password, and the request made
/// (its copy beside another file the helper found).
pub(super) fn requested(pki: &Pki) -> App<SetupHost> {
    let mut app = steps(2);
    let copy = "copy\t/home/u/openvibes-intermediate-2.csr";
    answer(&app, Ok(format!("request\n{copy}\n{}", pki.csr)));
    down(&mut app, 2);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app
}

/// From the request rows: open `which`, Paste it, and paste `text`.
pub(super) fn paste(app: &mut App<SetupHost>, which: Which, text: &str) {
    app.nav.row = if which == Which::Signed { 1 } else { 2 };
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Add(which)));
    app.key(Key::Enter);
    app.key(Key::Paste(text.to_owned()));
}

#[test]
fn certs_own_ca_is_default_space_chooses() {
    let mut app = steps(2);
    assert_eq!(app.install.ca, Ca::Own);
    let text = screen(&app);
    for row in [
        "(•) Your own CA",
        "your CA signs an intermediate for OpenVIBES",
        "( ) OpenVIBES makes one",
        "a new root CA; its key goes offline after",
        "ports",
        "For networks with their own PKI. Your root key never comes near this host.",
        "Space  Choose",
    ] {
        assert!(text.contains(row), "{row}\n{text}");
    }
    assert!(!text.contains("Root key file"), "{text}");
    app.key(Key::Down);
    app.key(Key::Char(' '));
    assert_eq!(app.install.ca, Ca::OpenVibes);
    let text = screen(&app);
    assert!(text.contains("(•) OpenVIBES makes one"), "{text}");
    assert!(
        text.contains("For networks without a CA of their own."),
        "{text}"
    );
    app.key(Key::Up);
    app.key(Key::Char(' '));
    assert_eq!(app.install.ca, Ca::Own);
}

#[test]
fn certs_openvibes_shows_root_key_file_row() {
    let mut app = steps(2);
    app.install.ca = Ca::OpenVibes;
    app.install.root_key_out = "openvibes.key".into();
    let text = screen(&app);
    assert!(text.contains("Root key file"), "{text}");
    assert!(
        text.contains("✗ Root key file: The path must start with /."),
        "{text}"
    );
    down(&mut app, 3);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
    app.key(Key::Up);
    app.key(Key::Enter);
    app.key(Key::ClearLine);
    let dir = folder("certs");
    let key = format!("{dir}/root.key");
    type_text(&mut app, &key);
    assert!(screen(&app).contains("root.key█"));
    app.key(Key::Enter);
    assert_eq!(app.install.root_key_out, key);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(3)));
    assert!(calls(&app).is_empty());
}

#[test]
fn own_ca_next_makes_request_and_shows_rows() {
    let pki = pki();
    let app = requested(&pki);
    assert_eq!(
        calls(&app),
        ["ca-request --copy /home/u/openvibes-intermediate.csr"]
    );
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
    assert_eq!(
        app.install.request,
        Some(RequestState::Request {
            csr: pki.csr.clone()
        })
    );
    let text = screen(&app);
    for row in [
        "Show the request",
        "to copy it to your CA",
        "Signed certificate",
        "not added yet",
        "Your CA's certificate",
        "once both are added",
        "OpenVIBES made a request; your CA signs it as an intermediate.",
        "Enter  Show the request",
    ] {
        assert!(text.contains(row), "{row}\n{text}");
    }
}

#[test]
fn a_refused_request_shows_only_its_sentence() {
    let mut app = steps(2);
    answer(
        &app,
        Err(HostError::Failed(
            "openvibes-admin helper: That file already exists: /home/u/x.csr. Choose another name."
                .into(),
        )),
    );
    down(&mut app, 2);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("That file already exists"), "{text}");
    assert!(!text.contains("helper"), "{text}");
    assert!(app.install.request.is_none());
}

#[test]
fn request_screen_shows_pem_and_saved_path() {
    let pki = pki();
    let mut app = requested(&pki);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Request));
    let text = screen(&app);
    for row in [
        "· Install › Certificates › Request",
        "The signing request",
        "Also saved as ~/openvibes-intermediate-2.csr",
        "-----BEGIN CERTIFICATE REQUEST-----",
        "-----END CERTIFICATE REQUEST-----",
        "Scroll",
    ] {
        assert!(text.contains(row), "{row}\n{text}");
    }
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
}

#[test]
fn paste_checked_at_once_then_use_it() {
    let pki = pki();
    let mut app = requested(&pki);
    app.nav.row = 1;
    app.key(Key::Enter);
    let text = screen(&app);
    for row in [
        "· Install › Certificates › Signed certificate",
        "Add the signed certificate",
        "Paste it",
        "paste the PEM text into this terminal",
        "From a file on this host",
        "copied here with scp or a USB stick",
        "Enter  Paste it",
    ] {
        assert!(text.contains(row), "{row}\n{text}");
    }
    app.key(Key::Enter);
    app.key(Key::Paste(pki.cert.clone()));
    let until = platform_pki::check_signed_request(&pki.csr, &pki.cert, chrono::Utc::now())
        .unwrap()
        .not_after;
    let text = screen(&app);
    for row in [
        "Paste the signed certificate",
        "Paste the whole block, BEGIN to END lines included.",
        "-----BEGIN CERTIFICATE-----",
        "-----END CERTIFICATE-----",
        "✓ Intermediate for limebox.lan · signed by OpenVIBES Root CA",
        &format!("✓ Matches the request · valid until {until}"),
        "Enter  Use it",
        "Esc  Cancel",
    ] {
        assert!(text.contains(row), "{row}\n{text}");
    }
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
    let text = screen(&app);
    assert!(
        text.contains("✓ added · signed by OpenVIBES Root CA"),
        "{text}"
    );
    // One certificate: nothing is sent yet.
    assert_eq!(calls(&app).len(), 1);
}

#[test]
fn paste_of_chain_says_two_certificates() {
    let pki = pki();
    let mut app = requested(&pki);
    paste(
        &mut app,
        Which::Signed,
        &format!("{}{}", pki.cert, pki.root),
    );
    let text = screen(&app);
    assert!(
        text.contains("That is 2 certificates: paste only the one signed for"),
        "{text}"
    );
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Add(Which::Signed)));
    assert!(app.install.cert.is_none());
}

#[test]
fn paste_wrong_request_and_wrong_root_say_why() {
    let pki = pki();
    let other = self::pki();
    let mut app = requested(&pki);
    paste(&mut app, Which::Signed, &other.cert);
    let text = screen(&app);
    assert!(
        text.contains("This certificate was signed for a different request"),
        "{text}"
    );
    app.key(Key::Enter);
    assert!(app.install.cert.is_none());
    app.key(Key::Esc);
    app.key(Key::Esc);
    paste(&mut app, Which::Signed, &pki.cert);
    app.key(Key::Enter);
    paste(&mut app, Which::Root, &other.root);
    let text = screen(&app);
    assert!(
        text.contains("Your CA's certificate must be the root that signed"),
        "{text}"
    );
    app.key(Key::Enter);
    assert!(app.install.root_added.is_none());
    app.key(Key::Esc);
    app.key(Key::Enter);
    app.key(Key::Paste(pki.cert.clone()));
    assert!(
        screen(&app).contains("This is not a root CA (self-signed)"),
        "{}",
        screen(&app)
    );
}

#[test]
fn typed_lines_without_bracketed_paste_end_at_end_line() {
    let pki = pki();
    let mut app = requested(&pki);
    paste(&mut app, Which::Signed, "");
    let lines: Vec<&str> = pki.cert.lines().collect();
    for line in &lines {
        type_text(&mut app, line);
        assert_eq!(app.nav.screen, Screen::Install(Stage::Add(Which::Signed)));
        app.key(Key::Enter);
    }
    // The last Enter came after the END line: Use it.
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
    assert_eq!(
        app.install.cert.as_ref().map(|c| c.0.trim()),
        Some(pki.cert.trim())
    );
}

#[test]
fn file_pick_lists_files_and_reads_one() {
    let pki = pki();
    let dir = folder("pick");
    std::fs::create_dir_all(format!("{dir}/sub")).unwrap();
    std::fs::write(format!("{dir}/signed.crt"), &pki.cert).unwrap();
    let big = format!("{}{}", pki.cert, "x".repeat(100 * 1024));
    std::fs::write(format!("{dir}/big.crt"), big).unwrap();
    let mut app = at(super::super::script_host::fresh_app(), 2);
    answer(&app, Ok(format!("request\n{}", pki.csr)));
    app.install.home = Some(dir.to_string());
    down(&mut app, 2);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.nav.row = 1;
    app.key(Key::Enter);
    app.key(Key::Down);
    app.key(Key::Enter);
    let text = screen(&app);
    for row in ["sub/", "signed.crt", "big.crt"] {
        assert!(text.contains(row), "{row}\n{text}");
    }
    // .., sub/, then the files in order: big.crt, signed.crt.
    let at = |name: &str| {
        app.install
            .pick
            .as_ref()
            .unwrap()
            .rows()
            .iter()
            .position(|(n, _)| n == name)
            .unwrap()
    };
    let (big, signed) = (at("big.crt"), at("signed.crt"));
    app.nav.row = big;
    app.key(Key::Enter);
    assert_eq!(app.install.paste.as_ref().unwrap().len(), 64 * 1024);
    app.key(Key::Esc);
    app.key(Key::Down);
    app.key(Key::Enter);
    app.nav.row = signed;
    app.key(Key::Enter);
    assert!(screen(&app).contains("✓ Matches the request"));
    app.key(Key::Enter);
    assert!(app.install.cert.is_some());
}

#[test]
fn next_disabled_until_both_added() {
    let pki = pki();
    let mut app = requested(&pki);
    down(&mut app, 3);
    assert!(screen(&app).contains("once both are added"));
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
    paste(&mut app, Which::Signed, &pki.cert);
    app.key(Key::Enter);
    app.nav.row = 3;
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
    assert!(screen(&app).contains("once both are added"));
}

#[test]
fn both_added_calls_ca_accept_and_review_says_signed_by() {
    let pki = pki();
    let mut app = requested(&pki);
    paste(&mut app, Which::Signed, &pki.cert);
    app.key(Key::Enter);
    answer(&app, Ok(format!("signed\tOpenVIBES Root CA\n{}", pki.csr)));
    paste(&mut app, Which::Root, &pki.root);
    assert!(screen(&app).contains("✓ OpenVIBES Root CA"));
    app.key(Key::Enter);
    // Both added: the helper checks and keeps them, with the password.
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let calls = calls(&app);
    assert!(calls[1].starts_with("ca-accept --cert "), "{calls:?}");
    assert_eq!(app.install.signed.as_deref(), Some("OpenVIBES Root CA"));
    let text = screen(&app);
    assert!(
        text.contains("✓ added · signed by OpenVIBES Root CA"),
        "{text}"
    );
    assert!(text.contains("✓ added · OpenVIBES Root CA"), "{text}");
    app.nav.row = 3;
    assert!(screen(&app).contains("ports"));
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(3)));
    app.nav.screen = Screen::Install(Stage::Step(4));
    let text = screen(&app);
    assert!(
        text.contains("your own CA · ✓ signed by OpenVIBES Root CA"),
        "{text}"
    );
}

#[test]
fn restart_with_signed_request_shows_added() {
    let pki = pki();
    let plan = format!("{PLAN}# no ca\n").replace("ca = \"quick\"", "ca = \"careful\"");
    let mut app = app_with_plan(
        &plan,
        vec![Ok(format!("signed\tLime Lab Root CA\n{}", pki.csr))],
    );
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(0)));
    for step in [1, 2] {
        down(&mut app, 2);
        app.key(Key::Enter);
        assert_eq!(app.nav.screen, Screen::Install(Stage::Step(step)));
    }
    down(&mut app, 2);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(calls(&app)[0].starts_with("ca-request"));
    let text = screen(&app);
    assert!(
        text.contains("✓ added · signed by Lime Lab Root CA"),
        "{text}"
    );
    assert!(text.contains("✓ added · Lime Lab Root CA"), "{text}");
    assert_eq!(app.install.signed.as_deref(), Some("Lime Lab Root CA"));
    app.nav.row = 3;
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(3)));
}

/// Own CA accepted, then OpenVIBES makes one: Finished shows no "signed by".
#[test]
fn switching_to_openvibes_ca_forgets_the_signed_certificates() {
    let pki = pki();
    let mut app = requested(&pki);
    paste(&mut app, Which::Signed, &pki.cert);
    app.key(Key::Enter);
    answer(&app, Ok(format!("signed\tOpenVIBES Root CA\n{}", pki.csr)));
    paste(&mut app, Which::Root, &pki.root);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.key(Key::Esc);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    assert_eq!(app.install.ca, Ca::OpenVibes);
    assert!(app.install.signed.is_none() && app.install.cert.is_none());
    assert!(app.install.root_pem.is_none() && app.install.root_added.is_none());
    let dir = folder("switch");
    let key = format!("{dir}/root.key");
    app.install.root_key_out = key.clone();
    // The plan, then Packages to Schema, then the CA step's own detail.
    answer(&app, Ok("written\n".into()));
    (0..5).for_each(|_| answer(&app, Ok("done\tok\n".into())));
    answer(
        &app,
        Ok(format!(
            "done\troot key saved to {key}: keep it offline; root certificate x\n"
        )),
    );
    app.nav.screen = Screen::Install(Stage::Step(4));
    app.nav.row = 4;
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Finished));
    let text = screen(&app);
    assert!(text.contains("Root key"), "{text}");
    assert!(!text.contains("signed by"), "{text}");
}
