//! Import from your PKI, "From a file on this host": a .p12 / .pfx opened
//! with its password fills both rows; a key file goes in the key row; a
//! binary file is never read as text.

use super::{
    Locked, Stage, Which,
    import_tests::{IMPORTED, OURS, OURS_KEY, PASSWORD, import, with_chain},
    steps_tests::{answer, folder},
};
use crate::tui::{
    app::{App, Key},
    nav::Screen,
    script_host::{SetupHost, screen, type_text},
};

/// The screen's words, one space apart: a long temp path wraps.
fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

const PFX: &[u8] = include_bytes!("../../../../platform-pki/tests/fixtures/modern.pfx");

/// From step 3: open `which`'s From a file on this host in `dir`, and
/// pick `name`.
fn pick(app: &mut App<SetupHost>, which: Which, dir: &str, name: &str) {
    app.install.home = Some(dir.to_owned());
    app.nav.row = if which == Which::Cert { 3 } else { 4 };
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Add(which)));
    app.key(Key::Down);
    app.key(Key::Enter);
    app.nav.row = (app.install.pick.as_ref().unwrap().rows().iter())
        .position(|(n, _)| n == name)
        .unwrap();
    app.key(Key::Enter);
}

#[test]
fn a_pfx_asks_its_password_then_fills_both_rows() {
    let dir = folder("import-pfx");
    let path = format!("{dir}/openvibes.pfx");
    std::fs::write(&path, PFX).unwrap();
    let mut app = import();
    pick(&mut app, Which::Cert, &dir.to_string(), "openvibes.pfx");
    let text = screen(&app);
    for line in [
        "Add the certificate",
        "a .pem, or a .p12 / .pfx with the key in it",
        &format!("✓ {path} · a .p12 file: it is locked with a password"),
        "Its password:",
        "Enter Open it",
    ] {
        assert!(flat(&text).contains(line), "{line}\n{text}");
    }
    answer(&app, Ok(IMPORTED.into()));
    type_text(&mut app, PASSWORD);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
    assert!(
        app.install.locked.is_none(),
        "the file's bytes are forgotten"
    );
    // Both rows filled: the helper takes them at once.
    assert!(screen(&app).contains("Your password (sudo)"));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(app.install.import_done.is_some());
    let text = screen(&app);
    for line in [
        "✓ added · Lime Lab OpenVIBES CA",
        "✓ added · matches the certificate",
        &format!("From {path}. Delete that file now: its key is kept here."),
        "Enter Next",
    ] {
        assert!(flat(&text).contains(line), "{line}\n{text}");
    }
}

#[test]
fn a_wrong_pfx_password_says_so() {
    let dir = folder("import-pfx-wrong");
    let path = format!("{dir}/openvibes.pfx");
    std::fs::write(&path, PFX).unwrap();
    let mut app = import();
    pick(&mut app, Which::Cert, &dir.to_string(), "openvibes.pfx");
    type_text(&mut app, "wrong");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Wrong password."), "{text}");
    assert!(
        flat(&text).contains(&format!("✗ Wrong password for {path}.")),
        "{text}"
    );
    assert!(text.contains("Its password:"), "asked again\n{text}");
    app.key(Key::Esc);
    assert!(app.install.locked.is_none());
    assert!(app.install.secret.is_none());
    assert!(app.install.imported.is_none());
    assert_eq!(app.nav.screen, Screen::Install(Stage::Add(Which::Cert)));
}

#[test]
fn a_key_file_is_accepted_in_the_key_row() {
    let dir = folder("import-key-file");
    std::fs::write(format!("{dir}/ours.key"), OURS_KEY).unwrap();
    std::fs::write(format!("{dir}/ours.crt"), OURS).unwrap();
    let mut app = with_chain();
    // A certificate is no key.
    pick(&mut app, Which::Key, &dir.to_string(), "ours.crt");
    assert!(app.install.paste.is_none());
    let text = screen(&app);
    assert!(
        text.contains("That file holds no private key: pick the key."),
        "{text}"
    );
    app.nav.row = (app.install.pick.as_ref().unwrap().rows().iter())
        .position(|(n, _)| n == "ours.key")
        .unwrap();
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("The private key, from ours.key"), "{text}");
    assert!(text.contains("✓ An EC P-256 key"), "{text}");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
    assert!(screen(&app).contains("✓ added · matches the certificate"));
}

#[test]
fn a_binary_file_is_not_read_lossily() {
    let dir = folder("import-binary");
    std::fs::write(format!("{dir}/blob.bin"), [0xff, 0xfe, 0x00, 0x2d, 0x2d]).unwrap();
    std::fs::write(format!("{dir}/openvibes.pfx"), PFX).unwrap();
    let mut app = import();
    pick(&mut app, Which::Cert, &dir.to_string(), "blob.bin");
    assert!(app.install.paste.is_none());
    assert!(
        screen(&app).contains("That file holds no certificate: pick the certificate."),
        "{}",
        screen(&app)
    );
    // A .p12 is kept as its bytes, exactly.
    app.nav.row = (app.install.pick.as_ref().unwrap().rows().iter())
        .position(|(n, _)| n == "openvibes.pfx")
        .unwrap();
    app.key(Key::Enter);
    match &app.install.locked {
        Some(Locked::P12(_, bytes)) => assert_eq!(bytes.as_slice(), PFX),
        _ => panic!("no .p12 kept"),
    }
}

#[test]
fn a_pfx_in_the_key_row_says_where_it_goes() {
    let dir = folder("import-pfx-key-row");
    std::fs::write(format!("{dir}/openvibes.pfx"), PFX).unwrap();
    let mut app = with_chain();
    pick(&mut app, Which::Key, &dir.to_string(), "openvibes.pfx");
    assert!(app.install.paste.is_none() && app.install.locked.is_none());
    let text = screen(&app);
    assert!(
        flat(&text)
            .contains(".p12 and .pfx files go in the Certificate row: they hold the key too."),
        "{text}"
    );
}
