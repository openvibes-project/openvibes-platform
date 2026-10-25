//! Step 3 with your own CA, "From a file on this host": the box says
//! where its text came from, and a private key is never read into it.

use super::{
    Which,
    certs_tests::{pki, requested},
    steps_tests::folder,
};
use crate::tui::{app::Key, script_host::SetupHost, script_host::screen};

/// From the request rows: open `which`'s From a file on this host in
/// `dir`, and pick `name`.
fn pick(app: &mut crate::tui::app::App<SetupHost>, which: Which, dir: &str, name: &str) {
    app.install.home = Some(dir.to_owned());
    app.nav.row = if which == Which::Signed { 1 } else { 2 };
    app.key(Key::Enter);
    app.key(Key::Down);
    app.key(Key::Enter);
    app.nav.row = app
        .install
        .pick
        .as_ref()
        .unwrap()
        .rows()
        .iter()
        .position(|(n, _)| n == name)
        .unwrap();
    app.key(Key::Enter);
}

#[test]
fn a_picked_file_titles_the_box_for_the_file() {
    let pki = pki();
    let dir = folder("file-title");
    std::fs::write(format!("{dir}/root.crt"), &pki.root).unwrap();
    let mut app = requested(&pki);
    pick(&mut app, Which::Root, &dir.to_string(), "root.crt");
    let text = screen(&app);
    assert!(
        text.contains("Your CA's certificate, from root.crt"),
        "{text}"
    );
    assert!(!text.contains("Paste"), "{text}");
    // Esc, then Paste it: the paste titles again.
    app.key(Key::Esc);
    app.key(Key::Up);
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Paste your CA's certificate"), "{text}");
    assert!(
        text.contains("Your CA's certificate, then each CA above it up to the root."),
        "{text}"
    );
}

#[test]
fn a_file_holding_a_private_key_is_refused_and_never_read_in() {
    let pki = pki();
    let dir = folder("file-key");
    let (_, key) = platform_pki::intermediate_request().unwrap();
    // A certificate and its key in one file is refused too.
    std::fs::write(format!("{dir}/root.key"), format!("{}{key}", pki.root)).unwrap();
    let mut app = requested(&pki);
    pick(&mut app, Which::Root, &dir.to_string(), "root.key");
    assert!(app.install.paste.is_none());
    assert!(app.install.pick.is_some(), "still picking");
    let text = screen(&app);
    assert!(
        text.contains("That file holds a private key: pick the certificate."),
        "{text}"
    );
    let body = key.lines().nth(1).unwrap();
    assert!(!text.contains(&body[..20]), "{text}");
}

/// A refusal is for the file picked: the next pick, or another folder,
/// says its own.
#[test]
fn a_refusal_is_cleared_by_the_next_pick_or_folder() {
    use std::os::unix::fs::PermissionsExt;
    let pki = pki();
    let dir = folder("file-next");
    let (_, key) = platform_pki::intermediate_request().unwrap();
    std::fs::write(format!("{dir}/root.key"), &key).unwrap();
    let locked = format!("{dir}/locked.crt");
    std::fs::write(&locked, &pki.root).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::create_dir_all(format!("{dir}/sub")).unwrap();
    let mut app = requested(&pki);
    pick(&mut app, Which::Root, &dir.to_string(), "root.key");
    let row = |app: &crate::tui::app::App<SetupHost>, name: &str| {
        let rows = app.install.pick.as_ref().unwrap().rows();
        rows.iter().position(|(n, _)| n == name).unwrap()
    };
    // Root reads any file: only a user is refused the locked one.
    if std::fs::read(&locked).is_err() {
        app.nav.row = row(&app, "locked.crt");
        app.key(Key::Enter);
        let text = screen(&app);
        assert!(!text.contains("private key"), "{text}");
        assert!(text.contains("cannot be read"), "{text}");
    }
    app.nav.row = row(&app, "root.key");
    app.key(Key::Enter);
    assert!(screen(&app).contains("private key"));
    app.nav.row = row(&app, "sub/");
    app.key(Key::Enter);
    assert!(!screen(&app).contains("private key"), "{}", screen(&app));
}

/// Only a file holding a certificate reaches the box.
#[test]
fn a_file_holding_no_certificate_is_refused() {
    let pki = pki();
    let dir = folder("file-none");
    std::fs::write(format!("{dir}/notes.txt"), "my CA notes").unwrap();
    let mut app = requested(&pki);
    pick(&mut app, Which::Root, &dir.to_string(), "notes.txt");
    assert!(app.install.paste.is_none());
    let text = screen(&app);
    assert!(
        text.contains("That file holds no certificate: pick the certificate."),
        "{text}"
    );
}
