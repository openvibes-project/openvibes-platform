//! Maintenance › Certificates and Replace for an imported intermediate
//! (certs4b.py #10-11): where it came from, then the next one through the
//! install's rows, `ca-import` first, then 4a's question and steps.

use platform_host::HostError;
use ratatui::{Terminal, backend::TestBackend, style::Modifier};

use crate::tui::{
    app::{App, Key},
    install::{Stage, Which},
    maint::{
        Page,
        certs_page_tests::{day, framed, keys, menu, put},
        certs_tests::{app_with, pems, plan_text},
    },
    nav::{Screen, render},
    script_host::{SetupHost, body, screen, type_text},
};

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!("../../../../platform-pki/tests/fixtures/", $name))
    };
}
const ROOT: &str = fixture!("root.crt");
const ISSUING: &str = fixture!("issuing.crt");
const OURS: &str = fixture!("ours-ec.crt");
const OURS_KEY: &str = fixture!("ours-ec.pkcs8.pem");
/// The intermediate in use, and its own key.
const OLD: &str = fixture!("ours-rsa.crt");
const OLD_KEY: &str = fixture!("ours-rsa.key");

const IMPORTED: &str =
    "imported\tLime Lab OpenVIBES CA\tLime Lab Issuing CA › Lime Lab Root CA\t2046-01-01\n";
const GREEN: &str = "    ✓ Under the same root: agents keep working.";

fn calls(app: &App<SetupHost>) -> Vec<String> {
    let calls = app.host.calls.borrow();
    calls.iter().map(|c| c.0.clone()).collect()
}

/// A host that imported `OLD` from a three-level PKI.
fn imported() -> App<SetupHost> {
    let leaf = pems(10).remove(0);
    let mut app = app_with(vec![
        leaf,
        ("/etc/openvibes/pki/intermediate.crt", OLD.into()),
    ]);
    app.host.plan = plan_text().replace("quick", "import");
    put(&app, "/etc/openvibes/pki/root.crt", ROOT);
    put(&app, "/etc/openvibes/pki/chain.crt", ISSUING);
    app
}

/// Certificates, then Replace the intermediate.
fn replace_page() -> App<SetupHost> {
    let mut app = imported();
    app.open_page(Page::Certificates);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Replace));
    app
}

/// From the Replace page: `row`'s Paste it with `text`, then Use it.
fn paste(app: &mut App<SetupHost>, row: usize, which: Which, text: &str) {
    app.nav.row = row;
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Add(which)));
    app.key(Key::Enter);
    app.key(Key::Paste(text.to_owned()));
}

/// Both rows added on the Replace page.
fn both_added() -> App<SetupHost> {
    let mut app = replace_page();
    paste(&mut app, 0, Which::Cert, &format!("{OURS}{ISSUING}{ROOT}"));
    app.key(Key::Enter);
    paste(&mut app, 1, Which::Key, OURS_KEY);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Replace));
    app
}

/// certs4b.py #11: the note, `rows`, then `line`.
fn replace_body(rows: &[(&str, String)], row: usize, line: &str, bar: &str) -> String {
    let mut lines = vec![
        "    The same screens as at install. Nothing changes until Replace.".to_owned(),
        String::new(),
    ];
    lines.extend(menu(rows, row));
    if !line.is_empty() {
        lines.extend([String::new(), line.to_owned()]);
    }
    framed("Replace the intermediate", lines, bar)
}

fn rows(cert: &str, key: &str) -> [(&'static str, String); 3] {
    [
        ("Certificate", cert.into()),
        ("Private key", key.into()),
        ("Replace", "agents move over in 30 days".into()),
    ]
}

#[test]
fn the_page_says_from_your_pki() {
    let mut app = imported();
    app.open_page(Page::Certificates);
    app.key(Key::Down);
    let mut lines: Vec<String> = [
        (
            "Web and agents",
            format!("renewed automatically · next {}", day(50)),
        ),
        ("Names", "limebox.lan, 192.168.1.10".into()),
        ("Intermediate", "from your PKI · until 2046-01-01".into()),
        ("Signed by", "Lime Lab Issuing CA › Lime Lab Root CA".into()),
    ]
    .iter()
    .map(|(n, v)| format!("    {n:<26} {v}"))
    .collect();
    lines.push(String::new());
    lines.extend(menu(
        &[
            ("Names", "add or remove a name agents use".into()),
            (
                "Replace the intermediate",
                "import the next one from your PKI".into(),
            ),
        ],
        1,
    ));
    let want = framed("Certificates", lines, &keys("Replace the intermediate"));
    assert_eq!(body(&app), want);

    // The root is bold, the CA below it is not.
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();
    let buffer = terminal.backend().buffer();
    let text = screen(&app);
    let y = text.lines().position(|l| l.contains("Signed by")).unwrap() as u16;
    let x = |name: &str| {
        let line = text.lines().nth(usize::from(y)).unwrap();
        line[..line.find(name).unwrap()].chars().count() as u16
    };
    let bold = |x: u16| buffer[(x, y)].modifier.contains(Modifier::BOLD);
    assert!(bold(x("Lime Lab Root CA")));
    assert!(!bold(x("Lime Lab Issuing CA")));

    // A two-level PKI: just the root.
    std::fs::remove_file(app.root.join("etc/openvibes/pki/chain.crt")).unwrap();
    app.open_page(Page::Certificates);
    let text = body(&app);
    assert!(
        text.contains("    Signed by                  Lime Lab Root CA\n"),
        "{text}"
    );
}

#[test]
fn replace_imports_then_asks() {
    let mut app = replace_page();
    let empty = rows("not added yet", "not added yet");
    assert_eq!(body(&app), replace_body(&empty, 0, "", &keys("Open")));

    // The install's screens: the chain, then its key.
    paste(&mut app, 0, Which::Cert, &format!("{OURS}{ISSUING}{ROOT}"));
    let text = screen(&app);
    assert!(
        text.contains("✓ Chain: Lime Lab Issuing CA › Lime Lab Root CA (root, also added)"),
        "{text}"
    );
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Replace));
    assert_eq!(app.nav.row, 1);
    paste(&mut app, 1, Which::Key, OURS_KEY);
    app.key(Key::Enter);
    assert_eq!(app.nav.row, 2);
    let added = rows(
        "✓ added · Lime Lab OpenVIBES CA",
        "✓ added · matches the certificate",
    );
    assert_eq!(body(&app), replace_body(&added, 2, "", &keys("Replace")));
    assert!(calls(&app).is_empty(), "nothing is sent before Replace");

    app.host.answers.borrow_mut().extend([
        Ok(IMPORTED.into()),
        Ok(format!(
            "Trusting the old and the new one\nIssuing the server certificates\n\
             Restarting the services\ndone\t{}\t{}\n",
            day(1460),
            day(31)
        )),
    ]);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(calls(&app), ["ca-import"]);
    // The helper has the key: no copy here.
    assert!(app.install.imported.as_ref().unwrap().key.is_none());
    let text = screen(&app);
    assert!(text.contains(GREEN.trim_start()), "{text}");
    assert!(text.contains("│ Replace it? agents keep working"), "{text}");
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(calls(&app), ["ca-import", "ca-replace"]);
    let text = body(&app);
    for want in [
        "    ✓ Trusting the old and the new one",
        "    ✓ Restarting the services",
        "    ✓ Replaced · agents move over in 30 days (0 s)",
    ] {
        assert!(text.contains(want), "{want}\n{text}");
    }
    assert!(!text.contains("Making the new intermediate"), "{text}");
    assert!(!text.contains("offline"), "{text}");
}

#[test]
fn no_then_replace_asks_without_importing_again() {
    let mut app = both_added();
    app.host.answers.borrow_mut().push_back(Ok(IMPORTED.into()));
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.key(Key::Right);
    app.key(Key::Enter);
    assert!(app.question.is_none());
    let added = rows(
        "✓ added · Lime Lab OpenVIBES CA",
        "✓ added · matches the certificate",
    );
    assert_eq!(body(&app), replace_body(&added, 2, GREEN, &keys("Replace")));
    app.key(Key::Enter);
    assert!(app.question.is_some());
    assert_eq!(calls(&app), ["ca-import"]);
}

#[test]
fn replace_refuses_another_root() {
    let mut app = both_added();
    let why = "openvibes-admin helper: Replace: under Other Root CA, not Lime Lab Root CA, so \
               agents would stop trusting this host. Ask for one under the same root.";
    let refused = Err(HostError::Failed(why.into()));
    app.host.answers.borrow_mut().push_back(refused);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(app.question.is_none());
    let text = body(&app);
    assert!(
        text.contains(
            "    ✗ Replace: under Other Root CA, not Lime Lab Root CA, so agents would stop\n    \
             trusting this host. Ask for one under the same root."
        ),
        "{text}"
    );
    assert_eq!(calls(&app), ["ca-import"]);
    // Replace again asks the helper again: nothing was kept.
    assert!(app.install.import_done.is_none());
}

#[test]
fn replace_refuses_the_old_key() {
    // The key of the intermediate in use, with the next certificate.
    let mut app = replace_page();
    paste(&mut app, 0, Which::Cert, &format!("{OURS}{ISSUING}{ROOT}"));
    app.key(Key::Enter);
    paste(&mut app, 1, Which::Key, OLD_KEY);
    let text = screen(&app);
    assert!(
        text.contains("✗ Not the key of Lime Lab OpenVIBES CA: paste the key it was made with."),
        "{text}"
    );
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Add(Which::Key)));
    app.key(Key::Esc);
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Replace));
    let text = screen(&app);
    assert!(
        text.contains("Private key                not added yet"),
        "{text}"
    );
    app.nav.row = 2;
    app.key(Key::Enter);
    assert!(app.question.is_none() && app.asking.is_none());
    assert!(calls(&app).is_empty(), "nothing staged");
}

#[test]
fn leaving_replace_forgets_the_key() {
    let mut app = both_added();
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Certificates));
    assert!(app.install.imported.is_none());
}
