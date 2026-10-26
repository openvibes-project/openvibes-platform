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
        certs_page_tests::{PLATFORM, day, framed, keys, menu, put},
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
/// Right under the root.
const DIRECT: &str = fixture!("client-only.crt");

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
            "Agents",
            format!("renewed automatically · next {}", day(50)),
        ),
        ("Console", PLATFORM.into()),
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
            ("Console certificate", "use your own".into()),
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
    let mut app = imported();
    app.host.pems[1].1 = DIRECT.into();
    std::fs::remove_file(app.root.join("etc/openvibes/pki/chain.crt")).unwrap();
    app.open_page(Page::Certificates);
    let text = body(&app);
    assert!(
        text.contains("    Signed by                  Lime Lab Root CA\n"),
        "{text}"
    );
}

/// The Signed by row's text, and whether it is red.
fn signed_by_row(app: &App<SetupHost>) -> Option<(String, bool)> {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| render(frame, app)).unwrap();
    let buffer = terminal.backend().buffer();
    let text = screen(app);
    let y = text.lines().position(|l| l.contains("Signed by"))?;
    let line = text.lines().nth(y).unwrap();
    let value = line["    Signed by".len()..].trim().to_owned();
    let x = line[..line.find(&value).unwrap()].chars().count() as u16;
    let red = buffer[(x, y as u16)].fg == ratatui::style::Color::Red;
    Some((value, red))
}

#[test]
fn a_lost_chain_is_said_not_the_root() {
    let mut app = imported();
    std::fs::remove_file(app.root.join("etc/openvibes/pki/chain.crt")).unwrap();
    app.open_page(Page::Certificates);
    assert_eq!(
        signed_by_row(&app),
        Some(("chain.crt is missing".into(), true))
    );
    // Your own CA, under a sub-CA, too.
    app.host.plan = plan_text().replace("quick", "careful");
    app.open_page(Page::Certificates);
    assert_eq!(
        signed_by_row(&app),
        Some(("chain.crt is missing".into(), true))
    );
}

#[test]
fn your_own_ca_under_a_sub_ca_shows_the_path() {
    let mut app = imported();
    app.host.plan = plan_text().replace("quick", "careful");
    app.open_page(Page::Certificates);
    assert_eq!(
        signed_by_row(&app),
        Some(("Lime Lab Issuing CA › Lime Lab Root CA".into(), false))
    );
    // Right under the root: the Intermediate row names it already.
    app.host.pems[1].1 = DIRECT.into();
    std::fs::remove_file(app.root.join("etc/openvibes/pki/chain.crt")).unwrap();
    app.open_page(Page::Certificates);
    assert_eq!(signed_by_row(&app), None);
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
    assert_eq!(body(&app), replace_body(&added, 2, GREEN, &keys("Replace")));
    assert!(calls(&app).is_empty(), "nothing is sent before Yes");

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
    assert!(
        screen(&app).contains("│ Replace it? agents keep working"),
        "{}",
        screen(&app)
    );
    assert!(calls(&app).is_empty(), "the question comes first");
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    // One run, one password: the import, then the replacement.
    assert_eq!(calls(&app), ["ca-import", "ca-replace"]);
    assert!(app.install.imported.as_ref().unwrap().key.is_none());
    match &app.run.as_ref().unwrap().work.calls[0] {
        crate::tui::run::Call::CaImport(bundle) => assert!(bundle.0.is_empty()),
        call => panic!("{call:?}"),
    }
    let text = body(&app);
    for want in [
        "    ✓ Trusting the old and the new one",
        "    ✓ Restarting the services",
        "    ✓ Replaced · agents move over in 30 days",
    ] {
        assert!(text.contains(want), "{want}\n{text}");
    }
    assert!(!text.contains("Making the new intermediate"), "{text}");
    assert!(!text.contains("offline"), "{text}");
}

#[test]
fn no_stages_nothing() {
    let mut app = both_added();
    app.key(Key::Enter);
    app.key(Key::Right);
    app.key(Key::Enter);
    assert!(app.question.is_none() && app.asking.is_none());
    let added = rows(
        "✓ added · Lime Lab OpenVIBES CA",
        "✓ added · matches the certificate",
    );
    assert_eq!(body(&app), replace_body(&added, 2, GREEN, &keys("Replace")));
    assert!(calls(&app).is_empty(), "no ca-import");
    app.key(Key::Esc);
    assert!(app.install.imported.is_none());
    assert!(calls(&app).is_empty());
}

#[test]
fn replace_refuses_another_root() {
    // This host's root is another: said at once, nothing to Replace.
    let mut app = imported();
    let other = platform_pki::generate_root(chrono::Utc::now()).unwrap();
    put(&app, "/etc/openvibes/pki/root.crt", &other.cert_pem);
    app.open_page(Page::Certificates);
    app.key(Key::Down);
    app.key(Key::Enter);
    paste(&mut app, 0, Which::Cert, &format!("{OURS}{ISSUING}{ROOT}"));
    app.key(Key::Enter);
    paste(&mut app, 1, Which::Key, OURS_KEY);
    app.key(Key::Enter);
    let text = body(&app);
    assert!(
        text.contains(
            "    ✗ Replace: under Lime Lab Root CA, not OpenVIBES Root CA, so agents would\n    \
             stop trusting this host. Ask for one under the same root."
        ),
        "{text}"
    );
    assert!(!text.contains("Enter  Replace"), "{text}");
    app.key(Key::Enter);
    assert!(app.question.is_none() && app.asking.is_none());
    assert!(calls(&app).is_empty());
}

#[test]
fn replace_refuses_the_intermediate_in_use() {
    let mut app = replace_page();
    paste(&mut app, 0, Which::Cert, &format!("{OLD}{ISSUING}{ROOT}"));
    app.key(Key::Enter);
    paste(&mut app, 1, Which::Key, OLD_KEY);
    app.key(Key::Enter);
    let text = body(&app);
    assert!(
        text.contains("    ✗ This is the intermediate already in use: ask your PKI for a new one."),
        "{text}"
    );
    app.key(Key::Enter);
    assert!(app.question.is_none());
    assert!(calls(&app).is_empty());
}

#[test]
fn a_helper_refusal_runs_no_ca_replace() {
    let mut app = both_added();
    let why = "openvibes-admin helper: Replace: under Other Root CA, not Lime Lab Root CA, so \
               agents would stop trusting this host. Ask for one under the same root.";
    let refused = Err(HostError::Failed(why.into()));
    app.host.answers.borrow_mut().push_back(refused);
    app.key(Key::Enter);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(calls(&app), ["ca-import"]);
    let text = body(&app);
    assert!(
        text.contains(
            "    ✗ Replace: under Other Root CA, not Lime Lab Root CA, so agents would stop"
        ),
        "{text}"
    );
    assert!(app.install.imported.as_ref().unwrap().key.is_none());
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

#[test]
fn a_pfx_reads_as_at_install_under_replace() {
    let mut app = replace_page();
    let home = app.root.join("home/lab");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("ours.pfx"), fixture_bytes()).unwrap();
    app.install.home = Some(home.display().to_string());
    // The location itself, not its drawn line: a long host name cuts that.
    app.hostname = "a-host-name-as-long-as-a-ci-runners".into();
    let location = |app: &App<SetupHost>| crate::tui::nav::header(app).0;
    app.key(Key::Enter);
    assert_eq!(
        location(&app),
        "a-host-name-as-long-as-a-ci-runners · Maintenance › Certificates › Replace › Certificate"
    );
    app.key(Key::Down);
    app.key(Key::Enter);
    app.nav.row = (app.install.pick.as_ref().unwrap().rows().iter())
        .position(|(n, _)| n == "ours.pfx")
        .unwrap();
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        text.contains("✓ ~/ours.pfx · a .p12 file: it is locked with a password"),
        "{text}"
    );
    type_text(&mut app, "correct horse");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Replace));
    let text = screen(&app);
    assert!(
        text.contains("✓ Under the same root: agents keep working."),
        "{text}"
    );
    assert!(
        text.contains("From ~/ours.pfx. Delete that file now: its key is kept here."),
        "{text}"
    );
    app.nav.row = 1;
    app.key(Key::Enter);
    assert_eq!(
        location(&app),
        "a-host-name-as-long-as-a-ci-runners · Maintenance › Certificates › Replace › Private key"
    );
}

fn fixture_bytes() -> &'static [u8] {
    include_bytes!("../../../../platform-pki/tests/fixtures/modern.pfx")
}

#[test]
fn with_every_row_the_console_certificate_is_still_reached() {
    // An import's Signed by and a previous intermediate: the list scrolls.
    let mut app = imported();
    put(&app, "/etc/openvibes/pki/previous.crt", OLD);
    let until = chrono::Utc::now() + chrono::Duration::days(31);
    put(
        &app,
        "/etc/openvibes/pki/previous-until",
        &until.to_rfc3339(),
    );
    app.open_page(Page::Certificates);
    app.key(Key::Down);
    app.key(Key::Down);
    let text = screen(&app);
    assert!(text.contains("  ▸ Console certificate"), "{text}");
    assert!(text.contains("⭡ 1 more"), "{text}");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::ConsoleUse));
}
