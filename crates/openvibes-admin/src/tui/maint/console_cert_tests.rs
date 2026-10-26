//! Maintenance › Certificates › Console certificate (certs4c.py #1-#11):
//! the Console row, your own certificate through 4b's rows, the question,
//! the result line, and going back to the platform's.

use crate::tui::{
    app::{App, Key},
    install::{Stage, Which},
    maint::{
        Page,
        certs_page_tests::{PLATFORM, framed, keys, menu, ours, page_body},
        certs_tests::{app_with, pems, plan_text},
    },
    nav::{Screen, header},
    run::Call,
    script_host::{SetupHost, body, screen, type_text},
};

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!("../../../../platform-pki/tests/fixtures/", $name))
    };
}
const SERVER: &str = fixture!("server.crt");
const SERVER_KEY: &str = fixture!("server.key");
const ISSUING: &str = fixture!("issuing.crt");
const OTHER_KEY: &str = fixture!("ours-ec.pkcs8.pem");
const NOTE: &str = "    For the console in the browser only; agents keep the platform's.";

/// The screen's words, one space apart: a long line wraps.
fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn calls(app: &App<SetupHost>) -> Vec<String> {
    let calls = app.host.calls.borrow();
    calls.iter().map(|c| c.0.clone()).collect()
}

/// A host whose names include one `*.limebox.se` covers.
fn host() -> App<SetupHost> {
    let mut app = app_with(pems(10));
    app.host.plan = plan_text().replace(
        "sans = [\"192.168.1.10\"]",
        "sans = [\"openvibes.limebox.se\", \"192.168.1.10\"]",
    );
    app
}

/// Certificates, on Console certificate.
fn certificates(app: &mut App<SetupHost>) {
    app.open_page(Page::Certificates);
    app.key(Key::Down);
    app.key(Key::Down);
}

/// Enter on Console certificate, with no certificate of your own.
fn use_page() -> App<SetupHost> {
    let mut app = host();
    certificates(&mut app);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::ConsoleUse));
    app
}

/// From the page: `row`'s Paste it with `text`.
fn paste(app: &mut App<SetupHost>, row: usize, which: Which, text: &str) {
    app.nav.row = row;
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Add(which)));
    app.key(Key::Enter);
    app.key(Key::Paste(text.to_owned()));
}

fn both_added() -> App<SetupHost> {
    let mut app = use_page();
    paste(&mut app, 0, Which::Cert, &format!("{SERVER}{ISSUING}"));
    app.key(Key::Enter);
    paste(&mut app, 1, Which::Key, SERVER_KEY);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::ConsoleUse));
    app
}

fn use_body(rows: &[(&str, String)], row: usize, bar: &str) -> String {
    let mut lines = vec![NOTE.to_owned(), String::new()];
    lines.extend(menu(rows, row));
    framed("Use your own certificate", lines, bar)
}

#[test]
fn certificates_shows_the_console_row_and_the_third_action() {
    let mut app = host();
    certificates(&mut app);
    let rows = ours(&app.host.pems, None);
    assert_eq!(rows[1], ("Console", PLATFORM.to_owned()));
    assert_eq!(body(&app), page_body(&rows, true, 2));
}

#[test]
fn the_page_and_its_rows_match_certs4c() {
    let app = use_page();
    let rows = [
        ("Certificate", "not added yet".into()),
        ("Private key", "not added yet".into()),
        ("Use it", "once both are added".into()),
    ];
    assert_eq!(body(&app), use_body(&rows, 0, &keys("Open")));
    assert!(
        header(&app)
            .0
            .ends_with(" · Maintenance › Certificates › Console")
    );
}

#[test]
fn a_pasted_certificate_says_what_it_covers() {
    let mut app = use_page();
    paste(&mut app, 0, Which::Cert, &format!("{SERVER}{ISSUING}"));
    assert!(
        header(&app)
            .0
            .ends_with(" · Maintenance › Certificates › Console › Certificate")
    );
    let text = screen(&app);
    for line in [
        "    The console's certificate first, then the CAs above it.",
        "    ✓ *.limebox.se · for server use · valid until 2046-01-01",
        "    ✓ Covers openvibes.limebox.se, one of this console's names.",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
    assert!(text.contains("Enter  Use it"), "{text}");
}

#[test]
fn covers_none_is_red_and_use_it_does_nothing() {
    let mut app = host();
    app.host.plan = plan_text();
    certificates(&mut app);
    app.key(Key::Enter);
    paste(&mut app, 0, Which::Cert, SERVER);
    let text = screen(&app);
    assert!(
        text.contains("    ✓ *.limebox.se · for server use · valid until 2046-01-01"),
        "{text}"
    );
    assert!(
        text.contains("    ✗ Covers none of this console's names: add one under Names first."),
        "{text}"
    );
    assert!(!text.contains("Use it"), "{text}");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Add(Which::Cert)));
    assert!(app.install.imported.is_none());
}

#[test]
fn refused_certificates_and_keys_say_so() {
    for (pem, said) in [
        (
            ISSUING,
            "✗ This is a CA certificate: pick the console's own certificate.",
        ),
        (
            fixture!("server-client-only.crt"),
            "✗ Not for servers (its extended key usage): ask for a server certificate.",
        ),
        (
            fixture!("server-expired.crt"),
            "✗ Expired on 2026-06-01: ask for a new one.",
        ),
        (
            fixture!("server-future.crt"),
            "✗ Valid from 2040-01-01: not valid yet.",
        ),
    ] {
        let mut app = use_page();
        paste(&mut app, 0, Which::Cert, pem);
        assert!(
            flat(&screen(&app)).contains(said),
            "{said}\n{}",
            screen(&app)
        );
    }
    let mut app = use_page();
    paste(&mut app, 0, Which::Cert, SERVER);
    app.key(Key::Enter);
    paste(&mut app, 1, Which::Key, OTHER_KEY);
    let text = flat(&screen(&app));
    assert!(
        text.contains("✗ Not the key of *.limebox.se: paste the key it was made with."),
        "{text}"
    );
}

#[test]
fn both_added_match_certs4c() {
    let app = both_added();
    let rows = [
        ("Certificate", "✓ added · *.limebox.se".into()),
        ("Private key", "✓ added · matches the certificate".into()),
        ("Use it", "the console restarts".into()),
    ];
    assert_eq!(body(&app), use_body(&rows, 2, &keys("Use it")));
    // Ours first, the CA above it, then the key.
    let Some(Call::ConsoleCertSet(bundle)) = app.install.import_call() else {
        panic!("no console-cert-set");
    };
    let want = format!(
        "{}\n{}\n{}\n",
        SERVER.trim_end(),
        ISSUING.trim_end(),
        SERVER_KEY.trim_end()
    );
    assert_eq!(*bundle.0, want);
}

#[test]
fn use_your_own_sends_set_on_yes() {
    let mut app = both_added();
    app.host
        .answers
        .borrow_mut()
        .push_back(Ok("set\t*.limebox.se\t2046-01-01\n".into()));
    app.key(Key::Enter);
    assert!(
        screen(&app).contains("│ Use it? the console restarts"),
        "{}",
        screen(&app)
    );
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(calls(&app), ["console-cert-set"]);
    assert_eq!(app.host.calls.borrow()[0].1, "pw");
    let text = screen(&app);
    assert!(
        text.contains("✓ The console uses your certificate · until 2046-01-01"),
        "{text}"
    );
    // The key is forgotten once the helper has it; the rows stay added.
    assert!(app.install.imported.as_ref().unwrap().key.is_none());
    assert!(text.contains("✓ added · matches the certificate"), "{text}");
    app.key(Key::Enter);
    assert_eq!(calls(&app).len(), 1);
}

#[test]
fn no_sends_nothing() {
    let mut app = both_added();
    app.key(Key::Enter);
    app.key(Key::Char('n'));
    assert!(calls(&app).is_empty());
    assert_eq!(app.nav.screen, Screen::Maint(Page::ConsoleUse));
    // Esc leaves the page: the key and the certificate are forgotten.
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Certificates));
    assert!(app.install.imported.is_none());
    assert!(app.install.server.is_none());
}

#[test]
fn a_pfx_fills_both_rows() {
    let mut app = use_page();
    let home = app.root.join("home/lab");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("console.pfx"),
        include_bytes!("../../../../platform-pki/tests/fixtures/server.pfx"),
    )
    .unwrap();
    app.install.home = Some(home.display().to_string());
    app.key(Key::Enter);
    app.key(Key::Down);
    app.key(Key::Enter);
    app.nav.row = (app.install.pick.as_ref().unwrap().rows().iter())
        .position(|(n, _)| n == "console.pfx")
        .unwrap();
    app.key(Key::Enter);
    type_text(&mut app, "correct horse");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::ConsoleUse));
    let text = screen(&app);
    assert!(text.contains("✓ added · *.limebox.se"), "{text}");
    assert!(text.contains("✓ added · matches the certificate"), "{text}");
    assert!(
        text.contains("From ~/console.pfx. Delete that file now: its key is kept here."),
        "{text}"
    );
    assert_eq!(app.nav.row, 2);
}

/// A host whose console uses your own certificate, on its page.
fn own_page() -> App<SetupHost> {
    let mut app = host();
    app.host.own = Some(format!("{SERVER}{ISSUING}"));
    certificates(&mut app);
    let text = body(&app);
    for line in [
        format!(
            "    {:<26} your own · *.limebox.se · until 2046-01-01",
            "Console"
        ),
        format!(
            "  ▸ {:<26} use a new one, or go back to the platform's",
            "Console certificate"
        ),
    ] {
        assert!(text.contains(&line), "{line}\n{text}");
    }
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Console));
    app
}

#[test]
fn once_yours_is_in_the_page_offers_new_or_back() {
    let mut app = own_page();
    let gone = |row| {
        let mut lines = vec![
            "    Yours: *.limebox.se, until 2046-01-01.".to_owned(),
            String::new(),
        ];
        lines.extend(menu(
            &[
                ("Use a new one", "paste or pick, as before".into()),
                (
                    "Go back to the platform's",
                    "renewed automatically with the agents".into(),
                ),
            ],
            row,
        ));
        lines
    };
    assert_eq!(
        body(&app),
        framed("The console's certificate", gone(0), &keys("Use a new one"))
    );
    app.key(Key::Down);
    assert_eq!(
        body(&app),
        framed("The console's certificate", gone(1), &keys("Go back"))
    );
    // Use a new one: the page of your own, empty; Esc comes back here.
    app.key(Key::Up);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::ConsoleUse));
    assert!(screen(&app).contains("not added yet"));
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Console));
}

#[test]
fn go_back_sends_reset() {
    let mut app = own_page();
    app.host
        .answers
        .borrow_mut()
        .push_back(Ok("reset\n".into()));
    app.key(Key::Down);
    app.key(Key::Enter);
    assert!(
        screen(&app).contains("│ Go back? the console restarts"),
        "{}",
        screen(&app)
    );
    app.key(Key::Char('n'));
    assert!(calls(&app).is_empty());
    app.key(Key::Enter);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(calls(&app), ["console-cert-reset"]);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Certificates));
    let text = screen(&app);
    assert!(
        text.contains("✓ The console uses the platform's certificate again"),
        "{text}"
    );
}

#[test]
fn a_refusal_is_said_in_the_bar() {
    let mut app = both_added();
    app.host
        .answers
        .borrow_mut()
        .push_back(Err(platform_host::HostError::Failed(
        "openvibes-admin helper: Covers none of this console's names: add one under Names first."
            .into(),
    )));
    app.key(Key::Enter);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        text.contains("✗ Covers none of this console's names: add one under Names first."),
        "{text}"
    );
    assert!(app.install.imported.as_ref().unwrap().key.is_none());
}

#[test]
fn soon_and_ended_rows_are_amber_and_red() {
    use super::certs::console_row;
    use chrono::{Duration, TimeZone, Utc};
    let app = host();
    let t = &app.theme;
    let end = Utc.with_ymd_and_hms(2046, 1, 1, 0, 0, 0).unwrap();
    let text = |at| {
        let spans = console_row(t, Some(SERVER), at);
        spans
            .iter()
            .map(|s| s.content.to_string())
            .collect::<String>()
    };
    assert_eq!(
        text(end - Duration::days(21)),
        "your own · ends 2046-01-01, in 21 days"
    );
    assert_eq!(
        text(end + Duration::days(1)),
        "your own · ended on 2046-01-01"
    );
    let red = console_row(t, Some(SERVER), end + Duration::days(1));
    assert_eq!(red[0].style, t.red());
    let amber = console_row(t, Some(SERVER), end - Duration::days(21));
    assert_eq!(amber[0].style, t.yellow());
}
