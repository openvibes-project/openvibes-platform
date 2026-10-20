//! Maintenance › Certificates and Names, key by key (maint2b.py #18-23).

use chrono::{Duration, Utc};
use platform_pki::{Issuer, generate_root, intermediate_request, sign_intermediate};

use crate::{
    setup::plan::plan_of,
    tui::{
        app::{App, Key},
        maint::Page,
        script_host::{PLAN, SetupHost, app_taken, screen, type_text},
    },
};

const INGEST: &str = "/etc/openvibes/tls/ingest.crt";
const INTERMEDIATE: &str = "/etc/openvibes/pki/intermediate.crt";

/// The plan of mockup #19: limebox.lan and one other name.
fn plan_text() -> String {
    PLAN.replace("platform.example.com", "limebox.lan")
        .replace("sans = []", "sans = [\"192.168.1.10\"]")
}

/// Real certificates, the server one issued `age` days ago.
fn pems(age: i64) -> Vec<(&'static str, String)> {
    let then = Utc::now() - Duration::days(age);
    let root = generate_root(then).unwrap();
    let (csr, key) = intermediate_request().unwrap();
    let int = sign_intermediate(&root, &csr, then).unwrap();
    let issuer = Issuer::load(&int, &key).unwrap();
    let names = ["limebox.lan".to_owned(), "192.168.1.10".to_owned()];
    let server = issuer.issue_server(&names, then).unwrap();
    vec![(INGEST, server.cert_pem), (INTERMEDIATE, int)]
}

fn app_with(pems: Vec<(&'static str, String)>) -> App<SetupHost> {
    let mut app = app_taken(true, vec![], vec![]);
    app.host.plan = plan_text();
    app.host.pems = pems;
    app
}

/// Certificates, then Names (Enter on its only entry).
fn names_page() -> App<SetupHost> {
    let mut app = app_with(pems(10));
    app.open_page(Page::Certificates);
    app.key(Key::Enter);
    app
}

fn type_row(app: &mut App<SetupHost>, row: usize, text: &str) {
    app.nav.row = row;
    app.key(Key::Enter);
    for _ in 0..40 {
        app.key(Key::Backspace);
    }
    type_text(app, text);
}

fn setup_plan_call(app: &App<SetupHost>) -> String {
    let calls = app.host.calls.borrow();
    calls
        .iter()
        .map(|c| c.0.clone())
        .find(|c| c.starts_with("setup-plan"))
        .expect("a setup-plan call")
}

#[test]
fn the_report_shows_dates_names_and_signer() {
    let mut app = app_with(pems(10));
    app.open_page(Page::Certificates);
    let end = (Utc::now() + Duration::days(80)).format("%Y-%m-%d");
    let text = screen(&app);
    for want in [
        "Maintenance › Certificates",
        &format!("valid until {end} · 80 days left"),
        "limebox.lan, 192.168.1.10",
        "signed by OpenVIBES Root CA · until",
        "Root key",
        "offline: needed only to replace the intermediate",
        "add or remove a name agents use",
        "Names agents and browsers may use to reach this host.",
        "Enter  Names",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    // A certificate that ended says so.
    let mut app = app_with(pems(100));
    app.open_page(Page::Certificates);
    let text = screen(&app);
    assert!(text.contains("expired 20"), "{text}");
    // A careful CA's root is not here: no Root key row.
    let mut app = app_with(pems(10));
    app.host.plan = plan_text().replace("quick", "careful");
    app.open_page(Page::Certificates);
    assert!(!screen(&app).contains("Root key"));
}

#[test]
fn no_certificates_says_run_repair() {
    let mut app = app_with(vec![]);
    app.host.plan = String::new();
    app.open_page(Page::Certificates);
    let text = screen(&app);
    assert!(text.contains("No certificates yet: run Repair."), "{text}");
    assert!(!text.contains("signed by"), "{text}");
}

#[test]
fn the_names_page_lists_the_host_and_the_other_names() {
    let app = names_page();
    let text = screen(&app);
    for want in [
        "Maintenance › Certificates › Names",
        "Host name",
        "limebox.lan",
        "Other name",
        "192.168.1.10",
        "Add a name",
        "an address or DNS name",
        "The name this host is known by.",
        "Enter  Change",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    assert!(!text.contains("Apply"), "{text}");
}

#[test]
fn a_bad_name_is_said_at_once() {
    let mut app = names_page();
    type_row(&mut app, 1, "openvibes.lime.lan");
    let text = screen(&app);
    assert!(
        text.contains("A valid DNS name.") && text.contains("Other name: type a name"),
        "{text}"
    );
    app.key(Key::Esc);
    type_row(&mut app, 1, "Open Vibes");
    let text = screen(&app);
    assert!(
        text.contains("✗ Not a DNS name or an address: letters, digits, dots and dashes."),
        "{text}"
    );
    // Enter keeps the text and adds nothing.
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        text.contains("open vibes█") && !text.contains("Apply"),
        "{text}"
    );
    app.key(Key::Esc);
    type_row(&mut app, 1, "192.168.1.11");
    assert!(screen(&app).contains("An address."));
    app.key(Key::Esc);
    type_row(&mut app, 1, "limebox.lan");
    assert!(screen(&app).contains("✗ That name is already in the list."));
}

#[test]
fn adding_a_name_then_apply_passes_every_san() {
    let mut app = names_page();
    // Add a name is row 2; the name is typed on the row before it.
    app.nav.row = 2;
    app.key(Key::Enter);
    type_text(&mut app, "openvibes.lime.lan");
    assert!(screen(&app).contains("A valid DNS name."));
    app.key(Key::Enter);
    let text = screen(&app);
    for want in [
        "* Other name",
        "openvibes.lime.lan · new",
        "Apply",
        "new certificates with these names",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    app.nav.row = 4;
    assert!(screen(&app).contains("Agents keep working; browsers see the new names."));
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        text.contains("Issue new certificates?") && text.contains("for these names"),
        "{text}"
    );
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let mut plan = plan_of(&plan_text()).unwrap();
    plan.sans.push("openvibes.lime.lan".into());
    let call = setup_plan_call(&app);
    assert_eq!(call, format!("setup-plan {}", plan.args().join(" ")));
    assert!(
        call.contains("--san 192.168.1.10 --san openvibes.lime.lan --ca quick"),
        "{call}"
    );
    let calls: Vec<String> = app
        .host
        .calls
        .borrow()
        .iter()
        .map(|c| c.0.clone())
        .collect();
    assert_eq!(calls.last().unwrap(), "setup-status");
    let text = screen(&app);
    for want in [
        "Save the names",
        "New certificates",
        "Restart services",
        "Ready",
        "Enter  Back",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    // The date is read again from the new certificate.
    let end = (Utc::now() + Duration::days(80)).format("%Y-%m-%d");
    assert!(
        text.contains(&format!(
            "New certificates with 3 names · valid until {end} ("
        )),
        "{text}"
    );
    // Back lands on the report.
    app.key(Key::Enter);
    assert!(
        screen(&app).contains("Maintenance › Certificates\n") || screen(&app).contains("signed by")
    );
}

#[test]
fn emptying_an_other_name_removes_it() {
    let mut app = names_page();
    type_row(&mut app, 1, "");
    assert!(screen(&app).contains("Enter removes this name."));
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        !text.contains("192.168.1.10") && text.contains("Apply"),
        "{text}"
    );
    app.nav.row = 2;
    app.key(Key::Enter);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let call = setup_plan_call(&app);
    assert!(!call.contains("--san"), "{call}");
    assert!(
        screen(&app).contains("New certificates with 1 name · valid until"),
        "{}",
        screen(&app)
    );
}

#[test]
fn the_host_name_cannot_be_emptied() {
    let mut app = names_page();
    type_row(&mut app, 0, "");
    assert!(screen(&app).contains("✗ The host name is needed."));
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(app.maint.editing() && !text.contains("Apply"), "{text}");
    app.key(Key::Esc);
    assert!(screen(&app).contains("limebox.lan"));
    // An address is not a host name.
    type_row(&mut app, 0, "192.168.1.10");
    assert!(screen(&app).contains("✗ Not a DNS name"));
}

#[test]
fn at_most_16_other_names() {
    let mut app = names_page();
    for i in 0..15 {
        // Add a name follows the host name and the other names.
        app.nav.row = 2 + i;
        app.key(Key::Enter);
        type_text(&mut app, &format!("n{i}.lan"));
        app.key(Key::Enter);
    }
    app.nav.row = 17;
    app.key(Key::Enter);
    assert!(!app.maint.editing());
    assert_eq!(
        app.outcome,
        Some((false, "✗ At most 16 other names.".to_owned()))
    );
}

/// The Apply row's help after `edit` on the page.
fn apply_help(edit: impl Fn(&mut App<SetupHost>)) -> String {
    let mut app = names_page();
    edit(&mut app);
    for _ in 0..10 {
        app.key(Key::Down);
    }
    screen(&app)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn apply_says_who_stops_connecting() {
    // Only added: agents keep working.
    let text = apply_help(|app| {
        app.nav.row = 2;
        app.key(Key::Enter);
        type_text(app, "new.lan");
        app.key(Key::Enter);
    });
    assert!(
        text.contains("Agents keep working; browsers see the new names."),
        "{text}"
    );
    // The host name changed.
    let text = apply_help(|app| {
        type_row(app, 0, "other.lan");
        app.key(Key::Enter);
    });
    assert!(
        text.contains(
            "Agents that use limebox.lan stop connecting: they need the new install line."
        ),
        "{text}"
    );
    // A name removed.
    let text = apply_help(|app| {
        type_row(app, 1, "");
        app.key(Key::Enter);
    });
    assert!(
        text.contains(
            "Agents that use 192.168.1.10 stop connecting: they need the new install line."
        ),
        "{text}"
    );
    // Both.
    let text = apply_help(|app| {
        type_row(app, 1, "");
        app.key(Key::Enter);
        type_row(app, 0, "other.lan");
        app.key(Key::Enter);
    });
    assert!(
        text.contains(
            "Agents that use a removed name stop connecting: they need the new install line."
        ),
        "{text}"
    );
}

#[test]
fn names_are_lowercased_as_typed() {
    let mut app = names_page();
    type_row(&mut app, 0, "LimeBox2.lan");
    let text = screen(&app);
    assert!(
        text.contains("limebox2.lan█") && text.contains("A valid DNS name."),
        "{text}"
    );
    app.key(Key::Enter);
    assert!(screen(&app).contains("limebox2.lan · was limebox.lan"));
}
