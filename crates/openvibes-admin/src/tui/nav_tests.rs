//! Navigation: Home, Esc, ?, q, and today's screens behind Maintenance.

use std::sync::mpsc;

use platform_host::{Database, Unit};

use super::{
    app::{App, Key, Tab},
    database::Check,
    nav::Screen,
    setup::Phase,
    setup_tests::set_up,
    status::Item,
    tests::{FakeHost, app, screen},
};

/// Configuration, highlighting a field Setup does not own (the first
/// fields are Setup's, read-only here).
fn editable_field(app: &mut App<FakeHost>) {
    app.open(Tab::Configuration);
    while app.config.form.as_ref().unwrap().fields()[app.config.selected].key
        != "max_inventory_in_flight"
    {
        app.key(Key::Down);
    }
}

fn type_text<H: platform_host::Host>(app: &mut App<H>, text: &str) {
    for c in text.chars() {
        app.key(Key::Char(c));
    }
}

#[test]
fn a_set_up_host_opens_home_with_the_frame() {
    let app = app(false);
    assert_eq!(app.nav.screen, Screen::Home);
    let text = screen(&app, 80, 24);
    assert!(text.contains("██████╗"), "the logo:\n{text}");
    for want in ["Status", "Maintenance", "Quit", " q  Quit", "⭡⭣  Move"] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    assert!(!text.contains("[Setup]"), "no tab bar any more");
}

#[test]
fn enter_opens_esc_goes_back_and_q_quits_only_from_home() {
    let mut app = app(false);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Status);
    app.key(Key::Char('q'));
    assert!(!app.quit, "q quits from Home only");
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Home);
    app.key(Key::Char('q'));
    assert!(app.quit);
}

#[test]
fn question_mark_opens_help_and_esc_closes_it() {
    let mut app = app(false);
    app.key(Key::Char('?'));
    assert!(matches!(app.nav.screen, Screen::Help(_)));
    let text = screen(&app, 80, 24);
    assert!(text.contains("Keys"), "{text}");
    let bar = text.lines().rev().nth(1).unwrap();
    assert!(
        bar.contains("Esc  Close") && !bar.contains("Move") && !bar.contains('?'),
        "Help's bar is Esc Close only:\n{text}"
    );
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Home);
}

#[test]
fn maintenance_reaches_todays_screens_and_esc_comes_back() {
    let mut app = app(false);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maintenance);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(
        (app.nav.screen.clone(), app.tab),
        (Screen::Legacy, Tab::Configuration)
    );
    let text = screen(&app, 80, 24);
    assert!(text.contains("Maintenance › Settings files"), "{text}");
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Maintenance);
}

#[test]
fn esc_while_typing_in_a_legacy_screen_cancels_the_field_not_the_screen() {
    let mut app = app(false);
    editable_field(&mut app);
    app.key(Key::Enter); // edit the field
    assert!(app.config.editing.is_some());
    app.key(Key::Esc);
    assert!(app.config.editing.is_none(), "the field is cancelled");
    assert_eq!(app.nav.screen, Screen::Legacy, "still on the screen");
}

#[test]
fn a_fresh_host_opens_the_setup_form_and_esc_does_not_leave_it() {
    let mut app = super::setup_tests::fresh_app();
    assert_eq!(
        (app.nav.screen.clone(), app.tab),
        (Screen::Legacy, Tab::Setup)
    );
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Legacy);
    app.key(Key::Char('q'));
    assert!(app.quit, "q still quits the install form");
}

#[test]
fn q_types_into_a_configuration_value() {
    let mut app = app(false);
    editable_field(&mut app);
    app.key(Key::Enter);
    app.key(Key::ClearLine);
    type_text(&mut app, "queue");
    assert_eq!(app.config.editing.as_deref(), Some("queue"));
    assert!(!app.quit);
}

#[test]
fn q_types_into_a_set_up_hosts_setup_password_and_quits_nothing_there() {
    let mut app = set_up(vec![Ok("failed\tport 443 is taken\n".into())]);
    app.open(Tab::Setup);
    app.key(Key::Char('r'));
    assert!(matches!(app.setup.phase, Phase::Password(_)));
    type_text(&mut app, "aqb");
    assert_eq!(app.setup.prompt.typed(), "aqb");
    app.key(Key::Enter);
    app.setup_tick();
    assert_eq!(app.setup.phase, Phase::Stopped(0));
    app.key(Key::Char('q'));
    assert!(!app.quit, "q quits from Home only, not from a stopped run");
    let text = super::setup_tests::screen(&app);
    let footer = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap();
    assert!(
        footer.contains("Esc back") && !footer.contains('q'),
        "a stopped run on a set-up host: {footer}"
    );
}

#[test]
fn esc_answers_the_database_question_no() {
    let mut app = app(false);
    app.open(Tab::Database);
    app.key(Key::Char('m'));
    assert!(app.database.confirm.is_some());
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Legacy);
    assert!(app.database.confirm.is_none());
    assert_eq!(*app.host.database_calls.borrow(), [Database::Status]);
}

#[test]
fn help_keys_sit_in_the_mockups_columns_and_name_the_screen() {
    let mut app = app(false);
    app.open_status();
    app.key(Key::Char('?'));
    let text = screen(&app, 80, 24);
    let col = |needle: &str| {
        let line = text.lines().find(|l| l.contains(needle)).unwrap();
        line.find(needle)
            .map(|b| line[..b].chars().count())
            .unwrap()
    };
    assert_eq!(col("move · lists scroll"), 14, "{text}");
    assert_eq!(col("back, or cancel"), 49, "{text}");
    assert!(text.contains("Here (Status):"), "{text}");
}

#[test]
fn enter_on_homes_quit_row_is_named_quit() {
    let mut app = app(false);
    assert!(screen(&app, 80, 24).contains("Enter  Open"));
    app.key(Key::Down);
    app.key(Key::Down);
    let text = screen(&app, 80, 24);
    assert!(text.contains("Enter  Quit"), "{text}");
}

#[test]
fn esc_goes_back_to_the_row_you_left() {
    let mut app = app(false);
    app.open_status();
    while !matches!(app.status_items()[app.nav.row], Item::Service(Unit::Ingest)) {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    assert_eq!(app.nav.row, 0, "the service screen starts at its top");
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Status);
    assert!(
        matches!(app.status_items()[app.nav.row], Item::Service(Unit::Ingest)),
        "ingest is highlighted again"
    );
    app.key(Key::Esc);
    app.key(Key::Down);
    app.key(Key::Enter);
    app.key(Key::Esc);
    assert_eq!((app.nav.screen.clone(), app.nav.row), (Screen::Home, 1));
}

#[test]
fn help_and_back_keep_the_scrolled_window() {
    let mut app = app(false);
    app.open_status();
    for i in 0..12 {
        app.database.health.push(Check {
            problem: true,
            text: format!("extra problem {i}"),
        });
    }
    for _ in 0..15 {
        app.key(Key::Down);
    }
    let before = screen(&app, 80, 24);
    app.key(Key::Char('?'));
    app.key(Key::Esc);
    assert_eq!(screen(&app, 80, 24), before);
}

#[test]
fn home_counts_the_health_problems_on_its_first_draw() {
    let app = app(false);
    let text = screen(&app, 80, 24);
    assert!(
        text.contains("things need attention") && !text.contains("All "),
        "{text}"
    );
    assert!(
        app.database
            .health
            .iter()
            .any(|c| c.problem && c.text.contains("ingest.crt")),
        "health was loaded at start"
    );
}

#[test]
fn health_arrives_from_the_background_without_blocking() {
    let mut app = app(false);
    app.database.health.clear();
    let (send, health) = mpsc::channel();
    app.health = Some(health);
    app.tick(std::time::Instant::now());
    assert!(app.database.health.is_empty(), "tick does not wait");
    send.send(vec![Check {
        problem: true,
        text: "disk 92% used".into(),
    }])
    .unwrap();
    app.tick(std::time::Instant::now());
    assert_eq!(app.database.health.len(), 1);
}

#[test]
fn a_failing_service_list_shows_its_error_on_home_status_and_service() {
    let mut app = app(false);
    *app.host.services_error.borrow_mut() = Some("systemctl is gone".into());
    app.refresh();
    let home = screen(&app, 80, 24);
    assert!(home.contains("systemctl is gone"), "{home}");
    app.open_status();
    *app.host.services_error.borrow_mut() = Some("systemctl is gone".into());
    app.refresh();
    let text = screen(&app, 80, 24);
    let bar = text.lines().rev().nth(1).unwrap();
    assert!(
        bar.contains("✗") && bar.contains("systemctl is gone"),
        "{text}"
    );
    *app.host.services_error.borrow_mut() = None;
    app.refresh();
    assert!(!screen(&app, 80, 24).contains("systemctl is gone"));
}

#[test]
fn no_services_is_a_problem_not_all_zero_running() {
    let mut app = app(false);
    app.services.clear();
    let text = screen(&app, 80, 24);
    assert!(!text.contains("All 0"), "{text}");
    assert!(text.contains("No services"), "{text}");
}

#[test]
fn one_problem_is_singular() {
    let mut app = app(false);
    app.database.health.clear();
    app.services
        .retain(|s| s.unit == Unit::Ingest || s.unit == Unit::Vulns);
    assert!(screen(&app, 80, 24).contains("1 thing needs attention"));
}

#[test]
fn esc_with_unsaved_settings_asks_and_yes_goes_back_to_maintenance() {
    let mut app = app(false);
    app.key(Key::Down);
    app.key(Key::Enter);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.tab, Tab::Configuration);
    editable_field(&mut app);
    app.key(Key::Enter);
    app.key(Key::ClearLine);
    type_text(&mut app, "8");
    app.key(Key::Enter);
    app.key(Key::Esc);
    assert!(app.config.prompt.is_some(), "unsaved: Esc asks first");
    app.key(Key::Esc);
    assert!(app.config.prompt.is_none());
    assert_eq!(app.nav.screen, Screen::Legacy, "Esc to the question stays");
    app.key(Key::Esc);
    app.key(Key::Char('y'));
    assert_eq!(app.nav.screen, Screen::Maintenance);
}

#[test]
fn the_update_notice_arrives_from_the_background_without_blocking() {
    let mut app = app(false);
    let (send, updates) = mpsc::channel();
    app.updates = Some(updates);
    app.tick(std::time::Instant::now());
    assert_eq!(app.update, None, "nothing yet: tick does not wait");
    send.send(Some("0.3.0".to_owned())).unwrap();
    app.tick(std::time::Instant::now());
    assert_eq!(app.update.as_deref(), Some("0.3.0"));
}

/// The line after `anchor` is the one empty line, then content follows.
fn one_gap_after(text: &str, anchor: impl Fn(&str) -> bool, what: &str) {
    let lines: Vec<&str> = text.lines().collect();
    let i = lines
        .iter()
        .position(|l| anchor(l))
        .unwrap_or_else(|| panic!("{what}: no anchor in\n{text}"));
    assert_eq!(lines[i + 1].trim(), "", "{what}: one empty line\n{text}");
    assert_ne!(
        lines[i + 2].trim(),
        "",
        "{what}: not two empty lines\n{text}"
    );
}

#[test]
fn every_screen_has_exactly_one_empty_line_under_its_title() {
    let rule = |l: &str| l.starts_with("    ━━ ");
    let mut app = app(false);
    one_gap_after(
        &screen(&app, 80, 24),
        |l| l.starts_with("    ●") || l.starts_with("    ▲"),
        "Home",
    );
    app.key(Key::Char('?'));
    one_gap_after(&screen(&app, 80, 24), rule, "Help");
    app.key(Key::Esc);
    app.key(Key::Enter);
    one_gap_after(&screen(&app, 80, 24), rule, "Status");
    while !matches!(
        app.status_items()[app.nav.row],
        super::status::Item::Service(_)
    ) {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    one_gap_after(&screen(&app, 80, 24), rule, "Service");
    app.key(Key::Esc);
    app.key(Key::Esc);
    app.key(Key::Down);
    app.key(Key::Enter);
    one_gap_after(&screen(&app, 80, 24), rule, "Maintenance");
}

#[test]
fn no_legacy_screen_advertises_tab_and_q_only_on_the_fresh_install_form() {
    for tab in [Tab::Setup, Tab::Configuration, Tab::Database] {
        let mut app = app(false);
        app.open(tab);
        let text = screen(&app, 80, 24);
        let footer = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap();
        assert!(!footer.contains("Tab"), "{tab:?}: {footer}");
        assert!(
            !footer.contains("q quit"),
            "{tab:?} on a set-up host: {footer}"
        );
        assert!(footer.contains("Esc back"), "{tab:?}: {footer}");
    }
    let fresh = super::setup_tests::fresh_app();
    let text = super::setup_tests::screen(&fresh);
    assert!(text.contains("q quit") && !text.contains("Tab"), "{text}");
}
