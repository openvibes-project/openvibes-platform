//! Navigation: Home, Esc, ?, q, and today's screens behind Maintenance.

use std::sync::mpsc;

use platform_host::Database;

use super::{
    app::{App, Key, Tab},
    nav::Screen,
    setup::Phase,
    setup_tests::set_up,
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
    assert!(
        text.contains("Esc  Back    ?"),
        "Help's bar keeps Back and ?:\n{text}"
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
    app.key(Key::Tab);
    assert_eq!(
        app.tab,
        Tab::Configuration,
        "Tab no longer switches screens"
    );
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
