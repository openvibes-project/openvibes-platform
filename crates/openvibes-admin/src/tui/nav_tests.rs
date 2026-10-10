//! Navigation: Home, Esc, ?, q, and today's screens behind Maintenance.

use super::{
    app::{Key, Tab},
    nav::Screen,
    tests::{app, screen},
};

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
    assert!(screen(&app, 80, 24).contains("Keys"));
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
    assert!(
        text.starts_with("    limebox") || text.contains("Maintenance › Settings files"),
        "{text}"
    );
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
    app.open(Tab::Configuration);
    // The first fields belong to Setup and are read-only here.
    while app.config.form.as_ref().unwrap().fields()[app.config.selected].key
        != "max_inventory_in_flight"
    {
        app.key(Key::Down);
    }
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
