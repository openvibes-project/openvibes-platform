//! Setup's maintenance screens from the user's first walk-through
//! (boards #73, #74): keys that must keep working, and a focus the user
//! can see.

use super::{
    app::{Key, Tab},
    maintain::UNINSTALL_START_ROW,
    setup::Phase,
    setup_tests::{screen, set_up, type_text},
};

/// A Repair whose first step fails: the run stops there.
fn after_a_failed_repair() -> super::app::App<super::setup_tests::SetupHost> {
    let mut app = set_up(vec![Ok("failed\tport 443 is taken\n".into())]);
    app.tab = Tab::Setup;
    app.key(Key::Char('r'));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.setup_tick();
    assert_eq!(app.setup.phase, Phase::Stopped(0));
    app
}

#[test]
fn a_failed_step_still_offers_uninstall_check_and_update() {
    // Board #73: the user's "Uninstall doesn't work" was x doing nothing
    // after a failed Repair; only r, Tab and q were live.
    let mut app = after_a_failed_repair();
    let text = screen(&app);
    for want in ["r retry", "c check", "u update", "x uninstall"] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    app.key(Key::Char('x'));
    assert_eq!(app.setup.phase, Phase::Uninstall);
}

#[test]
fn after_a_failed_step_c_checks_and_esc_goes_back() {
    let mut app = after_a_failed_repair();
    app.key(Key::Esc);
    assert_eq!(app.setup.phase, Phase::Status);
    let mut app = after_a_failed_repair();
    app.key(Key::Char('c'));
    assert!(matches!(app.setup.phase, Phase::Password(_)));
}

#[test]
fn keep_data_goes_straight_from_the_choice_to_the_button() {
    // Board #74: rows 1 and 2 (backup, typed name) exist only for Remove
    // everything; j used to land on them, invisible, and the button was
    // three presses away.
    let mut app = set_up(vec![]);
    app.tab = Tab::Setup;
    app.key(Key::Char('x'));
    assert_eq!(app.setup.row2, 0);
    app.key(Key::Char('j'));
    assert_eq!(
        app.setup.row2, UNINSTALL_START_ROW,
        "one j reaches [ Uninstall ]"
    );
    app.key(Key::Char('j'));
    assert_eq!(app.setup.row2, UNINSTALL_START_ROW, "nothing below it");
    app.key(Key::Char('k'));
    assert_eq!(app.setup.row2, 0, "and one k goes back");
}

#[test]
fn remove_everything_visits_its_two_fields() {
    let mut app = set_up(vec![]);
    app.tab = Tab::Setup;
    app.key(Key::Char('x'));
    app.key(Key::Char(' ')); // Remove everything
    let rows: Vec<usize> = (0..3)
        .map(|_| {
            app.key(Key::Down);
            app.setup.row2
        })
        .collect();
    assert_eq!(rows, [1, 2, UNINSTALL_START_ROW]);
}

#[test]
fn switching_to_keep_data_on_a_field_moves_to_a_visible_row() {
    let mut app = set_up(vec![]);
    app.tab = Tab::Setup;
    app.key(Key::Char('x'));
    app.key(Key::Char(' ')); // Remove everything
    app.key(Key::Down); // row 1
    app.setup.everything = false; // e.g. a later toggle
    app.key(Key::Down);
    assert_eq!(app.setup.row2, UNINSTALL_START_ROW, "never a hidden row");
}
