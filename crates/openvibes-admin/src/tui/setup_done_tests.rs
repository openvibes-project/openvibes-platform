//! The legacy Setup screen once the host is set up: a finished first
//! install offers no part or port changes (Maintenance has them).

use platform_host::Step;

use super::{
    app::{App, Key},
    nav::Screen,
    script_host::*,
    setup::{Phase, START_ROW},
};

/// A first install run to its Finished screen; setup.toml then exists.
fn finished() -> App<SetupHost> {
    let mut app = app(false, vec![]);
    while app.setup.row != START_ROW {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    for _ in Step::ALL {
        app.setup_tick();
    }
    assert_eq!(app.setup.phase, Phase::Finished);
    app.host.set_up = true;
    app.host.plan = PLAN.into();
    app
}

#[test]
fn a_finished_install_offers_no_part_or_port_changes() {
    let mut app = finished();
    let text = screen(&app);
    assert!(
        !text.contains("m components") && !text.contains("p ports"),
        "{text}"
    );
    assert!(text.contains("· Install"), "{text}");
    for key in ['m', 'p'] {
        app.key(Key::Char(key));
        assert_eq!(app.setup.phase, Phase::Finished, "{key}");
    }
    assert!(app.host.calls.borrow().len() == 1 + Step::ALL.len());
}

#[test]
fn enter_or_esc_on_finished_goes_home() {
    for key in [Key::Enter, Key::Esc] {
        let mut app = finished();
        app.key(key);
        assert_eq!(app.nav.screen, Screen::Home, "{key:?}");
    }
}
