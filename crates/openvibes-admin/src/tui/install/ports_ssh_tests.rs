//! The appliance's SSH row on Ports (#561).

use crate::tui::{
    app::Key,
    script_host::{screen, type_text},
};

use super::steps_tests::{down, steps};

#[test]
fn only_the_appliance_asks_for_the_ssh_port() {
    let app = steps(3);
    assert!(!screen(&app).contains("SSH"), "{}", screen(&app));

    let mut app = steps(3);
    app.host.appliance.set(true);
    down(&mut app, 4);
    let text = screen(&app);
    assert!(text.contains("SSH"), "{text}");
    assert!(
        text.contains("The port you sign in on; the firewall opens it"),
        "{text}"
    );
    // A taken or platform port is refused; another is kept and planned.
    app.key(Key::Enter);
    app.key(Key::ClearLine);
    type_text(&mut app, "18423");
    assert!(screen(&app).contains("one of the platform's own ports"));
    app.key(Key::Enter);
    assert!(app.install.editing.is_some());
    app.key(Key::ClearLine);
    type_text(&mut app, "2222");
    assert!(screen(&app).contains("SSH moves to 2222"));
    app.key(Key::Enter);
    assert_eq!(app.install.ssh_port, "2222");
    let args = app.install.plan_args();
    assert!(
        args.windows(2).any(|w| w == ["--ssh-port", "2222"]),
        "{args:?}"
    );
    // Next is the row under SSH.
    down(&mut app, 1);
    app.key(Key::Enter);
    assert_eq!(
        app.nav.screen,
        crate::tui::nav::Screen::Install(super::Stage::Step(4))
    );
    assert!(screen(&app).contains("SSH 2222"), "{}", screen(&app));
}

#[test]
fn the_default_ssh_port_is_not_passed() {
    let app = steps(3);
    assert!(!app.install.plan_args().contains(&"--ssh-port".to_owned()));
}
