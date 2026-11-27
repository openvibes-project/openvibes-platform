//! Appliance settings › OS access (#566) against the mockup (osaccess.py).

use platform_host::shell::Access;

use crate::tui::{
    app::{App, Key},
    nav::Screen,
    script_host::{SetupHost, screen, set_up, type_text},
};

fn os_access() -> App<SetupHost> {
    let mut app = set_up(vec![]);
    app.host.appliance.set(true);
    app.open_os_access();
    app
}

/// The level the main loop would open now, as it does: taken, then run.
fn opened(app: &mut App<SetupHost>) -> Option<Access> {
    let access = app.take_os_access()?;
    app.run_os_access(access);
    Some(access)
}

#[test]
fn three_levels_each_with_its_help() {
    let mut app = os_access();
    let text = screen(&app);
    for line in [
        "· Appliance settings › OS access",
        "━━ OS access",
        "▸ Read only          look at everything, change nothing",
        "User               danger: a shell as",
        "Root               bigger danger: a shell as root",
        "Files, logs and services can be read; nothing can be written or started.",
        "Enter  Open",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
    app.key(Key::Down);
    assert!(
        screen(&app).contains("What you change, OpenVIBES does not know about."),
        "{}",
        screen(&app)
    );
}

#[test]
fn read_only_asks_yes_first_then_opens() {
    let mut app = os_access();
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Open a read-only shell?"), "{text}");
    assert!(text.contains("[ Yes ]"), "Yes first\n{text}");
    app.key(Key::Enter);
    assert_eq!(opened(&mut app), Some(Access::ReadOnly));
    assert_eq!(*app.host.accesses.borrow(), [Access::ReadOnly]);
    assert_eq!(app.nav.screen, Screen::OsAccess, "back where it was");
}

#[test]
fn user_asks_no_first() {
    let mut app = os_access();
    app.key(Key::Down);
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Open a shell as"), "{text}");
    assert!(text.contains("[ No ]"), "No first\n{text}");
    app.key(Key::Enter);
    assert_eq!(opened(&mut app), None, "No opens nothing");
    app.key(Key::Enter);
    app.key(Key::Left);
    app.key(Key::Enter);
    assert_eq!(opened(&mut app), Some(Access::User));
}

#[test]
fn root_opens_only_on_the_typed_word() {
    let mut app = os_access();
    app.key(Key::Down);
    app.key(Key::Down);
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Type root to open it:"), "{text}");
    assert!(text.contains("Esc  Cancel"), "{text}");
    type_text(&mut app, "yes");
    app.key(Key::Enter);
    assert_eq!(opened(&mut app), None, "only root opens it");
    app.key(Key::ClearLine);
    type_text(&mut app, "root");
    app.key(Key::Enter);
    assert_eq!(opened(&mut app), Some(Access::Root));
    // Esc while typing cancels, and stays on the page.
    app.key(Key::Enter);
    app.key(Key::Esc);
    assert!(app.maint.os_typed.is_none());
    assert_eq!(app.nav.screen, Screen::OsAccess);
}

#[test]
fn the_appliance_has_no_maintenance_shell() {
    let mut app = os_access();
    app.nav.go(Screen::Maintenance);
    assert!(!screen(&app).contains("Shell"), "{}", screen(&app));
    let mut plain = set_up(vec![]);
    plain.nav.go(Screen::Maintenance);
    for _ in 0..9 {
        plain.key(Key::Down);
    }
    assert!(screen(&plain).contains("Shell"), "{}", screen(&plain));
}
