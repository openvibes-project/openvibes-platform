//! Maintenance › Console sign-in, key by key (maint2b.py #24-25).

use platform_host::HostError;

use crate::tui::{
    app::{App, Key},
    maint::Page,
    script_host::{SetupHost, screen, set_up, type_text},
};

const PASSWORD: &str = "Tz4m-W8qH-n2cR-7kLp";

fn page(answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    let mut app = set_up(answers);
    app.open_page(Page::SignIn);
    app
}

/// Enter, Yes, the password: the reset has run.
fn reset(app: &mut App<SetupHost>) {
    app.key(Key::Enter);
    app.key(Key::Enter);
    type_text(app, "pw");
    app.key(Key::Enter);
}

fn ok() -> Vec<Result<String, HostError>> {
    vec![Ok(format!("done\t{PASSWORD}\n"))]
}

#[test]
fn the_page_offers_the_reset() {
    let text = screen(&page(vec![]));
    for want in [
        "For when nobody can sign in to the console any more.",
        "Reset the admin password",
        "a new password, shown once",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn enter_asks_the_question() {
    let mut app = page(vec![]);
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Reset the admin password?"), "{text}");
    assert!(text.contains("old one stops"), "{text}");
    assert!(text.contains("Yes"), "{text}");
}

#[test]
fn yes_and_password_show_the_new_password_once() {
    let mut app = page(ok());
    reset(&mut app);
    let text = screen(&app);
    for want in [
        "Sign in as",
        "admin",
        PASSWORD,
        "shown only now",
        "You are asked to change it at the next sign-in.",
        "Done",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    assert!(!text.contains("Move"), "no ⭡⭣ while it shows: {text}");
    assert_eq!(app.host.calls.borrow()[0].0, "admin-reset");
}

#[test]
fn the_password_is_gone_after_leaving() {
    let mut app = page(ok());
    reset(&mut app);
    app.key(Key::Enter);
    app.open_page(Page::SignIn);
    let text = screen(&app);
    assert!(!text.contains(PASSWORD), "{text}");
    assert!(text.contains("a new password, shown once"), "{text}");
    // Esc leaves too.
    let mut app = page(ok());
    reset(&mut app);
    app.key(Key::Esc);
    app.open_page(Page::SignIn);
    assert!(!screen(&app).contains(PASSWORD));
    assert!(app.maint.signin.is_none());
}

#[test]
fn a_failed_reset_shows_no_password() {
    let mut app = page(vec![Err(HostError::Failed(
        "no local user named admin".into(),
    ))]);
    reset(&mut app);
    let text = screen(&app);
    assert!(text.contains("✗ no local user named admin"), "{text}");
    assert!(!text.contains("Sign in as"), "{text}");
    assert!(text.contains("Try again"), "{text}");
}

#[test]
fn the_menu_lists_console_sign_in_after_database() {
    let names = crate::tui::maint::names();
    let at = names.iter().position(|n| *n == "Database").unwrap();
    assert_eq!(names[at + 1], "Console sign-in");
}
