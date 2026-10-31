//! System › Login password, key by key.

use crate::tui::{
    app::{App, Key, Question},
    nav::Screen,
    script_host::{SetupHost, body, screen, set_up, type_text},
};

fn app_with(answers: Vec<Result<String, platform_host::HostError>>) -> App<SetupHost> {
    let app = set_up(answers);
    app.host.appliance.set(true);
    app
}

fn open(app: &mut App<SetupHost>) {
    app.open_system();
    app.nav.row = 0;
    let at = app.nav.row;
    assert_eq!(at, 0);
    app.open_login_password();
    app.nav.go(Screen::LoginPassword);
}

fn field(app: &mut App<SetupHost>, text: &str) {
    app.key(Key::Enter);
    type_text(app, text);
    app.key(Key::Enter);
}

#[test]
fn system_lists_it_on_the_appliance_only() {
    let mut app = app_with(vec![]);
    app.open_system();
    assert!(body(&app).contains("Login password"));
    let mut plain = set_up(vec![]);
    plain.open_system();
    assert!(!body(&plain).contains("Login password"));
}

#[test]
fn typed_text_is_masked_and_apply_needs_both_fields() {
    let mut app = app_with(vec![]);
    open(&mut app);
    assert_eq!(app.maint.login.row_count(), 2);
    app.key(Key::Enter);
    type_text(&mut app, "correct horse");
    let text = screen(&app);
    assert!(
        !text.contains("correct horse") && text.contains("*************"),
        "{text}"
    );
    app.key(Key::Enter);
    assert_eq!(app.maint.login.row_count(), 2);
    field(&mut app, "correct horse");
    assert_eq!(app.maint.login.row_count(), 3);
    assert!(!format!("{:?}", app.maint).contains("horse"));
}

#[test]
fn a_mismatch_or_a_short_password_is_said_and_asks_nothing() {
    let mut app = app_with(vec![]);
    open(&mut app);
    field(&mut app, "correct horse");
    field(&mut app, "correct hors");
    app.key(Key::Enter);
    assert!(screen(&app).contains("not the same"), "{}", screen(&app));
    assert!(app.question.is_none());

    let mut short = app_with(vec![]);
    open(&mut short);
    field(&mut short, "short");
    field(&mut short, "short");
    short.key(Key::Enter);
    assert!(screen(&short).contains("At least 10"));
    assert!(short.question.is_none());
}

#[test]
fn apply_runs_login_password_with_no_argument() {
    let mut app = app_with(vec![Ok("done\tchanged\n".into())]);
    open(&mut app);
    field(&mut app, "correct horse");
    field(&mut app, "correct horse");
    app.key(Key::Enter);
    assert!(matches!(app.question, Some((Question::Maint { .. }, true))));
    assert!(screen(&app).contains("Change your login password?"));
    app.key(Key::Enter);
    type_text(&mut app, "sudo-pw");
    app.key(Key::Enter);
    let calls = app.host.calls.borrow().clone();
    assert_eq!(calls, [("login-password".to_owned(), "sudo-pw".to_owned())]);
    let text = screen(&app);
    assert!(
        text.contains("Login password changed") && !text.contains("horse"),
        "{text}"
    );
    app.key(Key::Enter);
    assert_eq!(app.maint.login.row_count(), 2, "the fields are empty again");
}

#[test]
fn escape_while_typing_leaves_the_field_alone() {
    let mut app = app_with(vec![]);
    open(&mut app);
    app.key(Key::Enter);
    type_text(&mut app, "abc");
    app.key(Key::Esc);
    assert!(!app.maint.login.typing());
    assert_eq!(app.nav.screen, Screen::LoginPassword);
}
