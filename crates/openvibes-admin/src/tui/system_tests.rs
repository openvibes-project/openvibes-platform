//! The appliance's Home and System page, key by key (system.py).

use platform_host::HostError;

use super::{
    app::{App, Key},
    nav::Screen,
    script_host::{SetupHost, body, screen, set_up, type_text},
};

fn appliance(answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    let app = set_up(answers);
    app.host.appliance.set(true);
    app
}

fn calls(app: &App<SetupHost>) -> Vec<String> {
    app.host
        .calls
        .borrow()
        .iter()
        .map(|c| c.0.clone())
        .collect()
}

fn password(app: &mut App<SetupHost>) {
    type_text(app, "pw");
    app.key(Key::Enter);
}

#[test]
fn a_normal_host_has_no_system_and_still_quits() {
    let app = set_up(vec![]);
    let text = body(&app);
    assert!(text.contains("Quit") && !text.contains("System"), "{text}");
    assert!(!text.contains("Log out"), "{text}");
}

#[test]
fn the_appliance_adds_system_and_ends_in_log_out() {
    let mut app = appliance(vec![]);
    let text = body(&app);
    assert!(
        text.contains("System") && text.contains("restart, shut down"),
        "{text}"
    );
    assert!(text.contains("Log out"), "{text}");
    app.key(Key::Down);
    app.key(Key::Down);
    app.key(Key::Down);
    assert!(screen(&app).contains("Enter  Log out"));
    app.key(Key::Enter);
    assert!(app.quit);
}

#[test]
fn system_opens_with_restart_and_shut_down() {
    let mut app = appliance(vec![]);
    app.key(Key::Down);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::System);
    let text = screen(&app);
    assert!(text.contains("platform.lab · System"), "{text}");
    assert!(
        text.contains("Restart") && text.contains("Shut down"),
        "{text}"
    );
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Home);
}

#[test]
fn restart_asks_on_no_then_runs_the_verb() {
    let mut app = appliance(vec![Ok("done\trestarting\n".into())]);
    app.nav.go(Screen::System);
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Restart the appliance?"), "{text}");
    assert_eq!(app.question.as_ref().map(|q| q.1), Some(false));
    app.key(Key::Left);
    app.key(Key::Enter);
    password(&mut app);
    assert_eq!(calls(&app), ["os-restart"]);
}

#[test]
fn shut_down_asks_and_declining_runs_nothing() {
    let mut app = appliance(vec![]);
    app.nav.go(Screen::System);
    app.key(Key::Down);
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Shut the appliance down?"), "{text}");
    app.key(Key::Enter);
    assert!(calls(&app).is_empty());
}

#[test]
fn shut_down_runs_its_own_verb() {
    let mut app = appliance(vec![Ok("done\tshutting down\n".into())]);
    app.nav.go(Screen::System);
    app.key(Key::Down);
    app.key(Key::Enter);
    app.key(Key::Left);
    app.key(Key::Enter);
    password(&mut app);
    assert_eq!(calls(&app), ["os-power-off"]);
}

#[test]
fn a_failed_shut_down_says_why_and_can_be_tried_again() {
    let mut app = appliance(vec![
        Err(HostError::Failed(
            "An update is running; restart when it is done".into(),
        )),
        Ok("done\tshutting down\n".into()),
    ]);
    app.nav.go(Screen::System);
    app.key(Key::Down);
    app.key(Key::Enter);
    app.key(Key::Left);
    app.key(Key::Enter);
    password(&mut app);
    let text = screen(&app);
    assert!(text.contains("An update is running"), "{text}");
    assert!(text.contains("Enter  Try again"), "{text}");
    app.key(Key::Enter);
    password(&mut app);
    assert_eq!(calls(&app), ["os-power-off", "os-power-off"]);
}
