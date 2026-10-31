//! System › SSH, key by key.

use platform_host::ssh::SshInfo;

use super::ssh::At;
use crate::tui::{
    app::{App, Key, Question},
    nav::Screen,
    script_host::{SetupHost, body, screen, set_up, type_text},
};

fn app_with(
    info: SshInfo,
    answers: Vec<Result<String, platform_host::HostError>>,
) -> App<SetupHost> {
    let app = set_up(answers);
    app.host.appliance.set(true);
    *app.host.ssh.borrow_mut() = Some(info);
    app
}

fn both() -> SshInfo {
    SshInfo {
        keys: true,
        passwords: true,
        has_keys: Some(true),
    }
}

fn open(app: &mut App<SetupHost>) {
    app.open_system();
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Ssh);
}

#[test]
fn system_lists_ssh_with_the_ways_in() {
    let mut app = app_with(both(), vec![]);
    app.open_system();
    let text = body(&app);
    assert!(
        text.contains("SSH") && text.contains("keys and passwords"),
        "{text}"
    );
}

#[test]
fn the_last_way_in_cannot_be_turned_off() {
    let mut app = app_with(both(), vec![]);
    open(&mut app);
    app.key(Key::Char(' '));
    assert!(!app.maint.ssh.keys && app.maint.ssh.passwords);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    assert!(app.maint.ssh.passwords, "the last way in stays");
    assert!(screen(&app).contains("At least one") || app.maint.ssh.said.is_some());
}

#[test]
fn turning_passwords_off_with_no_key_warns_and_defaults_to_no() {
    let info = SshInfo {
        has_keys: Some(false),
        ..both()
    };
    let mut app = app_with(info, vec![]);
    open(&mut app);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    assert_eq!(app.maint.ssh.rows().last(), Some(&At::Apply));
    app.key(Key::Down);
    app.key(Key::Enter);
    let Some((Question::Maint { detail, .. }, yes_first)) = &app.question else {
        panic!("no question");
    };
    assert!(detail.contains("lock yourself out"), "{detail}");
    assert!(!yes_first);
}

#[test]
fn apply_runs_ssh_set() {
    let mut app = app_with(both(), vec![Ok("done\tset\n".into())]);
    open(&mut app);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    app.key(Key::Down);
    app.key(Key::Enter);
    assert!(screen(&app).contains("Change how people sign in over SSH?"));
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let calls: Vec<String> = app
        .host
        .calls
        .borrow()
        .iter()
        .map(|c| c.0.clone())
        .collect();
    assert_eq!(calls, ["ssh-set --keys yes --passwords no"]);
}
