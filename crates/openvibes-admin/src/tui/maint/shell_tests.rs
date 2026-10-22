//! Maintenance › Shell, key by key (shell.py, shellflow.py).

use std::{cell::RefCell, rc::Rc, sync::mpsc};

use chrono::{Local, TimeZone};
use platform_host::HostError;

use crate::tui::{
    app::{App, Key},
    maint::{names, row_of},
    nav::Screen,
    run::{Call, Kind, Work},
    script_host::{SetupHost, screen, set_up, type_text},
};

fn menu(answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    let mut app = set_up(answers);
    app.nav.go(Screen::Maintenance);
    for _ in 0..row_of("Shell") {
        app.key(Key::Down);
    }
    app
}

/// Enter on Shell, then Yes.
fn yes(app: &mut App<SetupHost>) {
    app.key(Key::Enter);
    app.key(Key::Enter);
}

#[test]
fn shell_is_second_to_last() {
    let names = names();
    assert_eq!(
        names[names.len() - 4..],
        ["Back up", "Settings files", "Shell", "Uninstall"]
    );
    let text = screen(&menu(vec![]));
    assert!(text.contains("▸ Shell"), "{text}");
    assert!(
        text.contains("the operating system's command line, for experts"),
        "{text}"
    );
    assert!(text.contains("Enter  Open the shell"), "{text}");
}

#[test]
fn enter_asks_open_a_shell() {
    let mut app = menu(vec![]);
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Open a shell?"), "{text}");
    assert!(text.contains("for experts; logged"), "{text}");
    assert!(text.contains(" Yes  [ No ]"), "Yes is highlighted: {text}");
    assert_eq!(app.question.as_ref().map(|q| q.1), Some(true));
    assert_eq!(app.nav.screen, Screen::Maintenance, "no page of its own");
}

#[test]
fn yes_asks_the_login_password() {
    let mut app = menu(vec![]);
    yes(&mut app);
    let text = screen(&app);
    assert!(text.contains("Your login password:"), "{text}");
    assert!(text.contains("Enter  Open"), "{text}");
    assert!(text.contains("Esc  Cancel"), "{text}");
    assert!(!text.contains("sudo"), "{text}");
    assert!(app.host.calls.borrow().is_empty());
}

#[test]
fn the_password_opens_the_shell_and_comes_back() {
    let mut app = menu(vec![Ok("done\topened\n".into())]);
    yes(&mut app);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(
        app.host.calls.borrow()[..],
        [("shell-open".to_owned(), "pw".to_owned())]
    );
    assert!(app.take_shell());
    assert!(!app.take_shell(), "once");
    app.run_shell();
    assert_eq!(app.host.shells.get(), 1);
    assert_eq!(app.nav.screen, Screen::Maintenance);
    let text = screen(&app);
    assert!(text.contains("▸ Shell"), "{text}");
    assert!(text.contains("Enter  Open the shell"), "{text}");
    assert!(app.run.is_none(), "no result left for Home");
    app.key(Key::Esc);
    assert_eq!(
        app.nav.screen,
        Screen::Home,
        "Maintenance once on the way back"
    );
}

#[test]
fn as_root_no_password_is_asked() {
    let mut app = menu(vec![Ok("done\topened\n".into())]);
    app.host.root = true;
    yes(&mut app);
    assert_eq!(app.host.calls.borrow()[0].0, "shell-open");
    assert!(app.take_shell());
}

#[test]
fn a_shell_that_cannot_start_says_so() {
    let mut app = menu(vec![]);
    app.host.no_shell = true;
    yes(&mut app);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(app.take_shell());
    app.run_shell();
    let text = screen(&app);
    assert!(
        text.contains("✗ The shell could not start: failed: no shell here"),
        "{text}"
    );
}

#[test]
fn three_wrong_passwords_open_no_shell() {
    let mut app = menu(vec![
        Err(HostError::WrongPassword),
        Err(HostError::WrongPassword),
        Err(HostError::WrongPassword),
    ]);
    yes(&mut app);
    for _ in 0..3 {
        type_text(&mut app, "bad");
        app.key(Key::Enter);
    }
    assert!(app.asking.is_none());
    assert!(!app.take_shell());
    assert_eq!(app.host.calls.borrow().len(), 3);
    let text = screen(&app);
    assert!(
        text.contains("three wrong passwords: nothing more was run"),
        "{text}"
    );
    assert!(!app.take_shell());
}

#[test]
fn no_shell_while_work_runs() {
    let mut app = menu(vec![]);
    app.host.root = true;
    // An Optional parts install runs in the background (its worker never ends).
    let keep = Rc::new(RefCell::new(None));
    let held = keep.clone();
    app.worker = Some(Box::new(move |_work, _from, _secret| {
        let (tx, rx) = mpsc::channel();
        *held.borrow_mut() = Some(tx);
        rx
    }));
    let parts = Kind::Parts {
        what: "Installing the agent".into(),
        done: "Agent installed".into(),
    };
    app.begin(Work::new(parts, vec![Call::Status]), 0);
    assert!(app.run.as_ref().is_some_and(|r| r.running()));
    yes(&mut app);
    let text = screen(&app);
    assert!(text.contains("Wait: other work is still running"), "{text}");
    assert!(app.host.calls.borrow().is_empty());
    assert!(!app.take_shell());
    assert_eq!(app.host.shells.get(), 0);
    drop(keep);
}

#[test]
fn the_bar_spins_while_the_shell_opens() {
    let mut app = menu(vec![]);
    let keep = Rc::new(RefCell::new(None));
    let held = keep.clone();
    app.worker = Some(Box::new(move |_work, _from, _secret| {
        let (tx, rx) = mpsc::channel();
        *held.borrow_mut() = Some(tx);
        rx
    }));
    yes(&mut app);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Opening the shell…"), "{text}");
    assert!(text.contains("━━ Maintenance"), "over Maintenance: {text}");
    assert!(!app.take_shell());
    drop(keep);
}

#[test]
fn the_header_names_the_user_and_time() {
    let at = Local.with_ymd_and_hms(2026, 10, 10, 21, 42, 0).unwrap();
    assert_eq!(
        super::shell::header_for("admin", at),
        [
            "OpenVIBES shell · type exit to go back to the menu. Logged as admin, 21:42.",
            "Changes here are yours: Repair can put OpenVIBES' own files right again.",
        ]
    );
    // The App names the person the journal names.
    let app = menu(vec![]);
    assert_eq!(
        app.shell_header(at),
        super::shell::header_for(&platform_host::shell::operator(), at)
    );
}
