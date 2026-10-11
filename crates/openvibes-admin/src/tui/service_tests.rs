//! The Service screen, its questions and the results of its actions.

use std::time::{Duration, Instant};

use platform_host::{ServiceAction, Unit};

use super::{
    app::{App, Key, Question},
    nav::Screen,
    status::Item,
    tests::{FakeHost, app, screen},
    work::ACTION_TIMEOUT,
};

fn open_service(app: &mut App<FakeHost>, unit: Unit) {
    app.open_status();
    while !matches!(app.status_items()[app.nav.row], Item::Service(u) if u == unit) {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
}

#[test]
fn the_service_screen_says_which_service_and_offers_its_actions() {
    let mut app = app(false);
    open_service(&mut app, Unit::Ingest);
    let text = screen(&app, 80, 24);
    for want in [
        "━━ Service: ingest",
        "running · ready",
        "Restart",
        "Stop",
        "Full log",
        "Recent log",
        "first log line of ingest",
        "Enter  Restart ingest",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn restart_asks_with_buttons_and_enter_confirms() {
    let mut app = app(false);
    open_service(&mut app, Unit::Ingest);
    app.key(Key::Enter);
    assert_eq!(
        app.question,
        Some((
            Question::Service(Unit::Ingest, ServiceAction::Restart),
            true
        ))
    );
    let text = screen(&app, 80, 24);
    assert!(
        text.contains("Restart ingest?")
            && text.contains("Enter  Confirm")
            && !text.contains("Move"),
        "{text}"
    );
    app.key(Key::Right); // No
    app.key(Key::Enter);
    assert!(
        app.question.is_none() && app.host.actions.borrow().is_empty(),
        "No does nothing"
    );
    app.key(Key::Enter);
    app.key(Key::Enter); // Yes
    assert_eq!(
        *app.host.actions.borrow(),
        [(Unit::Ingest, ServiceAction::Restart)]
    );
    assert!(app.pending.is_some());
    assert!(screen(&app, 80, 24).contains("Restarting ingest…"));
}

#[test]
fn work_ends_in_one_result_line() {
    let mut app = app(false);
    open_service(&mut app, Unit::Ingest);
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    let start = Instant::now();
    app.poll(start + Duration::from_secs(2));
    assert!(app.pending.is_none(), "ingest reports active and ready");
    let (ok, text) = app.outcome.clone().unwrap();
    assert!(
        ok && text.starts_with("ingest restarted and ready"),
        "{text}"
    );
}

#[test]
fn a_unit_that_never_gets_ready_fails_after_the_timeout_with_its_last_log_line() {
    let mut app = app(false);
    open_service(&mut app, Unit::Vulns); // failed in the fake
    app.key(Key::Enter); // Start
    app.key(Key::Char('y'));
    let start = Instant::now();
    app.poll(start + Duration::from_secs(5));
    assert!(app.pending.is_some(), "still waiting");
    app.poll(start + ACTION_TIMEOUT + Duration::from_secs(1));
    let (ok, text) = app.outcome.clone().unwrap();
    assert!(
        !ok && text.contains("vulns did not start within 30 s")
            && text.contains("first log line of vulns"),
        "{text}"
    );
}

#[test]
fn not_an_operator_is_explained_in_the_bar() {
    let mut app = app(true);
    open_service(&mut app, Unit::Ingest);
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    let (ok, text) = app.outcome.clone().unwrap();
    assert!(!ok && text.contains("openvibes-operators"), "{text}");
}

#[test]
fn full_log_shows_the_log_and_esc_comes_back() {
    let mut app = app(false);
    open_service(&mut app, Unit::Ingest);
    app.key(Key::Down);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Log(Unit::Ingest));
    assert!(screen(&app, 80, 24).contains("first log line of ingest"));
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Service(Unit::Ingest));
}

#[test]
fn fix_at_boot_asks_for_the_password_in_the_bar() {
    let mut app = app(false);
    app.host.disabled.borrow_mut().push(Unit::Ingest);
    app.open_status();
    app.refresh();
    while !matches!(&app.status_items()[app.nav.row], Item::Problem { text, .. } if text.contains("ingest does not start at boot"))
    {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    let text = screen(&app, 80, 24);
    assert!(
        text.contains("Your password (sudo):") && text.contains("Enter  Enable"),
        "{text}"
    );
    for c in "pw".chars() {
        app.key(Key::Char(c));
    }
    app.key(Key::Enter);
    assert_eq!(
        *app.host.privileged_calls.borrow(),
        [(
            "unit-enable openvibes-ingest.service".to_owned(),
            "pw".to_owned()
        )]
    );
    assert_eq!(
        app.outcome,
        Some((true, "ingest now starts at boot".into()))
    );
}

#[test]
fn q_on_home_while_work_runs_asks_first() {
    let mut app = app(false);
    open_service(&mut app, Unit::Ingest);
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    app.key(Key::Esc);
    app.key(Key::Esc);
    app.key(Key::Esc); // Home
    app.key(Key::Char('q'));
    assert_eq!(app.question, Some((Question::Quit, true)));
    assert!(!app.quit);
    app.key(Key::Enter);
    assert!(app.quit);
}

#[test]
fn a_second_yes_while_work_runs_starts_nothing() {
    let mut app = app(false);
    open_service(&mut app, Unit::Ingest);
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    assert!(app.pending.is_some());
    app.key(Key::Enter);
    assert!(app.question.is_none(), "no second question while work runs");
    app.key(Key::Char('y'));
    assert_eq!(app.host.actions.borrow().len(), 1);
}

#[test]
fn every_question_fits_the_bar_at_80_columns_without_a_cut() {
    let units = [
        Unit::Ingest,
        Unit::Distribution,
        Unit::Vulns,
        Unit::Netlog,
        Unit::Console,
        Unit::Llm,
        Unit::Maintenance,
        Unit::Signer,
    ];
    let actions = [
        ServiceAction::Start,
        ServiceAction::Stop,
        ServiceAction::Restart,
    ];
    for (unit, action) in units.into_iter().flat_map(|u| actions.map(|a| (u, a))) {
        let mut app = app(false);
        app.question = Some((Question::Service(unit, action), true));
        let text = screen(&app, 80, 24);
        assert!(!text.contains('…'), "{unit:?} {action:?}:\n{text}");
        assert!(text.contains("Enter  Confirm"), "{text}");
    }
}

#[test]
fn a_restart_is_done_only_once_the_unit_has_a_new_start_time() {
    let mut app = app(false);
    app.host.hold_restart.set(true);
    open_service(&mut app, Unit::Ingest);
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    let start = Instant::now();
    app.poll(start + Duration::from_secs(2));
    assert!(app.pending.is_some(), "still the old process");
    *app.host.since.borrow_mut() = "Sat 2099-01-01 00:00:00 CEST".into();
    app.poll(start + Duration::from_secs(4));
    assert!(app.pending.is_none());
    assert!(app.outcome.clone().unwrap().0);
}

#[test]
fn after_stop_the_highlight_is_on_the_first_action() {
    let mut app = app(false);
    open_service(&mut app, Unit::Ingest);
    app.key(Key::Down); // Stop
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    app.poll(Instant::now() + Duration::from_secs(2));
    assert!(app.pending.is_none());
    assert_eq!(app.nav.row, 0, "Start, not Full log");
}

#[test]
fn the_full_log_cannot_scroll_past_its_first_line() {
    let mut app = app(false);
    open_service(&mut app, Unit::Ingest);
    app.key(Key::Down);
    app.key(Key::Down);
    app.key(Key::Enter);
    app.logs = (0..100).map(|i| format!("line {i}")).collect();
    let _ = screen(&app, 80, 24); // the first draw learns the room
    for _ in 0..300 {
        app.key(Key::Up);
    }
    let text = screen(&app, 80, 24);
    let shown = text
        .lines()
        .filter(|l| l.trim_start().starts_with("line "))
        .count();
    assert_eq!(shown, 24 - 7 - 1 - 1 - 3 - 2, "a full page:\n{text}");
    assert!(text.contains("line 0") && !text.contains("⭡ "), "{text}");
    let hidden = 100 - shown;
    assert!(text.contains(&format!("⭣ {hidden} more")), "{text}");
}
