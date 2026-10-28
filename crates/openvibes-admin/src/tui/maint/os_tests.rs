//! Maintenance › Operating system, key by key (os2.py, osupdate.py).

use std::time::{SystemTime, UNIX_EPOCH};

use platform_host::{
    HostError,
    os_updates::{OsInfo, OsUpdates},
};

use super::os::ago;
use crate::tui::{
    app::{App, Key},
    maint::{Page, row_of},
    nav::Screen,
    script_host::{SetupHost, body, screen, set_up, type_text},
};

fn info(updates: Option<OsUpdates>) -> OsInfo {
    OsInfo {
        name: "AlmaLinux 9.6 (Sage Margay)".into(),
        kernel: "5.14.0-570".into(),
        updates,
    }
}

fn found(total: u32, security: u32, kernel: bool, restart: bool, ago_secs: i64) -> OsUpdates {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    OsUpdates {
        total,
        security,
        kernel,
        restart,
        checked_at: now - ago_secs,
    }
}

fn waiting() -> OsInfo {
    info(Some(found(23, 4, true, false, 600)))
}

fn page(os: Option<OsInfo>, answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    let mut app = set_up(answers);
    *app.host.os.borrow_mut() = os;
    app.nav.go(Screen::Maintenance);
    app.open_page(Page::Os);
    app
}

fn password(app: &mut App<SetupHost>) {
    type_text(app, "pw");
    app.key(Key::Enter);
}

fn calls(app: &App<SetupHost>) -> Vec<String> {
    app.host
        .calls
        .borrow()
        .iter()
        .map(|c| c.0.clone())
        .collect()
}

#[test]
fn the_menu_has_the_entry_second_with_the_counts() {
    assert_eq!(super::names()[1], "Operating system");
    let mut app = set_up(vec![]);
    *app.host.os.borrow_mut() = Some(waiting());
    app.nav.go(Screen::Maintenance);
    app.nav.row = row_of("Operating system");
    let text = screen(&app);
    assert!(
        text.contains("AlmaLinux 9.6 · 23 updates, 4 for security"),
        "{text}"
    );
}

#[test]
fn the_menu_value_before_a_check_and_without_updates() {
    for (os, want) in [
        (info(None), "AlmaLinux 9.6 · not checked yet"),
        (
            info(Some(found(0, 0, false, false, 5))),
            "AlmaLinux 9.6 · up to date",
        ),
        (
            info(Some(found(0, 0, false, true, 5))),
            "AlmaLinux 9.6 · restart needed",
        ),
        (
            info(Some(found(3, 0, false, false, 5))),
            "AlmaLinux 9.6 · 3 updates",
        ),
    ] {
        let mut app = set_up(vec![]);
        *app.host.os.borrow_mut() = Some(os);
        app.nav.go(Screen::Maintenance);
        let text = screen(&app);
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn the_page_shows_what_is_waiting_and_the_actions() {
    let app = page(Some(waiting()), vec![]);
    let text = body(&app);
    let from = text
        .lines()
        .position(|l| l.contains("━━ Operating system"))
        .unwrap();
    let shown = text
        .lines()
        .skip(from)
        .take(8)
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        shown,
        "    ━━ Operating system ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\
         \n\
         \x20   AlmaLinux 9.6 (Sage Margay) · kernel 5.14.0-570 · checked 10 minutes ago\n\
         \x20   ▲ 23 updates available, 4 for security · includes a new kernel\n\
         \n\
         \x20 ▸ Update everything    23 packages, then a restart\n\
         \n\
         \x20   Check again"
    );
    let text = screen(&app);
    assert!(text.contains("Enter  Update everything"), "{text}");
    assert!(text.contains("Check again"), "{text}");
}

#[test]
fn down_moves_to_check_again_and_the_bar_follows() {
    let mut app = page(Some(waiting()), vec![]);
    app.key(Key::Down);
    let text = screen(&app);
    assert!(text.contains("▸ Check again"), "{text}");
    assert!(text.contains("Enter  Check again"), "{text}");
}

#[test]
fn enter_on_update_asks_first() {
    let mut app = page(Some(waiting()), vec![]);
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Install 23 updates?"), "{text}");
    assert!(text.contains("restart after"), "{text}");
    assert_eq!(app.question.as_ref().map(|q| q.1), Some(true));
    assert!(calls(&app).is_empty());
}

#[test]
fn updating_runs_the_helper_and_offers_the_restart() {
    let mut app = page(Some(waiting()), vec![Ok("done\t0\t0\ttrue\n".into())]);
    *app.host.os.borrow_mut() = Some(info(Some(found(0, 0, false, true, 1))));
    app.key(Key::Enter);
    app.key(Key::Enter);
    password(&mut app);
    assert_eq!(calls(&app), ["os-update"]);
    let text = screen(&app);
    for want in [
        "✓ 23 packages updated",
        "▲ A restart is needed for the new kernel.",
        "agents keep their findings meanwhile.",
        "Restart now",
        "Later",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn later_goes_back_and_the_page_keeps_offering_the_restart() {
    let mut app = page(Some(waiting()), vec![Ok("done\t0\t0\ttrue\n".into())]);
    *app.host.os.borrow_mut() = Some(info(Some(found(0, 0, false, true, 1))));
    app.key(Key::Enter);
    app.key(Key::Enter);
    password(&mut app);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maintenance);
    app.open_page(Page::Os);
    let text = screen(&app);
    assert!(
        text.contains("A restart is needed for the updates already installed."),
        "{text}"
    );
    assert!(text.contains("Restart now"), "{text}");
    assert!(!text.contains("Update everything"), "{text}");
}

#[test]
fn restart_now_asks_and_starts_on_no() {
    let mut app = page(
        Some(info(Some(found(0, 0, false, true, 5)))),
        vec![Ok("done\trestarting\n".into())],
    );
    app.key(Key::Down);
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Restart this host?"), "{text}");
    assert_eq!(app.question.as_ref().map(|q| q.1), Some(false));
    app.key(Key::Left);
    app.key(Key::Enter);
    password(&mut app);
    assert_eq!(calls(&app), ["os-restart"]);
}

#[test]
fn check_again_runs_without_a_question_and_shows_the_new_counts() {
    let mut app = page(Some(info(None)), vec![Ok("done\t3\t1\tfalse\n".into())]);
    *app.host.os.borrow_mut() = Some(info(Some(found(3, 1, false, false, 1))));
    app.key(Key::Enter);
    assert!(app.question.is_none());
    password(&mut app);
    assert_eq!(calls(&app), ["os-check"]);
    let text = screen(&app);
    assert!(
        text.contains("3 updates available, 1 for security"),
        "{text}"
    );
    assert!(text.contains("checked just now"), "{text}");
}

#[test]
fn a_failed_check_says_why_and_offers_try_again() {
    let mut app = page(
        Some(info(None)),
        vec![Err(HostError::Failed(
            "dnf could not check: no route".into(),
        ))],
    );
    app.key(Key::Enter);
    password(&mut app);
    let text = screen(&app);
    assert!(text.contains("no route"), "{text}");
    assert!(text.contains("Enter  Try again"), "{text}");
}

#[test]
fn up_to_date_and_not_checked_yet() {
    let text = screen(&page(
        Some(info(Some(found(0, 0, false, false, 30)))),
        vec![],
    ));
    assert!(text.contains("✓ Up to date"), "{text}");
    assert!(!text.contains("Update everything"), "{text}");
    let text = screen(&page(Some(info(None)), vec![]));
    assert!(text.contains("not checked yet"), "{text}");
    assert!(
        text.contains("Check again asks dnf what is waiting."),
        "{text}"
    );
}

#[test]
fn without_dnf_the_page_says_so() {
    let mut app = page(None, vec![]);
    let text = screen(&app);
    assert!(
        text.contains("no package manager OpenVIBES knows"),
        "{text}"
    );
    app.key(Key::Enter);
    assert!(calls(&app).is_empty());
}

#[test]
fn other_work_running_refuses_the_question() {
    let mut app = page(Some(waiting()), vec![]);
    app.half_done = Some("update".into());
    app.key(Key::Enter);
    assert!(app.question.is_none());
    assert!(
        app.outcome
            .as_ref()
            .is_some_and(|(ok, why)| !ok && why.contains("half way"))
    );
}

#[test]
fn ago_reads_naturally() {
    assert_eq!(ago(5), "just now");
    assert_eq!(ago(60), "1 minute ago");
    assert_eq!(ago(600), "10 minutes ago");
    assert_eq!(ago(3 * 3600), "3 hours ago");
    assert_eq!(ago(2 * 86_400), "2 days ago");
    assert_eq!(ago(-5), "just now");
}

#[test]
fn home_shows_the_finished_update() {
    let mut app = page(Some(waiting()), vec![Ok("done\t0\t0\ttrue\n".into())]);
    *app.host.os.borrow_mut() = Some(info(Some(found(0, 0, false, true, 1))));
    app.key(Key::Enter);
    app.key(Key::Enter);
    password(&mut app);
    app.key(Key::Esc);
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Home);
    let text = screen(&app);
    assert!(text.contains("23 packages updated"), "{text}");
}
