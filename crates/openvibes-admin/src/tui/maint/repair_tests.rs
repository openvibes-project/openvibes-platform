//! Maintenance › Repair, key by key (maint1.py).

use platform_host::{HostError, Step, StepState};

use crate::tui::{
    app::Key,
    maint::{Page, repair::parse},
    script_host::{screen, set_up, type_text},
};

const TWO_PROBLEMS: &str = "packages\tdone\tall installed\n\
    certificates\ttodo\t\n\
    firewall\tfailed\t18424/tcp is closed\n\
    services\tdone\t8 of 8 running\n";

fn all_fine() -> String {
    Step::ALL
        .iter()
        .map(|s| format!("{}\tdone\tok\n", s.name()))
        .collect()
}

#[test]
fn the_status_output_is_read_step_by_step() {
    let steps = parse(TWO_PROBLEMS);
    assert_eq!(steps.len(), 4);
    assert_eq!(
        steps[2],
        (
            Step::Firewall,
            StepState::Failed("18424/tcp is closed".into())
        )
    );
}

#[test]
fn repair_checks_first_then_lists_the_problems_and_fixes_them() {
    let mut answers = vec![Ok(TWO_PROBLEMS.to_owned())];
    answers.extend(Step::ALL.iter().map(|_| Ok("done\tok\n".to_owned())));
    answers.push(Ok(all_fine()));
    let mut app = set_up(answers);
    app.open_page(Page::Repair);
    assert!(
        screen(&app).contains("Your password (sudo):"),
        "it checks first: the password"
    );
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(app.host.calls.borrow()[0].0, "setup-status");
    let text = screen(&app);
    for want in [
        "2 problems found",
        "Firewall",
        "18424/tcp is closed",
        "2 other steps in order",
        "Fix 2 problems",
        "Check again",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let calls = app.host.calls.borrow().clone();
    assert_eq!(calls[1].0, "setup-step packages --repair");
    assert_eq!(
        calls.last().unwrap().0,
        "setup-status",
        "it checks again after fixing"
    );
    let text = screen(&app);
    assert!(
        text.contains("Everything is in order") && text.contains("Repaired"),
        "{text}"
    );
    assert!(!text.contains("Fix 2"), "{text}");
}

#[test]
fn a_fix_that_stops_says_where_and_tries_again_from_there() {
    let mut answers = vec![Ok(TWO_PROBLEMS.to_owned())];
    answers.push(Ok("done\tok\n".into()));
    answers.push(Ok("failed\tpostgresql did not start\n".into()));
    let mut app = set_up(answers);
    app.open_page(Page::Repair);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        text.contains("✗ PostgreSQL") && text.contains("postgresql did not start"),
        "{text}"
    );
    assert!(
        text.contains("Nothing was broken") && text.contains("Enter  Try again"),
        "{text}"
    );
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(app.host.calls.borrow()[3].0, "setup-step postgres --repair");
}

#[test]
fn a_half_done_update_is_said_and_fix_is_not_offered() {
    let mut app = set_up(vec![Ok(TWO_PROBLEMS.to_owned())]);
    let dir = app.root.join("run/openvibes-admin");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("job"), "update").unwrap();
    app.open_page(Page::Repair);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        text.contains("An update stopped half way") && text.contains("Finish the update"),
        "{text}"
    );
    assert!(
        text.contains("Check again") && !text.contains("Fix 2"),
        "{text}"
    );
    app.key(Key::Down);
    app.key(Key::Enter);
    assert!(app.asking.is_some(), "Check again asks for a new check");
    assert_eq!(app.host.calls.borrow().len(), 1);
}

#[test]
fn a_wrong_password_ends_the_check_with_a_way_to_try_again() {
    let mut app = set_up(vec![
        Err(HostError::WrongPassword),
        Err(HostError::WrongPassword),
        Err(HostError::WrongPassword),
    ]);
    app.open_page(Page::Repair);
    for _ in 0..3 {
        type_text(&mut app, "bad");
        app.key(Key::Enter);
    }
    let text = screen(&app);
    assert!(
        text.contains("three wrong passwords") && text.contains("Try again"),
        "{text}"
    );
}

#[test]
fn a_clean_check_says_everything_is_in_order() {
    let mut app = set_up(vec![Ok(all_fine())]);
    app.open_page(Page::Repair);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        text.contains("Everything is in order") && !text.contains("Fix "),
        "{text}"
    );
}

#[test]
fn one_empty_line_sits_above_the_actions() {
    let mut app = set_up(vec![Ok(TWO_PROBLEMS.to_owned())]);
    app.open_page(Page::Repair);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.contains("other steps in order"))
        .expect("the summary line");
    assert!(lines[at + 1].trim().is_empty(), "{text}");
    assert!(
        !lines[at + 2].trim().is_empty(),
        "one empty line only:\n{text}"
    );
}

fn write_mark(app: &crate::tui::app::App<crate::tui::script_host::SetupHost>, kind: &str) {
    let dir = app.root.join("run/openvibes-admin");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("job"), kind).unwrap();
}

#[test]
fn finish_the_update_opens_the_update_page() {
    let mut app = set_up(vec![Ok(TWO_PROBLEMS.to_owned())]);
    write_mark(&app, "update");
    app.open_page(Page::Repair);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Finish the update"), "{text}");
    assert!(!text.contains("Fix 2"), "{text}");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, crate::tui::nav::Screen::Maint(Page::Update));
}

#[test]
fn an_uninstall_mark_is_named_as_an_uninstall() {
    let mut app = set_up(vec![Ok(TWO_PROBLEMS.to_owned())]);
    write_mark(&app, "uninstall");
    app.open_page(Page::Repair);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("An uninstall stopped half way"), "{text}");
    assert!(
        text.contains("Maintenance › Uninstall") && !text.contains("x uninstall"),
        "{text}"
    );
    assert!(
        text.contains("Finish the uninstall")
            && !text.contains("update")
            && !text.contains("Fix 2"),
        "{text}"
    );
    app.key(Key::Enter);
    assert_eq!(
        app.nav.screen,
        crate::tui::nav::Screen::Maint(Page::Uninstall)
    );
}

fn fix_with_final(last: Result<String, HostError>) -> String {
    let mut answers = vec![Ok(TWO_PROBLEMS.to_owned())];
    answers.extend(Step::ALL.iter().map(|_| Ok("done\tok\n".to_owned())));
    answers.push(last);
    let mut app = set_up(answers);
    app.open_page(Page::Repair);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    screen(&app)
}

#[test]
fn a_final_check_that_says_nothing_or_fails_is_not_repaired() {
    for last in [
        Ok("garbage\n".to_owned()),
        Err(HostError::Failed("sudo broke".into())),
    ] {
        let text = fix_with_final(last);
        assert!(
            text.contains("checking again failed") && !text.contains("Repaired"),
            "{text}"
        );
    }
}

#[test]
fn a_long_problem_wraps_under_its_column_at_80_columns() {
    let lost = "certificates\tfailed\t/etc/openvibes/pki/chain.crt is missing: restore it from \
                a backup (agents could not reach the root)\n";
    let mut app = set_up(vec![Ok(lost.to_owned())]);
    app.open_page(Page::Repair);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    let at = text.find("▲ Server certificates").unwrap();
    let lines: Vec<&str> = text[at..].lines().map(str::trim_end).take(3).collect();
    assert!(
        lines[0].ends_with("/etc/openvibes/pki/chain.crt is missing:"),
        "{text}"
    );
    assert_eq!(
        lines[1].trim_start(),
        "restore it from a backup (agents could not…",
        "{text}"
    );
    // Under the detail's column, not the title's (the first line starts at ▲).
    let column = |line: &str, word: &str| line[..line.find(word).unwrap()].chars().count();
    assert_eq!(
        column(lines[1], "restore"),
        column(lines[0], "/etc") + 4,
        "{text}"
    );
    assert!(lines[2].contains("other steps in order"), "{text}");
}

/// More problems than 80×24 holds: one line each, then how many more; the
/// actions stay in view.
#[test]
fn many_problems_leave_room_for_the_actions() {
    let long = "a sentence long enough to need a second line at eighty columns, and then some";
    let status: String = ["packages", "postgres", "certificates", "firewall"]
        .iter()
        .map(|s| format!("{s}\tfailed\t{long}\n"))
        .collect();
    let mut app = set_up(vec![Ok(status.clone())]);
    app.open_page(Page::Repair);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    for want in [
        "4 problems found",
        "▲ Install packages",
        "⭣ 2 more",
        "Fix 4 problems",
        "Check again",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    assert!(!text.contains("then some"), "one line each\n{text}");
    // Two long problems: one line each too, so both and the actions fit.
    let two: String = status.lines().take(2).map(|l| format!("{l}\n")).collect();
    let mut app = set_up(vec![Ok(two)]);
    app.open_page(Page::Repair);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    for want in [
        "▲ Install packages",
        "▲ PostgreSQL",
        "Fix 2 problems",
        "Check again",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}
