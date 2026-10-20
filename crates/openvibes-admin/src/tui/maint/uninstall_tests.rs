//! Maintenance › Uninstall, key by key (maint4.py, backupdefault.py).

use crate::tui::{
    app::Key,
    maint::Page,
    nav::Screen,
    script_host::{screen, set_up, type_text},
    status::{Fix, Item},
};

const ALL: &str = "--components ingest,console,distribution,vulns,rules,agent --remember-choice";

fn mark(app: &crate::tui::app::App<crate::tui::script_host::SetupHost>, text: &str) {
    let dir = app.root.join("run/openvibes-admin");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("job"), text).unwrap();
}

#[test]
fn keep_the_data_is_the_default_and_back_up_first_is_off() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    let text = screen(&app);
    for want in [
        "(•) Keep the data",
        "( ) Remove everything",
        "[ ] Back up first",
        "PostgreSQL stays installed",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn every_choice_shows_in_full_at_80_by_24() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    let text = screen(&app);
    for want in [
        "remove the programs; data stays for a reinstall",
        "programs, data, accounts, certificates, settings",
        "Back up first",
        "  Uninstall",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    assert!(!text.contains("more") && !text.contains('…'), "{text}");
}

#[test]
fn help_on_every_maintenance_page_is_not_cut_at_the_edge() {
    for page in [Page::Backup, Page::Update, Page::Uninstall, Page::Repair] {
        let mut app = set_up(vec![]);
        app.open_page(page);
        if page == Page::Repair {
            app.key(Key::Esc); // the password prompt
        }
        app.key(Key::Char('?'));
        let text = screen(&app);
        let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let last = page.help().split_whitespace().last().unwrap();
        assert!(flat.contains(last), "{page:?} help is cut:\n{text}");
    }
}

#[test]
fn maintenance_values_keep_clear_of_the_longest_name() {
    let mut app = set_up(vec![]);
    app.key(Key::Down);
    app.key(Key::Enter);
    (0..super::row_of("Components and ports")).for_each(|_| app.key(Key::Down));
    let text = screen(&app);
    assert!(
        text.contains("Components and ports   agent"),
        "the values start clear of the longest name:\n{text}"
    );
}

#[test]
fn the_help_never_touches_the_bar() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    let text = screen(&app);
    let lines: Vec<&str> = text.lines().collect();
    let bar = lines.iter().position(|l| l.contains('┌')).unwrap();
    assert!(lines[bar - 1].trim().is_empty(), "{text}");
    assert!(
        text.contains("PostgreSQL stays: Setup did not install it"),
        "{text}"
    );
}

#[test]
fn remove_everything_says_what_happens_to_postgresql() {
    let mut app = set_up(vec![]);
    macro_rules! everything {
        ($app:expr) => {{
            $app.open_page(Page::Uninstall);
            $app.key(Key::Down);
            $app.key(Key::Char(' '));
            screen(&$app)
        }};
    }
    assert!(everything!(app).contains("Setup did not install it"));
    let rec = app.root.join("etc/openvibes/setup-installed-postgresql");
    std::fs::create_dir_all(rec.parent().unwrap()).unwrap();
    std::fs::write(rec, "x\n").unwrap();
    let text = everything!(app);
    assert!(text.contains("PostgreSQL is not installed") && !text.contains("goes too"));
    let bin = app.root.join("usr/bin/postgres");
    std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
    std::fs::write(bin, "").unwrap();
    assert!(everything!(app).contains("PostgreSQL goes too"));
}

#[test]
fn remove_everything_needs_the_host_name_typed_exactly() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    assert!(screen(&app).contains("Nothing is left behind"));
    app.nav.row = 4; // Uninstall (Keep, Everything, Back up first, Type…, Uninstall)
    app.key(Key::Enter);
    assert!(
        app.question.is_none(),
        "no question before the name is typed"
    );
    assert_eq!(app.nav.row, 3, "the name's row is highlighted");
    assert!(screen(&app).contains("Type platform.example.com to confirm"));
    app.key(Key::Enter);
    type_text(&mut app, "platform.example.co");
    assert!(!screen(&app).contains('✓'), "{}", screen(&app));
    type_text(&mut app, "m");
    assert!(screen(&app).contains('✓'));
    app.key(Key::Enter);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert!(screen(&app).contains("Remove OpenVIBES and all its data?"));
    app.key(Key::Char('y'));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let calls = app.host.calls.borrow().clone();
    assert_eq!(calls.len(), 6);
    assert_eq!(
        calls[0].0,
        format!("remove-step backup {ALL} --confirm platform.example.com")
    );
    assert_eq!(
        calls[5].0,
        format!("remove-step admin {ALL} --confirm platform.example.com")
    );
    let text = screen(&app);
    assert!(
        text.contains("OpenVIBES is removed from this host") && text.contains("Quit"),
        "{text}"
    );
    // The program is gone: nothing but Enter or q does anything.
    app.key(Key::Esc);
    assert_eq!(
        app.nav.screen,
        Screen::Maint(Page::Uninstall),
        "nothing is left to go back to"
    );
    app.key(Key::Char('?'));
    app.key(Key::Char('r'));
    assert_eq!(app.nav.screen, Screen::Maint(Page::Uninstall));
    assert_eq!(app.host.calls.borrow().len(), 6, "no more helper calls");
    assert!(!app.quit);
    app.key(Key::Enter);
    assert!(app.quit);
}

#[test]
fn q_quits_once_the_program_is_gone() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    app.nav.row = 3;
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.key(Key::Char('q'));
    assert!(app.quit);
}

#[test]
fn keep_the_data_sends_no_confirmation_and_says_where_the_data_is() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    app.nav.row = 3;
    app.key(Key::Enter);
    assert!(screen(&app).contains("Remove OpenVIBES?"));
    app.key(Key::Char('y'));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(
        app.host.calls.borrow()[0].0,
        format!("remove-step backup {ALL}")
    );
    assert!(screen(&app).contains("The data stays"));
}

#[test]
fn a_failed_step_offers_try_again_and_keeps_the_program() {
    use platform_host::HostError;
    let mut app = set_up(vec![
        Ok("done\tok\n".into()),
        Err(HostError::Failed("boom".into())),
    ]);
    app.open_page(Page::Uninstall);
    app.nav.row = 3;
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        text.contains("boom") && text.contains("Try again") && text.contains("partly removed"),
        "{text}"
    );
    app.key(Key::Char('q'));
    assert!(!app.quit, "q does not quit a half-done uninstall");
}

#[test]
fn esc_cancels_the_typed_name_and_q_types_into_it() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    app.nav.row = 3;
    app.key(Key::Enter);
    type_text(&mut app, "q?");
    assert_eq!(app.maint.typed, "q?");
    assert!(!app.quit);
    app.key(Key::Esc);
    assert_eq!(app.maint.typed, "");
    assert_eq!(app.nav.screen, Screen::Maint(Page::Uninstall));
}

#[test]
fn with_back_up_first_the_backup_goes_to_a_new_file_in_the_folder() {
    let dir = std::env::temp_dir().join(format!("ov-uninstall-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut app = set_up(vec![]);
    let etc = app.root.join("etc/openvibes");
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::write(
        etc.join("backup.toml"),
        format!("folder = \"{}\"\nfirst = true\n", dir.display()),
    )
    .unwrap();
    app.open_page(Page::Uninstall);
    app.nav.row = 2;
    assert!(screen(&app).contains("Ticked because you backed up last time"));
    app.nav.row = 4; // Keep, Everything, Back up first, Save in folder, Uninstall
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let first = app.host.calls.borrow()[0].0.clone();
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        first.contains(&format!("--backup {}/openvibes-{version}-", dir.display())),
        "{first}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_half_done_uninstall_is_a_status_problem_that_opens_the_page() {
    let mut app = set_up(vec![]);
    mark(&app, "uninstall");
    app.files_changed();
    assert!(matches!(
        &app.status_items()[0],
        Item::Problem { text, fix: Some(Fix::Finish(Page::Uninstall)) }
            if text.contains("uninstall stopped half way")
    ));
    app.nav.go(Screen::Status);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Uninstall));
}

#[test]
fn the_menu_ends_with_uninstall() {
    let mut app = set_up(vec![]);
    app.nav.go(Screen::Maintenance);
    app.nav.row = super::row_of("Uninstall");
    assert!(screen(&app).contains("remove OpenVIBES from this host"));
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Uninstall));
}

#[test]
fn stray_enters_on_the_choices_never_start_an_uninstall() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    app.key(Key::Enter);
    assert_eq!(
        app.nav.row, 3,
        "Keep is chosen and the highlight is on Uninstall"
    );
    app.nav.row = 0;
    app.key(Key::Enter);
    assert!(app.question.is_none(), "one Enter only moves to Uninstall");
    app.key(Key::Enter);
    assert!(
        app.run.is_none() && app.asking.is_none(),
        "two Enters only ask"
    );
    assert!(app.host.calls.borrow().is_empty());
    app.key(Key::Esc);
    // Everything moves to the name row; Back up first toggles.
    app.nav.row = 1;
    app.key(Key::Enter);
    assert!(app.maint.everything);
    assert_eq!(app.nav.row, 3);
    app.nav.row = 2;
    app.key(Key::Enter);
    assert!(app.maint.first);
    assert!(app.question.is_none());
}

#[test]
fn a_missing_plan_is_said_on_the_page() {
    let mut app = set_up(vec![]);
    app.host.plan = String::new();
    app.open_page(Page::Uninstall);
    app.nav.row = 3;
    app.key(Key::Enter);
    assert!(
        screen(&app).contains("The plan cannot be read"),
        "{}",
        screen(&app)
    );
}

#[test]
fn a_run_that_ends_on_another_screen_brings_its_result_back() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    app.nav.row = 3;
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    // Tests run the calls at once; model "finished while elsewhere".
    app.nav.go(Screen::Status);
    app.run_ended(false);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Uninstall));
    assert!(screen(&app).contains("OpenVIBES is removed from this host"));
    app.key(Key::Esc);
    assert!(!app.quit);
    app.key(Key::Enter);
    assert!(app.quit);
}

#[test]
fn one_empty_line_separates_the_list_from_its_help() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    for _ in 0..4 {
        app.key(Key::Down);
    }
    let _ = screen(&app); // a frame drawn on Uninstall: the list scrolls to it
    app.key(Key::Enter); // without the name: moves to the name row
    let text = screen(&app);
    let lines: Vec<&str> = text.lines().collect();
    let help = lines
        .iter()
        .position(|l| l.contains("exactly; a tick shows"))
        .unwrap();
    // The list's hint line ("⭣ 1 more") or one empty line, never two.
    assert!(
        !(lines[help - 1].trim().is_empty() && lines[help - 2].trim().is_empty()),
        "{text}"
    );
}

#[test]
fn the_uninstall_question_starts_on_no() {
    // User, 2026-10-12: a stray Enter on the question never removes anything.
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    app.nav.row = 3; // Keep the data → Uninstall
    app.key(Key::Enter);
    assert!(screen(&app).contains("Remove OpenVIBES?"));
    assert!(
        matches!(app.question, Some((_, false))),
        "No is highlighted"
    );
    app.key(Key::Enter);
    assert!(app.question.is_none() && app.run.is_none() && app.asking.is_none());
    assert!(
        app.host.calls.borrow().is_empty(),
        "Enter on No removes nothing"
    );
}

#[test]
fn remove_everything_will_not_back_up_into_a_folder_it_removes() {
    // Review C1: said on the page, before the question.
    let mut app = set_up(vec![]);
    let etc = app.root.join("etc/openvibes");
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::write(
        etc.join("backup.toml"),
        "folder = \"/var/backups/openvibes\"\nfirst = true\n",
    )
    .unwrap();
    app.open_page(Page::Uninstall);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    app.maint.typed = "platform.example.com".into();
    app.nav.row = 5; // Keep, Everything, Back up first, Save in folder, Type…, Uninstall
    app.key(Key::Enter);
    assert!(app.question.is_none(), "{}", screen(&app));
    assert!(
        screen(&app).contains("Remove everything removes /var/backups/openvibes"),
        "{}",
        screen(&app)
    );
    assert_eq!(app.nav.row, 3, "the folder row is highlighted");
}

#[test]
fn a_half_done_remove_everything_reopens_as_remove_everything() {
    // Review I3: never silently Keep the data (gone already), no backup.
    let mut app = set_up(vec![]);
    mark(&app, "uninstall\neverything");
    let etc = app.root.join("etc/openvibes");
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::write(etc.join("backup.toml"), "folder = \"/srv\"\nfirst = true\n").unwrap();
    app.open_page(Page::Uninstall);
    let text = screen(&app);
    assert!(text.contains("(•) Remove everything"), "{text}");
    assert!(text.contains("[ ] Back up first"), "{text}");
}

fn uninstall_with(everything: bool, purge: &str, admin: &str) -> String {
    let ok = || Ok("done\tok\n".to_owned());
    let mut app = set_up(vec![
        ok(),
        ok(),
        ok(),
        ok(),
        Ok(format!("done\t{purge}\n")),
        Ok(format!("done\t{admin}\n")),
    ]);
    app.open_page(Page::Uninstall);
    if everything {
        app.key(Key::Down);
        app.key(Key::Char(' '));
        app.maint.typed = "platform.example.com".into();
    }
    app.nav.row = if everything { 4 } else { 3 };
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    screen(&app)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn the_result_says_what_the_helper_reported() {
    // Review I4: not a canned "Nothing is left behind".
    let text = uninstall_with(
        true,
        "database, roles, configuration, data and service accounts removed; PostgreSQL stays: it holds 2 other databases",
        "removed openvibes-admin; the package repository stays: openvibes-agent still uses it; this program closes here",
    );
    assert!(text.contains("OpenVIBES is removed"), "{text}");
    assert!(
        text.contains("PostgreSQL stays: it holds 2 other databases"),
        "{text}"
    );
    assert!(
        text.contains("The package repository stays: openvibes-agent still uses it"),
        "{text}"
    );
    assert!(!text.contains("Nothing is left behind"), "{text}");
    let text = uninstall_with(
        false,
        "data kept",
        "removed openvibes-admin; kept: /etc/openvibes, /var/backups/openvibes; this program closes here; the rest is removed",
    );
    assert!(
        text.contains("Kept: /etc/openvibes, /var/backups/openvibes"),
        "{text}"
    );
}
