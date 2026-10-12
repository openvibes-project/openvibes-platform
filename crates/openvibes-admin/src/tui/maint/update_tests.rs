//! Maintenance › Update OpenVIBES, key by key (maint1.py, flows.py,
//! backupfolder.py, backupdefault.py, general.py).

use std::path::Path;

use platform_host::HostError;

use crate::tui::{
    app::{App, Key},
    maint::Page,
    nav::Screen,
    script_host::{SetupHost, screen, set_up, type_text},
    status::Item,
};

fn update_app(answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    let mut app = set_up(answers);
    app.update = Some("0.2.9".into());
    app.packages = Some(Ok(Vec::new()));
    app
}

fn remember(app: &App<SetupHost>, text: &str) {
    let dir = app.root.join("etc/openvibes");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("backup.toml"), text).unwrap();
}

fn temp(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!("ov-update-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.display().to_string()
}

fn yes_and_password(app: &mut App<SetupHost>) {
    app.key(Key::Enter);
    type_text(app, "pw");
    app.key(Key::Enter);
}

#[test]
fn the_first_update_offers_no_folder_and_back_up_first_is_off() {
    let mut app = update_app(vec![]);
    app.open_page(Page::Update);
    let text = screen(&app);
    let installed = format!("v{} installed", env!("CARGO_PKG_VERSION"));
    for want in [
        installed.as_str(),
        "0.2.9 available",
        "[ ] Back up first",
        "no folder chosen yet",
        "Update now",
        "What's new",
        "Off unless you chose it last time.",
        "Space  Select/deselect",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn ticking_back_up_first_needs_a_folder_before_update_now() {
    let mut app = update_app(vec![]);
    app.open_page(Page::Update);
    app.key(Key::Char(' '));
    let text = screen(&app);
    assert!(
        text.contains("[x] Back up first") && text.contains("choose a folder"),
        "{text}"
    );
    app.key(Key::Down);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert!(app.question.is_none(), "no question without a folder");
    assert_eq!(app.nav.row, 1, "Save in folder is highlighted");
    assert!(screen(&app).contains("Choose a folder for the backup first"));
}

#[test]
fn update_with_a_remembered_folder_runs_six_steps_with_a_new_file() {
    let dir = temp("six");
    let mut app = update_app(vec![]);
    remember(&app, &format!("folder = \"{dir}\"\nfirst = true\n"));
    app.open_page(Page::Update);
    let text = screen(&app);
    assert!(
        text.contains("[x] Back up first")
            && text.contains("Ticked because you backed up last time"),
        "{text}"
    );
    app.nav.row = 2;
    app.key(Key::Enter);
    assert!(screen(&app).contains("Update to 0.2.9?"));
    yes_and_password(&mut app);
    let calls = app.host.calls.borrow().clone();
    assert_eq!(calls.len(), 6);
    assert!(
        calls[0].0.starts_with(&format!(
            "update-step backup --remember-choice --backup {dir}/openvibes-{}-",
            env!("CARGO_PKG_VERSION")
        )),
        "{}",
        calls[0].0
    );
    assert!(calls[5].0.starts_with("update-step ready"));
    let text = screen(&app);
    assert!(
        text.contains("Updated to 0.2.9 · everything is ready"),
        "{text}"
    );
    assert!(text.contains("Enter  Open 0.2.9"), "{text}");
    app.key(Key::Enter);
    assert!(app.reopen, "Enter starts the new version");
}

#[test]
fn without_back_up_first_the_choice_is_still_remembered() {
    let mut app = update_app(vec![]);
    app.open_page(Page::Update);
    app.nav.row = 1;
    app.key(Key::Enter);
    yes_and_password(&mut app);
    assert_eq!(
        app.host.calls.borrow()[0].0,
        "update-step backup --remember-choice"
    );
}

#[test]
fn a_failed_upgrade_starts_the_services_again_and_says_so() {
    let mut app = update_app(vec![
        Ok("skipped\tno backup chosen\n".into()),
        Ok("done\tstopped\n".into()),
        Ok("failed\trepo.openvibes.org timed out after 30 s\n".into()),
        Ok("done\tstarted again\n".into()),
        Ok("done\tready\n".into()),
    ]);
    app.open_page(Page::Update);
    app.nav.row = 1;
    app.key(Key::Enter);
    yes_and_password(&mut app);
    let calls = app.host.calls.borrow().clone();
    assert!(calls[3].0.starts_with("update-step start"));
    assert!(
        calls[4].0.starts_with("update-step ready"),
        "Ready starts the agent and ends the half-done mark"
    );
    let text = screen(&app);
    for want in [
        "✗ Install packages",
        "timed out",
        "started again",
        "partly updated",
        "Try again",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(
        app.host.calls.borrow()[5].0.starts_with("update-step stop"),
        "Try again stops them again first"
    );
}

#[test]
fn a_failed_migration_keeps_the_services_stopped_and_says_why() {
    let mut app = update_app(vec![
        Ok("skipped\tno backup chosen\n".into()),
        Ok("done\tstopped\n".into()),
        Ok("done\tupgraded\n".into()),
        Ok("failed\tschema 47 needs a backup first\n".into()),
    ]);
    app.open_page(Page::Update);
    app.nav.row = 1;
    app.key(Key::Enter);
    yes_and_password(&mut app);
    assert_eq!(
        app.host.calls.borrow().len(),
        4,
        "the old services are not started on a new schema"
    );
    assert!(screen(&app).contains("the database is not yet"));
}

#[test]
fn a_half_done_update_is_a_status_problem_and_finishes_without_a_new_version() {
    let mut app = set_up(vec![]);
    app.packages = Some(Ok(Vec::new()));
    let run = app.root.join("run/openvibes-admin");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(run.join("job"), "update").unwrap();
    app.files_changed();
    assert!(
        matches!(&app.status_items()[0], Item::Problem { text, .. } if text.contains("update stopped half way"))
    );
    app.open_page(Page::Update);
    assert!(screen(&app).contains("Finish the update"));
    app.key(Key::Enter);
    assert!(screen(&app).contains("Finish the update?"));
    yes_and_password(&mut app);
    assert!(
        app.host.calls.borrow()[0].0.starts_with("update-step stop"),
        "no backup when finishing"
    );
    assert_eq!(app.host.calls.borrow().len(), 5);
}

#[test]
fn whats_new_lists_every_package_and_up_to_date_offers_only_it() {
    let mut app = set_up(vec![]);
    app.packages = Some(Ok(vec![platform_host::PackageUpdate {
        name: "openvibes-ingest".into(),
        installed: "0.2.8-1.fc44".into(),
        available: None,
    }]));
    app.open_page(Page::Update);
    let text = screen(&app);
    assert!(
        text.contains("up to date") && !text.contains("Update now"),
        "{text}"
    );
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::WhatsNew));
    let text = screen(&app);
    assert!(
        text.contains("openvibes-ingest") && text.contains("0.2.8-1.fc44 · up to date"),
        "{text}"
    );
    assert!(text.contains("releases/tag/v"), "{text}");
}

#[test]
fn the_half_done_mark_is_read_from_run() {
    let root = std::env::temp_dir().join(format!("ov-half-{}", std::process::id()));
    std::fs::create_dir_all(root.join("run/openvibes-admin")).unwrap();
    assert_eq!(super::update::half_done(&root), None);
    std::fs::write(root.join("run/openvibes-admin/job"), "uninstall\n").unwrap();
    assert_eq!(
        super::update::half_done(&root).as_deref(),
        Some("uninstall")
    );
    assert_eq!(super::update::half_done(Path::new("/nonexistent")), None);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_failed_start_of_the_rescue_is_not_called_started() {
    let mut app = update_app(vec![
        Ok("skipped\tno backup chosen\n".into()),
        Ok("done\tstopped\n".into()),
        Ok("failed\ttimed out\n".into()),
        Ok("failed\tingest would not start\n".into()),
        Ok("failed\tnot ready\n".into()),
    ]);
    app.open_page(Page::Update);
    app.nav.row = 1;
    app.key(Key::Enter);
    yes_and_password(&mut app);
    let text = screen(&app);
    assert!(text.contains("could not be started again"), "{text}");
}

#[test]
fn finishing_a_half_done_update_never_starts_the_services_on_a_failure() {
    let mut app = set_up(vec![
        Ok("done\tstopped\n".into()),
        Ok("failed\ttimed out\n".into()),
    ]);
    app.packages = Some(Ok(Vec::new()));
    let run = app.root.join("run/openvibes-admin");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(run.join("job"), "update").unwrap();
    app.files_changed();
    app.open_page(Page::Update);
    app.key(Key::Enter);
    yes_and_password(&mut app);
    assert_eq!(app.host.calls.borrow().len(), 2, "no rescue");
    let text = screen(&app);
    assert!(
        text.contains("stay stopped until the update is finished"),
        "{text}"
    );
    assert!(text.contains("Try again"), "{text}");
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(
        app.host.calls.borrow()[2]
            .0
            .starts_with("update-step upgrade"),
        "Try again goes on from the step that failed"
    );
}

#[test]
fn a_newer_agent_alone_offers_update_now() {
    let mut app = set_up(vec![]);
    app.packages = Some(Ok(vec![platform_host::PackageUpdate {
        name: "openvibes-agent".into(),
        installed: "0.2.8-1.fc44".into(),
        available: Some("0.2.9-1.fc44".into()),
    }]));
    app.open_page(Page::Update);
    let text = screen(&app);
    assert!(
        text.contains("Update now") && text.contains("updates available"),
        "{text}"
    );
    app.nav.row = 1;
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        text.contains("Install updates (agent 0.2.9)?") && !text.contains("Update to"),
        "the question names what is newer, not the installed version\n{text}"
    );
    yes_and_password(&mut app);
    let text = screen(&app);
    assert!(text.contains("Updated: agent 0.2.9"), "{text}");
    assert!(text.contains(&format!("Open {}", env!("CARGO_PKG_VERSION"))));
}
