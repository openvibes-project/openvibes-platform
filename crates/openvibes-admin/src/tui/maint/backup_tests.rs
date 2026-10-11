//! Maintenance › Back up and the folder field, key by key.

use std::{
    cell::RefCell,
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant},
};

use crate::tui::{
    app::{App, Key},
    maint::Page,
    nav::Screen,
    script_host::{SetupHost, screen, set_up, type_text},
};

/// The typing has paused: the folder's slow check (probe file, df) runs.
fn pause(app: &mut App<SetupHost>) {
    app.tick(Instant::now() + Duration::from_secs(1));
}

fn folder(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ov-backup-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("nas")).unwrap();
    dir
}

#[test]
fn back_up_asks_for_a_folder_checks_it_as_typed_and_writes_a_new_file() {
    let dir = folder("now");
    let shown = dir.display().to_string();
    let mut app = set_up(vec![Ok(format!(
        "done\tbackup saved to {shown}/x.dump (431000000 bytes) and {shown}/x.dump.roles.sql\n"
    ))]);
    app.open_page(Page::Backup);
    let text = screen(&app);
    assert!(
        text.contains("choose a folder") && text.contains("Certificates"),
        "{text}"
    );
    app.key(Key::Enter);
    assert!(
        screen(&app).contains("Folder: type, or"),
        "{}",
        screen(&app)
    );
    type_text(&mut app, &shown);
    pause(&mut app);
    assert!(
        screen(&app).contains("exists and is writable · 1.8T free"),
        "{}",
        screen(&app)
    );
    app.key(Key::Enter);
    pause(&mut app);
    app.key(Key::Down);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let call = app.host.calls.borrow()[0].0.clone();
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        call.starts_with(&format!(
            "update-step backup --backup {shown}/openvibes-{version}-"
        )),
        "{call}"
    );
    assert!(call.ends_with(".dump"), "{call}");
    let text = screen(&app);
    assert!(
        text.contains("✓ Saved") && text.contains("411 MB"),
        "{text}"
    );
    assert!(text.contains("Copy it off this host"), "{text}");
    app.key(Key::Enter);
    assert_eq!(
        app.nav.screen,
        Screen::Home,
        "Enter Done goes back to where Back up was opened from"
    );
    assert!(app.run.is_none(), "the result was seen");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn back_up_now_without_a_good_folder_says_so_and_runs_nothing() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Backup);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert!(app.asking.is_none() && app.host.calls.borrow().is_empty());
    assert!(screen(&app).contains("Choose a folder first"));
    assert_eq!(app.nav.row, 0, "the folder row is highlighted");
}

#[test]
fn esc_while_typing_puts_the_folder_back_and_q_types_into_it() {
    let dir = folder("esc");
    let mut app = set_up(vec![]);
    let memory = app.root.join("etc/openvibes");
    std::fs::create_dir_all(&memory).unwrap();
    std::fs::write(
        memory.join("backup.toml"),
        format!("folder = \"{}\"\n", dir.display()),
    )
    .unwrap();
    app.open_page(Page::Backup);
    assert_eq!(
        app.maint.folder.text,
        dir.display().to_string(),
        "the remembered folder"
    );
    app.key(Key::Enter);
    type_text(&mut app, "/q?");
    assert!(app.maint.folder.text.ends_with("/q?") && !app.quit);
    app.key(Key::Esc);
    assert_eq!(app.maint.folder.text, dir.display().to_string());
    assert_eq!(
        app.nav.screen,
        Screen::Maint(Page::Backup),
        "Esc cancels, it does not leave"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn tab_browses_folders_and_use_this_folder_picks_one() {
    let dir = folder("tab");
    let mut app = set_up(vec![]);
    app.open_page(Page::Backup);
    app.key(Key::Enter);
    type_text(&mut app, &dir.display().to_string());
    app.key(Key::Tab);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Folder));
    assert!(screen(&app).contains("nas/"), "{}", screen(&app));
    app.key(Key::Down);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.maint.browse.as_ref().unwrap().dir, dir.join("nas"));
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Backup));
    assert_eq!(app.maint.folder.text, dir.join("nas").display().to_string());
    assert!(!app.maint.editing(), "picking a folder ends the typing");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn typing_does_the_cheap_checks_and_df_waits_for_a_pause() {
    let dir = folder("df");
    let mut app = set_up(vec![]);
    app.open_page(Page::Backup);
    app.key(Key::Enter);
    type_text(&mut app, "backups");
    assert!(screen(&app).contains("a full path, starting with /"));
    for _ in 0.."backups".len() {
        app.key(Key::Backspace);
    }
    type_text(&mut app, &format!("{}/nope", dir.display()));
    assert!(screen(&app).contains("does not exist"), "{}", screen(&app));
    app.key(Key::ClearLine);
    type_text(&mut app, &dir.display().to_string());
    app.tick(Instant::now());
    assert_eq!(app.host.free_calls.get(), 0, "no df while typing");
    assert!(!app.maint.folder.ok(), "not good before it is checked");
    pause(&mut app);
    assert_eq!(
        app.host.free_calls.get(),
        1,
        "one df once the typing paused"
    );
    assert!(app.maint.folder.ok());
    pause(&mut app);
    assert_eq!(app.host.free_calls.get(), 1, "and not again");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_slow_check_runs_on_another_thread_and_gives_up_on_a_stuck_mount() {
    let dir = folder("stuck");
    let mut app = set_up(vec![]);
    let (answer, receiver) = mpsc::channel();
    let receiver = RefCell::new(Some(receiver));
    app.checker = Some(Box::new(move |_| receiver.borrow_mut().take().unwrap()));
    app.open_page(Page::Backup);
    app.key(Key::Enter);
    type_text(&mut app, &dir.display().to_string());
    pause(&mut app);
    assert_eq!(app.host.free_calls.get(), 0, "not on the UI thread");
    assert!(screen(&app).contains("Checking"), "{}", screen(&app));
    app.tick(Instant::now() + Duration::from_secs(60));
    assert!(screen(&app).contains("does not answer"), "{}", screen(&app));
    assert!(!app.maint.folder.ok());
    drop(answer);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_late_answer_for_old_text_is_not_taken() {
    let dir = folder("late");
    let mut app = set_up(vec![]);
    let (answer, receiver) = mpsc::channel();
    let receiver = RefCell::new(Some(receiver));
    app.checker = Some(Box::new(move |_| receiver.borrow_mut().take().unwrap()));
    app.open_page(Page::Backup);
    app.key(Key::Enter);
    type_text(&mut app, &dir.display().to_string());
    pause(&mut app);
    answer.send(Ok("fine".into())).unwrap();
    app.key(Key::Char('x'));
    pause(&mut app);
    assert!(
        !app.maint.folder.ok(),
        "the answer was for the folder before 'x'"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
