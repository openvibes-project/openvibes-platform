//! What Optional parts, Ports and addresses and Names share before they
//! ask: other work running, an older plan, a plan changed meanwhile, and
//! the menu when the plan cannot be read.

use std::time::Instant;

use crate::tui::{
    app::{App, Key},
    maint::Page,
    nav::Screen,
    run::{Call, Kind, Run, Work},
    script_host::{PLAN, SetupHost, screen, set_up, type_text},
};

/// Each page with one change made, the cursor on Apply.
fn changed(page: Page) -> App<SetupHost> {
    let mut app = set_up(vec![]);
    app.open_page(page);
    match page {
        Page::Parts => {
            app.nav.row = 1;
            app.key(Key::Char(' '));
            app.nav.row = 2;
        }
        Page::Ports => {
            app.nav.row = 1;
            app.key(Key::Enter);
            for _ in 0..5 {
                app.key(Key::Backspace);
            }
            type_text(&mut app, "18500");
            app.key(Key::Enter);
            app.nav.row = 4;
        }
        _ => {
            app.nav.row = 1;
            app.key(Key::Enter);
            type_text(&mut app, "other.lan");
            app.key(Key::Enter);
            app.nav.row = 3;
        }
    }
    app
}

const PAGES: [Page; 3] = [Page::Parts, Page::Ports, Page::Names];

fn refused(app: &App<SetupHost>, want: &str, page: Page) {
    assert!(app.question.is_none() && app.asking.is_none(), "{page:?}");
    assert!(app.host.calls.borrow().is_empty(), "{page:?}");
    let said = app.outcome.as_ref().map(|(_, s)| s.as_str());
    assert_eq!(said, Some(want), "{page:?}\n{}", screen(app));
}

#[test]
fn a_change_asks_when_nothing_is_in_the_way() {
    for page in PAGES {
        let mut app = changed(page);
        app.key(Key::Enter);
        assert!(app.question.is_some(), "{page:?}\n{}", screen(&app));
    }
}

#[test]
fn other_work_running_is_said_before_the_question() {
    for page in PAGES {
        let mut app = changed(page);
        let work = Work::new(Kind::Fix, vec![Call::Status]);
        app.run = Some(Run::new(work, Instant::now()));
        app.key(Key::Enter);
        refused(&app, "Wait: other work is still running", page);
    }
}

#[test]
fn a_plan_changed_meanwhile_is_refused() {
    for page in PAGES {
        let mut app = changed(page);
        app.host.plan = PLAN.replace("sans = []", "sans = [\"10.0.0.9\"]");
        app.key(Key::Enter);
        refused(
            &app,
            "The setup changed meanwhile: open the page again.",
            page,
        );
    }
}

#[test]
fn a_plan_from_an_older_version_needs_repair_first() {
    let old = PLAN
        .lines()
        .filter(|l| !l.contains("_port"))
        .collect::<Vec<_>>()
        .join("\n");
    for page in PAGES {
        let mut app = set_up(vec![]);
        app.host.plan = old.clone();
        app.open_page(page);
        let text = screen(&app);
        assert!(
            text.contains("Run Repair first: this plan is from an older version."),
            "{page:?}\n{text}"
        );
        // And when it turns old while the page is open.
        let mut app = changed(page);
        app.host.plan = old.clone();
        app.key(Key::Enter);
        refused(
            &app,
            "Run Repair first: this plan is from an older version.",
            page,
        );
    }
}

#[test]
fn the_menu_says_an_unreadable_plan_cannot_be_read() {
    let mut app = set_up(vec![]);
    app.host.plan = "not a plan".into();
    app.nav.go(Screen::Maintenance);
    let text = screen(&app);
    for name in ["Optional parts", "Ports and addresses"] {
        let line = text.lines().find(|l| l.contains(name)).unwrap();
        assert!(line.contains("cannot be read"), "{line}");
    }
}
