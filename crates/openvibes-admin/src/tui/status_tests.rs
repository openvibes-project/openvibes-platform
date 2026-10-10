//! Status against the fake host (`tests::FakeHost`: ingest active and
//! ready, distribution not installed, vulns failed, llm inactive,
//! maintenance active).

use platform_host::Unit;

use super::{
    app::Key,
    nav::Screen,
    status::{Fix, Item, items},
    tests::{app, screen},
};

#[test]
fn a_stopped_service_is_a_problem_first_and_llm_idling_is_not() {
    let app = app(false);
    let items = app.status_items();
    assert!(
        matches!(&items[0], Item::Problem { text, fix: Some(Fix::Start(Unit::Vulns)) } if text.contains("vulns is stopped")),
        "{:?}",
        items[0]
    );
    assert!(
        !items
            .iter()
            .any(|i| matches!(i, Item::Problem { text, .. } if text.contains("llm")))
    );
    assert!(
        items
            .iter()
            .any(|i| matches!(i, Item::Service(Unit::Ingest)))
    );
    assert!(
        !items
            .iter()
            .any(|i| matches!(i, Item::Service(Unit::Distribution))),
        "not installed: not listed"
    );
}

#[test]
fn status_renders_problems_then_services_with_the_frame() {
    let mut app = app(false);
    app.key(Key::Enter); // Home → Status
    assert_eq!(app.nav.screen, Screen::Status);
    let text = screen(&app, 80, 24);
    for want in [
        "━━ Status",
        "Needs attention",
        "vulns is stopped",
        "Start vulns",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    // At 80x24 three problems leave no room for the service rows: the
    // hint says so (select a service to see them, see the scroll test).
    assert!(text.contains("⭣ 4 more"), "{text}");
    let mut app = app;
    while !matches!(app.status_items()[app.nav.row], Item::Service(Unit::Ingest)) {
        app.key(Key::Down);
    }
    let text = screen(&app, 80, 24);
    assert!(
        text.contains("Services") && text.contains("running"),
        "a heading is shown with its entries: {text}"
    );
    assert!(
        screen(&app, 80, 24)
            .lines()
            .any(|l| l.contains("ingest") && l.contains("active") && !l.contains(".crt")),
        "{}",
        screen(&app, 80, 24)
    );
}

#[test]
fn health_problems_are_listed_before_services() {
    let mut app = app(false);
    app.key(Key::Enter);
    let items = app.status_items();
    let first_service = items
        .iter()
        .position(|i| matches!(i, Item::Service(_)))
        .unwrap();
    assert!(
        items[..first_service]
            .iter()
            .all(|i| matches!(i, Item::Problem { .. }))
    );
    // Fake host: the unreadable certificate is a health problem without a fix.
    assert!(
        items[..first_service]
            .iter()
            .any(|i| matches!(i, Item::Problem { text, fix: None } if text.contains("ingest.crt")))
    );
    assert!(
        !items
            .iter()
            .any(|i| matches!(i, Item::Problem { text, .. } if text.contains("vulns: failed"))),
        "unit lines are built in status, not in checks"
    );
}

#[test]
fn enter_on_a_service_opens_it() {
    let mut app = app(false);
    app.key(Key::Enter);
    while !matches!(app.status_items()[app.nav.row], Item::Service(Unit::Ingest)) {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Service(Unit::Ingest));
}

#[test]
fn items_without_services_still_list_health_problems() {
    let checks = vec![super::database::Check {
        problem: true,
        text: "disk 92% used".into(),
    }];
    let items = items(&[], &checks);
    assert!(matches!(&items[0], Item::Problem { text, fix: None } if text.contains("disk 92%")));
}

fn marked(text: &str) -> usize {
    text.lines()
        .position(|l| l.contains('▸'))
        .unwrap_or_else(|| panic!("no highlight in\n{text}"))
}

fn more(text: &str, arrow: char) -> Option<usize> {
    text.lines().find_map(|l| {
        let rest = l.trim().strip_prefix(arrow)?.trim().strip_suffix(" more")?;
        rest.parse().ok()
    })
}

#[test]
fn status_scrolls_one_row_and_keeps_its_window_going_back_up() {
    let mut app = app(false);
    app.key(Key::Enter);
    for i in 0..12 {
        app.database.health.push(super::database::Check {
            problem: true,
            text: format!("extra problem {i}"),
        });
    }
    let total = app.status_items().len();
    let mut below = more(&screen(&app, 80, 24), '⭣').expect("hint below");
    assert_eq!(more(&screen(&app, 80, 24), '⭡'), None);
    for _ in 1..total {
        app.key(Key::Down);
        let text = screen(&app, 80, 24);
        marked(&text);
        let now = more(&text, '⭣').unwrap_or(0);
        assert!(now <= below, "{text}");
        below = now;
    }
    let bottom = screen(&app, 80, 24);
    assert_eq!(more(&bottom, '⭣'), None, "{bottom}");
    assert!(more(&bottom, '⭡').is_some(), "{bottom}");
    // Up from the bottom: the highlight moves, the window stays.
    let (line, above) = (marked(&bottom), more(&bottom, '⭡'));
    app.key(Key::Up);
    let up = screen(&app, 80, 24);
    assert_eq!(marked(&up) + 2, line, "highlight moves up one entry\n{up}");
    assert_eq!(more(&up, '⭡'), above, "window stays\n{up}");
}

#[test]
fn the_row_is_clamped_when_the_list_shrinks() {
    let mut app = app(false);
    app.key(Key::Enter);
    app.nav.row = 99;
    app.refresh();
    assert_eq!(app.nav.row, app.status_items().len() - 1);
}
