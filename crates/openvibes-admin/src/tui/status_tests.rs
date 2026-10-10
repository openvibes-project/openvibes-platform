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
        "Services",
        "ingest",
        "running",
        "Start vulns",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
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
