//! Home's summary and result lines, and Status's columns. Split from
//! `nav_tests.rs` and `status_tests.rs` (size).

use std::time::{Duration, Instant};

use platform_host::{ServiceStatus, Unit};
use ratatui::{Terminal, backend::TestBackend, style::Color};

use super::{
    app::{App, Key},
    database::Check,
    kind::Kind,
    nav::Screen,
    run::{Run, Work},
    tests::{FakeHost, app, screen},
};

/// Home's summary line and the colour of its mark.
fn summary(app: &App<FakeHost>) -> (String, Option<Color>) {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| super::render(frame, app)).unwrap();
    let buffer = terminal.backend().buffer();
    let text = screen(app, 80, 24);
    let (y, line) = text
        .lines()
        .enumerate()
        .find(|(_, l)| l.contains("attention") || l.contains("running"))
        .unwrap();
    let x = line.chars().position(|c| c == '■' || c == '▲' || c == '●');
    let fg = x.and_then(|x| buffer.cell((x as u16, y as u16)).unwrap().style().fg);
    (line.trim().to_owned(), fg)
}

#[test]
fn a_stopped_unit_makes_home_red() {
    // The fake's vulns has failed.
    let app = app(false);
    let (line, fg) = summary(&app);
    assert!(line.starts_with("■ "), "{line}");
    assert_eq!(fg, Some(Color::Red), "{line}");
}

#[test]
fn a_red_check_makes_home_red_and_amber_ones_stay_amber() {
    let mut app = app(false);
    app.host.started.borrow_mut().push(Unit::Vulns);
    app.refresh();
    app.database.health = vec![Check {
        problem: true,
        text: "disk 92% used".into(),
        ..Check::default()
    }];
    let (line, fg) = summary(&app);
    assert!(line.starts_with("▲ 1 thing needs attention"), "{line}");
    assert_eq!(fg, Some(Color::Yellow), "{line}");
    app.database.health.push(Check {
        problem: true,
        red: true,
        text: "ingest.crt ended".into(),
        ..Check::default()
    });
    let (line, fg) = summary(&app);
    assert!(line.starts_with("■ 2 things need attention"), "{line}");
    assert_eq!(fg, Some(Color::Red), "{line}");
}

/// Back on Home, the summary comes from fresh checks, not the ones Status
/// read last.
#[test]
fn home_reads_fresh_checks_when_shown_again() {
    let mut app = app(false);
    let fresh = summary(&app).0;
    app.database.health.push(Check {
        problem: true,
        text: "disk 92% used".into(),
        ..Check::default()
    });
    assert_ne!(summary(&app).0, fresh);
    app.health_at = Instant::now().checked_sub(Duration::from_secs(11));
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maintenance);
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Home);
    assert_eq!(summary(&app).0, fresh);
}

/// The longest result, with the summary beside it, wraps to its own line
/// instead of being cut at 80 columns.
#[test]
fn a_long_result_on_home_wraps_rather_than_cut() {
    let mut app = app(false);
    let done = "Replaced · agents move over in 30 days · put the key offline again";
    let mut run = Run::new(
        Work::new(Kind::Replace { done: done.into() }, vec![]),
        Instant::now(),
    );
    run.ended = Some(Instant::now());
    app.run = Some(run);
    let text = screen(&app, 80, 24);
    assert!(text.contains(&format!("✓ {done}")), "{text}");
    assert!(
        text.contains("things need attention · see Status"),
        "{text}"
    );
}

/// A long unit name widens the name column; the states still line up.
#[test]
fn status_columns_line_up_with_certificate_renewal() {
    let mut app = app(false);
    app.open_status();
    app.services.push(ServiceStatus {
        unit: Unit::Certificates,
        installed: true,
        enabled: true,
        active: "active".into(),
        ready: None,
        since: None,
        last_run_failed: false,
    });
    let text = screen(&app, 80, 40);
    let column = |name: &str| {
        let line = text
            .lines()
            .find(|l| l.contains(&format!("● {name} ")))
            .unwrap();
        line.find("running").unwrap()
    };
    assert_eq!(
        column("maintenance"),
        column("certificate renewal"),
        "{text}"
    );
}

/// Esc to Home reads the checks again only when they are 10 s old or a run
/// ended since: each read is sudo, systemctl and psql on this thread.
#[test]
fn home_reads_the_checks_again_only_when_old_or_after_a_run() {
    let mut app = app(false);
    let reads = |app: &App<FakeHost>| app.host.disk_calls.get();
    let help_and_back = |app: &mut App<FakeHost>| {
        app.key(Key::Char('?'));
        app.key(Key::Esc);
        assert_eq!(app.nav.screen, Screen::Home);
    };
    let before = reads(&app);
    help_and_back(&mut app);
    assert_eq!(reads(&app), before, "fresh checks are kept");
    app.health_at = Instant::now().checked_sub(Duration::from_secs(11));
    help_and_back(&mut app);
    assert_eq!(reads(&app), before + 1, "10 s old: read again");
    let mut run = Run::new(Work::new(Kind::Check, vec![]), Instant::now());
    run.ended = Some(Instant::now());
    app.run = Some(run);
    help_and_back(&mut app);
    assert_eq!(reads(&app), before + 2, "a run ended since: read again");
    help_and_back(&mut app);
    assert_eq!(reads(&app), before + 2);
}

/// A refresh that fails on the way back stays on Home.
#[test]
fn a_failed_refresh_on_the_way_home_is_shown() {
    let mut app = app(false);
    app.health_at = None;
    *app.host.services_error.borrow_mut() = Some("systemctl is gone".into());
    app.key(Key::Char('?'));
    app.key(Key::Esc);
    let text = screen(&app, 80, 24);
    assert!(text.contains("systemctl is gone"), "{text}");
}
