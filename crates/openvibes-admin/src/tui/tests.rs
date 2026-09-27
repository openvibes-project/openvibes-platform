//! The Services screen against a fake host, rendered at 80×24.

use std::cell::RefCell;

use platform_host::{Host, HostError, ServiceAction, ServiceStatus, Unit};
use ratatui::{Terminal, backend::TestBackend};

use super::{app::App, render};

struct FakeHost {
    actions: RefCell<Vec<(Unit, ServiceAction)>>,
    log_reads: RefCell<usize>,
    refuse: bool,
}

fn status(unit: Unit, installed: bool, active: &str, ready: Option<bool>) -> ServiceStatus {
    ServiceStatus {
        unit,
        installed,
        enabled: installed,
        active: active.into(),
        ready,
        since: None,
    }
}

impl Host for FakeHost {
    fn services(&self) -> Result<Vec<ServiceStatus>, HostError> {
        Ok(vec![
            status(Unit::Ingest, true, "active", Some(true)),
            status(Unit::Distribution, false, "inactive", None),
            status(Unit::Vulns, true, "failed", None),
            status(Unit::Llm, true, "inactive", None),
            status(Unit::Maintenance, true, "active", None),
        ])
    }
    fn service_action(&self, unit: Unit, action: ServiceAction) -> Result<(), HostError> {
        if self.refuse {
            return Err(HostError::NotOperator);
        }
        self.actions.borrow_mut().push((unit, action));
        Ok(())
    }
    fn logs(&self, unit: Unit, _lines: u16) -> Result<Vec<String>, HostError> {
        *self.log_reads.borrow_mut() += 1;
        Ok(vec![format!("first log line of {}", unit.label())])
    }
}

fn app(refuse: bool) -> App<FakeHost> {
    App::new(FakeHost {
        actions: RefCell::new(Vec::new()),
        log_reads: RefCell::new(0),
        refuse,
    })
}

fn screen(app: &App<FakeHost>, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| render(frame, app)).unwrap();
    let buffer = terminal.backend().buffer();
    let mut text = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            text.push_str(buffer[(x, y)].symbol());
        }
        text.push('\n');
    }
    text
}

fn select(app: &mut App<FakeHost>, unit: Unit) {
    while app.services[app.selected].unit != unit {
        app.key('j');
    }
}

#[test]
fn renders_services_at_80x24() {
    let app = app(false);
    let text = screen(&app, 80, 24);
    for want in [
        "ingest",
        "active",
        "ready",
        "distribution",
        "not installed",
        "vulns",
        "failed",
        "s start  t stop  r restart  R refresh  q quit",
        "first log line of ingest",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn restart_asks_first() {
    let mut app = app(false);
    select(&mut app, Unit::Vulns);
    app.key('r');
    assert_eq!(app.confirm, Some((Unit::Vulns, ServiceAction::Restart)));
    assert!(screen(&app, 80, 24).contains("Restart openvibes-vulns.service? y/n"));
    app.key('n');
    assert!(app.host.actions.borrow().is_empty());
    assert_eq!(app.confirm, None);
    app.key('r');
    app.key('y');
    assert_eq!(
        *app.host.actions.borrow(),
        [(Unit::Vulns, ServiceAction::Restart)]
    );
    assert!(
        app.message
            .as_deref()
            .unwrap_or("")
            .contains("restart requested"),
        "{:?}",
        app.message
    );
}

// The periodic refresh reloads unit states only: reading logs goes through
// sudo, and every sudo call is written to the auth log (quiet by default).
#[test]
fn periodic_refresh_does_not_read_logs() {
    let mut app = app(false);
    let reads = *app.host.log_reads.borrow();
    app.refresh();
    app.refresh();
    assert_eq!(*app.host.log_reads.borrow(), reads);
    app.key('R');
    assert_eq!(*app.host.log_reads.borrow(), reads + 1, "R reloads the log");
}

#[test]
fn not_installed_offers_nothing() {
    let mut app = app(false);
    select(&mut app, Unit::Distribution);
    app.key('s');
    assert_eq!(app.confirm, None);
    assert!(
        app.message
            .as_deref()
            .unwrap_or("")
            .contains("not installed")
    );
}

#[test]
fn not_an_operator_is_explained() {
    let mut app = app(true);
    app.key('r');
    app.key('y');
    assert!(
        app.message
            .as_deref()
            .unwrap_or("")
            .contains("openvibes-operators"),
        "{:?}",
        app.message
    );
}

#[test]
fn too_small_asks_for_more_room() {
    let app = app(false);
    assert!(screen(&app, 60, 20).contains("needs at least 80×24"));
}

#[test]
fn logs_follow_the_selection_and_q_quits() {
    let mut app = app(false);
    select(&mut app, Unit::Vulns);
    assert_eq!(app.logs, ["first log line of vulns"]);
    app.key('q');
    assert!(app.quit);
}
