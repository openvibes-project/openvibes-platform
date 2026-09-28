//! The Services screen against a fake host, rendered at 80×24.

use std::cell::RefCell;

use platform_host::{
    Host, HostError, PackageUpdate, Privileged, Secret, Service, ServiceAction, ServiceStatus, Unit,
};
use ratatui::{Terminal, backend::TestBackend};

use super::{
    app::{App, Key, Tab},
    configuration::Prompt,
    render,
};

struct FakeHost {
    actions: RefCell<Vec<(Unit, ServiceAction)>>,
    log_reads: RefCell<usize>,
    writes: RefCell<Vec<(Service, String)>>,
    /// What a read returns instead, as if edited by hand meanwhile.
    hand_edit: RefCell<Option<String>>,
    refuse: bool,
    /// (verb, password) of each privileged call.
    privileged_calls: RefCell<Vec<(String, String)>>,
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
    fn read_config(&self, service: Service) -> Result<String, HostError> {
        if let Some(text) = self.hand_edit.borrow().clone() {
            return Ok(text);
        }
        if let Some((_, text)) = self
            .writes
            .borrow()
            .iter()
            .rev()
            .find(|(s, _)| *s == service)
        {
            return Ok(text.clone());
        }
        match service {
            Service::Ingest => Ok(include_str!("../../../../packaging/rpm/ingest.toml").into()),
            Service::Distribution => {
                Ok(include_str!("../../../../packaging/rpm/distribution.toml").into())
            }
            Service::Vulns => Ok(include_str!("../../../../packaging/rpm/vulns.toml").into()),
            Service::Console => Err(HostError::Failed(
                "openvibes-admin helper: /etc/openvibes/console.toml: not installed (no such file)"
                    .into(),
            )),
            Service::Admin => Ok("database_url = \n".into()),
        }
    }
    fn write_config(&self, service: Service, toml: &str) -> Result<(), HostError> {
        if self.refuse {
            return Err(HostError::NotOperator);
        }
        self.writes.borrow_mut().push((service, toml.into()));
        Ok(())
    }
    fn is_set_up(&self) -> bool {
        true
    }
    fn packages(&self) -> Result<Vec<PackageUpdate>, HostError> {
        Ok(Vec::new())
    }
    fn setup_plan(&self) -> Result<String, HostError> {
        Err(HostError::Failed("not set up".into()))
    }
    fn privileged(&self, verb: Privileged<'_>, password: &Secret) -> Result<String, HostError> {
        self.privileged_calls
            .borrow_mut()
            .push((verb.args().join(" "), password.expose().to_owned()));
        Ok(String::new())
    }
}

fn app(refuse: bool) -> App<FakeHost> {
    App::new(FakeHost {
        actions: RefCell::new(Vec::new()),
        log_reads: RefCell::new(0),
        writes: RefCell::new(Vec::new()),
        hand_edit: RefCell::new(None),
        refuse,
        privileged_calls: RefCell::new(Vec::new()),
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
        app.key(Key::Char('j'));
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
        "s start  t stop  r restart  e/d boot  R refresh  q quit",
        "first log line of ingest",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn restart_asks_first() {
    let mut app = app(false);
    select(&mut app, Unit::Vulns);
    app.key(Key::Char('r'));
    assert_eq!(app.confirm, Some((Unit::Vulns, ServiceAction::Restart)));
    assert!(screen(&app, 80, 24).contains("Restart openvibes-vulns.service? y/n"));
    app.key(Key::Char('n'));
    assert!(app.host.actions.borrow().is_empty());
    assert_eq!(app.confirm, None);
    app.key(Key::Char('r'));
    app.key(Key::Char('y'));
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
    app.key(Key::Char('R'));
    assert_eq!(*app.host.log_reads.borrow(), reads + 1, "R reloads the log");
}

#[test]
fn not_installed_offers_nothing() {
    let mut app = app(false);
    select(&mut app, Unit::Distribution);
    app.key(Key::Char('s'));
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
    app.key(Key::Char('r'));
    app.key(Key::Char('y'));
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
    app.key(Key::Char('q'));
    assert!(app.quit);
}

fn configuration(refuse: bool) -> App<FakeHost> {
    let mut app = app(refuse);
    app.key(Key::Tab);
    app
}

fn type_text(app: &mut App<FakeHost>, text: &str) {
    for c in text.chars() {
        app.key(Key::Char(c));
    }
}

/// Selects `key`, opens it, replaces its value with `value`, presses Enter.
fn set(app: &mut App<FakeHost>, key: &str, value: &str) {
    app.config.selected = 0;
    while app.config.form.as_ref().unwrap().fields()[app.config.selected].key != key {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    for _ in 0..app.config.editing.as_ref().unwrap().chars().count() {
        app.key(Key::Backspace);
    }
    type_text(app, value);
    app.key(Key::Enter);
}

fn message(app: &App<FakeHost>) -> String {
    app.message.clone().unwrap_or_default()
}

#[test]
fn configuration_renders_the_ingest_form_at_80x24() {
    let app = configuration(false);
    let text = screen(&app, 80, 24);
    for want in [
        "[Configuration]",
        "[ingest]",
        "/etc/openvibes/ingest.toml",
        "0.0.0.0:18423",
        "max_in_flight",
        "w save",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    assert!(text.lines().any(|line| line.trim() == "valid"), "{text}");
}

#[test]
fn an_edit_is_checked_by_the_service_type() {
    let mut app = configuration(false);
    set(&mut app, "max_inventory_in_flight", "200");
    assert!(
        app.config.editing.is_none(),
        "a number is accepted as typed"
    );
    let text = screen(&app, 80, 24);
    assert!(
        text.contains("invalid: invalid ingest configuration"),
        "{text}"
    );
    assert!(text.contains("1 unsaved change"), "{text}");
    app.key(Key::Char('w'));
    assert_eq!(app.config.prompt, None);
    assert!(
        message(&app).starts_with("cannot save"),
        "{}",
        message(&app)
    );
    assert!(app.host.writes.borrow().is_empty());
}

#[test]
fn a_value_of_the_wrong_kind_is_not_accepted() {
    let mut app = configuration(false);
    set(&mut app, "max_inventory_in_flight", "eight");
    assert!(app.config.editing.is_some(), "still editing");
    assert!(
        message(&app).contains("not a whole number"),
        "{}",
        message(&app)
    );
    app.key(Key::Char('q'));
    assert!(!app.quit, "q is typed while editing");
    app.key(Key::Esc);
    assert!(app.config.editing.is_none());
    assert!(app.config.form.as_ref().unwrap().changes().is_empty());
}

#[test]
fn save_shows_the_changes_writes_and_offers_a_restart() {
    let mut app = configuration(false);
    set(&mut app, "max_inventory_in_flight", "8");
    app.key(Key::Char('w'));
    assert_eq!(app.config.prompt, Some(Prompt::Save));
    let text = screen(&app, 80, 24);
    assert!(
        text.contains("max_inventory_in_flight: (default) → 8"),
        "{text}"
    );
    assert!(
        text.contains("Write /etc/openvibes/ingest.toml? y/n"),
        "{text}"
    );
    app.key(Key::Char('y'));
    let writes = app.host.writes.borrow().clone();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].0, Service::Ingest);
    assert!(writes[0].1.contains("max_inventory_in_flight = 8"));
    assert!(
        writes[0]
            .1
            .contains("max_in_flight = 4096                        # above this: 503"),
        "untouched lines keep their comments"
    );
    assert_eq!(app.config.prompt, Some(Prompt::Restart(Unit::Ingest)));
    assert!(screen(&app, 80, 24).contains("Saved. Restart openvibes-ingest.service now? y/n"));
    app.key(Key::Char('y'));
    assert_eq!(
        *app.host.actions.borrow(),
        [(Unit::Ingest, ServiceAction::Restart)]
    );
    assert!(app.config.form.as_ref().unwrap().changes().is_empty());
}

#[test]
fn leaving_with_unsaved_changes_asks_first() {
    let mut app = configuration(false);
    set(&mut app, "max_inventory_in_flight", "8");
    app.key(Key::Char('l'));
    assert!(matches!(app.config.prompt, Some(Prompt::Discard(_))));
    app.key(Key::Char('n'));
    assert_eq!(Service::ALL[app.config.service], Service::Ingest);
    assert_eq!(app.config.form.as_ref().unwrap().changes().len(), 1);
    app.key(Key::Char('l'));
    app.key(Key::Char('y'));
    assert_eq!(Service::ALL[app.config.service], Service::Distribution);
    assert!(app.config.form.as_ref().unwrap().changes().is_empty());
}

#[test]
fn unreadable_and_broken_files_are_explained() {
    let mut app = configuration(false);
    while Service::ALL[app.config.service] != Service::Console {
        app.key(Key::Char('l'));
    }
    assert!(app.config.form.is_none());
    assert!(message(&app).contains("not installed"), "{}", message(&app));
    app.key(Key::Enter);
    app.key(Key::Char('w'));
    assert!(app.config.editing.is_none() && app.config.prompt.is_none());
    app.key(Key::Char('l'));
    assert_eq!(Service::ALL[app.config.service], Service::Admin);
    assert!(app.config.form.is_none());
    assert!(
        message(&app).contains("not valid TOML"),
        "{}",
        message(&app)
    );
}

#[test]
fn u_puts_the_file_value_back() {
    let mut app = configuration(false);
    set(&mut app, "max_in_flight", "10");
    app.key(Key::Char('u'));
    let form = app.config.form.as_ref().unwrap();
    assert!(form.changes().is_empty());
    assert_eq!(form.get("max_in_flight").as_deref(), Some("4096"));
}

#[test]
fn a_file_changed_on_disk_is_not_overwritten() {
    let mut app = configuration(false);
    set(&mut app, "max_inventory_in_flight", "8");
    app.host
        .hand_edit
        .replace(Some("listen = \"0.0.0.0:1\"\n".into()));
    app.key(Key::Char('w'));
    app.key(Key::Char('y'));
    assert!(app.host.writes.borrow().is_empty());
    assert!(
        message(&app).contains("changed on disk"),
        "{}",
        message(&app)
    );
}

#[test]
fn a_refused_save_keeps_the_edits() {
    let mut app = configuration(true);
    set(&mut app, "max_inventory_in_flight", "8");
    app.key(Key::Char('w'));
    app.key(Key::Char('y'));
    assert!(
        message(&app).contains("openvibes-operators"),
        "{}",
        message(&app)
    );
    assert_eq!(app.config.form.as_ref().unwrap().changes().len(), 1);
}

#[test]
fn tab_switches_screens() {
    let mut app = configuration(false);
    assert_eq!(app.tab, Tab::Configuration);
    app.key(Key::Tab);
    assert_eq!(app.tab, Tab::Setup);
    assert!(screen(&app, 80, 24).contains("[Setup]"));
}

#[test]
fn a_long_value_being_typed_shows_its_end() {
    let mut app = configuration(false);
    while app.config.form.as_ref().unwrap().fields()[app.config.selected].key != "database_url" {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    type_text(&mut app, "&application_name=tail");
    let text = screen(&app, 80, 24);
    assert!(text.contains("application_name=tail_"), "{text}");
}

#[test]
fn enable_at_boot_asks_for_the_password() {
    let mut app = app(false);
    select(&mut app, Unit::Vulns);
    app.key(Key::Char('e'));
    for c in "pw".chars() {
        app.key(Key::Char(c));
    }
    assert!(
        screen(&app, 80, 24).contains("Enable openvibes-vulns.service at boot: your password: **")
    );
    app.key(Key::Enter);
    assert_eq!(
        *app.host.privileged_calls.borrow(),
        [(
            "unit-enable openvibes-vulns.service".to_owned(),
            "pw".to_owned()
        )]
    );
    assert_eq!(message(&app), "enabled openvibes-vulns.service at boot");
}
