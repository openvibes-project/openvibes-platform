//! The Services screen against a fake host, rendered at 80×24.

use std::cell::{Cell, RefCell};

use platform_host::{
    Database, DiskUse, Host, HostError, PackageUpdate, Privileged, Secret, Service, ServiceAction,
    ServiceStatus, Unit,
};
use ratatui::{Terminal, backend::TestBackend};

use super::{app::App, render};

pub(super) struct FakeHost {
    pub(super) actions: RefCell<Vec<(Unit, ServiceAction)>>,
    writes: RefCell<Vec<(Service, String)>>,
    /// What a read returns instead, as if edited by hand meanwhile.
    hand_edit: RefCell<Option<String>>,
    refuse: bool,
    /// Units reported as not enabled at boot.
    pub(super) disabled: RefCell<Vec<Unit>>,
    /// (verb, password) of each privileged call.
    pub(super) privileged_calls: RefCell<Vec<(String, String)>>,
    /// Database commands run.
    pub(super) database_calls: RefCell<Vec<Database>>,
    /// Disk reads made.
    pub(super) disk_calls: Cell<usize>,
    /// Ingest's ActiveEnterTimestamp; a restart changes it unless held.
    pub(super) since: RefCell<String>,
    /// A restart that leaves the old process running (its stamp unchanged).
    pub(super) hold_restart: Cell<bool>,
    /// Units stopped by an action.
    stopped: RefCell<Vec<Unit>>,
    /// Units running after an action (failed in the fake until then).
    pub(super) started: RefCell<Vec<Unit>>,
    /// `services()` fails with this.
    pub(super) services_error: RefCell<Option<String>>,
}

fn status(unit: Unit, installed: bool, active: &str, ready: Option<bool>) -> ServiceStatus {
    ServiceStatus {
        unit,
        installed,
        enabled: installed,
        active: active.into(),
        ready,
        since: None,
        last_run_failed: false,
    }
}

impl Host for FakeHost {
    fn services(&self) -> Result<Vec<ServiceStatus>, HostError> {
        if let Some(error) = &*self.services_error.borrow() {
            return Err(HostError::Failed(error.clone()));
        }
        let mut all = vec![
            status(Unit::Ingest, true, "active", Some(true)),
            status(Unit::Distribution, false, "inactive", None),
            status(Unit::Vulns, true, "failed", None),
            status(Unit::Llm, true, "inactive", None),
            status(Unit::Maintenance, true, "active", None),
        ];
        for s in &mut all {
            s.enabled &= !self.disabled.borrow().contains(&s.unit);
            if self.started.borrow().contains(&s.unit) {
                s.active = "active".into();
                s.ready = Some(true);
            }
            if self.stopped.borrow().contains(&s.unit) {
                s.active = "inactive".into();
                s.ready = None;
            }
            if s.unit == Unit::Ingest && s.active == "active" {
                s.since = Some(self.since.borrow().clone());
            }
        }
        Ok(all)
    }
    fn service_action(&self, unit: Unit, action: ServiceAction) -> Result<(), HostError> {
        if self.refuse {
            return Err(HostError::NotOperator);
        }
        self.actions.borrow_mut().push((unit, action));
        match action {
            ServiceAction::Stop => self.stopped.borrow_mut().push(unit),
            ServiceAction::Restart if unit == Unit::Ingest && !self.hold_restart.get() => {
                *self.since.borrow_mut() = "Sat 2099-01-01 00:00:00 CEST".into();
            }
            _ => {}
        }
        Ok(())
    }
    fn logs(&self, unit: Unit, _lines: u16) -> Result<Vec<String>, HostError> {
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
    fn database(&self, command: Database) -> Result<String, HostError> {
        self.database_calls.borrow_mut().push(command);
        match command {
            _ if self.refuse => Err(HostError::NotOperator),
            Database::Status => Ok(format!(
                "schema version {}\npartitions 2026-06-30..2026-10-05\n\
                                    partition count 98\ndatabase size 42 MiB\n",
                platform_store::SCHEMA_VERSION
            )),
            Database::RulesList => Ok("baseline v1 keys 1 expires 2028-09-27T00:00:00Z\n".into()),
            Database::SsoStatus => Ok("on\n".into()),
            Database::FeedsStatus => {
                Ok("osv-rocky 10 advisories checked 2026-09-28 changed never \
                                         error: HTTP 503\n"
                    .into())
            }
        }
    }
    fn certificates(&self) -> Vec<(&'static str, Result<String, HostError>)> {
        // A set-up host has its CA (#87: without one it opens the install form).
        static CA: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let ca = CA.get_or_init(|| {
            platform_pki::generate_root(chrono::Utc::now())
                .unwrap()
                .cert_pem
        });
        vec![
            (
                "/etc/openvibes/tls/ingest.crt",
                Err(HostError::Failed("permission denied".into())),
            ),
            ("/etc/openvibes/pki/intermediate.crt", Ok(ca.clone())),
        ]
    }
    fn disk(&self) -> Result<Vec<DiskUse>, HostError> {
        self.disk_calls.set(self.disk_calls.get() + 1);
        Ok(vec![DiskUse {
            path: "/var/lib/pgsql".into(),
            size: "100G".into(),
            used_percent: 40,
            available: "20G".into(),
        }])
    }
}

pub(super) fn app(refuse: bool) -> App<FakeHost> {
    let mut app = App::new(FakeHost {
        actions: RefCell::new(Vec::new()),
        writes: RefCell::new(Vec::new()),
        hand_edit: RefCell::new(None),
        refuse,
        disabled: RefCell::new(Vec::new()),
        privileged_calls: RefCell::new(Vec::new()),
        database_calls: RefCell::new(Vec::new()),
        disk_calls: Cell::new(0),
        since: RefCell::new("Sat 2026-10-10 18:40:00 CEST".into()),
        hold_restart: Cell::new(false),
        stopped: RefCell::new(Vec::new()),
        started: RefCell::new(Vec::new()),
        services_error: RefCell::new(None),
    });
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    app.root = std::env::temp_dir().join(format!("ov-tui-root-{}-{n}", std::process::id()));
    // The health checks at start are not what the test is about.
    app.host.database_calls.borrow_mut().clear();
    app
}

pub(super) fn screen(app: &App<FakeHost>, width: u16, height: u16) -> String {
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
