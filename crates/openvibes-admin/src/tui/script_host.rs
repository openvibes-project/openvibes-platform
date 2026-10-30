//! A scripted host for flow tests: each privileged call returns the next
//! queued answer ("done\tok" once they run out), and the calls and their
//! passwords are recorded.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
};

use platform_host::{
    Host, HostError, PackageUpdate, Privileged, Secret, Service, ServiceAction, ServiceStatus,
    Unit, os_updates::OsInfo,
};
use ratatui::{Terminal, backend::TestBackend};

use super::{
    app::{App, Key},
    render,
};

pub(super) struct SetupHost {
    pub(super) set_up: bool,
    /// What each privileged call returns, in order.
    pub(super) answers: RefCell<VecDeque<Result<String, HostError>>>,
    /// (verb, password) of each call.
    pub(super) calls: RefCell<Vec<(String, String)>>,
    /// `setup.toml`'s text; empty: not set up.
    pub(super) plan: String,
    pub(super) packages: Vec<PackageUpdate>,
    /// Ports another process listens on.
    pub(super) taken: Vec<u16>,
    /// Running as root: sudo needs no password.
    pub(super) root: bool,
    /// `df` calls made (the backup folder's check).
    pub(super) free_calls: Cell<usize>,
    /// Real certificates for `certificates()` (path, PEM); empty: the
    /// stand-in below.
    pub(super) pems: Vec<(&'static str, String)>,
    /// `shell()` calls made (Maintenance › Shell; nothing is spawned).
    pub(super) shells: Cell<usize>,
    /// `shell()` fails, as when the login shell cannot start.
    pub(super) no_shell: bool,
    /// `own_console_cert()`: your own console certificate, if any.
    pub(super) own: Option<String>,
    /// `certificates()` calls made.
    pub(super) cert_reads: Cell<usize>,
    /// `os_info()`: the distribution and its last update check.
    pub(super) os: RefCell<Option<OsInfo>>,
    /// `os_update_running()` calls made.
    pub(super) os_reads: Cell<usize>,
    /// `database(SsoStatus)`: what single sign-on reads as; none: cannot be read.
    pub(super) sso: RefCell<Option<String>>,
    /// `is_appliance()`: Home adds System and Log out.
    pub(super) appliance: Cell<bool>,
}

impl Host for SetupHost {
    fn services(&self) -> Result<Vec<ServiceStatus>, HostError> {
        Ok(Vec::new())
    }
    fn service_action(&self, _: Unit, _: ServiceAction) -> Result<(), HostError> {
        Ok(())
    }
    fn logs(&self, _: Unit, _: u16) -> Result<Vec<String>, HostError> {
        Ok(Vec::new())
    }
    fn read_config(&self, _: Service) -> Result<String, HostError> {
        Err(HostError::NotOperator)
    }
    fn is_set_up(&self) -> bool {
        self.set_up
    }
    fn needs_password(&self) -> bool {
        !self.root
    }
    fn certificates(&self) -> Vec<(&'static str, Result<String, HostError>)> {
        self.cert_reads.set(self.cert_reads.get() + 1);
        if !self.pems.is_empty() {
            return self.pems.iter().map(|(p, t)| (*p, Ok(t.clone()))).collect();
        }
        // A set-up host has its CA; a plan left by a first install that
        // stopped before the CA step does not (#87).
        if self.plan.is_empty() || self.plan.contains("# no ca") {
            Vec::new()
        } else {
            vec![("/etc/openvibes/pki/intermediate.crt", Ok(String::new()))]
        }
    }
    fn own_console_cert(&self) -> Option<String> {
        self.own.clone()
    }
    fn is_appliance(&self) -> bool {
        self.appliance.get()
    }
    fn os_info(&self) -> Option<OsInfo> {
        self.os.borrow().clone()
    }
    fn os_update_running(&self) -> bool {
        self.os_reads.set(self.os_reads.get() + 1);
        false
    }
    fn packages(&self) -> Result<Vec<PackageUpdate>, HostError> {
        Ok(self.packages.clone())
    }
    fn listeners(&self, port: u16) -> Result<String, HostError> {
        Ok(if self.taken.contains(&port) {
            format!("LISTEN 0 511 *:{port} *:*\n")
        } else {
            String::new()
        })
    }
    fn free_space(&self, _: &str) -> Option<String> {
        self.free_calls.set(self.free_calls.get() + 1);
        Some("1.8T".into())
    }
    fn setup_plan(&self) -> Result<String, HostError> {
        if self.plan.is_empty() {
            Err(HostError::Failed("not set up".into()))
        } else {
            Ok(self.plan.clone())
        }
    }
    fn shell(&self) -> Result<(), HostError> {
        self.shells.set(self.shells.get() + 1);
        if self.no_shell {
            Err(HostError::Failed("no shell here".into()))
        } else {
            Ok(())
        }
    }
    fn database(&self, command: platform_host::Database) -> Result<String, HostError> {
        match (command, self.sso.borrow().clone()) {
            (platform_host::Database::SsoStatus, Some(state)) => Ok(format!("{state}\n")),
            _ => Err(HostError::Failed("not supported on this host".into())),
        }
    }
    fn privileged(&self, verb: Privileged<'_>, password: &Secret) -> Result<String, HostError> {
        self.calls
            .borrow_mut()
            .push((verb.args().join(" "), password.expose().to_owned()));
        self.answers
            .borrow_mut()
            .pop_front()
            .unwrap_or(Ok("done\tok\n".into()))
    }
}

pub(super) fn app(set_up: bool, answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    app_taken(set_up, answers, vec![])
}

/// A host not set up yet, as the other fresh-host tests build it.
pub(super) fn fresh_app() -> App<SetupHost> {
    built(false, vec![], vec![], String::new())
}

pub(super) fn app_taken(
    set_up: bool,
    answers: Vec<Result<String, HostError>>,
    taken: Vec<u16>,
) -> App<SetupHost> {
    // A set-up host has its plan (and so its CA) from the start.
    let plan = if set_up { PLAN.into() } else { String::new() };
    built(set_up, answers, taken, plan)
}

/// A set-up host whose `setup.toml` is `plan` from the start, so the start
/// screen is chosen from it (#87).
pub(super) fn app_with_plan(plan: &str, answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    built(true, answers, vec![], plan.into())
}

fn built(
    set_up: bool,
    answers: Vec<Result<String, HostError>>,
    taken: Vec<u16>,
    plan: String,
) -> App<SetupHost> {
    let mut app = App::new(SetupHost {
        set_up,
        answers: RefCell::new(answers.into()),
        calls: RefCell::new(Vec::new()),
        plan,
        packages: Vec::new(),
        taken,
        root: false,
        free_calls: Cell::new(0),
        pems: Vec::new(),
        shells: Cell::new(0),
        no_shell: false,
        own: None,
        cert_reads: Cell::new(0),
        os: RefCell::new(None),
        os_reads: Cell::new(0),
        sso: RefCell::new(None),
        appliance: Cell::new(false),
    });
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    app.root = std::env::temp_dir().join(format!("ov-tui-script-{}-{n}", std::process::id()));
    // The location line, whatever this machine is called (a long name
    // cuts it).
    app.hostname = "platform.lab".into();
    app
}

pub(super) fn screen(app: &App<SetupHost>) -> String {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| render(frame, app)).unwrap();
    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                + "\n"
        })
        .collect()
}

/// The screen below the location line, each line without its trailing
/// blanks: what a mockup shows, whatever the host name and version.
pub(super) fn body(app: &App<SetupHost>) -> String {
    let text = screen(app);
    let lines: Vec<&str> = text.lines().skip(7).map(str::trim_end).collect();
    lines.join("\n")
}

pub(super) fn type_text(app: &mut App<SetupHost>, text: &str) {
    for c in text.chars() {
        app.key(Key::Char(c));
    }
}

pub(super) const PLAN: &str = "components = [\"ingest\", \"console\", \"distribution\", \"vulns\", \"rules\", \"agent\"]\nhostname = \"platform.example.com\"\nsans = []\nca = \"quick\"\noperator = \"alice\"\nconsole_port = 443\ningest_port = 18423\ndistribution_port = 18424\n";

pub(super) fn set_up(answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    let mut app = app(true, answers);
    app.host.plan = PLAN.into();
    app
}
