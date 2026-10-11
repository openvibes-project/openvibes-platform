//! TUI state and key handling, free of terminal code so it can be tested.

use std::{
    cell::Cell,
    sync::mpsc::{Receiver, TryRecvError},
    time::Instant,
};

use platform_host::{Host, HostError, PackageUpdate, ServiceStatus, Unit};

use super::{
    configuration::Configuration,
    database::{Check, DatabaseScreen},
    nav::{Nav, Screen},
    password::PasswordPrompt,
    setup::Setup,
    ui::theme::Theme,
};

/// Journal lines shown for the selected unit.
pub const LOG_LINES: u16 = 50;

pub use super::work::{Pending, Question};

/// A key press, as the event loop maps it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Key {
    Char(char),
    Up,
    Down,
    Left,
    Right,
    Enter,
    Esc,
    Backspace,
    /// Ctrl+U: empty the field being edited.
    ClearLine,
}

/// Which of today's screens `Screen::Legacy` shows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tab {
    Setup,
    Configuration,
    Database,
}

/// The TUI's state: where the operator is (`nav`), what the host reports
/// (`services`, the health checks in `database`), the bar's question, prompt
/// and running work, and today's screens' own state (`setup`, `config`,
/// `database`).
pub struct App<H: Host> {
    pub host: H,
    pub tab: Tab,
    pub setup: Setup,
    pub config: Configuration,
    pub database: DatabaseScreen,
    pub services: Vec<ServiceStatus>,
    /// Index into `services` of the unit whose log `logs` holds.
    pub selected: usize,
    /// The last error (a failed refresh): Home, Status and Service show it;
    /// today's screens also keep their notes here, above their key help.
    pub message: Option<String>,
    /// Journal lines of the unit at `selected`.
    pub logs: Vec<String>,
    pub quit: bool,
    pub theme: Theme,
    pub nav: Nav,
    /// From `/etc/hostname` (else the kernel's), lowercased: the location line starts with it.
    pub hostname: String,
    /// A newer `openvibes-admin` version, shown on the location line.
    pub update: Option<String>,
    versions_loaded: bool,
    /// The update notice, looked up on another thread (`run`): dnf may
    /// take long offline. Without it, `tick` asks the host itself (tests).
    pub updates: Option<Receiver<Option<String>>>,
    /// The health checks, collected on another thread (`run`): the probes
    /// take a while. Without it, `new` collects them itself (tests).
    pub health: Option<Receiver<Vec<Check>>>,
    /// The full log's page length at its last draw; it caps how far up
    /// the log scrolls.
    pub log_room: Cell<usize>,
    /// A question in the bar; the bool is the highlighted answer (Yes).
    pub question: Option<(Question, bool)>,
    /// The sudo password being typed in the bar (enable at boot).
    pub prompt: Option<(Unit, PasswordPrompt)>,
    /// Work running in the background.
    pub pending: Option<Pending>,
    /// The last action's result line, until the next key.
    pub outcome: Option<(bool, String)>,
    pub(super) tick_count: usize,
}

impl<H: Host> App<H> {
    /// Collects the health checks before returning (tests: a real host
    /// uses `lazy` and a thread).
    #[cfg(test)]
    pub fn new(host: H) -> Self {
        let mut app = Self::lazy(host);
        app.database.health = super::database::health_checks(&app.host);
        app
    }

    /// As `new`, but the health checks come later through `health`.
    pub fn lazy(host: H) -> Self {
        let set_up = host.is_set_up();
        let hostname = hostname_from(&["/etc/hostname", "/proc/sys/kernel/hostname"]);
        // Under sudo, HOME is root's, but the root key belongs in the
        // person's own home (#92); directory users too (#94).
        let home = crate::setup::plan::operator_from_env()
            .and_then(|user| host.user_home(&user))
            .or_else(|| std::env::var("HOME").ok());
        let mut setup = Setup::new(set_up, hostname.clone(), home);
        if !set_up {
            setup.propose_ports(&host);
        }
        let mut app = App {
            host,
            tab: Tab::Setup,
            setup,
            config: Configuration::default(),
            database: DatabaseScreen::default(),
            services: Vec::new(),
            selected: 0,
            message: None,
            logs: Vec::new(),
            quit: false,
            theme: Theme::from_env(),
            nav: Nav::new(if set_up { Screen::Home } else { Screen::Legacy }),
            hostname,
            update: None,
            versions_loaded: false,
            updates: None,
            health: None,
            log_room: Cell::new(0),
            question: None,
            prompt: None,
            pending: None,
            outcome: None,
            tick_count: 0,
        };
        app.refresh();
        app.load_logs();
        app
    }

    /// Reloads the unit states (the periodic refresh). Logs are reloaded
    /// only on selection, `R`, and after an action: each read goes through
    /// sudo, which writes to the auth log.
    pub fn refresh(&mut self) {
        // The highlighted Status item stays highlighted if it is still there.
        let held = (self.nav.screen == Screen::Status)
            .then(|| self.status_items().get(self.nav.row).cloned())
            .flatten();
        match self.host.services() {
            Ok(services) => {
                self.services = services;
                if self.nav.screen != Screen::Legacy {
                    self.message = None;
                }
            }
            Err(error) => self.message = Some(error.to_string()),
        }
        self.selected = self.selected.min(self.services.len().saturating_sub(1));
        if self.nav.screen == Screen::Status {
            let items = self.status_items();
            self.nav.row = held
                .and_then(|held| items.iter().position(|i| *i == held))
                .unwrap_or(self.nav.row)
                .min(items.len().saturating_sub(1));
        }
    }

    pub(super) fn load_logs(&mut self) {
        let Some(status) = self.services.get(self.selected) else {
            self.logs.clear();
            return;
        };
        self.logs = if status.installed {
            self.host
                .logs(status.unit, LOG_LINES)
                .unwrap_or_else(|error| vec![error.to_string()])
        } else {
            Vec::new()
        };
    }

    /// Set up already, or being changed from a set-up host.
    pub fn setup_done(&self) -> bool {
        self.setup.previous.is_some() || self.host.is_set_up()
    }

    /// Opens Status, with fresh health checks.
    pub(super) fn open_status(&mut self) {
        self.message = None;
        self.nav.go(Screen::Status);
        self.load_health();
        // A new screen starts at the top, whatever the refresh held.
        self.nav.row = 0;
    }

    /// Opens `tab`, loading what it shows: today's screen behind Maintenance.
    pub(super) fn open(&mut self, tab: Tab) {
        self.message = None;
        if self.nav.screen != Screen::Legacy {
            self.nav.go(Screen::Legacy);
        }
        match tab {
            Tab::Setup => self.tab = Tab::Setup,
            Tab::Configuration => {
                self.tab = Tab::Configuration;
                self.load_config();
            }
            Tab::Database => self.open_database(),
        }
    }

    /// One key: a legacy screen keeps its own keys; elsewhere ? opens Help,
    /// Esc goes back, q quits from Home, the rest is the screen's.
    pub fn key(&mut self, key: Key) {
        self.outcome = None;
        if self.nav.screen == Screen::Legacy {
            return self.legacy_key(key);
        }
        if self.question.is_some() {
            return self.question_key(key);
        }
        if self.prompt.is_some() {
            return self.prompt_key(key);
        }
        match key {
            Key::Char('?') if !matches!(self.nav.screen, Screen::Help(_)) => {
                let from = Box::new(self.nav.screen.clone());
                self.nav.go(Screen::Help(from));
            }
            Key::Esc => {
                self.nav.pop();
                if matches!(self.nav.screen, Screen::Service(_)) {
                    self.load_logs();
                }
            }
            Key::Char('q') if self.nav.screen == Screen::Home => self.quit_or_ask(),
            _ => match self.nav.screen.clone() {
                Screen::Home => self.home_key(key),
                Screen::Maintenance => self.maintenance_key(key),
                Screen::Status => self.status_key(key),
                Screen::Service(unit) => self.service_key(unit, key),
                Screen::Log(_) => self.log_key(key),
                Screen::Help(_) | Screen::Legacy => {}
            },
        }
    }

    /// Takes the health checks and the update notice once they have been
    /// looked up, then polls running work.
    pub fn tick(&mut self, now: Instant) {
        if let Some(rx) = &self.health {
            match rx.try_recv() {
                Ok(checks) => {
                    self.database.health = checks;
                    self.health = None;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => self.health = None,
            }
        }
        if !self.versions_loaded {
            match self.updates.as_ref().map(Receiver::try_recv) {
                Some(Err(TryRecvError::Empty)) => {}
                Some(found) => {
                    self.update = found.ok().flatten();
                    self.versions_loaded = true;
                    self.updates = None;
                }
                None => {
                    self.update = newer_admin(self.host.packages());
                    self.versions_loaded = true;
                }
            }
        }
        self.poll(now);
    }

    /// Today's screens' own keys.
    pub(super) fn legacy_dispatch(&mut self, key: Key) {
        match self.tab {
            Tab::Setup => self.setup_key(key),
            Tab::Configuration => self.config_key(key),
            Tab::Database => self.database_key(key),
        }
    }
}

/// The first non-empty of `paths`, trimmed and lowercased; empty if none.
fn hostname_from(paths: &[&str]) -> String {
    paths
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .map(|h| h.trim().to_lowercase())
        .find(|h| !h.is_empty())
        .unwrap_or_default()
}

/// The newer `openvibes-admin` version (without its release), if any.
pub fn newer_admin(packages: Result<Vec<PackageUpdate>, HostError>) -> Option<String> {
    packages.ok()?.into_iter().find_map(|p| {
        let v = p.available.filter(|_| p.name == "openvibes-admin")?;
        Some(v.split('-').next().unwrap_or(&v).to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::hostname_from;

    #[test]
    fn the_hostname_falls_back_to_the_kernels_when_etc_hostname_is_missing() {
        let name = hostname_from(&["/nonexistent/hostname", "/proc/sys/kernel/hostname"]);
        assert!(!name.is_empty());
        assert_eq!(name, name.to_lowercase());
        assert_eq!(hostname_from(&["/nonexistent/hostname"]), "");
    }
}
