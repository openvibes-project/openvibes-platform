//! TUI state and key handling, free of terminal code so it can be tested.

use std::{
    sync::mpsc::{Receiver, TryRecvError},
    time::Instant,
};

use platform_host::{Host, HostError, PackageUpdate, ServiceStatus, Unit};

use super::{
    configuration::Configuration,
    database::DatabaseScreen,
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
    Tab,
    /// Shift+Tab: the previous screen.
    BackTab,
    /// Ctrl+U: empty the field being edited.
    ClearLine,
}

/// Which of today's screens `Screen::Legacy` shows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tab {
    Setup,
    Configuration,
    Database,
    Health,
}

/// The TUI's state: the Services screen's fields, and the Configuration
/// screen's in `config`.
pub struct App<H: Host> {
    pub host: H,
    pub tab: Tab,
    pub setup: Setup,
    pub config: Configuration,
    pub database: DatabaseScreen,
    pub services: Vec<ServiceStatus>,
    pub selected: usize,
    /// The last outcome or error, shown above the key help.
    pub message: Option<String>,
    pub logs: Vec<String>,
    pub quit: bool,
    pub theme: Theme,
    pub nav: Nav,
    /// From `/etc/hostname`, lowercased: the location line starts with it.
    pub hostname: String,
    /// A newer `openvibes-admin` version, shown on the location line.
    pub update: Option<String>,
    versions_loaded: bool,
    /// The update notice, looked up on another thread (`run`): dnf may
    /// take long offline. Without it, `tick` asks the host itself (tests).
    pub updates: Option<Receiver<Option<String>>>,
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
    pub fn new(host: H) -> Self {
        let set_up = host.is_set_up();
        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|h| h.trim().to_lowercase())
            .unwrap_or_default();
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
        match self.host.services() {
            Ok(services) => self.services = services,
            Err(error) => self.message = Some(error.to_string()),
        }
        self.selected = self.selected.min(self.services.len().saturating_sub(1));
        if self.nav.screen == Screen::Status {
            self.nav.row = self
                .nav
                .row
                .min(self.status_items().len().saturating_sub(1));
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

    /// Opens `tab`, loading what it shows: Health opens Status,
    /// the others today's screen behind Maintenance.
    pub(super) fn open(&mut self, tab: Tab) {
        self.message = None;
        if matches!(tab, Tab::Health) {
            self.nav.go(Screen::Status);
        } else if self.nav.screen != Screen::Legacy {
            self.nav.go(Screen::Legacy);
        }
        match tab {
            Tab::Setup => self.tab = Tab::Setup,
            Tab::Health => self.load_health(),
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

    /// Loads the update notice once, then polls running work.
    pub fn tick(&mut self, now: Instant) {
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
            Tab::Health => {}
        }
    }
}

/// The newer `openvibes-admin` version (without its release), if any.
pub fn newer_admin(packages: Result<Vec<PackageUpdate>, HostError>) -> Option<String> {
    packages.ok()?.into_iter().find_map(|p| {
        let v = p.available.filter(|_| p.name == "openvibes-admin")?;
        Some(v.split('-').next().unwrap_or(&v).to_owned())
    })
}
