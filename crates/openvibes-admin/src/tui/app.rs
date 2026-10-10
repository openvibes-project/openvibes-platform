//! TUI state and key handling, free of terminal code so it can be tested.

use std::time::Instant;

use platform_host::{Host, Privileged, ServiceAction, ServiceStatus, Unit};
use ratatui::text::Line;

use super::{
    configuration::Configuration,
    database::DatabaseScreen,
    nav::{Nav, Screen},
    password::{PasswordPrompt, Typed},
    setup::Setup,
    ui::{bar::Bar, theme::Theme},
};

/// Journal lines shown for the selected unit.
pub const LOG_LINES: u16 = 50;

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
    Services,
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
    /// An action waiting for y/n.
    pub confirm: Option<(Unit, ServiceAction)>,
    /// Enable (true) or disable at boot, waiting for the password.
    pub boot: Option<(Unit, bool, PasswordPrompt)>,
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
    /// A question in the bar (Task 8 gives it its type).
    pub question: Option<()>,
    /// A value typed in the bar (Task 8 gives it its type).
    pub prompt: Option<()>,
    /// Work running in the background (Task 8 gives it its type).
    #[allow(dead_code, reason = "used in Task 8")]
    pub pending: Option<()>,
    /// The last action's outcome in the bar (Task 8 gives it its type).
    #[allow(dead_code, reason = "used in Task 8")]
    pub outcome: Option<()>,
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
            confirm: None,
            boot: None,
            message: None,
            logs: Vec::new(),
            quit: false,
            theme: Theme::from_env(),
            nav: Nav::new(if set_up { Screen::Home } else { Screen::Legacy }),
            hostname,
            update: None,
            versions_loaded: false,
            question: None,
            prompt: None,
            pending: None,
            outcome: None,
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
    }

    fn load_logs(&mut self) {
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

    /// Opens `tab`, loading what it shows: Services and Health open Status,
    /// the others today's screen behind Maintenance.
    pub(super) fn open(&mut self, tab: Tab) {
        self.message = None;
        if matches!(tab, Tab::Services | Tab::Health) {
            self.nav.go(Screen::Status);
        } else if self.nav.screen != Screen::Legacy {
            self.nav.go(Screen::Legacy);
        }
        match tab {
            Tab::Setup => self.tab = Tab::Setup,
            Tab::Services => self.refresh(),
            Tab::Configuration => {
                self.tab = Tab::Configuration;
                self.load_config();
            }
            Tab::Database => self.open_database(),
            Tab::Health => self.open_health(),
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

    /// Loads the update notice once, then polls running work (Task 8).
    pub fn tick(&mut self, now: Instant) {
        if !self.versions_loaded {
            self.versions_loaded = true;
            self.update = self.host.packages().ok().and_then(|packages| {
                packages
                    .iter()
                    .find(|p| p.name == "openvibes-admin")
                    .and_then(|p| p.available.as_deref())
                    .map(|v| v.split('-').next().unwrap_or(v).to_owned())
            });
        }
        self.poll(now);
    }

    fn poll(&mut self, _now: Instant) {}

    fn question_key(&mut self, _key: Key) {}

    fn prompt_key(&mut self, _key: Key) {}

    /// Task 8 asks first while work runs.
    pub(super) fn quit_or_ask(&mut self) {
        self.quit = true;
    }

    /// Home's one-line summary (Task 7 fills it from the Status model).
    pub(super) fn status_line(&self) -> Line<'static> {
        Line::raw("")
    }

    /// The bar: `default`, unless a question, a prompt or work takes its
    /// place (Task 8).
    pub(super) fn bar(&self, default: Bar) -> Bar {
        default
    }

    /// Today's screens' own keys.
    pub(super) fn legacy_dispatch(&mut self, key: Key) {
        match self.tab {
            Tab::Setup => self.setup_key(key),
            Tab::Services => self.services_key(key),
            Tab::Configuration => self.config_key(key),
            Tab::Database => self.database_key(key),
            Tab::Health => self.health_key(key),
        }
    }

    /// j/k (arrows) move, s/t/r ask to start/stop/restart, y answers, R
    /// refreshes, Tab opens Configuration, q quits.
    fn services_key(&mut self, key: Key) {
        if let Some((unit, enable, mut prompt)) = self.boot.take() {
            match prompt.key(key) {
                Typed::Pending => self.boot = Some((unit, enable, prompt)),
                Typed::Cancelled => {}
                Typed::Entered(secret) => {
                    let verb = if enable {
                        Privileged::UnitEnable(unit)
                    } else {
                        Privileged::UnitDisable(unit)
                    };
                    let done = if enable { "enabled" } else { "disabled" };
                    self.message = Some(match self.host.privileged(verb, &secret) {
                        Ok(_) => format!("{done} {} at boot", unit.name()),
                        Err(error) => error.to_string(),
                    });
                    self.refresh();
                }
            }
            return;
        }
        if let Some((unit, action)) = self.confirm.take() {
            if key == Key::Char('y') {
                self.message = Some(match self.host.service_action(unit, action) {
                    Ok(()) => format!("{} requested for {}", action.verb(), unit.name()),
                    Err(error) => error.to_string(),
                });
                self.refresh();
                self.load_logs();
            }
            return;
        }
        match key {
            Key::Char('j') | Key::Down if self.selected + 1 < self.services.len() => {
                self.selected += 1;
                self.load_logs();
            }
            Key::Char('k') | Key::Up if self.selected > 0 => {
                self.selected -= 1;
                self.load_logs();
            }
            Key::Char('s') => self.ask(ServiceAction::Start),
            Key::Char('t') => self.ask(ServiceAction::Stop),
            Key::Char('r') => self.ask(ServiceAction::Restart),
            Key::Char('e') => self.ask_boot(true),
            Key::Char('d') => self.ask_boot(false),
            Key::Char('R') => {
                self.message = None;
                self.refresh();
                self.load_logs();
            }
            Key::Tab => self.open(Tab::Configuration),
            Key::BackTab => self.open(Tab::Setup),
            Key::Char('q') => self.quit = true,
            _ => {}
        }
    }

    fn ask(&mut self, action: ServiceAction) {
        let Some(status) = self.services.get(self.selected) else {
            return;
        };
        if status.installed {
            self.confirm = Some((status.unit, action));
            self.message = None;
        } else {
            self.message = Some(format!("{} is not installed", status.unit.name()));
        }
    }

    fn ask_boot(&mut self, enable: bool) {
        let Some(status) = self.services.get(self.selected) else {
            return;
        };
        if status.installed {
            self.boot = Some((status.unit, enable, PasswordPrompt::default()));
            self.message = None;
        } else {
            self.message = Some(format!("{} is not installed", status.unit.name()));
        }
    }
}
