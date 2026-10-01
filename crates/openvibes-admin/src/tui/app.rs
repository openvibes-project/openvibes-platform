//! TUI state and key handling, free of terminal code so it can be tested.

use platform_host::{Host, Privileged, ServiceAction, ServiceStatus, Unit};

use super::{
    configuration::Configuration,
    database::DatabaseScreen,
    password::{PasswordPrompt, Typed},
    setup::Setup,
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

/// The screen shown.
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
    /// Colour in the banner; off when `NO_COLOR` is set (no-color.org).
    pub color: bool,
}

impl<H: Host> App<H> {
    pub fn new(host: H) -> Self {
        let set_up = host.is_set_up();
        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|h| h.trim().to_lowercase())
            .unwrap_or_default();
        let home = crate::setup::plan::operator_from_env()
            .and_then(|user| {
                person_home(
                    &std::fs::read_to_string("/etc/passwd").unwrap_or_default(),
                    &user,
                )
            })
            .or_else(|| std::env::var("HOME").ok());
        let mut setup = Setup::new(set_up, hostname, home);
        if !set_up {
            setup.propose_ports(&host);
        }
        let mut app = App {
            color: std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()),
            host,
            tab: if set_up { Tab::Services } else { Tab::Setup },
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

    /// One key, handled by the screen shown.
    /// Opens `tab`, loading what it shows, as reaching it with Tab does.
    pub(super) fn open(&mut self, tab: Tab) {
        self.message = None;
        match tab {
            Tab::Setup => self.tab = Tab::Setup,
            Tab::Services => {
                self.tab = Tab::Services;
                self.refresh();
            }
            Tab::Configuration => {
                self.tab = Tab::Configuration;
                self.load_config();
            }
            Tab::Database => self.open_database(),
            Tab::Health => self.open_health(),
        }
    }

    pub fn key(&mut self, key: Key) {
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

/// The home directory of `user` from `/etc/passwd` text. Under sudo, HOME
/// is root's, but the root key belongs in the person's own home (#92).
fn person_home(passwd: &str, user: &str) -> Option<String> {
    passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.len() >= 7 && fields[0] == user && fields[5].starts_with('/'))
            .then(|| fields[5].to_owned())
    })
}

#[cfg(test)]
mod home_tests {
    #[test]
    fn under_sudo_the_root_key_goes_to_the_persons_home() {
        let passwd =
            "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n";
        assert_eq!(
            super::person_home(passwd, "alice").as_deref(),
            Some("/home/alice")
        );
        assert_eq!(super::person_home(passwd, "bob"), None);
    }
}
