//! TUI state and key handling, free of terminal code so it can be tested.

use platform_host::{Host, ServiceAction, ServiceStatus, Unit};

use super::configuration::Configuration;

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
}

/// The screen shown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tab {
    Services,
    Configuration,
}

/// The TUI's state: the Services screen's fields, and the Configuration
/// screen's in `config`.
pub struct App<H: Host> {
    pub host: H,
    pub tab: Tab,
    pub config: Configuration,
    pub services: Vec<ServiceStatus>,
    pub selected: usize,
    /// An action waiting for y/n.
    pub confirm: Option<(Unit, ServiceAction)>,
    /// The last outcome or error, shown above the key help.
    pub message: Option<String>,
    pub logs: Vec<String>,
    pub quit: bool,
}

impl<H: Host> App<H> {
    pub fn new(host: H) -> Self {
        let mut app = App {
            host,
            tab: Tab::Services,
            config: Configuration::default(),
            services: Vec::new(),
            selected: 0,
            confirm: None,
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
    pub fn key(&mut self, key: Key) {
        match self.tab {
            Tab::Services => self.services_key(key),
            Tab::Configuration => self.config_key(key),
        }
    }

    /// j/k (arrows) move, s/t/r ask to start/stop/restart, y answers, R
    /// refreshes, Tab opens Configuration, q quits.
    fn services_key(&mut self, key: Key) {
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
            Key::Char('R') => {
                self.message = None;
                self.refresh();
                self.load_logs();
            }
            Key::Tab => {
                self.tab = Tab::Configuration;
                self.message = None;
                self.load_config();
            }
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
}
