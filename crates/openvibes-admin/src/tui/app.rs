//! TUI state and key handling, free of terminal code so it can be tested.

use platform_host::{Host, ServiceAction, ServiceStatus, Unit};

/// Journal lines shown for the selected unit.
pub const LOG_LINES: u16 = 50;

/// The Services screen's state.
pub struct App<H: Host> {
    pub host: H,
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
            services: Vec::new(),
            selected: 0,
            confirm: None,
            message: None,
            logs: Vec::new(),
            quit: false,
        };
        app.refresh();
        app
    }

    /// Reloads the units and the selected unit's log.
    pub fn refresh(&mut self) {
        match self.host.services() {
            Ok(services) => self.services = services,
            Err(error) => self.message = Some(error.to_string()),
        }
        self.selected = self.selected.min(self.services.len().saturating_sub(1));
        self.load_logs();
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

    /// One key: j/k move, s/t/r ask to start/stop/restart, y/n answer,
    /// R refreshes, q quits (the event loop maps arrows to j/k).
    pub fn key(&mut self, key: char) {
        if let Some((unit, action)) = self.confirm.take() {
            if key == 'y' {
                self.message = Some(match self.host.service_action(unit, action) {
                    Ok(()) => format!("{} {}: done", action.verb(), unit.name()),
                    Err(error) => error.to_string(),
                });
                self.refresh();
            }
            return;
        }
        match key {
            'j' if self.selected + 1 < self.services.len() => {
                self.selected += 1;
                self.load_logs();
            }
            'k' if self.selected > 0 => {
                self.selected -= 1;
                self.load_logs();
            }
            's' => self.ask(ServiceAction::Start),
            't' => self.ask(ServiceAction::Stop),
            'r' => self.ask(ServiceAction::Restart),
            'R' => {
                self.message = None;
                self.refresh();
            }
            'q' => self.quit = true,
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
