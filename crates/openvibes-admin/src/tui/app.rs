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
    /// Tab: browse for a folder (a typed folder only).
    Tab,
    /// Ctrl+U: empty the field being edited.
    ClearLine,
}

/// Which of today's screens `Screen::Legacy` shows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tab {
    Setup,
    Configuration,
}

/// The TUI's state: where the operator is (`nav`), what the host reports
/// (`services`, the health checks in `database`), the bar's question, prompt
/// and running work, and today's screens' own state (`setup`, `config`,
/// `database`).
pub struct App<H: Host> {
    pub host: H,
    pub tab: Tab,
    pub setup: Setup,
    pub install: super::install::Install,
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
    /// Every package's version change (Update › What's new); `None` until looked up.
    pub packages: Option<Result<Vec<PackageUpdate>, String>>,
    /// The kind of job the helper left half done (`update`), from `/run`.
    pub half_done: Option<String>,
    /// Enter after an update: start the new version of the menu.
    pub reopen: bool,
    /// The update notice, looked up on another thread (`run`): dnf may
    /// take long offline. Without it, `tick` asks the host itself (tests).
    pub updates: Option<Receiver<Result<Vec<PackageUpdate>, HostError>>>,
    /// The health checks, collected on another thread (`run`): the probes
    /// take a while. Without it, `new` collects them itself (tests).
    pub health: Option<Receiver<Vec<Check>>>,
    /// The full log's page length at its last draw; it caps how far up
    /// the log scrolls.
    pub log_room: Cell<usize>,
    /// The Status item highlighted when Status was left; Esc looks it up
    /// again, as the list may have changed meanwhile.
    pub(super) held: Option<super::status::Item>,
    /// A question in the bar; the bool is the highlighted answer (Yes).
    pub question: Option<(Question, bool)>,
    /// The sudo password being typed in the bar (enable at boot).
    pub prompt: Option<(Unit, PasswordPrompt)>,
    /// Work running in the background.
    pub pending: Option<Pending>,
    /// The last action's result line, until the next key.
    pub outcome: Option<(bool, String)>,
    /// The current or last action (Update, Back up, Fix, Uninstall): Home
    /// shows it; Quit waits for it.
    pub run: Option<super::run::Run>,
    /// The current or last read (Repair's check, the Database report).
    pub load: Option<super::run::Run>,
    /// The password for a run, typed in the bar.
    pub asking: Option<super::run::Asking>,
    /// Runs work on another thread (`run` sets it; tests leave it out).
    pub worker: Option<super::run::Worker>,
    /// Yes to "Quit when it is done?".
    pub quit_when_done: bool,
    /// The Maintenance pages' state.
    pub maint: super::maint::Maint,
    /// `/` on a host: where the TUI reads `/etc/openvibes/backup.toml` and
    /// `/run/openvibes-admin/job`; tests point it elsewhere.
    pub root: std::path::PathBuf,
    /// Checks the backup folder on another thread (`run` sets it; tests leave it out).
    pub checker: Option<super::maint::folder::Checker>,
    pub(super) tick_count: usize,
    /// The CA exists (`ca_exists`), read at start, on refresh and after
    /// each Setup step, not on every draw.
    pub(super) ca: bool,
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
        let install = super::install::Install::new(hostname.clone(), home.clone());
        let mut install = install;
        let mut setup = Setup::new(hostname.clone(), home);
        if !set_up {
            setup.propose_ports(&host);
            install.port_note = super::install::fields::propose_ports(&host, &mut install);
        }
        let mut app = App {
            host,
            tab: Tab::Setup,
            setup,
            install,
            config: Configuration::default(),
            database: DatabaseScreen::default(),
            services: Vec::new(),
            selected: 0,
            message: None,
            logs: Vec::new(),
            quit: false,
            theme: Theme::from_env(),
            nav: Nav::new(if set_up {
                Screen::Home
            } else {
                Screen::Install(super::install::Stage::Welcome)
            }),
            hostname,
            update: None,
            versions_loaded: false,
            packages: None,
            half_done: None,
            reopen: false,
            updates: None,
            health: None,
            log_room: Cell::new(0),
            held: None,
            question: None,
            prompt: None,
            pending: None,
            outcome: None,
            run: None,
            load: None,
            asking: None,
            worker: None,
            quit_when_done: false,
            maint: super::maint::Maint::default(),
            root: std::path::PathBuf::from("/"),
            checker: None,
            tick_count: 0,
            ca: false,
        };
        app.refresh();
        app.start_screen();
        app.load_logs();
        app.files_changed();
        app
    }

    /// #87 (ruling 6): set up but stopped before its CA, the host opens
    /// the install form, filled from its plan; unless a job is half done
    /// (Remove everything deletes the CA before `setup.toml`): Home, whose
    /// Status offers to finish it.
    pub(super) fn start_screen(&mut self) {
        if !self.host.is_set_up() {
            return;
        }
        if !self.ca && self.half_done.is_none() {
            self.nav = Nav::new(Screen::Legacy);
            self.fill_from_plan();
        } else {
            self.nav = Nav::new(Screen::Home);
        }
    }

    /// Reloads the unit states (the periodic refresh). Logs are reloaded
    /// only on selection, `R`, and after an action: each read goes through
    /// sudo, which writes to the auth log.
    pub fn refresh(&mut self) {
        self.files_changed();
        self.ca = self.ca_exists();
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

    /// Set up, CA included: a host whose first install stopped before its
    /// CA is still installing (#87), so its form quits with q as on a
    /// fresh host.
    pub fn setup_done(&self) -> bool {
        self.host.is_set_up() && self.ca_exists()
    }

    /// `setup_done` for drawing: the CA as last read (`ca`), no file reads.
    pub fn setup_done_seen(&self) -> bool {
        self.host.is_set_up() && self.ca
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
        }
    }

    /// One key: a legacy screen keeps its own keys; elsewhere ? opens Help,
    /// Esc goes back, q quits from Home, the rest is the screen's.
    pub fn key(&mut self, key: Key) {
        self.outcome = None;
        // The tool removed itself: Enter (or q) quits, nothing else is left.
        if self.gone() {
            if matches!(key, Key::Enter | Key::Char('q')) {
                self.quit = true;
            }
            return;
        }
        if self.asking.is_some() {
            return self.asking_key(key);
        }
        if self.nav.screen == Screen::Legacy {
            return self.legacy_key(key);
        }
        if self.maint.editing()
            && let Screen::Maint(page) = self.nav.screen.clone()
        {
            return self.maint_key(page, key);
        }
        if self.question.is_some() {
            return self.question_key(key);
        }
        if self.prompt.is_some() {
            return self.prompt_key(key);
        }
        if let Screen::Install(stage) = self.nav.screen {
            return self.install_key(stage, key);
        }
        match key {
            Key::Char('?') if !matches!(self.nav.screen, Screen::Help(_)) => {
                self.hold_status_item();
                let from = Box::new(self.nav.screen.clone());
                self.nav.go(Screen::Help(from));
            }
            Key::Esc => {
                if self.nav.screen == Screen::Maint(super::maint::Page::SignIn) {
                    self.signin_left();
                }
                self.nav.pop();
                // A note from another screen is not news here.
                self.message = None;
                self.find_held_status_item();
                if matches!(self.nav.screen, Screen::Service(_)) {
                    self.load_logs();
                }
                // Back from Names, run or not: the report may be new.
                if self.nav.screen == Screen::Maint(super::maint::Page::Certificates) {
                    self.read_certs();
                }
            }
            Key::Char('q') if self.nav.screen == Screen::Home => self.quit_or_ask(),
            _ => match self.nav.screen.clone() {
                Screen::Home => self.home_key(key),
                Screen::Maintenance => self.menu_key(key),
                Screen::Maint(page) => self.maint_key(page, key),
                Screen::Status => self.status_key(key),
                Screen::Service(unit) => self.service_key(unit, key),
                Screen::Log(_) => self.log_key(key),
                Screen::Help(_) | Screen::Legacy | Screen::Install(_) => {}
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
            let found = match self.updates.as_ref().map(Receiver::try_recv) {
                Some(Err(TryRecvError::Empty)) => None,
                Some(Ok(found)) => Some(found),
                Some(Err(TryRecvError::Disconnected)) => {
                    Some(Err(HostError::Failed("the update check stopped".into())))
                }
                None => Some(self.host.packages()),
            };
            if let Some(found) = found {
                self.update = found.as_ref().ok().and_then(|p| newer_admin(p));
                self.packages = Some(found.map_err(|e| e.to_string()));
                self.versions_loaded = true;
                self.updates = None;
            }
        }
        self.poll(now);
        self.poll_runs(now);
        self.poll_folder(now);
    }

    /// Reads again what the helper writes for the TUI (the half-done mark).
    pub(super) fn files_changed(&mut self) {
        self.half_done = super::maint::update_half_done(&self.root);
    }

    /// Today's screens' own keys.
    pub(super) fn legacy_dispatch(&mut self, key: Key) {
        match self.tab {
            Tab::Setup => self.setup_key(key),
            Tab::Configuration => self.config_key(key),
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
pub fn newer_admin(packages: &[PackageUpdate]) -> Option<String> {
    packages.iter().find_map(|p| {
        let v = p
            .available
            .as_ref()
            .filter(|_| p.name == "openvibes-admin")?;
        Some(v.split('-').next().unwrap_or(v).to_owned())
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
