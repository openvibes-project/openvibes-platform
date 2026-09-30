//! The Setup tab's state and keys (admin TUI spec §6.3): a form, the
//! password once per run, then one step per event-loop tick through
//! `helper setup-step`, stopping at the first step that fails or waits.

use std::collections::BTreeSet;

use platform_host::{Host, HostError, Privileged, Secret, Step, StepState};

use super::{
    app::{App, Key},
    jobs::Job,
    password::{PasswordPrompt, Typed},
};
use crate::setup::{
    plan::{CaMode, Component},
    ports,
};

pub const HOSTNAME_ROW: usize = 7;
pub const SANS_ROW: usize = 8;
pub const CA_ROW: usize = 9;
pub const KEY_ROW: usize = 10;
pub const PORT_ROW: usize = 11;
pub const AGENT_PORTS_ROW: usize = 12;
pub const START_ROW: usize = 13;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum After {
    Plan,
    Run(usize),
    Status,
    /// Start this job at its first step.
    Job(Job),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Form,
    Password(After),
    Running(usize),
    Stopped(usize),
    Finished,
    /// A set-up host: `c` checks every step.
    Status,
    /// What Update will upgrade, and the backup.
    Update,
    /// Keep data or remove everything, the backup, the typed hostname.
    Uninstall,
}

pub struct Setup {
    pub components: BTreeSet<Component>,
    pub row: usize,
    pub hostname: String,
    pub sans: String,
    pub ca: CaMode,
    pub root_key_out: String,
    pub console_port: String,
    /// "INGEST, DISTRIBUTION": one row, so the form fits 80×24.
    pub agent_ports: String,
    /// Why the console's or the agent ports are not their defaults
    /// ("443 is taken by another process"), shown on their rows.
    pub console_note: Option<String>,
    pub agent_ports_note: Option<String>,
    pub editing: bool,
    pub prompt: PasswordPrompt,
    pub password: Option<Secret>,
    pub states: Vec<Option<StepState>>,
    pub phase: Phase,
    /// What a run runs, and the helper arguments it passes.
    pub job: Job,
    pub job_args: Vec<String>,
    /// Components unticked by Change components: removed after the install run.
    pub then_remove: Option<Vec<String>>,
    /// The components before Change components.
    pub previous: Option<BTreeSet<Component>>,
    pub home: Option<String>,
    /// Update and Uninstall screens: backup file, typed hostname, the
    /// choice, the packages, and the row under the cursor.
    pub backup: String,
    pub confirm: String,
    pub everything: bool,
    pub packages: Vec<platform_host::PackageUpdate>,
    pub row2: usize,
}

impl Setup {
    pub fn new(set_up: bool, hostname: String, home: Option<String>) -> Setup {
        use Component::*;
        Setup {
            components: [Ingest, Console, Distribution, Vulns, Rules, Agent].into(),
            row: 0,
            hostname,
            sans: String::new(),
            ca: CaMode::Quick,
            root_key_out: home
                .as_ref()
                .map(|home| format!("{home}/openvibes-root-ca.key"))
                .unwrap_or_default(),
            console_port: ports::CONSOLE_DEFAULT.to_string(),
            agent_ports: format!("{}, {}", ports::INGEST_DEFAULT, ports::DISTRIBUTION_DEFAULT),
            console_note: None,
            agent_ports_note: None,
            editing: false,
            prompt: PasswordPrompt::default(),
            password: None,
            states: vec![None; Step::ALL.len()],
            phase: if set_up { Phase::Status } else { Phase::Form },
            job: Job::Install,
            job_args: Vec::new(),
            then_remove: None,
            previous: None,
            home,
            backup: String::new(),
            confirm: String::new(),
            everything: false,
            packages: Vec::new(),
            row2: 0,
        }
    }

    pub fn plan_args(&self) -> Vec<String> {
        let components: Vec<&str> = self.components.iter().map(|c| c.name()).collect();
        let mut args = vec![
            "--components".into(),
            components.join(","),
            "--hostname".into(),
            self.hostname.trim().into(),
        ];
        for san in self
            .sans
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            args.extend(["--san".into(), san.into()]);
        }
        args.extend([
            "--ca".into(),
            match self.ca {
                CaMode::Quick => "quick",
                CaMode::Careful => "careful",
            }
            .into(),
        ]);
        if self.ca == CaMode::Quick && !self.root_key_out.trim().is_empty() {
            args.extend(["--root-key-out".into(), self.root_key_out.trim().into()]);
        }
        args.extend(["--console-port".into(), self.console_port.trim().into()]);
        // Two numbers; anything else goes through as typed, so Setup's own
        // check names what is wrong.
        let mut agent = self.agent_ports.split([',', ' ']).filter(|p| !p.is_empty());
        let ingest = agent.next().unwrap_or("").to_owned();
        let distribution = agent.collect::<Vec<_>>().join(" ");
        args.extend([
            "--ingest-port".into(),
            ingest,
            "--distribution-port".into(),
            distribution,
        ]);
        args
    }

    /// For each port another process holds, proposes the first free one
    /// (from 8443 for the console, 18425 for ingest and distribution) and
    /// notes it on the row. Unprivileged, so the holder is rarely known
    /// here; Setup's own check (as root) names it if it is still there.
    pub fn propose_ports<H: Host>(&mut self, host: &H) {
        let taken = |port: u16| {
            host.listeners(port)
                .map(|lines| ports::parse(&lines).is_some())
                .map_err(|error| error.to_string())
        };
        let defaults = [
            ports::CONSOLE_DEFAULT,
            ports::INGEST_DEFAULT,
            ports::DISTRIBUTION_DEFAULT,
        ];
        let mut chosen: Vec<u16> = defaults.to_vec();
        for (index, from) in [8443, 18425, 18425].into_iter().enumerate() {
            let default = defaults[index];
            // Free, or unknown: Setup checks again before starting.
            let Ok(true) = taken(default) else {
                continue;
            };
            let Ok(port) = ports::suggest(from, |port| Ok(chosen.contains(&port) || taken(port)?))
            else {
                continue;
            };
            chosen[index] = port;
            let note = format!("{default} is in use");
            if index == 0 {
                self.console_note = Some(note);
            } else {
                let joined = self
                    .agent_ports_note
                    .take()
                    .map_or(note.clone(), |n| format!("{n}; {note}"));
                self.agent_ports_note = Some(joined);
            }
        }
        self.console_port = chosen[0].to_string();
        self.agent_ports = format!("{}, {}", chosen[1], chosen[2]);
    }

    fn toggle(&mut self, component: Component) {
        use Component::*;
        if matches!(component, Ingest | Console) {
            return; // always installed
        }
        if !self.components.remove(&component) {
            self.components.insert(component);
            if component == Rules {
                self.components.insert(Distribution);
            }
        } else if component == Distribution {
            self.components.remove(&Rules);
        }
    }

    fn field(&mut self) -> Option<&mut String> {
        match self.row {
            HOSTNAME_ROW => Some(&mut self.hostname),
            SANS_ROW => Some(&mut self.sans),
            KEY_ROW => Some(&mut self.root_key_out),
            PORT_ROW => Some(&mut self.console_port),
            AGENT_PORTS_ROW => Some(&mut self.agent_ports),
            _ => None,
        }
    }
}

impl<H: Host> App<H> {
    pub fn setup_key(&mut self, key: Key) {
        match self.setup.phase {
            Phase::Password(after) => self.password_key(key, after),
            Phase::Form => self.form_key(key),
            Phase::Running(_) => {}
            Phase::Update => self.update_key(key),
            Phase::Uninstall => self.uninstall_key(key),
            // A stopped run keeps every other action (#73): the user's
            // "Uninstall doesn't work" was x ignored after a failed Repair.
            Phase::Stopped(at) => match key {
                Key::Char('r') => self.ask_password(After::Run(at)),
                Key::Esc => self.setup.phase = Phase::Status,
                _ => self.status_key(key),
            },
            Phase::Finished | Phase::Status => self.status_key(key),
        }
    }

    fn status_key(&mut self, key: Key) {
        match key {
            Key::Char('c') => self.ask_password(After::Status),
            Key::Char('r') => {
                self.setup.job_args.clear();
                self.ask_password(After::Job(Job::Repair));
            }
            Key::Char('m') => self.change_components(),
            Key::Char('u') => self.open_update(),
            Key::Char('x') => self.open_uninstall(),
            Key::Tab => self.leave_setup(),
            Key::BackTab => self.open(super::app::Tab::Health),
            Key::Char('q') => self.quit = true,
            _ => {}
        }
    }

    /// Back to the form, filled from `setup.toml`; what is unticked is
    /// removed (keep data) after the install run.
    fn change_components(&mut self) {
        let plan = match self
            .host
            .setup_plan()
            .map_err(|e| e.to_string())
            .and_then(|text| {
                toml::from_str::<crate::setup::plan::Plan>(&text).map_err(|e| e.to_string())
            }) {
            Ok(plan) => plan,
            Err(error) => {
                self.message = Some(error);
                return;
            }
        };
        self.setup.components = plan.components.iter().copied().collect();
        self.setup.previous = Some(self.setup.components.clone());
        self.setup.hostname = plan.hostname.clone();
        self.setup.sans = plan.sans.join(", ");
        self.setup.ca = plan.ca;
        self.setup.root_key_out.clear(); // the CA exists; no new root key
        self.setup.row = 0;
        self.setup.phase = Phase::Form;
    }

    fn start_job(&mut self, job: Job, secret: Secret) {
        self.setup.job = job;
        self.setup.states = vec![None; job.steps()];
        self.setup.password = Some(secret);
        self.setup.phase = Phase::Running(0);
    }

    fn leave_setup(&mut self) {
        self.tab = super::app::Tab::Services;
        self.message = None;
        self.refresh();
    }

    fn ask_password(&mut self, after: After) {
        self.setup.prompt = PasswordPrompt::default();
        self.setup.phase = Phase::Password(after);
        self.message = None;
    }

    fn form_key(&mut self, key: Key) {
        if self.setup.editing {
            let Some(field) = self.setup.field() else {
                return;
            };
            match key {
                Key::Char(c) if field.len() < 512 => field.push(c),
                Key::Backspace => {
                    field.pop();
                }
                Key::ClearLine => field.clear(),
                Key::Enter | Key::Esc => self.setup.editing = false,
                _ => {}
            }
            return;
        }
        match key {
            Key::Char('j') | Key::Down if self.setup.row < START_ROW => self.setup.row += 1,
            Key::Char('k') | Key::Up => self.setup.row = self.setup.row.saturating_sub(1),
            Key::Char(' ') if self.setup.row < Component::ALL.len() => {
                self.setup.toggle(Component::ALL[self.setup.row])
            }
            Key::Char(' ') | Key::Enter if self.setup.row == CA_ROW => {
                self.setup.ca = match self.setup.ca {
                    CaMode::Quick => CaMode::Careful,
                    CaMode::Careful => CaMode::Quick,
                };
            }
            Key::Enter if self.setup.row == START_ROW => self.ask_password(After::Plan),
            Key::Enter if self.setup.field().is_some() => self.setup.editing = true,
            Key::Tab => self.leave_setup(),
            Key::BackTab => self.open(super::app::Tab::Health),
            Key::Char('q') => self.quit = true,
            _ => {}
        }
    }

    fn password_key(&mut self, key: Key, after: After) {
        let secret = match self.setup.prompt.key(key) {
            Typed::Pending => return,
            Typed::Cancelled => {
                self.setup.phase = match after {
                    After::Plan => Phase::Form,
                    After::Run(at) => Phase::Stopped(at),
                    After::Status | After::Job(_) => Phase::Status,
                };
                return;
            }
            Typed::Entered(secret) => secret,
        };
        match after {
            After::Job(job) => self.start_job(job, secret),
            After::Run(at) => {
                self.setup.password = Some(secret);
                self.setup.phase = Phase::Running(at);
            }
            After::Plan => {
                let args = self.setup.plan_args();
                match self.host.privileged(Privileged::SetupPlan(&args), &secret) {
                    Ok(_) => {
                        self.setup.prompt.failures = 0;
                        self.setup.job_args.clear();
                        let job = if self.setup.previous.is_some() {
                            Job::Repair
                        } else {
                            Job::Install
                        };
                        if let Some(previous) = self.setup.previous.take() {
                            let removed: Vec<&str> = previous
                                .difference(&self.setup.components)
                                .map(|c| c.name())
                                .collect();
                            if !removed.is_empty() {
                                self.setup.then_remove =
                                    Some(vec!["--components".into(), removed.join(",")]);
                            }
                        }
                        // Change components keeps the CA: repair mode.
                        self.start_job(job, secret);
                    }
                    Err(HostError::WrongPassword) => self.wrong_password(after),
                    Err(error) => {
                        self.message = Some(error.to_string());
                        self.setup.phase = Phase::Form;
                    }
                }
            }
            After::Status => match self.host.privileged(Privileged::SetupStatus, &secret) {
                Ok(out) => {
                    self.setup.job = Job::Install;
                    self.setup.states = vec![None; Step::ALL.len()];
                    for line in out.lines() {
                        let Some((name, rest)) = line.split_once('\t') else {
                            continue;
                        };
                        if let (Some(step), Some(state)) =
                            (Step::parse(name), StepState::parse(rest))
                        {
                            let index = Step::ALL.iter().position(|s| *s == step).unwrap_or(0);
                            self.setup.states[index] = Some(state);
                        }
                    }
                    self.setup.phase = Phase::Status;
                }
                Err(HostError::WrongPassword) => self.wrong_password(after),
                Err(error) => {
                    self.message = Some(error.to_string());
                    self.setup.phase = Phase::Status;
                }
            },
        }
    }

    fn wrong_password(&mut self, after: After) {
        self.setup.prompt.failures += 1;
        if self.setup.prompt.failures >= 3 {
            self.message = Some("three wrong passwords; try again later".into());
            self.setup.prompt = PasswordPrompt::default();
            self.setup.phase = match after {
                After::Plan => Phase::Form,
                After::Run(at) => Phase::Stopped(at),
                After::Status | After::Job(_) => Phase::Status,
            };
        } else {
            self.message = Some(HostError::WrongPassword.to_string());
            self.setup.phase = Phase::Password(after);
        }
    }

    /// Runs the next step, if a run is going (called once per loop turn).
    pub fn setup_tick(&mut self) {
        let Phase::Running(next) = self.setup.phase else {
            return;
        };
        let Some(password) = &self.setup.password else {
            self.setup.phase = Phase::Stopped(next);
            return;
        };
        let args = self.setup.job_args.clone();
        let verb = self.setup.job.verb(next, &args);
        let state = match self.host.privileged(verb, password) {
            Ok(out) => StepState::parse(out.trim_end()).unwrap_or_else(|| {
                StepState::Failed(format!("unexpected helper output: {}", out.trim()))
            }),
            Err(HostError::WrongPassword) => {
                self.setup.password = None;
                self.wrong_password(After::Run(next));
                return;
            }
            Err(error) => StepState::Failed(error.to_string()),
        };
        // The password worked: wrong ones are counted per attempt.
        self.setup.prompt.failures = 0;
        let finished = state.finished();
        self.setup.states[next] = Some(state);
        self.setup.phase = if !finished {
            self.setup.password = None;
            Phase::Stopped(next)
        } else if next + 1 == self.setup.job.steps() {
            if let Some(args) = self.setup.then_remove.take() {
                // Components unticked in the form: removed, data kept.
                self.setup.job = Job::Remove;
                self.setup.job_args = args;
                self.setup.states = vec![None; Job::Remove.steps()];
                Phase::Running(0)
            } else {
                self.setup.password = None;
                Phase::Finished
            }
        } else {
            Phase::Running(next + 1)
        };
    }
}
