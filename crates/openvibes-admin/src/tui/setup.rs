//! The Setup tab's state and keys (admin TUI spec §6.3): a form, the
//! password once per run, then one step per event-loop tick through
//! `helper setup-step`, stopping at the first step that fails or waits.

use std::collections::BTreeSet;

use platform_host::{Host, HostError, Privileged, Secret, Step, StepState};

use super::{
    app::{App, Key},
    password::{PasswordPrompt, Typed},
};
use crate::setup::{
    plan::{CaMode, Component, ModelChoice},
    ports,
};

// The form's rows: one per component, then these. Counted from the
// component list, so a new component cannot share a row with the hostname
// (the signer once did: both lit, and space there ticked the signer).
pub const HOSTNAME_ROW: usize = Component::ALL.len();
pub const SANS_ROW: usize = HOSTNAME_ROW + 1;
pub const CA_ROW: usize = HOSTNAME_ROW + 2;
pub const KEY_ROW: usize = HOSTNAME_ROW + 3;
pub const PORT_ROW: usize = HOSTNAME_ROW + 4;
pub const AGENT_PORTS_ROW: usize = HOSTNAME_ROW + 5;
pub const START_ROW: usize = HOSTNAME_ROW + 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum After {
    Plan,
    Run(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Form,
    Password(After),
    /// Whether to download the assistant's model (asked before the password).
    Model,
    Running(usize),
    Stopped(usize),
    Finished,
}

pub struct Setup {
    pub components: BTreeSet<Component>,
    pub row: usize,
    pub hostname: String,
    pub sans: String,
    pub ca: CaMode,
    pub model: ModelChoice,
    /// The model is already installed: Setup does not ask.
    pub model_present: bool,
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
    pub home: Option<String>,
}

impl Setup {
    pub fn new(hostname: String, home: Option<String>) -> Setup {
        use Component::*;
        let mut components: BTreeSet<Component> =
            [Ingest, Console, Distribution, Vulns, Rules].into();
        // Tests run on any host: the full default there.
        if cfg!(test) || crate::setup::agent_by_default(std::path::Path::new("/")) {
            components.insert(Agent);
        }
        Setup {
            components,
            row: 0,
            hostname,
            sans: String::new(),
            ca: CaMode::Quick,
            model: ModelChoice::Fetch,
            model_present: crate::assistant_setup::model_installed()
                || crate::model_fetch::staged_in(std::path::Path::new("/")).is_some(),
            root_key_out: super::setup_form::default_root_key(home.as_deref()),
            console_port: ports::CONSOLE_DEFAULT.to_string(),
            agent_ports: format!("{}, {}", ports::INGEST_DEFAULT, ports::DISTRIBUTION_DEFAULT),
            console_note: None,
            agent_ports_note: None,
            editing: false,
            prompt: PasswordPrompt::default(),
            password: None,
            states: vec![None; Step::ALL.len()],
            phase: Phase::Form,
            home,
        }
    }
}

impl<H: Host> App<H> {
    pub fn setup_key(&mut self, key: Key) {
        match self.setup.phase {
            Phase::Password(after) => self.password_key(key, after),
            Phase::Form => self.form_key(key),
            Phase::Model => self.model_key(key),
            Phase::Running(_) => {}
            // #87 (ruling 6): before the CA, the filled form again; after
            // it, Home (Maintenance › Repair finishes the install).
            Phase::Stopped(at) => match key {
                Key::Char('r') => self.ask_password(After::Run(at)),
                Key::Esc if self.ca_exists() => self.back(),
                Key::Esc => self.fill_from_plan(),
                Key::Char('q') => self.quit = true,
                _ => {}
            },
            Phase::Finished => match key {
                Key::Enter if self.setup_done() => self.back(),
                Key::Char('q') => self.quit = true,
                _ => {}
            },
        }
    }

    /// Start: the model question first if needed, then the password.
    pub(super) fn start_plan(&mut self) {
        // The model is a 2.7 GB download: asked first, unless it is there.
        if self.setup.components.contains(&Component::Assistant) && !self.setup.model_present {
            self.setup.phase = Phase::Model;
            return;
        }
        self.setup.model = ModelChoice::Fetch;
        self.ask_password(After::Plan);
    }

    /// Y (or Enter) downloads the model, N leaves the assistant off.
    fn model_key(&mut self, key: Key) {
        let choice = match key {
            Key::Enter | Key::Char('y' | 'Y') => ModelChoice::Fetch,
            Key::Char('n' | 'N') => ModelChoice::Skip,
            Key::Esc => {
                self.setup.phase = Phase::Form;
                return;
            }
            _ => return,
        };
        self.setup.model = choice;
        self.ask_password(After::Plan);
    }

    /// Asks for the sudo password before `after`, or goes straight on as
    /// root, which sudo lets through without one (#82).
    pub(super) fn ask_password(&mut self, after: After) {
        self.setup.prompt = PasswordPrompt::default();
        self.message = None;
        if self.host.needs_password() {
            self.setup.phase = Phase::Password(after);
        } else {
            self.with_password(after, Secret::new(String::new()));
        }
    }

    fn password_key(&mut self, key: Key, after: After) {
        let secret = match self.setup.prompt.key(key) {
            Typed::Pending => return,
            Typed::Cancelled => {
                self.setup.phase = match after {
                    After::Plan => Phase::Form,
                    After::Run(at) => Phase::Stopped(at),
                };
                return;
            }
            Typed::Entered(secret) => secret,
        };
        self.with_password(after, secret);
    }

    fn with_password(&mut self, after: After, secret: Secret) {
        match after {
            After::Run(at) => {
                self.setup.password = Some(secret);
                self.setup.phase = Phase::Running(at);
            }
            After::Plan => {
                let args = self.setup.plan_args();
                match self.host.privileged(Privileged::SetupPlan(&args), &secret) {
                    Ok(_) => {
                        self.setup.prompt.failures = 0;
                        self.setup.states = vec![None; Step::ALL.len()];
                        self.setup.password = Some(secret);
                        self.setup.phase = Phase::Running(0);
                    }
                    Err(HostError::WrongPassword) => self.wrong_password(after),
                    Err(error) => {
                        self.message = Some(error.to_string());
                        self.setup.phase = Phase::Form;
                    }
                }
            }
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
            };
        } else {
            self.message = Some(HostError::WrongPassword.to_string());
            self.setup.phase = Phase::Password(after);
        }
    }

    /// One turn of the main loop after its draw: the key, if any, then a
    /// Setup step, but only if a run was already going before the key. A run
    /// the key just started waits a turn, so its checklist is drawn before
    /// the first step blocks (dnf held the form on screen for minutes).
    pub fn key_then_tick(&mut self, key: Option<Key>) {
        let was_running = matches!(self.setup.phase, Phase::Running(_));
        if let Some(key) = key {
            self.key(key);
        }
        if was_running && self.tab == super::app::Tab::Setup {
            self.setup_tick();
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
        let state = match self
            .host
            .privileged(Privileged::SetupStep(Step::ALL[next]), password)
        {
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
        // The model step is last and optional: its failure still ends on
        // the Finished screen, which shows the URL and password.
        let optional_last = Step::ALL.get(next) == Some(&Step::AssistantModel);
        self.setup.phase = if !finished && !optional_last {
            self.setup.password = None;
            Phase::Stopped(next)
        } else if next + 1 == Step::ALL.len() {
            self.setup.password = None;
            Phase::Finished
        } else {
            Phase::Running(next + 1)
        };
    }
}
