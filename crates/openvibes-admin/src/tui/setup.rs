//! The Setup tab's state and keys (admin TUI spec §6.3): a form, the
//! password once per run, then one step per event-loop tick through
//! `helper setup-step`, stopping at the first step that fails or waits.

use std::collections::BTreeSet;

use platform_host::{Host, HostError, Privileged, Secret, Step, StepState};

use super::{
    app::{App, Key},
    password::{PasswordPrompt, Typed},
};
use crate::setup::plan::{CaMode, Component};

pub const HOSTNAME_ROW: usize = 7;
pub const SANS_ROW: usize = 8;
pub const CA_ROW: usize = 9;
pub const KEY_ROW: usize = 10;
pub const START_ROW: usize = 11;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum After {
    Plan,
    Run(usize),
    Status,
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
}

pub struct Setup {
    pub components: BTreeSet<Component>,
    pub row: usize,
    pub hostname: String,
    pub sans: String,
    pub ca: CaMode,
    pub root_key_out: String,
    pub editing: bool,
    pub prompt: PasswordPrompt,
    pub password: Option<Secret>,
    pub states: [Option<StepState>; 13],
    pub phase: Phase,
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
                .map(|home| format!("{home}/openvibes-root-ca.key"))
                .unwrap_or_default(),
            editing: false,
            prompt: PasswordPrompt::default(),
            password: None,
            states: Default::default(),
            phase: if set_up { Phase::Status } else { Phase::Form },
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
        args
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
            Phase::Stopped(at) => match key {
                Key::Char('r') => self.ask_password(After::Run(at)),
                Key::Tab => self.leave_setup(),
                Key::Char('q') => self.quit = true,
                _ => {}
            },
            Phase::Finished | Phase::Status => match key {
                Key::Char('c') => self.ask_password(After::Status),
                Key::Tab => self.leave_setup(),
                Key::Char('q') => self.quit = true,
                _ => {}
            },
        }
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
                    After::Status => Phase::Status,
                };
                return;
            }
            Typed::Entered(secret) => secret,
        };
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
                        self.setup.states = Default::default();
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
            After::Status => match self.host.privileged(Privileged::SetupStatus, &secret) {
                Ok(out) => {
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
                After::Status => Phase::Status,
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
        let step = Step::ALL[next];
        let state = match self.host.privileged(Privileged::SetupStep(step), password) {
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
        } else if next + 1 == Step::ALL.len() {
            self.setup.password = None;
            Phase::Finished
        } else {
            Phase::Running(next + 1)
        };
    }
}
