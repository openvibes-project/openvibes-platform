//! Work that takes long (spec §2): helper calls run one after the other on
//! another thread, so the screen keeps drawing; the password is typed in
//! the bar, moved to that thread and dropped when its work ends. A run
//! stops at the first call that does not finish; a rescue (Update: start
//! the services again) may follow. Without a worker (tests) the calls run
//! at once on the TUI's own host.

use std::{sync::mpsc::Receiver, time::Instant};

use platform_host::{
    Database, Host, HostError, Privileged, RemoveStep, Secret, Step, StepState, Unit, UpdateStep,
};

use super::password::PasswordPrompt;

/// One helper call, or one read for a report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Call {
    /// `setup-status`: every step's state.
    Status,
    Repair(Step),
    Update(UpdateStep, Vec<String>),
    #[allow(dead_code, reason = "first used in Task 9 of the 2a plan")]
    Remove(RemoveStep, Vec<String>),
    /// A database command (no password).
    Database(Database),
    /// The database's disk: `size<TAB>percent<TAB>free`, empty when unknown.
    Disk,
    /// The unit's last journal lines, joined (no password).
    Logs(Unit, u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    Update {
        to: String,
        /// "agent 0.2.9": the packages that are newer when the admin is
        /// not, so the words name what changes, not the installed version.
        others: Option<String>,
    },
    Backup {
        file: String,
    },
    Check,
    Fix,
    #[allow(dead_code, reason = "first used in Task 9 of the 2a plan")]
    Uninstall {
        everything: bool,
    },
    /// The Database page's reads.
    Report,
}

impl Kind {
    /// Reads, which may be dropped: Home does not show them, Quit does not wait.
    pub fn background(&self) -> bool {
        matches!(self, Kind::Check | Kind::Report)
    }
    pub fn doing(&self) -> String {
        match self {
            Kind::Update {
                others: Some(what), ..
            } => format!("Updating {what}"),
            Kind::Update { to, .. } => format!("Updating to {to}"),
            Kind::Backup { .. } => "Backing up".into(),
            Kind::Check => "Checking every step".into(),
            Kind::Fix => "Repairing".into(),
            Kind::Uninstall { .. } => "Uninstalling".into(),
            Kind::Report => "Reading the database".into(),
        }
    }
    pub fn done(&self) -> String {
        match self {
            Kind::Update {
                others: Some(what), ..
            } => format!("Updated: {what}"),
            Kind::Update { to, .. } => format!("Updated to {to}"),
            Kind::Backup { .. } => "Backed up".into(),
            Kind::Check => "Checked".into(),
            Kind::Fix => "Repaired".into(),
            Kind::Uninstall { .. } => "OpenVIBES is removed".into(),
            Kind::Report => "Read".into(),
        }
    }
    pub fn stopped(&self) -> String {
        match self {
            Kind::Update { .. } => "The update stopped".into(),
            Kind::Backup { .. } => "The backup failed".into(),
            Kind::Check => "The check failed".into(),
            Kind::Fix => "The repair stopped".into(),
            Kind::Uninstall { .. } => "The uninstall stopped".into(),
            Kind::Report => "The database could not be read".into(),
        }
    }
    /// What Enter does once the password is typed.
    pub fn verb(&self) -> &'static str {
        match self {
            Kind::Update { .. } => "Update",
            Kind::Backup { .. } => "Back up",
            Kind::Check => "Check",
            Kind::Fix => "Fix",
            Kind::Uninstall { .. } => "Uninstall",
            Kind::Report => "Read",
        }
    }
}

/// A stop at a main call in `from..to` runs `calls` next, same password.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rescue {
    pub from: usize,
    pub to: usize,
    pub calls: Vec<Call>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Work {
    pub kind: Kind,
    pub calls: Vec<Call>,
    pub rescue: Option<Rescue>,
}

impl Work {
    pub fn new(kind: Kind, calls: Vec<Call>) -> Work {
        Work {
            kind,
            calls,
            rescue: None,
        }
    }
}

/// One call's result; `index` counts the main calls, then the rescue's.
pub struct Progress {
    pub index: usize,
    pub result: Result<String, HostError>,
}

/// Runs `work` from `from` on another thread with its own host.
pub type Worker = Box<dyn Fn(Work, usize, Secret) -> Receiver<Progress>>;

pub fn execute<H: Host>(host: &H, call: &Call, secret: &Secret) -> Result<String, HostError> {
    match call {
        Call::Status => host.privileged(Privileged::SetupStatus, secret),
        Call::Repair(step) => host.privileged(Privileged::Repair(*step), secret),
        Call::Update(step, args) => host.privileged(Privileged::Update(*step, args), secret),
        Call::Remove(step, args) => host.privileged(Privileged::Remove(*step, args), secret),
        Call::Database(command) => host.database(*command),
        Call::Disk => host.disk().map(|disks| {
            disks
                .into_iter()
                .find(|d| d.path == "/var/lib/pgsql")
                .map_or_else(String::new, |d| {
                    format!("{}\t{}\t{}", d.size, d.used_percent, d.available)
                })
        }),
        Call::Logs(unit, lines) => host.logs(*unit, *lines).map(|l| l.join("\n")),
    }
}

/// What a call's result reads as: a step's `STATE<TAB>DETAIL`, or its output.
pub fn state_of(call: &Call, result: &Result<String, HostError>) -> StepState {
    match (call, result) {
        (_, Err(error)) => StepState::Failed(error.to_string()),
        (Call::Repair(_) | Call::Update(..) | Call::Remove(..), Ok(out)) => {
            StepState::parse(out.trim_end()).unwrap_or_else(|| {
                StepState::Failed(format!("unexpected helper output: {}", out.trim()))
            })
        }
        (_, Ok(out)) => StepState::Done(out.clone()),
    }
}

/// Whether the run goes on. The assistant's model is optional: its
/// download failing does not stop a repair.
pub fn goes_on(call: &Call, result: &Result<String, HostError>) -> bool {
    state_of(call, result).finished()
        || (*call == Call::Repair(Step::AssistantModel) && result.is_ok())
}

/// Runs the calls from `from` in order, reporting each; stops at the first
/// that does not go on, then runs the rescue if it covers that call (never
/// after a wrong password). `report` returning false stops it.
pub fn work_through<H: Host>(
    host: &H,
    work: &Work,
    from: usize,
    secret: &Secret,
    mut report: impl FnMut(Progress) -> bool,
) {
    for (index, call) in work.calls.iter().enumerate().skip(from) {
        let result = execute(host, call, secret);
        let on = goes_on(call, &result);
        let wrong = matches!(result, Err(HostError::WrongPassword));
        if !report(Progress { index, result }) {
            return;
        }
        if on {
            continue;
        }
        if let Some(rescue) = work
            .rescue
            .as_ref()
            .filter(|r| !wrong && (r.from..r.to).contains(&index))
        {
            for (j, call) in rescue.calls.iter().enumerate() {
                let result = execute(host, call, secret);
                if !report(Progress {
                    index: work.calls.len() + j,
                    result,
                }) {
                    return;
                }
            }
        }
        return;
    }
}

pub struct Run {
    pub work: Work,
    /// Each call's state (main calls, then the rescue's) once it has run.
    pub states: Vec<Option<StepState>>,
    /// The last main call that reported.
    pub at: usize,
    pub started: Instant,
    pub ended: Option<Instant>,
    /// Wrong passwords so far; three stop the run.
    pub wrong: u8,
    pub(super) rx: Option<Receiver<Progress>>,
}

impl Run {
    pub(super) fn new(work: Work, now: Instant) -> Run {
        let n = work.calls.len() + work.rescue.as_ref().map_or(0, |r| r.calls.len());
        Run {
            work,
            states: vec![None; n],
            at: 0,
            started: now,
            ended: None,
            wrong: 0,
            rx: None,
        }
    }

    pub fn running(&self) -> bool {
        self.ended.is_none()
    }

    /// The first main call that did not finish (the optional model aside).
    pub fn stopped_at(&self) -> Option<usize> {
        (0..self.work.calls.len()).find(|&i| {
            self.states[i].as_ref().is_some_and(|s| !s.finished())
                && self.work.calls[i] != Call::Repair(Step::AssistantModel)
        })
    }

    /// The main call running now; `None` once stopped (a rescue may run).
    pub fn current(&self) -> Option<usize> {
        if !self.running() || self.stopped_at().is_some() {
            return None;
        }
        (0..self.work.calls.len()).find(|&i| self.states[i].is_none())
    }

    pub fn ok(&self) -> bool {
        !self.running()
            && (0..self.work.calls.len()).all(|i| {
                self.states[i].as_ref().is_some_and(|s| s.finished())
                    || (self.states[i].is_some()
                        && self.work.calls[i] == Call::Repair(Step::AssistantModel))
            })
    }

    /// The `j`th rescue call's state.
    pub fn rescued(&self, j: usize) -> Option<&StepState> {
        self.states.get(self.work.calls.len() + j)?.as_ref()
    }

    /// How long it took: "2 min 41 s", "12 s".
    pub fn took(&self) -> String {
        let s = self
            .ended
            .unwrap_or_else(Instant::now)
            .saturating_duration_since(self.started)
            .as_secs();
        if s >= 60 {
            format!("{} min {} s", s / 60, s % 60)
        } else {
            format!("{s} s")
        }
    }

    /// Takes one result; true when the password was wrong.
    pub(super) fn take(&mut self, p: Progress, now: Instant) -> bool {
        let main = self.work.calls.len();
        if p.index >= main {
            let j = p.index - main;
            let count = self.work.rescue.as_ref().map_or(0, |r| r.calls.len());
            if let Some(call) = self.work.rescue.as_ref().and_then(|r| r.calls.get(j)) {
                self.states[p.index] = Some(state_of(call, &p.result));
            }
            if j + 1 >= count {
                self.ended = Some(now);
            }
            return false;
        }
        self.at = p.index;
        if matches!(p.result, Err(HostError::WrongPassword)) {
            self.ended = Some(now);
            return true;
        }
        let call = &self.work.calls[p.index];
        let on = goes_on(call, &p.result);
        self.states[p.index] = Some(state_of(call, &p.result));
        let rescued = !on
            && self
                .work
                .rescue
                .as_ref()
                .is_some_and(|r| (r.from..r.to).contains(&p.index));
        if (on && p.index + 1 == main) || (!on && !rescued) {
            self.ended = Some(now);
        }
        false
    }
}

/// The password for a run, typed in the bar.
pub struct Asking {
    pub work: Work,
    pub from: usize,
    pub prompt: PasswordPrompt,
    /// Asked again after a wrong password: the same run goes on.
    pub resume: bool,
}
