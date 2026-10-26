//! Work that takes long (spec §2): helper calls run one after the other on
//! another thread, so the screen keeps drawing; the password is typed in
//! the bar, moved to that thread and dropped when its work ends. A run
//! stops at the first call that does not finish; a rescue (Update: start
//! the services again) may follow. Without a worker (tests) the calls run
//! at once on the TUI's own host.

use std::{ops::Range, sync::mpsc::Receiver, time::Instant};

use platform_host::{
    Database, Host, HostError, Privileged, RemoveStep, Secret, Step, StepState, Unit, UpdateStep,
};

pub use super::kind::Kind;
use super::password::PasswordPrompt;

/// One helper call, or one read for a report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Call {
    /// `setup-status`: every step's state.
    Status,
    Repair(Step),
    /// `setup-step STEP` (no `--repair`): the install's own step, which may make the CA.
    Setup(Step),
    Update(UpdateStep, Vec<String>),
    Remove(RemoveStep, Vec<String>),
    /// `setup-plan` with these arguments (the whole plan: see `Plan::args`).
    SetupPlan(Vec<String>),
    /// A database command (no password).
    Database(Database),
    /// The database's disk: `size<TAB>percent<TAB>free`, empty when unknown.
    Disk,
    /// The unit's last journal lines, joined (no password).
    Logs(Unit, u16),
    /// `admin-reset`: a new one-time password for the console's `admin`.
    AdminReset,
    /// `shell-open`: sudo checks the password and the call is journalled;
    /// the shell itself opens once the run is done.
    ShellOpen,
    /// `ca-request [--copy PATH]`: the request for "Your own CA", made or reused.
    CaRequest(Option<String>),
    /// `ca-accept`: the signed certificate and your CA's, checked and kept.
    CaAccept(String, String),
    /// `ca-replace [--root-key PATH]`: a new intermediate beside the old one.
    CaReplace(Option<String>),
    /// `ca-import`: a company intermediate, its chain and key, on stdin.
    CaImport(Bundle),
    /// `console-cert-set`: the console's own certificate and key, on stdin.
    ConsoleCertSet(Bundle),
    /// `console-cert-reset`: back to the platform's certificate.
    ConsoleCertReset,
}

/// `ca-import`'s or `console-cert-set`'s certificates and key; Debug never shows them.
#[derive(Clone, Eq, PartialEq)]
pub struct Bundle(pub zeroize::Zeroizing<String>);

impl std::fmt::Debug for Bundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("..")
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
    /// The step list's rows: a title and the calls (indices) it covers.
    pub labels: Vec<(String, Range<usize>)>,
    pub rescue: Option<Rescue>,
}

impl Work {
    /// Wipes the key any `ca-import` or `console-cert-set` call carries: the run is over.
    pub fn wipe(&mut self) {
        for call in &mut self.calls {
            if let Call::CaImport(bundle) | Call::ConsoleCertSet(bundle) = call {
                zeroize::Zeroize::zeroize(&mut *bundle.0);
            }
        }
    }

    /// Every call is its own row (the caller titles them).
    pub fn new(kind: Kind, calls: Vec<Call>) -> Work {
        let labels = (0..calls.len())
            .map(|i| (String::new(), i..i + 1))
            .collect();
        Work {
            kind,
            calls,
            labels,
            rescue: None,
        }
    }

    /// Several calls under one row each.
    pub fn grouped(kind: Kind, groups: Vec<(String, Vec<Call>)>) -> Work {
        let mut calls = Vec::new();
        let mut labels = Vec::new();
        for (title, group) in groups {
            labels.push((title, calls.len()..calls.len() + group.len()));
            calls.extend(group);
        }
        Work {
            kind,
            calls,
            labels,
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
        Call::Setup(step) => host.privileged(Privileged::SetupStep(*step), secret),
        Call::Update(step, args) => host.privileged(Privileged::Update(*step, args), secret),
        Call::Remove(step, args) => host.privileged(Privileged::Remove(*step, args), secret),
        Call::SetupPlan(args) => host.privileged(Privileged::SetupPlan(args), secret),
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
        Call::AdminReset => host.privileged(Privileged::AdminReset, secret),
        Call::ShellOpen => host.privileged(Privileged::ShellOpen, secret),
        Call::CaRequest(copy) => host.privileged(Privileged::CaRequest(copy.as_deref()), secret),
        Call::CaAccept(cert, root) => host.privileged(Privileged::CaAccept(cert, root), secret),
        Call::CaReplace(key) => host.privileged(Privileged::CaReplace(key.as_deref()), secret),
        Call::CaImport(bundle) => {
            let bundle = Secret::new(String::clone(&bundle.0));
            host.privileged(Privileged::CaImport(&bundle), secret)
        }
        Call::ConsoleCertSet(bundle) => {
            let bundle = Secret::new(String::clone(&bundle.0));
            host.privileged(Privileged::ConsoleCertSet(&bundle), secret)
        }
        Call::ConsoleCertReset => host.privileged(Privileged::ConsoleCertReset, secret),
    }
}

/// What a call's result reads as: a step's `STATE<TAB>DETAIL`, or its output.
pub fn state_of(call: &Call, result: &Result<String, HostError>) -> StepState {
    match (call, result) {
        (_, Err(error)) => StepState::Failed(error.to_string()),
        (
            Call::Repair(_)
            | Call::Setup(_)
            | Call::Update(..)
            | Call::Remove(..)
            | Call::AdminReset
            | Call::ShellOpen,
            Ok(out),
        ) => StepState::parse(out.trim_end()).unwrap_or_else(|| {
            StepState::Failed(format!("unexpected helper output: {}", out.trim()))
        }),
        (_, Ok(out)) => StepState::Done(out.clone()),
    }
}

/// The optional assistant model's call: its download failing never stops a run.
pub fn is_model(call: &Call) -> bool {
    matches!(
        call,
        Call::Repair(Step::AssistantModel) | Call::Setup(Step::AssistantModel)
    )
}

/// Whether the run goes on. The assistant's model is optional: its
/// download failing does not stop a repair or an install.
pub fn goes_on(call: &Call, result: &Result<String, HostError>) -> bool {
    state_of(call, result).finished() || (is_model(call) && result.is_ok())
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
            self.states[i].as_ref().is_some_and(|s| !s.finished()) && !is_model(&self.work.calls[i])
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
                    || (self.states[i].is_some() && is_model(&self.work.calls[i]))
            })
    }

    /// The `j`th rescue call's state.
    pub fn rescued(&self, j: usize) -> Option<&StepState> {
        self.states.get(self.work.calls.len() + j)?.as_ref()
    }

    /// How long it took, to end a result line: " (2 min 41 s)", " (12 s)";
    /// nothing under a second.
    pub fn took(&self) -> String {
        took(
            self.ended
                .unwrap_or_else(Instant::now)
                .saturating_duration_since(self.started),
        )
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

/// Each label's state: the first call that did not finish; when all
/// finished, Done if one call did the work (Skipped only when every call
/// was); `None` before it is reached. The optional
/// model's call is left out of a label that holds other calls: it never
/// stops a run, so it must not turn them red.
pub fn label_states(run: &Run) -> Vec<Option<StepState>> {
    run.work
        .labels
        .iter()
        .map(|(_, calls)| {
            let mut own: Vec<&Option<StepState>> = calls
                .clone()
                .filter(|i| !is_model(&run.work.calls[*i]))
                .map(|i| &run.states[i])
                .collect();
            if own.is_empty() {
                own = run.states[calls.clone()].iter().collect();
            }
            own.iter()
                .copied()
                .flatten()
                .find(|s| !s.finished())
                .or_else(|| {
                    // Finished: one call that did the work makes the row done.
                    own.iter().all(|s| s.is_some()).then(|| {
                        let mut all = own.iter().copied().flatten();
                        let first = all.clone().next();
                        all.find(|s| matches!(s, StepState::Done(_))).or(first)
                    })?
                })
                .cloned()
        })
        .collect()
}

/// The password for a run, typed in the bar.
pub struct Asking {
    pub work: Work,
    pub from: usize,
    pub prompt: PasswordPrompt,
    /// Asked again after a wrong password: the same run goes on.
    pub resume: bool,
}

/// `took` for any wait: " (2 min 41 s)", " (12 s)"; nothing under a second.
pub(super) fn took(waited: std::time::Duration) -> String {
    match waited.as_secs() {
        0 => String::new(),
        s @ 1..60 => format!(" ({s} s)"),
        s => format!(" ({} min {} s)", s / 60, s % 60),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_bundle_is_never_printed() {
        let bundle = super::Bundle(zeroize::Zeroizing::new(
            "-----BEGIN PRIVATE KEY-----".into(),
        ));
        assert_eq!(
            format!("{:?}", super::Call::CaImport(bundle.clone())),
            "CaImport(..)"
        );
        assert_eq!(
            format!("{:?}", super::Call::ConsoleCertSet(bundle)),
            "ConsoleCertSet(..)"
        );
        assert_eq!(
            format!("{:?}", super::Call::ConsoleCertReset),
            "ConsoleCertReset"
        );
    }
}
