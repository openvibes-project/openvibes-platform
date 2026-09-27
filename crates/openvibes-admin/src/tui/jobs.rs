//! What the Setup tab runs step by step through the helper: install and
//! repair (§6.3–6.4), update (§6.5a), remove (§6.5).

use platform_host::{Privileged, RemoveStep, Step, UpdateStep};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Job {
    Install,
    Repair,
    Update,
    Remove,
}

impl Job {
    pub fn titles(self) -> Vec<&'static str> {
        match self {
            Job::Install | Job::Repair => Step::ALL.iter().map(|s| s.title()).collect(),
            Job::Update => UpdateStep::ALL.iter().map(|s| s.title()).collect(),
            Job::Remove => RemoveStep::ALL.iter().map(|s| s.title()).collect(),
        }
    }

    pub fn steps(self) -> usize {
        self.titles().len()
    }

    /// The helper verb for step `index`, with the job's arguments.
    pub fn verb(self, index: usize, args: &[String]) -> Privileged<'_> {
        match self {
            Job::Install => Privileged::SetupStep(Step::ALL[index]),
            Job::Repair => Privileged::Repair(Step::ALL[index]),
            Job::Update => Privileged::Update(UpdateStep::ALL[index], args),
            Job::Remove => Privileged::Remove(RemoveStep::ALL[index], args),
        }
    }
}
