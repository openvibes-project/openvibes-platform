//! Setup's steps and their states (admin TUI spec §6.3), the password a
//! Setup run holds, and the password-gated helper verbs (§3).

use zeroize::Zeroizing;

use crate::Unit;

/// The plan Setup works from (§6.2).
pub const SETUP_FILE: &str = "/etc/openvibes/setup.toml";

/// One Setup step, in the order Setup runs them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Step {
    Packages,
    Postgres,
    Operators,
    Database,
    Schema,
    Ca,
    Certificates,
    Console,
    Services,
    Firewall,
    Rules,
    Agent,
    AssistantModel,
    Ready,
}

impl Step {
    /// Every step, in order.
    pub const ALL: [Step; 14] = [
        Step::Packages,
        Step::Postgres,
        Step::Operators,
        Step::Database,
        Step::Schema,
        Step::Ca,
        Step::Certificates,
        Step::Console,
        Step::Services,
        Step::Firewall,
        Step::Rules,
        Step::Agent,
        Step::AssistantModel,
        Step::Ready,
    ];

    /// The name the helper takes.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Step::Packages => "packages",
            Step::Postgres => "postgres",
            Step::Operators => "operators",
            Step::Database => "database",
            Step::Schema => "schema",
            Step::Ca => "ca",
            Step::Certificates => "certificates",
            Step::Console => "console",
            Step::Services => "services",
            Step::Firewall => "firewall",
            Step::Rules => "rules",
            Step::Agent => "agent",
            Step::AssistantModel => "assistant-model",
            Step::Ready => "ready",
        }
    }

    /// The title screens show.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Step::Packages => "Install packages",
            Step::Postgres => "PostgreSQL",
            Step::Operators => "Operator group",
            Step::Database => "Database and role",
            Step::Schema => "Schema",
            Step::Ca => "Certificate authority",
            Step::Certificates => "Server certificates",
            Step::Console => "Console and admin account",
            Step::Services => "Start services",
            Step::Firewall => "Firewall",
            Step::Rules => "Baseline rules",
            Step::Agent => "Agent on this host",
            Step::AssistantModel => "Assistant model",
            Step::Ready => "Readiness",
        }
    }

    /// The step with exactly this name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Step> {
        Step::ALL.into_iter().find(|step| step.name() == name)
    }
}

/// One step of Update (§6.5a), in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum UpdateStep {
    Backup,
    Stop,
    Upgrade,
    Migrate,
    Start,
    Ready,
}

impl UpdateStep {
    pub const ALL: [UpdateStep; 6] = [
        UpdateStep::Backup,
        UpdateStep::Stop,
        UpdateStep::Upgrade,
        UpdateStep::Migrate,
        UpdateStep::Start,
        UpdateStep::Ready,
    ];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            UpdateStep::Backup => "backup",
            UpdateStep::Stop => "stop",
            UpdateStep::Upgrade => "upgrade",
            UpdateStep::Migrate => "migrate",
            UpdateStep::Start => "start",
            UpdateStep::Ready => "ready",
        }
    }

    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            UpdateStep::Backup => "Database backup",
            UpdateStep::Stop => "Stop services",
            UpdateStep::Upgrade => "Upgrade packages",
            UpdateStep::Migrate => "Migrate the database",
            UpdateStep::Start => "Start services",
            UpdateStep::Ready => "Readiness",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<UpdateStep> {
        UpdateStep::ALL.into_iter().find(|step| step.name() == name)
    }
}

/// One step of removing components or uninstalling (§6.5), in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RemoveStep {
    Backup,
    Stop,
    Firewall,
    Packages,
    Purge,
}

impl RemoveStep {
    pub const ALL: [RemoveStep; 5] = [
        RemoveStep::Backup,
        RemoveStep::Stop,
        RemoveStep::Firewall,
        RemoveStep::Packages,
        RemoveStep::Purge,
    ];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            RemoveStep::Backup => "backup",
            RemoveStep::Stop => "stop",
            RemoveStep::Firewall => "firewall",
            RemoveStep::Packages => "packages",
            RemoveStep::Purge => "purge",
        }
    }

    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            RemoveStep::Backup => "Database backup",
            RemoveStep::Stop => "Stop and disable services",
            RemoveStep::Firewall => "Close firewall ports",
            RemoveStep::Packages => "Remove packages",
            RemoveStep::Purge => "Remove all data",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<RemoveStep> {
        RemoveStep::ALL.into_iter().find(|step| step.name() == name)
    }
}

/// What a step's check found, or what running it achieved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepState {
    /// Done; what is in place.
    Done(String),
    /// Not done yet.
    Todo,
    /// Needs something from the user first (careful CA: the signed
    /// certificate); what to do.
    Waiting(String),
    /// Does not apply to this plan or host; why.
    Skipped(String),
    /// Could not be checked or done; the error.
    Failed(String),
}

fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_owned()
}

impl StepState {
    /// The helper's output: `STATE<TAB>DETAIL`, on one line.
    #[must_use]
    pub fn line(&self) -> String {
        format!("{}\t{}", self.label_word(), one_line(self.detail()))
    }

    /// The state the helper printed.
    #[must_use]
    pub fn parse(line: &str) -> Option<StepState> {
        let (state, detail) = line.split_once('\t').unwrap_or((line, ""));
        let detail = detail.to_owned();
        Some(match state {
            "done" => StepState::Done(detail),
            "todo" => StepState::Todo,
            "waiting" => StepState::Waiting(detail),
            "skipped" => StepState::Skipped(detail),
            "failed" => StepState::Failed(detail),
            _ => return None,
        })
    }

    /// Whether the run may go on to the next step.
    #[must_use]
    pub fn finished(&self) -> bool {
        matches!(self, StepState::Done(_) | StepState::Skipped(_))
    }

    fn label_word(&self) -> &'static str {
        match self {
            StepState::Done(_) => "done",
            StepState::Todo => "todo",
            StepState::Waiting(_) => "waiting",
            StepState::Skipped(_) => "skipped",
            StepState::Failed(_) => "failed",
        }
    }

    /// A word for screens.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            StepState::Todo => "to do",
            other => other.label_word(),
        }
    }

    /// The detail, empty for `Todo`.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            StepState::Done(text)
            | StepState::Waiting(text)
            | StepState::Skipped(text)
            | StepState::Failed(text) => text,
            StepState::Todo => "",
        }
    }
}

/// The user's password during one Setup run; zeroed when dropped (§3).
pub struct Secret(Zeroizing<String>);

impl Secret {
    #[must_use]
    pub fn new(text: String) -> Secret {
        Secret(Zeroizing::new(text))
    }

    /// The password, for sudo's stdin only.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// A helper verb that needs the user's password (§3).
#[derive(Clone, Copy, Debug)]
pub enum Privileged<'a> {
    /// `setup-plan ARGS…`: checks the arguments and writes `setup.toml`.
    SetupPlan(&'a [String]),
    /// `setup-status`: every step's state.
    SetupStatus,
    /// `setup-step STEP`: checks the step and runs it unless done.
    SetupStep(Step),
    /// `setup-step STEP --repair`: as `SetupStep`, but never makes a new CA.
    Repair(Step),
    /// `update-step STEP [--backup PATH]`.
    Update(UpdateStep, &'a [String]),
    /// `remove-step STEP --components LIST [--backup PATH] [--confirm HOSTNAME]`.
    Remove(RemoveStep, &'a [String]),
    /// `unit-enable UNIT`: start at boot.
    UnitEnable(Unit),
    /// `unit-disable UNIT`: do not start at boot.
    UnitDisable(Unit),
}

impl Privileged<'_> {
    /// The helper's arguments after `helper`.
    #[must_use]
    pub fn args(&self) -> Vec<String> {
        match self {
            Privileged::SetupPlan(args) => {
                let mut all = vec!["setup-plan".to_owned()];
                all.extend(args.iter().cloned());
                all
            }
            Privileged::SetupStatus => vec!["setup-status".into()],
            Privileged::SetupStep(step) => vec!["setup-step".into(), step.name().into()],
            Privileged::Repair(step) => {
                vec!["setup-step".into(), step.name().into(), "--repair".into()]
            }
            Privileged::Update(step, args) => {
                let mut all = vec!["update-step".to_owned(), step.name().to_owned()];
                all.extend(args.iter().cloned());
                all
            }
            Privileged::Remove(step, args) => {
                let mut all = vec!["remove-step".to_owned(), step.name().to_owned()];
                all.extend(args.iter().cloned());
                all
            }
            Privileged::UnitEnable(unit) => vec!["unit-enable".into(), unit.name().into()],
            Privileged::UnitDisable(unit) => vec!["unit-disable".into(), unit.name().into()],
        }
    }

    /// What the journal records (no arguments of `setup-plan`, `update-step`, `remove-step`).
    #[must_use]
    pub fn journal(&self) -> String {
        match self {
            Privileged::SetupPlan(_) => "setup-plan".into(),
            Privileged::Update(step, _) => format!("update-step {}", step.name()),
            Privileged::Remove(step, _) => format!("remove-step {}", step.name()),
            other => other.args().join(" "),
        }
    }
}
