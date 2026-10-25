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
    Ready,
    /// Last: a failed download must not hide the end of the install.
    AssistantModel,
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
        Step::Ready,
        Step::AssistantModel,
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
    /// Last: the administration tool itself and its repository.
    Admin,
}

impl RemoveStep {
    pub const ALL: [RemoveStep; 6] = [
        RemoveStep::Backup,
        RemoveStep::Stop,
        RemoveStep::Firewall,
        RemoveStep::Packages,
        RemoveStep::Purge,
        RemoveStep::Admin,
    ];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            RemoveStep::Backup => "backup",
            RemoveStep::Stop => "stop",
            RemoveStep::Firewall => "firewall",
            RemoveStep::Packages => "packages",
            RemoveStep::Purge => "purge",
            RemoveStep::Admin => "admin",
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
            RemoveStep::Admin => "Remove the administration tool",
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
    /// `admin-reset`: a new one-time password for the console's `admin`,
    /// printed as `done<TAB>PASSWORD` and never journalled.
    AdminReset,
    /// `shell-open`: does nothing itself; sudo checks the password and the
    /// call is journalled before Maintenance › Shell opens a shell.
    ShellOpen,
    /// `ca-request [--copy PATH]`: makes or reuses the CA request before
    /// install; prints `request` or `signed<TAB>ISSUER`, then the request.
    CaRequest(Option<&'a str>),
    /// `ca-accept --cert PEM --root-cert PEM`: checks and keeps the CA's
    /// answer; journalled as `ca-accept /etc/openvibes/pki/request` (no PEM).
    CaAccept(&'a str, &'a str),
    /// `ca-replace [--root-key PATH]`: a new intermediate, the old one
    /// trusted beside it; journalled as `ca-replace
    /// /etc/openvibes/pki/intermediate.crt` (no key path).
    CaReplace(Option<&'a str>),
    /// `ca-import`: a company intermediate, its chain and key, on stdin
    /// (never argv); journalled as `ca-import /etc/openvibes/pki/request`.
    CaImport(&'a Secret),
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
            Privileged::AdminReset => vec!["admin-reset".into()],
            Privileged::ShellOpen => vec!["shell-open".into()],
            Privileged::CaRequest(copy) => {
                let mut all = vec!["ca-request".to_owned()];
                if let Some(path) = copy {
                    all.extend(["--copy".to_owned(), (*path).to_owned()]);
                }
                all
            }
            Privileged::CaAccept(cert, root) => vec![
                "ca-accept".into(),
                "--cert".into(),
                (*cert).into(),
                "--root-cert".into(),
                (*root).into(),
            ],
            Privileged::CaReplace(root_key) => {
                let mut all = vec!["ca-replace".to_owned()];
                if let Some(path) = root_key {
                    all.extend(["--root-key".to_owned(), (*path).to_owned()]);
                }
                all
            }
            Privileged::CaImport(_) => vec!["ca-import".into()],
        }
    }

    /// The helper's stdin: sudo's password line (none as root), then the
    /// verb's own input; `None` when there is nothing to send.
    #[must_use]
    pub fn stdin(&self, password: Option<&Secret>) -> Option<Zeroizing<Vec<u8>>> {
        let input = match self {
            Privileged::CaImport(bundle) => bundle.expose(),
            _ => "",
        };
        if password.is_none() && input.is_empty() {
            return None;
        }
        let mut bytes = Zeroizing::new(Vec::new());
        if let Some(password) = password {
            bytes.extend_from_slice(password.expose().as_bytes());
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(input.as_bytes());
        Some(bytes)
    }

    /// What the journal records (no arguments of `setup-plan`, `update-step`,
    /// `remove-step`, `ca-request`, `ca-accept`, `ca-replace`, `ca-import`).
    #[must_use]
    pub fn journal(&self) -> String {
        match self {
            Privileged::SetupPlan(_) => "setup-plan".into(),
            Privileged::Update(step, _) => format!("update-step {}", step.name()),
            Privileged::Remove(step, _) => format!("remove-step {}", step.name()),
            // Two words: no step detail, so the password stays out (journal.rs).
            Privileged::AdminReset => "admin-reset admin".into(),
            Privileged::ShellOpen => format!("shell-open {}", crate::shell::operator()),
            // Two words: the request folder is the audit target, never
            // the copy path or the PEM.
            Privileged::CaRequest(_) => "ca-request /etc/openvibes/pki/request".into(),
            Privileged::CaAccept(..) => "ca-accept /etc/openvibes/pki/request".into(),
            Privileged::CaReplace(_) => "ca-replace /etc/openvibes/pki/intermediate.crt".into(),
            Privileged::CaImport(_) => "ca-import /etc/openvibes/pki/request".into(),
            other => other.args().join(" "),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Privileged, Secret};

    #[test]
    fn ca_import_keeps_the_pem_out_of_argv_and_journal() {
        let bundle = Secret::new("-----BEGIN PRIVATE KEY-----\nK\n".into());
        let import = Privileged::CaImport(&bundle);
        assert_eq!(import.args(), ["ca-import"]);
        assert_eq!(import.journal(), "ca-import /etc/openvibes/pki/request");
        assert!(!format!("{import:?}").contains("BEGIN"));
        let password = Secret::new("pw".into());
        let sudo = import.stdin(Some(&password)).unwrap();
        assert_eq!(*sudo, b"pw\n-----BEGIN PRIVATE KEY-----\nK\n");
        assert_eq!(*import.stdin(None).unwrap(), bundle.expose().as_bytes());
        assert_eq!(
            *Privileged::SetupStatus.stdin(Some(&password)).unwrap(),
            b"pw\n"
        );
        assert!(Privileged::SetupStatus.stdin(None).is_none());
    }

    #[test]
    fn ca_verbs_keep_the_pem_out_of_the_journal() {
        assert_eq!(Privileged::CaRequest(None).args(), ["ca-request"]);
        assert_eq!(
            Privileged::CaRequest(Some("/home/alice/openvibes-request.csr")).args(),
            ["ca-request", "--copy", "/home/alice/openvibes-request.csr"]
        );
        assert_eq!(
            Privileged::CaRequest(Some("/x")).journal(),
            "ca-request /etc/openvibes/pki/request"
        );
        let accept = Privileged::CaAccept("CERT PEM", "ROOT PEM");
        assert_eq!(
            accept.args(),
            ["ca-accept", "--cert", "CERT PEM", "--root-cert", "ROOT PEM"]
        );
        assert_eq!(accept.journal(), "ca-accept /etc/openvibes/pki/request");
    }

    #[test]
    fn ca_replace_keeps_the_key_path_out_of_the_journal() {
        assert_eq!(Privileged::CaReplace(None).args(), ["ca-replace"]);
        let quick = Privileged::CaReplace(Some("/media/usb/openvibes-root.key"));
        assert_eq!(
            quick.args(),
            ["ca-replace", "--root-key", "/media/usb/openvibes-root.key"]
        );
        assert_eq!(
            quick.journal(),
            "ca-replace /etc/openvibes/pki/intermediate.crt"
        );
    }
}
