//! What a run is (an update, a backup, the install…): its titles, its
//! result line and its password bar's words. Split from `run.rs` (size).

/// What a Maintenance › Operating system run does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OsAction {
    Check,
    /// Upgrades `packages` packages (the count of the last check); `kernel`
    /// says the last check found a new kernel among them.
    Update {
        packages: u32,
        kernel: bool,
    },
    Restart,
    PowerOff,
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
    Uninstall {
        everything: bool,
    },
    /// The Database page's reads.
    Report,
    /// A new one-time password for the console's admin.
    SignIn,
    /// Single sign-on turned off.
    SsoOff,
    /// Maintenance › Shell: the password, then the operator's shell.
    Shell,
    /// The first install, run from the Install screens.
    Install,
    /// Your own CA's request (`accept`: its two certificates), before install.
    Ca {
        accept: bool,
    },
    /// Optional parts added or removed; `what` is the title.
    Parts {
        what: String,
        /// The result line, without how long it took.
        done: String,
    },
    /// Ports moved; `what` is the title.
    Ports {
        what: String,
        /// The result line, without how long it took.
        done: String,
    },
    /// New certificates for changed names; `what` is the title.
    Names {
        what: String,
        /// The result line, without how long it took.
        done: String,
    },
    /// A new intermediate (Maintenance › Certificates › Replace).
    Replace {
        /// The result line, without how long it took.
        done: String,
    },
    /// The console's own certificate used (`set`), or the platform's again.
    ConsoleCert {
        set: bool,
        /// The result line, without how long it took.
        done: String,
    },
    /// Maintenance › Operating system.
    Os(OsAction),
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
            Kind::SignIn => "Resetting the admin password".into(),
            Kind::SsoOff => "Turning single sign-on off".into(),
            Kind::Shell => "Opening the shell".into(),
            Kind::Install => "Installing".into(),
            Kind::Ca { accept: false } => "Making the request".into(),
            Kind::Ca { accept: true } => "Adding the certificates".into(),
            Kind::Parts { what, .. } => what.clone(),
            Kind::Ports { what, .. } => what.clone(),
            Kind::Names { what, .. } => what.clone(),
            Kind::Replace { .. } => "Replacing the intermediate".into(),
            Kind::ConsoleCert { set: true, .. } => "Using your certificate".into(),
            Kind::ConsoleCert { set: false, .. } => {
                "Going back to the platform's certificate".into()
            }
            Kind::Os(OsAction::Check) => "Checking for updates".into(),
            Kind::Os(OsAction::Update { packages, .. }) => {
                format!("Updating {packages} packages")
            }
            Kind::Os(OsAction::Restart) => "Restarting".into(),
            Kind::Os(OsAction::PowerOff) => "Shutting down".into(),
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
            Kind::SignIn => "Admin password reset".into(),
            Kind::SsoOff => "Single sign-on is off".into(),
            Kind::Shell => "Shell opened".into(),
            Kind::Install => "OpenVIBES is installed".into(),
            Kind::Ca { accept: false } => "Request made".into(),
            Kind::Ca { accept: true } => "Certificates added".into(),
            Kind::Parts { done, .. } => done.clone(),
            Kind::Ports { done, .. } => done.clone(),
            Kind::Names { done, .. } => done.clone(),
            Kind::Replace { done } | Kind::ConsoleCert { done, .. } => done.clone(),
            Kind::Os(OsAction::Check) => "Checked".into(),
            Kind::Os(OsAction::Update { packages, .. }) => format!("{packages} packages updated"),
            Kind::Os(OsAction::Restart) => "Restart started".into(),
            Kind::Os(OsAction::PowerOff) => "Shutting down".into(),
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
            Kind::SignIn => "The reset failed".into(),
            Kind::SsoOff => "Single sign-on is still as it was".into(),
            Kind::Shell => "The shell did not open".into(),
            Kind::Install => "The install stopped".into(),
            Kind::Ca { accept: false } => "The request failed".into(),
            Kind::Ca { accept: true } => "The certificates were refused".into(),
            Kind::Parts { .. } => "The change stopped".into(),
            Kind::Ports { .. } => "The move stopped".into(),
            Kind::Names { .. } => "The change stopped".into(),
            Kind::Replace { .. } => "The replacement stopped".into(),
            Kind::ConsoleCert { .. } => "The console's certificate did not change".into(),
            Kind::Os(OsAction::Check) => "The check failed".into(),
            Kind::Os(OsAction::Update { .. }) => "The update stopped".into(),
            Kind::Os(OsAction::Restart) => "The restart failed".into(),
            Kind::Os(OsAction::PowerOff) => "The shutdown failed".into(),
        }
    }
    /// The password bar's label (the bar adds the colon): the shell asks
    /// for the same sudo password, as the operator knows it (shellflow.py).
    pub fn password_label(&self) -> &'static str {
        match self {
            Kind::Shell => "Your login password",
            _ => "Your password (sudo)",
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
            Kind::SignIn => "Reset",
            Kind::SsoOff => "Turn off",
            Kind::Shell => "Open",
            Kind::Install => "Install",
            Kind::Ca { accept: false } => "Continue",
            Kind::Ca { accept: true } => "Add",
            Kind::Parts { .. } | Kind::Ports { .. } | Kind::Names { .. } => "Apply",
            Kind::Replace { .. } => "Replace",
            Kind::ConsoleCert { set: true, .. } => "Use it",
            Kind::ConsoleCert { set: false, .. } => "Go back",
            Kind::Os(OsAction::Check) => "Check",
            Kind::Os(OsAction::Update { .. }) => "Update",
            Kind::Os(OsAction::Restart) => "Restart",
            Kind::Os(OsAction::PowerOff) => "Shut down",
        }
    }
}
