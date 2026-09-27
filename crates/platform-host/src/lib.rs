//! Host operations for the administration TUI (admin TUI spec §4): what the
//! screens may do to this host, behind [`Host`]. [`native::Native`] runs
//! them on systemd; later deployments (pods, Kubernetes) implement the same
//! trait. No terminal code lives here.

pub mod native;
pub mod runner;
pub mod service;
pub mod setup;
pub mod unit;

pub use service::{CONFIG_DIR, Service};
pub use setup::{Privileged, SETUP_FILE, Secret, Step, StepState};
pub use unit::Unit;

/// A lifecycle action an operator may take without a password.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceAction {
    /// `systemctl start`.
    Start,
    /// `systemctl stop`.
    Stop,
    /// `systemctl restart`.
    Restart,
}

impl ServiceAction {
    /// The systemctl verb.
    #[must_use]
    pub fn verb(self) -> &'static str {
        match self {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
        }
    }
}

/// One unit as the Services screen shows it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceStatus {
    /// Which unit.
    pub unit: Unit,
    /// Whether its package is installed.
    pub installed: bool,
    /// Whether it starts at boot.
    pub enabled: bool,
    /// systemd's active state: `active`, `inactive`, `failed`, …
    pub active: String,
    /// Readiness; `None` when not active or the unit has no endpoint.
    pub ready: Option<bool>,
    /// When it became active.
    pub since: Option<String>,
}

/// Why a host operation failed.
#[derive(Debug, Eq, PartialEq)]
pub enum HostError {
    /// The user is not in `openvibes-operators` (polkit or sudo refused).
    NotOperator,
    /// sudo refused the password.
    WrongPassword,
    /// The user may not use sudo at all.
    NotSudoer,
    /// The command failed; its error text, control characters escaped.
    Failed(String),
    /// The command could not be run.
    Io(String),
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostError::NotOperator => f.write_str(
                "this needs membership of the openvibes-operators group (ask an administrator: \
                 usermod -aG openvibes-operators $USER, then log in again)",
            ),
            HostError::WrongPassword => f.write_str("wrong password"),
            HostError::NotSudoer => f.write_str(
                "this needs sudo rights (on Fedora: membership of wheel); ask an administrator",
            ),
            HostError::Failed(text) => write!(f, "failed: {text}"),
            HostError::Io(text) => write!(f, "could not run: {text}"),
        }
    }
}

/// What the screens may do to the host.
pub trait Host {
    /// Every allow-listed unit and its state.
    fn services(&self) -> Result<Vec<ServiceStatus>, HostError>;
    /// Starts, stops or restarts a unit.
    fn service_action(&self, unit: Unit, action: ServiceAction) -> Result<(), HostError>;
    /// The unit's last `lines` journal lines.
    fn logs(&self, unit: Unit, lines: u16) -> Result<Vec<String>, HostError>;
    /// The service's configuration file, as text.
    fn read_config(&self, service: Service) -> Result<String, HostError>;
    /// Replaces the service's configuration file with `toml` (checked again
    /// by the helper; the old file is kept as `NAME.toml.bak`).
    fn write_config(&self, service: Service, toml: &str) -> Result<(), HostError>;
    /// Whether Setup has run on this host (`/etc/openvibes/setup.toml`).
    fn is_set_up(&self) -> bool;
    /// Runs a password-gated helper verb through sudo; its standard output.
    fn privileged(&self, verb: Privileged<'_>, password: &Secret) -> Result<String, HostError>;
}
