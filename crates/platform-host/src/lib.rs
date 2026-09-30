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
pub use setup::{Privileged, RemoveStep, SETUP_FILE, Secret, Step, StepState, UpdateStep};
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

/// An installed OpenVIBES package and the newer version the repository has.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageUpdate {
    pub name: String,
    /// `VERSION-RELEASE`.
    pub installed: String,
    /// A newer `VERSION-RELEASE`, when there is one.
    pub available: Option<String>,
}

/// A database command the Database and Health screens run: the admin CLI
/// as `openvibes-admin`, through the operators' sudoers entry (spec §3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Database {
    /// `status`: schema, partitions, size.
    Status,
    /// `migrate`.
    Migrate,
    /// `maintenance`, as the daily timer runs it.
    Maintenance,
    /// `feeds status`.
    FeedsStatus,
    /// `rules list`.
    RulesList,
}

impl Database {
    /// The CLI arguments.
    #[must_use]
    pub fn args(self) -> &'static [&'static str] {
        match self {
            Database::Status => &["status"],
            Database::Migrate => &["migrate"],
            Database::Maintenance => &["maintenance"],
            Database::FeedsStatus => &["feeds", "status"],
            Database::RulesList => &["rules", "list"],
        }
    }
}

/// The public certificates Health checks (spec §5): the ingest and
/// distribution server certificates and the intermediate, all 0644.
pub const CERTIFICATES: [&str; 3] = [
    "/etc/openvibes/tls/ingest.crt",
    "/etc/openvibes/tls/distribution.crt",
    "/etc/openvibes/pki/intermediate.crt",
];

/// Disk use of the file system holding one data directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiskUse {
    /// The directory, e.g. `/var/lib/pgsql`.
    pub path: String,
    /// Percent of the file system used.
    pub used_percent: u8,
    /// Space left, as `df -h` writes it.
    pub available: String,
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
    /// Installed OpenVIBES packages with any newer version (no password).
    fn packages(&self) -> Result<Vec<PackageUpdate>, HostError>;
    /// `/etc/openvibes/setup.toml` as text (world-readable, no secrets).
    fn setup_plan(&self) -> Result<String, HostError>;
    /// Runs a database command; its standard output. Hosts without a local
    /// database do not support it (spec §10).
    fn database(&self, command: Database) -> Result<String, HostError> {
        let _ = command;
        Err(HostError::Failed("not supported on this host".into()))
    }
    /// Each of [`CERTIFICATES`] that exists, as PEM text.
    fn certificates(&self) -> Vec<(&'static str, Result<String, HostError>)> {
        Vec::new()
    }
    /// This host's own global IPv4 addresses ([`host_addresses`]).
    fn addresses(&self) -> Vec<String> {
        Vec::new()
    }
    /// Disk use of `/var/lib/pgsql` and each `/var/lib/openvibes-*`.
    fn disk(&self) -> Result<Vec<DiskUse>, HostError> {
        Ok(Vec::new())
    }
    /// `ss -ltnpH` lines for TCP `port` on any address; empty when nobody
    /// listens there (Setup's port check).
    fn listeners(&self, port: u16) -> Result<String, HostError> {
        let _ = port;
        Ok(String::new())
    }
}

/// `ip` arguments listing the host's global IPv4 addresses.
pub const IP_ADDRESSES: [&str; 6] = ["-o", "-4", "addr", "show", "scope", "global"];

/// Interfaces whose addresses never name this host to a browser: container
/// and VM bridges.
/// VPN interfaces (wg, tun, tailscale) stay: reaching the console over a
/// VPN is why the addresses are named at all.
const BRIDGES: [&str; 12] = [
    "docker", "podman", "br-", "veth", "virbr", "cni", "lxcbr", "lxdbr", "incusbr", "cali",
    "flannel", "vxlan",
];

/// The addresses in `ip -o -4 addr show scope global` output, bridges left
/// out (board #71: the console opens by IP, so its certificate names them).
#[must_use]
pub fn host_addresses(listing: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    for line in listing.lines() {
        // `2: enp5s0    inet 192.168.1.10/24 brd ...`
        let mut fields = line.split_whitespace().skip(1);
        let (Some(interface), Some("inet"), Some(address)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let address = address.split('/').next().unwrap_or_default();
        if !BRIDGES.iter().any(|bridge| interface.starts_with(bridge))
            && address.parse::<std::net::Ipv4Addr>().is_ok()
            && !addresses.iter().any(|known| known == address)
        {
            addresses.push(address.to_owned());
        }
    }
    addresses
}
