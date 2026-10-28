//! Host operations for the administration TUI (admin TUI spec §4): what the
//! screens may do to this host, behind [`Host`]. [`native::Native`] runs
//! them on systemd; later deployments (pods, Kubernetes) implement the same
//! trait. No terminal code lives here.

mod journal;
pub mod native;
pub mod os_updates;
pub mod runner;
pub mod service;
pub mod setup;
pub mod shell;
mod stderr;
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
    /// A timer's last run failed (the certificate timer's service); the
    /// timer itself goes on.
    pub last_run_failed: bool,
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

/// A database read the Database page and Status run: the admin CLI
/// as `openvibes-admin`, through the operators' sudoers entry (spec §3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Database {
    /// `status`: schema, partitions, size.
    Status,
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
            Database::FeedsStatus => &["feeds", "status"],
            Database::RulesList => &["rules", "list"],
        }
    }
}

/// The public certificates Health checks (spec §5): the ingest and
/// distribution server certificates, the console's chain (leaf first) and
/// the intermediate, all 0644.
pub const CERTIFICATES: [&str; 4] = [
    "/etc/openvibes/tls/ingest.crt",
    "/etc/openvibes/tls/distribution.crt",
    "/etc/openvibes/tls/console-chain.pem",
    "/etc/openvibes/pki/intermediate.crt",
];

/// The admin's own certificate for the console (4c), 0644; its presence
/// is what makes the console's certificate "own".
pub const OWN_CONSOLE_CERT: &str = "/etc/openvibes/tls/console-own.crt";

/// The root agents trust, and the CAs between it and our intermediate
/// (an imported or company-signed one under a sub-CA); both 0644.
pub const ROOT_CERT: &str = "/etc/openvibes/pki/root.crt";
pub const CHAIN: &str = "/etc/openvibes/pki/chain.crt";
/// What a Replace cut short by a crash leaves beside the files in use: the
/// bundle, the key and the chain, as `.new` (the admin's `interrupted`).
pub const REPLACE_STAGED: [&str; 3] = [
    "/etc/openvibes/pki/intermediate.crt.new",
    "/var/lib/openvibes-ingest/intermediate.key.new",
    "/etc/openvibes/pki/chain.crt.new",
];

/// The rule signer's `status.json` (operators may read it).
pub const SIGNER_STATUS: &str = "/var/lib/openvibes-signer/status.json";
/// The site key's trust lines Setup saved (public).
pub const SITE_TRUST: &str = "/etc/openvibes/site-rules.trust";

/// What Health shows about the rule signer (board #107).
#[derive(Debug)]
pub struct SignerFiles {
    /// [`SIGNER_STATUS`] as text, or why it can't be read.
    pub status: Result<String, HostError>,
    /// [`SITE_TRUST`] as text, when saved.
    pub trust: Option<String>,
}

/// Disk use of the file system holding one data directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiskUse {
    /// The directory, e.g. `/var/lib/pgsql`.
    pub path: String,
    /// The file system's size, as `df -h` writes it.
    pub size: String,
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
                "this needs sudo rights (on Fedora: membership of wheel; just added? log out and in \
                 again); ask an administrator",
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
    /// Whether [`Host::privileged`] needs the user's password. Root runs
    /// sudo without one, so the screens skip the prompt.
    fn needs_password(&self) -> bool {
        true
    }
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
    /// [`ROOT_CERT`] as text and whether [`CHAIN`] exists, or the new one
    /// a Replace cut short left beside it; `None` without a readable root.
    fn root_and_chain(&self) -> Option<(String, bool)> {
        None
    }
    /// [`OWN_CONSOLE_CERT`] as text; `None` when the console uses the
    /// platform's own.
    fn own_console_cert(&self) -> Option<String> {
        None
    }
    /// This host's own global IPv4 addresses ([`host_addresses`]).
    fn addresses(&self) -> Vec<String> {
        Vec::new()
    }
    /// The rule signer's files; `None` when it isn't set up here.
    fn signer(&self) -> Option<SignerFiles> {
        None
    }
    /// The home directory of `user`, directory users included; `None` when
    /// unknown (the TUI then keeps `HOME`).
    fn user_home(&self, user: &str) -> Option<String> {
        let _ = user;
        None
    }
    /// Disk use of `/var/lib/pgsql` and each `/var/lib/openvibes-*`.
    fn disk(&self) -> Result<Vec<DiskUse>, HostError> {
        Ok(Vec::new())
    }
    /// Space left on the file system holding `path`, as `df -h` writes it;
    /// `None` when unknown (the backup folder's check).
    fn free_space(&self, path: &str) -> Option<String> {
        let _ = path;
        None
    }
    /// `ss -ltnpH` lines for TCP `port` on any address; empty when nobody
    /// listens there (Setup's port check).
    fn listeners(&self, port: u16) -> Result<String, HostError> {
        let _ = port;
        Ok(String::new())
    }
    /// The distribution, kernel and last update check; `None` on a host
    /// without dnf (Maintenance › Operating system).
    fn os_info(&self) -> Option<os_updates::OsInfo> {
        None
    }
    /// Opens the operator's login shell on this terminal and returns when
    /// it exits (Maintenance › Shell).
    fn shell(&self) -> Result<(), HostError> {
        Err(HostError::Failed("this host has no shell".into()))
    }
}

/// The home directory of `user` in `passwd` lines (`/etc/passwd`, or
/// `getent passwd` output); only an absolute path counts.
#[must_use]
pub fn passwd_home(passwd: &str, user: &str) -> Option<String> {
    passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.len() >= 7 && fields[0] == user && fields[5].starts_with('/'))
            .then(|| fields[5].to_owned())
    })
}

/// `ip` arguments listing the host's global addresses, IPv4 and IPv6.
/// A dnf option that refreshes only the OpenVIBES repository's metadata
/// (dnf otherwise trusts a cache up to 48 hours old, so a release from
/// today reads as "nothing to do"). Only for dnf run as root: as a user,
/// a refresh needs the repository key in the user's own cache.
pub const REFRESH_OURS: &str = "--setopt=openvibes.metadata_expire=0";

pub const IP_ADDRESSES: [&str; 5] = ["-o", "addr", "show", "scope", "global"];

/// Interfaces whose addresses never name this host to a browser: container
/// and VM bridges.
/// VPN interfaces (wg, tun, tailscale) stay: reaching the console over a
/// VPN is why the addresses are named at all.
const BRIDGES: [&str; 12] = [
    "docker", "podman", "br-", "veth", "virbr", "cni", "lxcbr", "lxdbr", "incusbr", "cali",
    "flannel", "vxlan",
];

/// The addresses in `ip -o addr show scope global` output, bridges left
/// out (board #71: the console opens by IP, so its certificate names them).
/// IPv6 privacy (`temporary`) and `deprecated` addresses rotate, and would
/// make every Check want a new certificate: they are left out too.
#[must_use]
pub fn host_addresses(listing: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    for line in listing.lines() {
        // `2: enp5s0    inet 192.168.1.10/24 brd ...`
        let mut fields = line.split_whitespace().skip(1);
        let (Some(interface), Some(family), Some(address)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let rotating = line
            .split_whitespace()
            .any(|flag| flag == "temporary" || flag == "deprecated");
        let address = match (family, address.split('/').next().unwrap_or_default()) {
            ("inet", v4) => v4.parse::<std::net::Ipv4Addr>().ok().map(|a| a.to_string()),
            ("inet6", v6) => v6.parse::<std::net::Ipv6Addr>().ok().map(|a| a.to_string()),
            _ => None,
        };
        let Some(address) = address else {
            continue;
        };
        if !rotating
            && !BRIDGES.iter().any(|bridge| interface.starts_with(bridge))
            && !addresses.contains(&address)
        {
            addresses.push(address);
        }
    }
    addresses
}

/// Whether `chain` exists, or a Replace cut short by a crash left one of
/// `staged` (Repair finishes or undoes that; the chain is not lost).
pub(crate) fn chain_in_place(chain: &str, staged: &[&str]) -> bool {
    std::iter::once(&chain)
        .chain(staged)
        .any(|path| std::path::Path::new(path).exists())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_replace_cut_short_counts_as_the_chain_in_place() {
        let dir = std::env::temp_dir().join(format!("ov-chain-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths =
            ["chain.crt", "a.new", "b.new", "c.new"].map(|n| dir.join(n).display().to_string());
        let [chain, staged @ ..] = paths.each_ref().map(String::as_str);
        assert!(!super::chain_in_place(chain, &staged));
        for path in paths.iter() {
            std::fs::write(path, "").unwrap();
            assert!(super::chain_in_place(chain, &staged));
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
