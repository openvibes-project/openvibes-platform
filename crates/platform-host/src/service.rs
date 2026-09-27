//! The configuration files the administration TUI may edit (admin TUI spec
//! §5). An enum, so no other path can be expressed.

use crate::Unit;

/// Where every OpenVIBES service configuration lives.
pub const CONFIG_DIR: &str = "/etc/openvibes";

/// One service whose `/etc/openvibes/NAME.toml` the TUI edits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Service {
    /// `ingest.toml`.
    Ingest,
    /// `distribution.toml`.
    Distribution,
    /// `vulns.toml`.
    Vulns,
    /// `console.toml` (with the assistant's `[assistant]` section).
    Console,
    /// `admin.toml`, the admin CLI's own.
    Admin,
}

impl Service {
    /// Every service, in display order.
    pub const ALL: [Service; 5] = [
        Service::Ingest,
        Service::Distribution,
        Service::Vulns,
        Service::Console,
        Service::Admin,
    ];

    /// The short name the helper takes.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Service::Ingest => "ingest",
            Service::Distribution => "distribution",
            Service::Vulns => "vulns",
            Service::Console => "console",
            Service::Admin => "admin",
        }
    }

    /// The file name in [`CONFIG_DIR`].
    #[must_use]
    pub fn file_name(self) -> &'static str {
        match self {
            Service::Ingest => "ingest.toml",
            Service::Distribution => "distribution.toml",
            Service::Vulns => "vulns.toml",
            Service::Console => "console.toml",
            Service::Admin => "admin.toml",
        }
    }

    /// The absolute path.
    #[must_use]
    pub fn path(self) -> String {
        format!("{CONFIG_DIR}/{}", self.file_name())
    }

    /// The unit to restart after a save; the admin CLI has none.
    #[must_use]
    pub fn unit(self) -> Option<Unit> {
        match self {
            Service::Ingest => Some(Unit::Ingest),
            Service::Distribution => Some(Unit::Distribution),
            Service::Vulns => Some(Unit::Vulns),
            Service::Console => Some(Unit::Console),
            Service::Admin => None,
        }
    }

    /// The service with exactly this name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Service> {
        Service::ALL
            .into_iter()
            .find(|service| service.name() == name)
    }
}
