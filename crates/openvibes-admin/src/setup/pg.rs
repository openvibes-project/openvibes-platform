//! Which PostgreSQL packages and paths this host uses. Fedora's own
//! PostgreSQL is 17 or later; on AlmaLinux 10 the distribution carries 16,
//! and the migrations need 17, so there it is the PostgreSQL project's
//! packages (PGDG), which are named and laid out differently.

use platform_host::runner::{Program, Runner};

use super::Ctx;

/// The names and paths that differ between the two.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pg {
    /// The server package; its presence means PostgreSQL is installed.
    pub server: &'static str,
    /// What Setup may install and Remove everything may remove.
    pub packages: [&'static str; 3],
    /// First initialisation.
    pub setup: Program,
    pub setup_args: &'static [&'static str],
    /// The systemd unit.
    pub service: &'static str,
    /// Marks an initialised cluster.
    pub version_file: &'static str,
}

/// The distribution's own PostgreSQL (Fedora).
pub const DISTRO: Pg = Pg {
    server: "postgresql-server",
    packages: ["postgresql-server", "postgresql", "postgresql-private-libs"],
    setup: Program::PostgresqlSetup,
    setup_args: &["--initdb"],
    service: "postgresql",
    version_file: "/var/lib/pgsql/data/PG_VERSION",
};

/// PGDG's PostgreSQL 17.
pub const PGDG: Pg = Pg {
    server: "postgresql17-server",
    packages: ["postgresql17-server", "postgresql17", "postgresql17-libs"],
    setup: Program::PostgresqlSetupPgdg,
    setup_args: &["initdb"],
    service: "postgresql-17",
    version_file: "/var/lib/pgsql/17/data/PG_VERSION",
};

/// The host's `ID` and `VERSION_ID`.
fn os_release<R: Runner>(ctx: &Ctx<R>) -> (String, String) {
    let text = ctx.read("/etc/os-release").unwrap_or_default();
    let value = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_owned())
            .unwrap_or_default()
    };
    (value("ID"), value("VERSION_ID"))
}

/// The packages this host uses: PGDG's on AlmaLinux, the distribution's
/// everywhere else.
pub fn flavour<R: Runner>(ctx: &Ctx<R>) -> Pg {
    if os_release(ctx).0 == "almalinux" {
        PGDG
    } else {
        DISTRO
    }
}

/// The address of PGDG's repository package for this host.
pub fn repo_package<R: Runner>(ctx: &Ctx<R>) -> String {
    let major = os_release(ctx).1;
    let major = major.split('.').next().unwrap_or("10");
    format!(
        "https://download.postgresql.org/pub/repos/yum/reporpms/EL-{major}-x86_64/pgdg-redhat-repo-latest.noarch.rpm"
    )
}
