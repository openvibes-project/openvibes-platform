//! Operating system updates (TUI rework §6, "Operating system"): what
//! `dnf` says is waiting, kept by the root helper in [`OS_UPDATES_FILE`] so
//! the screens read the last check without a password. Parsing only; the
//! commands run in the helper.

/// The last check, `key=value` lines, 0644 root (written by `os-check`).
pub const OS_UPDATES_FILE: &str = "/etc/openvibes/os-updates";

/// What the last check found.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OsUpdates {
    /// Packages with a newer version.
    pub total: u32,
    /// Of those, packages named by a security advisory.
    pub security: u32,
    /// A new kernel is among them.
    pub kernel: bool,
    /// `needs-restarting -r` says the running system is out of date.
    pub restart: bool,
    /// Seconds since the epoch when the check finished.
    pub checked_at: i64,
}

/// The packages `dnf check-update` lists: lines of `NAME.ARCH VERSION REPO`
/// up to the "Obsoleting Packages" heading (dnf starts with a blank line).
#[must_use]
pub fn check_update_packages(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .take_while(|line| !line.starts_with("Obsoleting"))
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [full, _version, _repo] = fields[..] else {
                return None;
            };
            full.contains('.').then(|| name_of(full).to_owned())
        })
        .collect()
}

fn name_of(full: &str) -> &str {
    full.rsplit_once('.').map_or(full, |(name, _arch)| name)
}

/// The packages `dnf updateinfo list --security` names, without the
/// version, each once.
#[must_use]
pub fn security_packages(stdout: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [_advisory, _severity, package] = fields[..] else {
            continue;
        };
        let Some(name) = package_name(package) else {
            continue;
        };
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// `openssl-libs-1:3.2.2-6.el9.x86_64` → `openssl-libs`: drops the arch,
/// release and version (the last two dashes).
fn package_name(nevra: &str) -> Option<String> {
    let (rest, _arch) = nevra.rsplit_once('.')?;
    let (rest, _release) = rest.rsplit_once('-')?;
    let (name, _version) = rest.rsplit_once('-')?;
    Some(name.to_owned())
}

impl OsUpdates {
    /// The counts from the two dnf listings, both of the same check.
    #[must_use]
    pub fn from_listings(
        check_update: &str,
        security: &str,
        restart: bool,
        checked_at: i64,
    ) -> OsUpdates {
        let packages = check_update_packages(check_update);
        let security = security_packages(security)
            .iter()
            .filter(|name| packages.contains(name))
            .count();
        OsUpdates {
            total: packages.len() as u32,
            security: security as u32,
            kernel: packages
                .iter()
                .any(|name| name == "kernel" || name.starts_with("kernel-core")),
            restart,
            checked_at,
        }
    }

    #[must_use]
    pub fn to_file(self) -> String {
        format!(
            "total={}\nsecurity={}\nkernel={}\nrestart={}\nchecked_at={}\n",
            self.total, self.security, self.kernel, self.restart, self.checked_at
        )
    }

    /// Reads [`OsUpdates::to_file`]; unknown keys are ignored, a file
    /// without `checked_at` is not a check.
    #[must_use]
    pub fn from_file(text: &str) -> Option<OsUpdates> {
        let mut found = OsUpdates::default();
        let mut checked = false;
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "total" => found.total = value.parse().ok()?,
                "security" => found.security = value.parse().ok()?,
                "kernel" => found.kernel = value == "true",
                "restart" => found.restart = value == "true",
                "checked_at" => {
                    found.checked_at = value.parse().ok()?;
                    checked = true;
                }
                _ => {}
            }
        }
        checked.then_some(found)
    }
}

/// `PRETTY_NAME` of an os-release file: "AlmaLinux 9.6 (Sage Margay)".
#[must_use]
pub fn os_release(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let value = line.strip_prefix("PRETTY_NAME=")?;
        let value = value.trim().trim_matches('"').trim_matches('\'');
        (!value.is_empty()).then(|| value.to_owned())
    })
}
