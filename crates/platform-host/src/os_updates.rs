//! Operating system updates (TUI rework §6, "Operating system"): what
//! `dnf` says is waiting, kept by the root helper in [`OS_UPDATES_FILE`] so
//! the screens read the last check without a password. Parsing only; the
//! commands run in the helper.

/// The last check, `key=value` lines, 0644 root (written by `os-check`).
pub const OS_UPDATES_FILE: &str = "/etc/openvibes/os-updates";

/// What the Operating system page shows about this host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OsInfo {
    /// "AlmaLinux 9.6 (Sage Margay)".
    pub name: String,
    /// The running kernel, `uname -r`.
    pub kernel: String,
    /// The last check; `None` before the first.
    pub updates: Option<OsUpdates>,
    /// An update is running now (the `openvibes-os-update` unit), maybe
    /// started from another session.
    pub running: bool,
}

/// The unit the root helper runs the upgrade in, so a dropped terminal
/// does not stop it half way.
pub const UPDATE_UNIT: &str = "openvibes-os-update";

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
/// dnf4 puts a name wider than its column on a line of its own and the
/// version and repository on the next: the two are joined.
#[must_use]
pub fn check_update_packages(stdout: &str) -> Vec<String> {
    let lines: Vec<Vec<&str>> = stdout
        .lines()
        .take_while(|line| !line.starts_with("Obsoleting"))
        .map(|line| line.split_whitespace().collect())
        .collect();
    let mut names = Vec::new();
    let mut at = 0;
    while at < lines.len() {
        let (full, used) = match (&lines[at][..], lines.get(at + 1).map(Vec::as_slice)) {
            ([full, _, _], _) => (*full, 1),
            ([full], Some([_, _])) => (*full, 2),
            _ => ("", 1),
        };
        if full.contains('.') {
            names.push(name_of(full).to_owned());
        }
        at += used;
    }
    names
}

fn name_of(full: &str) -> &str {
    full.rsplit_once('.').map_or(full, |(name, _arch)| name)
}

/// What `needs-restarting -r` said: yes and no are its own words (dnf4 and
/// dnf5 print the same); anything else (the plugin is missing, no D-Bus) is
/// not an answer.
#[must_use]
pub fn restart_answer(stdout: &str) -> Option<bool> {
    if stdout.contains("Reboot is required") {
        Some(true)
    } else if stdout.contains("Reboot should not be necessary") {
        Some(false)
    } else {
        None
    }
}

/// The kernel version without its distribution and architecture tail:
/// `5.14.0-570.12.1.el9_6.x86_64` → `5.14.0-570.12.1`.
#[must_use]
pub fn short_kernel(release: &str) -> &str {
    let release = release.trim();
    for marker in [".el", ".fc"] {
        if let Some((head, _)) = release.split_once(marker) {
            return head;
        }
    }
    release.rsplit_once('.').map_or(release, |(head, arch)| {
        if arch.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && arch.chars().any(|c| c.is_ascii_alphabetic())
        {
            head
        } else {
            release
        }
    })
}

impl OsUpdates {
    /// The counts from `check-update` and `check-update --security`
    /// (the same format), and the restart answer.
    #[must_use]
    pub fn from_listings(
        check_update: &str,
        security: &str,
        restart: bool,
        checked_at: i64,
    ) -> OsUpdates {
        let packages = check_update_packages(check_update);
        OsUpdates {
            total: packages.len() as u32,
            security: check_update_packages(security).len() as u32,
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

/// `PRETTY_NAME` of an os-release file: "AlmaLinux 9.6 (Sage Margay)";
/// without it `NAME VERSION_ID`, else "Linux".
#[must_use]
pub fn os_release(text: &str) -> String {
    let value = |key: &str| {
        text.lines().find_map(|line| {
            let value = line.strip_prefix(key)?.strip_prefix('=')?;
            let value = value.trim().trim_matches('"').trim_matches('\'');
            (!value.is_empty()).then(|| value.to_owned())
        })
    };
    value("PRETTY_NAME").unwrap_or_else(|| match (value("NAME"), value("VERSION_ID")) {
        (Some(name), Some(version)) => format!("{name} {version}"),
        (Some(name), None) => name,
        _ => "Linux".to_owned(),
    })
}
