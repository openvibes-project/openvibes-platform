//! System › Time, on the appliance (spec §7; system.py): the NTP servers
//! chrony asks and the time zone. Apply runs `time-set`, which also
//! restarts chrony.

mod draw;
mod keys;

use platform_host::timesync::{self, TimeInfo};

pub use draw::draw;

/// A page row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum At {
    Servers,
    Zone,
    Apply,
}

/// The page's state: what the host says, the edits, the value being typed.
#[derive(Debug, Default)]
pub struct TimePage {
    /// As read when the page opened; `None`: no `timedatectl`.
    pub info: Option<TimeInfo>,
    /// For System's menu line: read when System opens.
    pub menu: Option<String>,
    /// The servers as typed, `a, b`; empty: the distribution's own.
    pub servers: String,
    pub zone: String,
    pub typing: Option<String>,
    pub note: Option<Result<String, String>>,
}

/// `in sync · ntp.lime.lab · Europe/Stockholm`, System's line for the page.
pub fn menu_line(info: &TimeInfo) -> String {
    let state = match info.synced {
        Some(true) => "in sync",
        Some(false) => "not in sync",
        None => "unknown",
    };
    format!("{state} · {} · {}", info.in_use, info.zone)
}

impl TimePage {
    pub fn typing(&self) -> bool {
        self.typing.is_some()
    }

    pub fn from_info(info: Option<TimeInfo>) -> Self {
        let Some(info) = info else {
            return Self::default();
        };
        TimePage {
            servers: info.servers.join(", "),
            zone: info.zone.clone(),
            menu: Some(menu_line(&info)),
            info: Some(info),
            ..TimePage::default()
        }
    }

    pub fn changed(&self) -> bool {
        self.info.as_ref().is_some_and(|i| {
            self.zone != i.zone || timesync::servers(&self.servers).is_ok_and(|s| s != i.servers)
        })
    }

    pub fn rows(&self) -> Vec<At> {
        let mut rows = vec![At::Servers, At::Zone];
        if self.changed() {
            rows.push(At::Apply);
        }
        rows
    }

    /// What the line under the list says of `typed` for `at`.
    pub fn note_for(at: At, typed: &str) -> Option<Result<String, String>> {
        let t = typed.trim();
        match at {
            At::Servers => Some(match timesync::servers(t) {
                Ok(list) if list.is_empty() => {
                    Ok("Empty: automatic. The DHCP server if there is one, else the distribution's pool.".into())
                }
                Ok(_) => Ok("Separate several with commas.".into()),
                Err(why) => Err(format!("✗ {why}")),
            }),
            At::Zone => Some(if timesync::zone_name(t) {
                Ok("For example Europe/Stockholm.".into())
            } else {
                Err("✗ Not a time zone: Area/City, for example Europe/Stockholm.".into())
            }),
            At::Apply => None,
        }
    }

    /// The `time-set` arguments.
    pub fn args(&self) -> Result<Vec<String>, String> {
        let servers = timesync::servers(&self.servers)?;
        if !timesync::zone_name(&self.zone) {
            return Err(format!("{} is not a time zone", self.zone));
        }
        Ok(vec![
            "--servers".into(),
            servers.join(","),
            "--zone".into(),
            self.zone.clone(),
        ])
    }
}

#[cfg(test)]
mod tests;
