//! System › Network, on the appliance (spec §7; system.py, approved.md 43):
//! DHCP or a fixed address with its gateway, the DNS servers (DHCP's or
//! your own, each asked before Apply), the search domain and the host name
//! on one page. Apply runs `net-apply` (and `hostname-set`), after which the
//! page offers Keep or Put back for a minute: the helper's timer puts the
//! old settings back by itself if nobody answers (a wrong address can cut
//! the very session that set it).

mod draw;
mod keys;

use std::time::Instant;

use platform_host::network::{self, KEEP_SECONDS, Method, NetInfo};

pub use draw::draw;

/// A page row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum At {
    Dhcp,
    Fixed,
    Address,
    Gateway,
    /// `[x] Use the DNS from DHCP`.
    DnsAuto,
    Dns,
    Search,
    Host,
    Apply,
    /// After an apply: keep, or put the old settings back.
    Keep,
    Revert,
}

/// The page's state: what the host says, the edits, the value being typed.
#[derive(Debug, Default)]
pub struct Net {
    /// The wired connection as read when the page opened; `None`: there is
    /// no NetworkManager connection to manage.
    pub info: Option<NetInfo>,
    /// For System's menu line: read when System opens.
    pub menu: Option<String>,
    pub mode: Option<Method>,
    pub address: String,
    pub gateway: String,
    pub own_dns: bool,
    pub dns: String,
    pub search: String,
    pub host: String,
    pub typing: Option<String>,
    pub note: Option<Result<String, String>>,
    /// When the new settings came up and wait to be kept.
    pub keep: Option<Instant>,
    /// The minute passed and the helper had not put the old settings back.
    pub lapsed: bool,
    /// Said under the list after a keep, a put back or a lapse.
    pub said: Option<Result<String, String>>,
}

/// `192.168.1.50 · DHCP · eth0`, System's line for the page.
pub fn menu_line(info: &NetInfo) -> String {
    let ip = info.now_address.split('/').next().unwrap_or_default();
    let how = match info.method {
        Some(Method::Dhcp) => "DHCP",
        Some(Method::Fixed) => "fixed",
        None => "other",
    };
    if ip.is_empty() {
        format!("{how} · {}", info.device)
    } else {
        format!("{ip} · {how} · {}", info.device)
    }
}

impl Net {
    pub fn typing(&self) -> bool {
        self.typing.is_some()
    }

    /// Starts the edits from what the host says.
    pub fn from_info(info: Option<NetInfo>) -> Self {
        let Some(info) = info else {
            return Self::default();
        };
        Net {
            mode: info.method,
            address: info.address.clone(),
            gateway: info.gateway.clone(),
            own_dns: info.method == Some(Method::Fixed) || !info.dns_auto,
            dns: info.dns.join(", "),
            search: info.search.clone(),
            host: info.hostname.clone(),
            menu: Some(menu_line(&info)),
            info: Some(info),
            ..Net::default()
        }
    }

    /// Fixed address: the fields start from what DHCP gave.
    pub fn choose_fixed(&mut self) {
        if self.mode == Some(Method::Fixed) {
            return;
        }
        self.mode = Some(Method::Fixed);
        self.own_dns = true;
        if let Some(info) = &self.info {
            if self.address.is_empty() {
                self.address.clone_from(&info.now_address);
            }
            if self.gateway.is_empty() {
                self.gateway.clone_from(&info.now_gateway);
            }
            if self.dns.is_empty() {
                self.dns = info.now_dns.join(", ");
            }
            if self.search.is_empty() {
                self.search.clone_from(&info.now_search);
            }
        }
    }

    pub fn choose_dhcp(&mut self) {
        self.mode = Some(Method::Dhcp);
        self.own_dns = self.info.as_ref().is_some_and(|i| !i.dns_auto);
    }

    /// The network settings differ from the host's.
    pub fn net_changed(&self) -> bool {
        let Some(info) = &self.info else { return false };
        let Some(mode) = self.mode else { return false };
        if info.method != Some(mode) {
            return true;
        }
        let dns = self.dns_text();
        let was = info.dns.join(", ");
        let dns_changed = if mode == Method::Fixed || self.own_dns {
            // NetworkManager's own default leaves `ignore-auto-dns` off for a
            // fixed address too, where it does nothing: not a change.
            dns != was || (mode == Method::Dhcp && info.dns_auto)
        } else {
            !info.dns_auto
        };
        self.search != info.search
            || dns_changed
            || (mode == Method::Fixed
                && (self.address != info.address || self.gateway != info.gateway))
    }

    pub fn host_changed(&self) -> bool {
        self.info.as_ref().is_some_and(|i| self.host != i.hostname)
    }

    pub fn changed(&self) -> bool {
        self.net_changed() || self.host_changed()
    }

    /// The DNS servers as typed, normalised to `a, b`.
    pub fn dns_text(&self) -> String {
        self.dns
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn rows(&self) -> Vec<At> {
        if self.keep.is_some() {
            return vec![At::Keep, At::Revert];
        }
        let Some(mode) = self.mode else {
            // A method this page does not manage: only the host name.
            return if self.info.is_some() {
                let mut rows = vec![At::Host];
                if self.host_changed() {
                    rows.push(At::Apply);
                }
                rows
            } else {
                Vec::new()
            };
        };
        let mut rows = vec![At::Dhcp, At::Fixed];
        match mode {
            Method::Fixed => rows.extend([At::Address, At::Gateway, At::Dns]),
            Method::Dhcp => {
                rows.push(At::DnsAuto);
                if self.own_dns {
                    rows.push(At::Dns);
                }
            }
        }
        rows.extend([At::Search, At::Host]);
        if self.changed() {
            rows.push(At::Apply);
        }
        rows
    }

    /// What the line under the list says of `typed` for `at`.
    pub fn note_for(&self, at: At, typed: &str) -> Option<Result<String, String>> {
        let t = typed.trim();
        match at {
            At::Address => Some(match network::cidr(t) {
                Some(_) => Ok("A usable address.".into()),
                None => Err("✗ ADDRESS/PREFIX, for example 192.168.1.50/24.".into()),
            }),
            At::Gateway => Some(match network::host_address(t) {
                None => Err("✗ Not an address.".into()),
                Some(gw) => match network::cidr(&self.address) {
                    Some((ip, prefix)) if !network::same_subnet(ip, gw, prefix) => {
                        Err("✗ Not on the same network as the address.".into())
                    }
                    _ => Ok("An address.".into()),
                },
            }),
            At::Dns => {
                let servers: Vec<&str> = t
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect();
                if servers.len() > 3 {
                    return Some(Err("✗ At most 3 servers.".into()));
                }
                match servers.iter().find(|s| network::host_address(s).is_none()) {
                    Some(bad) => Some(Err(format!("✗ {bad} is not an address."))),
                    None if servers.is_empty() => Some(Ok("No servers.".into())),
                    None => Some(Ok("Separate several with commas.".into())),
                }
            }
            At::Search => Some(if t.is_empty() || network::dns_name(t) {
                Ok("Added to short names.".into())
            } else {
                Err("✗ Not a domain: letters, digits, dots and dashes.".into())
            }),
            At::Host => Some(if network::host_name(t) {
                Ok("A valid host name.".into())
            } else {
                Err("✗ Not a host name: letters, digits, dots and dashes, at most 64.".into())
            }),
            _ => None,
        }
    }

    /// The instant a change made at Unix second `at` came up (the helper's
    /// pending file is written right after its timer is armed).
    pub fn pending_instant(at: i64) -> Instant {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
        let age = u64::try_from(now.saturating_sub(at)).unwrap_or(0);
        // Far enough back to read as lapsed, never so far it cannot be built.
        let age = age.min(KEEP_SECONDS + 600);
        Instant::now()
            .checked_sub(std::time::Duration::from_secs(age))
            .unwrap_or_else(Instant::now)
    }

    /// Seconds left to keep the new settings.
    pub fn seconds_left(&self) -> u64 {
        self.keep
            .map_or(0, |at| KEEP_SECONDS.saturating_sub(at.elapsed().as_secs()))
    }
}

#[cfg(test)]
mod tests;
