//! The appliance's network settings (TUI rework §7): what NetworkManager
//! says about the wired connection, and the checks every value passes
//! before the root helper hands it to `nmcli` or `hostnamectl`. Pure
//! parsing and validation; the commands themselves run in the admin crate.
//! IPv4 only.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// The transient timer that puts the old settings back unless they are kept.
pub const REVERT_UNIT: &str = "openvibes-net-revert";
/// Seconds the new settings wait to be kept.
pub const KEEP_SECONDS: u64 = 60;
/// Under the root, the old settings while a change waits to be kept.
pub const PENDING_FILE: &str = "run/openvibes-admin/net-previous";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Dhcp,
    Fixed,
}

/// The wired connection as configured, and as it is now.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetInfo {
    /// NetworkManager's connection name and its device.
    pub connection: String,
    pub device: String,
    /// `None`: a method this screen does not manage (link-local, shared…).
    pub method: Option<Method>,
    /// Configured: `ADDRESS/PREFIX`, gateway, DNS servers, search domain.
    pub address: String,
    pub gateway: String,
    pub dns: Vec<String>,
    pub search: String,
    /// DNS from DHCP is used (`ipv4.ignore-auto-dns` is no).
    pub dns_auto: bool,
    /// What is in use now (from DHCP, or as configured).
    pub now_address: String,
    pub now_gateway: String,
    pub now_dns: Vec<String>,
    pub now_search: String,
    /// The host name.
    pub hostname: String,
    /// A change is waiting to be kept: when it was made (Unix seconds).
    pub pending_since: Option<i64>,
}

/// A request for `net-apply`, already checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Change {
    pub method: Method,
    /// Fixed only: `ADDRESS/PREFIX` and the gateway.
    pub address: String,
    pub gateway: String,
    /// Own DNS servers; none with DHCP means the ones DHCP gives.
    pub dns: Vec<String>,
    pub search: String,
}

/// `nmcli -t` fields split on unescaped colons (`\:` is a colon, `\\` a backslash).
#[must_use]
pub fn terse(line: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    fields.last_mut().expect("one field").push(next);
                }
            }
            ':' => fields.push(String::new()),
            c => fields.last_mut().expect("one field").push(c),
        }
    }
    fields
}

/// The first active wired connection of
/// `nmcli -t -f NAME,TYPE,DEVICE connection show --active`: (name, device).
#[must_use]
pub fn wired_connection(listing: &str) -> Option<(String, String)> {
    listing.lines().find_map(|line| {
        let f = terse(line);
        (f.len() == 3 && f[1] == "802-3-ethernet" && !f[0].is_empty() && !f[2].is_empty())
            .then(|| (f[0].clone(), f[2].clone()))
    })
}

/// `key:value` lines of `nmcli -t`: the value of `key`, or of `key[1]`… in order.
fn values(text: &str, key: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            let base = name.split('[').next()?;
            (base == key && !value.trim().is_empty()).then(|| terse_value(value))
        })
        .collect()
}

fn terse_value(value: &str) -> String {
    terse(value).join(":").trim().to_owned()
}

fn first(text: &str, key: &str) -> String {
    values(text, key).into_iter().next().unwrap_or_default()
}

fn list(value: &str) -> Vec<String> {
    value
        .split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "--")
        .map(str::to_owned)
        .collect()
}

/// Fills `info` from `nmcli -t -f ipv4.method,ipv4.addresses,ipv4.gateway,
/// ipv4.dns,ipv4.dns-search,ipv4.ignore-auto-dns connection show NAME`.
pub fn read_config(info: &mut NetInfo, text: &str) {
    info.method = match first(text, "ipv4.method").as_str() {
        "auto" => Some(Method::Dhcp),
        "manual" => Some(Method::Fixed),
        _ => None,
    };
    info.address = list(&first(text, "ipv4.addresses"))
        .into_iter()
        .next()
        .unwrap_or_default();
    info.gateway = first(text, "ipv4.gateway");
    info.dns = list(&first(text, "ipv4.dns"));
    info.search = list(&first(text, "ipv4.dns-search"))
        .into_iter()
        .next()
        .unwrap_or_default();
    info.dns_auto = first(text, "ipv4.ignore-auto-dns") != "yes";
}

/// Fills `info` from `nmcli -t -f IP4.ADDRESS,IP4.GATEWAY,IP4.DNS,IP4.DOMAIN
/// device show DEV`.
pub fn read_now(info: &mut NetInfo, text: &str) {
    info.now_address = first(text, "IP4.ADDRESS");
    info.now_gateway = first(text, "IP4.GATEWAY");
    info.now_dns = values(text, "IP4.DNS");
    info.now_search = first(text, "IP4.DOMAIN");
}

/// An address that can be given to a host.
#[must_use]
pub fn host_address(text: &str) -> Option<Ipv4Addr> {
    let ip: Ipv4Addr = text.parse().ok()?;
    let usable = !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_link_local();
    usable.then_some(ip)
}

/// `ADDRESS/PREFIX` with a prefix of 1 to 30.
#[must_use]
pub fn cidr(text: &str) -> Option<(Ipv4Addr, u8)> {
    let (address, prefix) = text.split_once('/')?;
    let prefix: u8 = prefix.parse().ok().filter(|p| (1..=30).contains(p))?;
    Some((host_address(address)?, prefix))
}

fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX << (32 - u32::from(prefix));
    u32::from(a) & mask == u32::from(b) & mask
}

/// A DNS name or search domain: labels of letters, digits and hyphens.
#[must_use]
pub fn dns_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 253
        && text.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// A host name `hostnamectl` may be given.
#[must_use]
pub fn host_name(text: &str) -> bool {
    dns_name(text) && !text.eq_ignore_ascii_case("localhost") && !text.ends_with('.')
}

/// Checks the pieces of a request, with the words the screen shows.
pub fn change(
    mode: &str,
    address: &str,
    gateway: &str,
    dns: &str,
    search: &str,
) -> Result<Change, String> {
    let method = match mode {
        "dhcp" => Method::Dhcp,
        "fixed" => Method::Fixed,
        _ => return Err("the mode is dhcp or fixed".into()),
    };
    let servers: Vec<String> = dns
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if servers.len() > 3 {
        return Err("at most 3 DNS servers".into());
    }
    for server in &servers {
        if host_address(server).is_none() {
            return Err(format!("{server} is not a DNS server address"));
        }
    }
    if !search.is_empty() && !dns_name(search) {
        return Err(format!("{search} is not a search domain"));
    }
    match method {
        Method::Dhcp if !address.is_empty() || !gateway.is_empty() => {
            return Err("DHCP takes no address or gateway".into());
        }
        Method::Fixed => {
            let (ip, prefix) =
                cidr(address).ok_or("the address is ADDRESS/PREFIX, e.g. 192.168.1.50/24")?;
            let gw = host_address(gateway).ok_or("the gateway is not an address")?;
            if gw == ip || !same_subnet(ip, gw, prefix) {
                return Err("the gateway must be another host on the same network".into());
            }
            if servers.is_empty() {
                return Err("a fixed address needs at least one DNS server".into());
            }
        }
        Method::Dhcp => {}
    }
    Ok(Change {
        method,
        address: address.to_owned(),
        gateway: gateway.to_owned(),
        dns: servers,
        search: search.to_owned(),
    })
}

/// Does `server` answer a DNS query within two seconds? Asks for the root
/// name servers over UDP, which any resolver answers.
#[must_use]
pub fn dns_answers(server: &str) -> bool {
    dns_answers_at(SocketAddr::new(
        server
            .parse()
            .map_or(Ipv4Addr::UNSPECIFIED.into(), |ip: Ipv4Addr| ip.into()),
        53,
    ))
}

/// As [`dns_answers`], at an explicit socket address (tests use a local one).
#[must_use]
pub fn dns_answers_at(to: SocketAddr) -> bool {
    // id 0x4f56, recursion desired, one question: "." NS IN
    const QUERY: [u8; 17] = [
        0x4f, 0x56, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x01,
    ];
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return false;
    };
    let timeout = Some(Duration::from_secs(2));
    if socket.set_read_timeout(timeout).is_err() || socket.send_to(&QUERY, to).is_err() {
        return false;
    }
    let mut buffer = [0_u8; 512];
    matches!(socket.recv_from(&mut buffer), Ok((n, from)) if n >= 12 && from == to && buffer[..2] == QUERY[..2])
}

/// The old settings while a change waits, one `key=value` per line.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    pub connection: String,
    pub method: String,
    pub addresses: String,
    pub gateway: String,
    pub dns: String,
    pub search: String,
    pub ignore_auto_dns: String,
}

impl Snapshot {
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "connection={}\nmethod={}\naddresses={}\ngateway={}\ndns={}\nsearch={}\nignore_auto_dns={}\n",
            self.connection,
            self.method,
            self.addresses,
            self.gateway,
            self.dns,
            self.search,
            self.ignore_auto_dns
        )
    }

    /// `None` for anything that is not exactly what [`encode`](Self::encode) writes.
    #[must_use]
    pub fn decode(text: &str) -> Option<Self> {
        let mut snapshot = Self::default();
        let mut seen = 0;
        for line in text.lines() {
            let (key, value) = line.split_once('=')?;
            if value.chars().any(char::is_control) {
                return None;
            }
            let slot = match key {
                "connection" => &mut snapshot.connection,
                "method" => &mut snapshot.method,
                "addresses" => &mut snapshot.addresses,
                "gateway" => &mut snapshot.gateway,
                "dns" => &mut snapshot.dns,
                "search" => &mut snapshot.search,
                "ignore_auto_dns" => &mut snapshot.ignore_auto_dns,
                _ => return None,
            };
            *slot = value.to_owned();
            seen += 1;
        }
        (seen == 7 && !snapshot.connection.is_empty()).then_some(snapshot)
    }
}
