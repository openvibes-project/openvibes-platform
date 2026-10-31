//! The appliance's network settings (TUI rework §7): what NetworkManager
//! says about the wired connection, and the checks every value passes
//! before the root helper hands it to `nmcli` or `hostnamectl`. Pure
//! parsing and validation; the commands themselves run in the admin crate.
//! IPv4 only.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// The transient timer that puts the old settings back unless they are kept.
pub const REVERT_UNIT: &str = "openvibes-net-revert";
/// The timer that covers the change itself (the connection can take a
/// minute and a half to come up); a unit of its own, so starting the
/// [`REVERT_UNIT`] one never waits for this one to unload.
pub const SETTLE_UNIT: &str = "openvibes-net-settle";
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
    /// NetworkManager's connection name, its UUID (what the verbs address it
    /// by: names are not unique) and its device.
    pub connection: String,
    pub uuid: String,
    pub device: String,
    /// `None`: a method this screen does not manage (link-local, shared…).
    pub method: Option<Method>,
    /// Configured: `ADDRESS/PREFIX`, gateway, DNS servers, search domain.
    pub address: String,
    pub gateway: String,
    pub dns: Vec<String>,
    pub search: String,
    /// Everything NetworkManager holds for these (several addresses, DNS
    /// servers and search domains); what a rollback puts back.
    pub all_addresses: String,
    pub all_dns: String,
    pub all_search: String,
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

/// A connection UUID as NetworkManager writes it.
#[must_use]
pub fn uuid(text: &str) -> bool {
    text.len() == 36 && text.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// The first active wired connection of
/// `nmcli -t -f NAME,UUID,TYPE,DEVICE connection show --active`:
/// (name, uuid, device).
#[must_use]
pub fn wired_connection(listing: &str) -> Option<(String, String, String)> {
    listing.lines().find_map(|line| {
        let f = terse(line);
        (f.len() == 4
            && f[2] == "802-3-ethernet"
            && !f[0].is_empty()
            && uuid(&f[1])
            && !f[3].is_empty())
        .then(|| (f[0].clone(), f[1].clone(), f[3].clone()))
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
    info.all_addresses = first(text, "ipv4.addresses");
    info.all_dns = first(text, "ipv4.dns");
    info.all_search = first(text, "ipv4.dns-search");
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

#[must_use]
pub fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
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
    // hostnamectl keeps a static name to 64 characters.
    dns_name(text)
        && text.len() <= 64
        && !text.eq_ignore_ascii_case("localhost")
        && !text.ends_with('.')
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
    let raw: Vec<&str> = dns
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if raw.len() > 3 {
        return Err("at most 3 DNS servers".into());
    }
    // Rebuilt from the parsed addresses: only checked values go on.
    let mut servers = Vec::new();
    for server in raw {
        let ip = host_address(server).ok_or(format!("{server} is not a DNS server address"))?;
        servers.push(ip.to_string());
    }
    if !search.is_empty() && !dns_name(search) {
        return Err(format!("{search} is not a search domain"));
    }
    let (mut address_out, mut gateway_out) = (String::new(), String::new());
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
            address_out = format!("{ip}/{prefix}");
            gateway_out = gw.to_string();
        }
        Method::Dhcp => {}
    }
    Ok(Change {
        method,
        address: address_out,
        gateway: gateway_out,
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
    pub uuid: String,
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
            "uuid={}\nmethod={}\naddresses={}\ngateway={}\ndns={}\nsearch={}\nignore_auto_dns={}\n",
            self.uuid,
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
                "uuid" => &mut snapshot.uuid,
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
        (seen == 7 && uuid(&snapshot.uuid)).then_some(snapshot)
    }
}
