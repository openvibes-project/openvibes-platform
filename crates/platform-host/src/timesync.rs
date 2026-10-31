//! The appliance's clock settings (System › Time): the NTP servers `chrony`
//! asks and the time zone. Everything typed is parsed here, with the words
//! the screen shows, before it reaches a command line or a config file.

/// The most NTP servers the page takes.
pub const MAX_SERVERS: usize = 4;

/// Where the helper writes the chosen servers (a `chrony.conf` `confdir`
/// drop-in).
pub const DROP_IN: &str = "etc/chrony.d/50-openvibes.conf";

/// What the host says about its clock.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TimeInfo {
    /// The time zone, e.g. `Europe/Stockholm`.
    pub zone: String,
    /// The servers chosen here, empty when the distribution's own are used.
    pub servers: Vec<String>,
    /// The server actually in use, with where it comes from: the chosen
    /// ones, `10.0.0.1 (from DHCP)` or `2.fedora.pool.ntp.org (default)`.
    pub in_use: String,
    /// `Some(true)` when the clock follows its servers.
    pub synced: Option<bool>,
}

/// An NTP server: a host name or an IPv4 address.
#[must_use]
pub fn server_name(text: &str) -> bool {
    crate::network::dns_name(text) || crate::network::host_address(text).is_some()
}

/// The servers of a comma separated list, checked: one to
/// [`MAX_SERVERS`], no repeats.
pub fn servers(text: &str) -> Result<Vec<String>, String> {
    let list: Vec<String> = text
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if list.len() > MAX_SERVERS {
        return Err(format!("At most {MAX_SERVERS} servers."));
    }
    if let Some(bad) = list.iter().find(|s| !server_name(s)) {
        return Err(format!("{bad} is not a host name or an address."));
    }
    for (i, one) in list.iter().enumerate() {
        if list[..i].iter().any(|s| s.eq_ignore_ascii_case(one)) {
            return Err(format!("{one} is listed twice."));
        }
    }
    Ok(list)
}

/// The shape of a zone name (`Europe/Stockholm`, `UTC`, `America/Port-au-Prince`);
/// whether it exists is `timedatectl list-timezones`' to say.
#[must_use]
pub fn zone_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && !text.starts_with('/')
        && !text.ends_with('/')
        && text
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '+'))
}

/// The drop-in the helper writes for `servers`.
#[must_use]
pub fn drop_in(servers: &[String]) -> String {
    let mut text = String::from("# Written by OpenVIBES (System > Time). Do not edit.\n");
    for server in servers {
        text.push_str("server ");
        text.push_str(server);
        text.push_str(" iburst\n");
    }
    text
}

/// The servers a drop-in written by [`drop_in`] names.
#[must_use]
pub fn read_drop_in(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("server"))
                .then(|| words.next())
                .flatten()
                .map(str::to_owned)
        })
        .collect()
}

/// Where NetworkManager's DHCP hook puts the servers it was handed.
pub const DHCP_DIR: &str = "run/chrony-dhcp";

/// The first `server` or `pool` host of a chrony config text.
fn first_source(text: &str) -> Option<&str> {
    text.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        matches!(words.next(), Some("server" | "pool"))
            .then(|| words.next())
            .flatten()
    })
}

/// The server in use, for the page and System's line: the chosen ones, else
/// the first one DHCP handed out (`dhcp` holds the texts of the files in
/// [`DHCP_DIR`]), else the distribution's first (`conf`, the `chrony.conf`).
#[must_use]
pub fn in_use(chosen: &[String], dhcp: &[String], conf: &str) -> String {
    if !chosen.is_empty() {
        return chosen.join(", ");
    }
    if let Some(host) = dhcp.iter().find_map(|text| first_source(text)) {
        return format!("{host} (from DHCP)");
    }
    match first_source(conf) {
        Some(host) => format!("{host} (default)"),
        None => "none found".to_owned(),
    }
}

/// `timedatectl show -p NTPSynchronized --value`.
#[must_use]
pub fn read_synced(text: &str) -> Option<bool> {
    match text.trim() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// Is `zone` one of the lines of `timedatectl list-timezones`?
#[must_use]
pub fn known_zone(list: &str, zone: &str) -> bool {
    list.lines().any(|line| line.trim() == zone)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servers_are_names_or_addresses_to_four() {
        assert_eq!(
            servers("ntp.lime.lab, 192.168.1.1").unwrap(),
            ["ntp.lime.lab", "192.168.1.1"]
        );
        assert!(servers("").unwrap().is_empty());
        assert!(servers("a.b,c.d,e.f,g.h,i.j").is_err());
        assert!(servers("not a host").is_err());
        assert!(servers("ntp.lab, NTP.lab").is_err());
        assert!(servers("ntp.lab; reboot").is_err());
    }

    #[test]
    fn zone_names_have_a_safe_shape() {
        for ok in [
            "UTC",
            "Europe/Stockholm",
            "America/Port-au-Prince",
            "Etc/GMT+1",
        ] {
            assert!(zone_name(ok), "{ok}");
        }
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "Europe//X",
            "a b",
            "x;y",
            "Europe/",
        ] {
            assert!(!zone_name(bad), "{bad}");
        }
    }

    #[test]
    fn the_drop_in_round_trips() {
        let list = vec!["ntp.lime.lab".to_owned(), "10.0.0.1".to_owned()];
        let text = drop_in(&list);
        assert!(text.contains("server ntp.lime.lab iburst\n"));
        assert_eq!(read_drop_in(&text), list);
        assert!(read_drop_in("").is_empty());
    }

    #[test]
    fn the_server_in_use_is_chosen_then_dhcp_then_the_default() {
        let conf = "# c\npool 2.fedora.pool.ntp.org iburst\nserver 10.9.9.9\n";
        let dhcp = vec!["server 10.0.0.1 iburst\n".to_owned()];
        let chosen = vec!["ntp.lab".to_owned(), "10.1.1.1".to_owned()];
        assert_eq!(in_use(&chosen, &dhcp, conf), "ntp.lab, 10.1.1.1");
        assert_eq!(in_use(&[], &dhcp, conf), "10.0.0.1 (from DHCP)");
        assert_eq!(
            in_use(&[], &["\n".to_owned()], conf),
            "2.fedora.pool.ntp.org (default)"
        );
        // Marked-out lines are not the default.
        assert_eq!(
            in_use(&[], &[], "#openvibes# pool a.b\nserver c.d\n"),
            "c.d (default)"
        );
        assert_eq!(in_use(&[], &[], "driftfile /x\n"), "none found");
    }

    #[test]
    fn sync_and_zone_lists_are_read() {
        assert_eq!(read_synced("yes\n"), Some(true));
        assert_eq!(read_synced("no"), Some(false));
        assert_eq!(read_synced(""), None);
        assert!(known_zone("UTC\nEurope/Stockholm\n", "Europe/Stockholm"));
        assert!(!known_zone("UTC\n", "Europe/Stockholm"));
    }
}
