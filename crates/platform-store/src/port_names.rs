//! A fixed map of well-known ports (step 5e ruling 9): the usual name and
//! use of a port, and the class that decides "Needs a look". It is the
//! spec's "fixed list of plain rules in code"; one file to edit.

/// What kind of service a port usually is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortClass {
    /// A database server.
    Database,
    /// Remote administration of a machine.
    RemoteAdmin,
    /// Anything else.
    Other,
}

/// What the map knows about a port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortInfo {
    /// The usual name, e.g. `SSH`.
    pub name: &'static str,
    /// The usual use, one plain phrase.
    pub usual_use: &'static str,
    /// Its class.
    pub class: PortClass,
    /// The compliance area whose checks concern it, when there is one.
    pub area: Option<&'static str>,
    /// Packages of its usual server (the vulnerabilities link).
    pub packages: &'static [&'static str],
}

const fn info(name: &'static str, usual_use: &'static str, class: PortClass) -> PortInfo {
    PortInfo {
        name,
        usual_use,
        class,
        area: None,
        packages: &[],
    }
}

use PortClass::{Database, Other, RemoteAdmin};

/// Every known `(protocol, port)`.
const PORTS: &[(&str, u16, PortInfo)] = &[
    ("tcp", 21, info("FTP", "File transfer", Other)),
    (
        "tcp",
        22,
        PortInfo {
            name: "SSH",
            usual_use: "Secure remote login",
            class: Other,
            area: Some("SSH"),
            packages: &["openssh-server", "openssh"],
        },
    ),
    (
        "tcp",
        23,
        info("Telnet", "Unencrypted remote login", RemoteAdmin),
    ),
    (
        "tcp",
        25,
        info("SMTP", "Mail delivery between servers", Other),
    ),
    ("tcp", 53, info("DNS", "Name lookups", Other)),
    ("udp", 53, info("DNS", "Name lookups", Other)),
    ("tcp", 80, info("HTTP", "Web pages", Other)),
    ("tcp", 110, info("POP3", "Mail download", Other)),
    (
        "tcp",
        111,
        info("RPC", "Remote procedure calls (rpcbind)", Other),
    ),
    ("udp", 123, info("NTP", "Time sync", Other)),
    (
        "udp",
        137,
        info("NetBIOS name", "Windows name service", Other),
    ),
    (
        "udp",
        138,
        info("NetBIOS datagram", "Windows file sharing", Other),
    ),
    (
        "tcp",
        139,
        info("NetBIOS session", "Windows file sharing", Other),
    ),
    ("tcp", 143, info("IMAP", "Mail access", Other)),
    ("udp", 161, info("SNMP", "Device monitoring", Other)),
    ("tcp", 389, info("LDAP", "Directory lookups", Other)),
    ("tcp", 443, info("HTTPS", "Encrypted web pages", Other)),
    ("tcp", 445, info("SMB", "Windows file sharing", Other)),
    (
        "tcp",
        465,
        info("SMTPS", "Encrypted mail submission", Other),
    ),
    ("tcp", 587, info("Submission", "Mail submission", Other)),
    ("tcp", 631, info("IPP", "Printing (CUPS)", Other)),
    (
        "tcp",
        636,
        info("LDAPS", "Encrypted directory lookups", Other),
    ),
    ("tcp", 993, info("IMAPS", "Encrypted mail access", Other)),
    ("tcp", 995, info("POP3S", "Encrypted mail download", Other)),
    (
        "tcp",
        1433,
        info("SQL Server", "Microsoft SQL Server database", Database),
    ),
    ("tcp", 1521, info("Oracle", "Oracle database", Database)),
    ("tcp", 2049, info("NFS", "Network file sharing", Other)),
    (
        "tcp",
        2375,
        info("Docker", "Docker API without encryption", RemoteAdmin),
    ),
    ("tcp", 2376, info("Docker TLS", "Docker API", Other)),
    (
        "tcp",
        3306,
        info("MySQL", "MySQL or MariaDB database", Database),
    ),
    (
        "tcp",
        3389,
        info("RDP", "Windows remote desktop", RemoteAdmin),
    ),
    (
        "tcp",
        5432,
        info("PostgreSQL", "PostgreSQL database", Database),
    ),
    ("tcp", 5900, info("VNC", "Remote desktop", RemoteAdmin)),
    ("tcp", 5984, info("CouchDB", "CouchDB database", Database)),
    (
        "tcp",
        5985,
        info("WinRM", "Windows remote management", RemoteAdmin),
    ),
    (
        "tcp",
        5986,
        info("WinRM TLS", "Windows remote management", RemoteAdmin),
    ),
    ("tcp", 6379, info("Redis", "Redis database", Database)),
    (
        "tcp",
        8080,
        info("HTTP alternate", "Web pages and proxies", Other),
    ),
    (
        "tcp",
        8443,
        info("HTTPS alternate", "Encrypted web pages", Other),
    ),
    (
        "tcp",
        9042,
        info("Cassandra", "Cassandra database", Database),
    ),
    (
        "tcp",
        9200,
        info("Elasticsearch", "Elasticsearch database", Database),
    ),
    ("tcp", 11211, info("Memcached", "Memcached cache", Database)),
    ("tcp", 27017, info("MongoDB", "MongoDB database", Database)),
];

/// What the map knows about `protocol`/`port`, if anything.
#[must_use]
pub fn port_info(protocol: &str, port: u16) -> Option<PortInfo> {
    PORTS
        .iter()
        .find(|(p, n, _)| *p == protocol && *n == port)
        .map(|(_, _, info)| *info)
}

/// The log and list key of a port: `tcp/22`.
fn key(protocol: &str, port: u16) -> String {
    format!("{protocol}/{port}")
}

/// Keys (`tcp/5432`) of every known port.
#[must_use]
pub fn known_keys() -> Vec<String> {
    PORTS.iter().map(|(p, n, _)| key(p, *n)).collect()
}

/// Keys of every known port of `class`.
#[must_use]
pub fn keys_of(class: PortClass) -> Vec<String> {
    PORTS
        .iter()
        .filter(|(_, _, info)| info.class == class)
        .map(|(p, n, _)| key(p, *n))
        .collect()
}

/// Keys of the known ports whose name or usual use contains `needle`
/// (any case), for the list's search.
#[must_use]
pub fn keys_named(needle: &str) -> Vec<String> {
    let needle = needle.to_lowercase();
    PORTS
        .iter()
        .filter(|(_, _, info)| {
            info.name.to_lowercase().contains(&needle)
                || info.usual_use.to_lowercase().contains(&needle)
        })
        .map(|(p, n, _)| key(p, *n))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_ports_are_none() {
        assert!(port_info("tcp", 8081).is_none());
        assert!(port_info("udp", 22).is_none());
        assert_eq!(port_info("tcp", 22).unwrap().area, Some("SSH"));
    }

    #[test]
    fn classes_are_listed() {
        let databases = keys_of(PortClass::Database);
        assert_eq!(databases.len(), 10);
        assert!(databases.contains(&"tcp/5432".to_string()));
        let admin = keys_of(PortClass::RemoteAdmin);
        assert_eq!(admin.len(), 6);
        assert!(!admin.contains(&"tcp/22".to_string()));
        assert!(
            PORTS
                .iter()
                .all(|(_, _, i)| !i.name.is_empty() && !i.usual_use.is_empty())
        );
    }

    #[test]
    fn names_are_searchable() {
        assert!(keys_named("postgres").contains(&"tcp/5432".to_string()));
        assert!(keys_named("DNS").contains(&"udp/53".to_string()));
        assert!(keys_named("zzz").is_empty());
    }
}
