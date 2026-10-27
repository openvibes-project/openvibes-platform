//! A fixed map of well-known services (step 5f ruling 3): what a unit
//! usually is, the class that decides "Needs a look", and the packages of
//! its usual server. Like `port_names`, the spec's "fixed list of plain
//! rules in code"; one file to edit.
//!
//! A unit is looked up by its *base*: lower case, with `.service` and any
//! `@instance` removed (`postgresql@16-main.service` is `postgresql`). The
//! SQL twin of `base` is `BASE_SQL`.

/// What kind of service a unit usually is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceClass {
    /// A database server.
    Database,
    /// Remote administration of a machine.
    RemoteAdmin,
    /// Anything else.
    Other,
}

/// What the map knows about a service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceInfo {
    /// The usual name, e.g. `OpenSSH server`.
    pub name: &'static str,
    /// The usual use, one plain phrase.
    pub usual_use: &'static str,
    /// Its class.
    pub class: ServiceClass,
    /// The compliance area whose checks concern it, when there is one.
    pub area: Option<&'static str>,
    /// Packages of the server (a host "has it from a package" when one of
    /// these, or a package named like the unit, is installed).
    pub packages: &'static [&'static str],
}

use ServiceClass::{Database, Other, RemoteAdmin};

const fn info(
    name: &'static str,
    usual_use: &'static str,
    class: ServiceClass,
    packages: &'static [&'static str],
) -> ServiceInfo {
    ServiceInfo {
        name,
        usual_use,
        class,
        area: None,
        packages,
    }
}

/// Every known service: its base names (aliases across distributions) and
/// what it is.
const SERVICES: &[(&[&str], ServiceInfo)] = &[
    (
        &["sshd", "ssh"],
        ServiceInfo {
            area: Some("SSH"),
            ..info(
                "OpenSSH server",
                "Secure remote login",
                Other,
                &["openssh-server", "openssh"],
            )
        },
    ),
    (
        &["nginx"],
        info("nginx", "Web server and proxy", Other, &["nginx"]),
    ),
    (
        &["apache2", "httpd"],
        info(
            "Apache HTTP Server",
            "Web server",
            Other,
            &["apache2", "httpd"],
        ),
    ),
    (
        &["haproxy"],
        info("HAProxy", "Load balancer", Other, &["haproxy"]),
    ),
    (
        &["postgresql"],
        info(
            "PostgreSQL",
            "PostgreSQL database",
            Database,
            &["postgresql", "postgresql-server"],
        ),
    ),
    (
        &["mysqld", "mysql", "mariadb"],
        info(
            "MySQL or MariaDB",
            "MySQL or MariaDB database",
            Database,
            &["mysql-server", "mariadb-server", "mysql-community-server"],
        ),
    ),
    (
        &["mongod", "mongodb"],
        info(
            "MongoDB",
            "MongoDB database",
            Database,
            &["mongodb-org-server", "mongodb-server"],
        ),
    ),
    (
        &["redis", "redis-server"],
        info(
            "Redis",
            "Redis database",
            Database,
            &["redis", "redis-server"],
        ),
    ),
    (
        &["memcached"],
        info("Memcached", "Memcached cache", Database, &["memcached"]),
    ),
    (
        &["elasticsearch"],
        info(
            "Elasticsearch",
            "Elasticsearch database",
            Database,
            &["elasticsearch"],
        ),
    ),
    (
        &["cassandra"],
        info("Cassandra", "Cassandra database", Database, &["cassandra"]),
    ),
    (
        &["docker"],
        info(
            "Docker",
            "Container engine",
            Other,
            &["docker-ce", "docker.io", "moby-engine"],
        ),
    ),
    (
        &["containerd"],
        info(
            "containerd",
            "Container runtime",
            Other,
            &["containerd", "containerd.io"],
        ),
    ),
    (
        &["kubelet"],
        info("kubelet", "Kubernetes node agent", Other, &["kubelet"]),
    ),
    (
        &["libvirtd"],
        info(
            "libvirt",
            "Virtual machine manager",
            Other,
            &["libvirt-daemon", "libvirt-bin"],
        ),
    ),
    (
        &["crond", "cron"],
        info("cron", "Scheduled jobs", Other, &["cronie", "cron"]),
    ),
    (
        &["atd"],
        info("at", "One-off scheduled jobs", Other, &["at"]),
    ),
    (
        &["rsyslog", "rsyslogd"],
        info("rsyslog", "System logging", Other, &["rsyslog"]),
    ),
    (
        &["auditd"],
        info("Linux audit", "Audit logging", Other, &["audit", "auditd"]),
    ),
    (
        &["chronyd", "chrony"],
        info("chrony", "Time sync", Other, &["chrony"]),
    ),
    (
        &["ntpd", "ntp"],
        info("ntpd", "Time sync", Other, &["ntp", "ntpsec"]),
    ),
    (
        &["systemd-timesyncd"],
        info(
            "systemd-timesyncd",
            "Time sync",
            Other,
            &["systemd-timesyncd"],
        ),
    ),
    (
        &["named", "bind9"],
        info("BIND", "Name server", Other, &["bind", "bind9"]),
    ),
    (
        &["unbound"],
        info("Unbound", "Name resolver", Other, &["unbound"]),
    ),
    (
        &["dnsmasq"],
        info("dnsmasq", "DNS and DHCP", Other, &["dnsmasq"]),
    ),
    (
        &["smb", "smbd"],
        info(
            "Samba",
            "Windows file sharing",
            Other,
            &["samba", "samba-common-bin"],
        ),
    ),
    (
        &["nmb", "nmbd"],
        info(
            "Samba names",
            "Windows name service",
            Other,
            &["samba", "samba-common-bin"],
        ),
    ),
    (
        &["nfs-server", "nfs-kernel-server"],
        info(
            "NFS server",
            "Network file sharing",
            Other,
            &["nfs-utils", "nfs-kernel-server"],
        ),
    ),
    (
        &["rpcbind"],
        info("rpcbind", "Remote procedure calls", Other, &["rpcbind"]),
    ),
    (
        &["cups", "cupsd"],
        info("CUPS", "Printing", Other, &["cups"]),
    ),
    (
        &["avahi-daemon"],
        info(
            "Avahi",
            "Local network discovery (mDNS)",
            Other,
            &["avahi", "avahi-daemon"],
        ),
    ),
    (
        &["bluetooth"],
        info("Bluetooth", "Bluetooth devices", Other, &["bluez"]),
    ),
    (
        &["firewalld"],
        info("firewalld", "Host firewall", Other, &["firewalld"]),
    ),
    (
        &["fail2ban"],
        info(
            "Fail2ban",
            "Blocks repeated failed logins",
            Other,
            &["fail2ban"],
        ),
    ),
    (
        &["networkmanager"],
        info(
            "NetworkManager",
            "Network configuration",
            Other,
            &["NetworkManager", "network-manager"],
        ),
    ),
    (
        &["postfix"],
        info("Postfix", "Mail server", Other, &["postfix"]),
    ),
    (
        &["exim4", "exim"],
        info("Exim", "Mail server", Other, &["exim4", "exim"]),
    ),
    (
        &["sendmail"],
        info("Sendmail", "Mail server", Other, &["sendmail"]),
    ),
    (
        &["dovecot"],
        info(
            "Dovecot",
            "Mail access (IMAP, POP3)",
            Other,
            &["dovecot", "dovecot-core"],
        ),
    ),
    (
        &["vsftpd"],
        info("vsftpd", "File transfer (FTP)", Other, &["vsftpd"]),
    ),
    (
        &["snmpd"],
        info(
            "SNMP agent",
            "Device monitoring",
            Other,
            &["net-snmp", "snmpd"],
        ),
    ),
    (
        &["sssd"],
        info("SSSD", "Directory logins", Other, &["sssd"]),
    ),
    (
        &["tailscaled"],
        info("Tailscale", "VPN", Other, &["tailscale"]),
    ),
    (
        &["telnet", "telnetd", "telnet.socket"],
        info(
            "Telnet server",
            "Unencrypted remote login",
            RemoteAdmin,
            &["telnetd", "telnet-server"],
        ),
    ),
    (
        &["xrdp"],
        info("xrdp", "Remote desktop (RDP)", RemoteAdmin, &["xrdp"]),
    ),
    (
        &["vncserver", "tigervnc", "x11vnc"],
        info(
            "VNC server",
            "Remote desktop",
            RemoteAdmin,
            &["tigervnc-server", "x11vnc"],
        ),
    ),
];

/// The base of a unit: lower case, `.service` and any `@instance` removed.
#[must_use]
pub fn base(unit: &str) -> String {
    let lower = unit.to_lowercase();
    match lower.strip_suffix(".service") {
        Some(name) => name.split('@').next().unwrap_or(name).to_owned(),
        None => lower,
    }
}

/// The SQL twin of [`base`] for a unit column `unit` (kept equal by a test).
pub const BASE_SQL: &str = "lower(regexp_replace({unit}, '(@.*)?\\.service$', ''))";

/// [`BASE_SQL`] for the column `column`.
#[must_use]
pub fn base_sql(column: &str) -> String {
    BASE_SQL.replace("{unit}", column)
}

/// What the map knows about `unit`, if anything.
#[must_use]
pub fn service_info(unit: &str) -> Option<ServiceInfo> {
    let base = base(unit);
    SERVICES
        .iter()
        .find(|(names, _)| names.contains(&base.as_str()))
        .map(|(_, info)| *info)
}

/// The installed-package names (lower case) that count as "from a package"
/// for `unit`: its base and the map's packages for it.
#[must_use]
pub fn candidates(unit: &str) -> Vec<String> {
    let base = base(unit);
    let mut names = vec![base.clone()];
    if let Some(info) = service_info(unit) {
        names.extend(info.packages.iter().map(|p| p.to_lowercase()));
    }
    names.sort();
    names.dedup();
    names
}

/// Bases of every known service.
#[must_use]
pub fn known_bases() -> Vec<String> {
    SERVICES
        .iter()
        .flat_map(|(names, _)| names.iter().map(|n| (*n).to_owned()))
        .collect()
}

/// Bases of every known service of `class`.
#[must_use]
pub fn bases_of(class: ServiceClass) -> Vec<String> {
    SERVICES
        .iter()
        .filter(|(_, info)| info.class == class)
        .flat_map(|(names, _)| names.iter().map(|n| (*n).to_owned()))
        .collect()
}

/// Bases whose name or usual use contains `needle` (any case), for the
/// list's search.
#[must_use]
pub fn bases_named(needle: &str) -> Vec<String> {
    let needle = needle.to_lowercase();
    SERVICES
        .iter()
        .filter(|(_, info)| {
            info.name.to_lowercase().contains(&needle)
                || info.usual_use.to_lowercase().contains(&needle)
        })
        .flat_map(|(names, _)| names.iter().map(|n| (*n).to_owned()))
        .collect()
}

/// The map's packages as two parallel lists (base, package name), for the
/// SQL that matches a unit to installed packages.
#[must_use]
pub fn package_pairs() -> (Vec<String>, Vec<String>) {
    SERVICES
        .iter()
        .flat_map(|(names, info)| {
            names.iter().flat_map(move |n| {
                info.packages
                    .iter()
                    .map(move |p| ((*n).to_owned(), (*p).to_lowercase()))
            })
        })
        .unzip()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unit_is_found_by_its_base() {
        assert_eq!(base("sshd.service"), "sshd");
        assert_eq!(base("PostgreSQL@16-main.service"), "postgresql");
        assert_eq!(base("getty@tty1.service"), "getty");
        assert_eq!(base("telnet.socket"), "telnet.socket");
        assert_eq!(base("Spooler"), "spooler");
        assert_eq!(service_info("ssh.service").unwrap().area, Some("SSH"));
        assert_eq!(
            service_info("postgresql@16-main.service").unwrap().class,
            Database
        );
        assert!(service_info("mystery.service").is_none());
    }

    #[test]
    fn classes_and_names_are_listed() {
        let databases = bases_of(Database);
        assert!(databases.contains(&"redis-server".to_owned()));
        assert!(!databases.contains(&"sshd".to_owned()));
        assert!(bases_of(RemoteAdmin).contains(&"xrdp".to_owned()));
        assert!(bases_named("postgres").contains(&"postgresql".to_owned()));
        assert!(bases_named("zzz").is_empty());
        let (bases, packages) = package_pairs();
        assert_eq!(bases.len(), packages.len());
        assert!(
            bases
                .iter()
                .zip(&packages)
                .any(|(b, p)| b == "sshd" && p == "openssh-server")
        );
        for (names, info) in SERVICES {
            assert!(!names.is_empty() && !info.name.is_empty() && !info.usual_use.is_empty());
            assert!(
                names.iter().all(|n| *n == n.to_lowercase()),
                "{names:?} is lower case"
            );
        }
    }
}
