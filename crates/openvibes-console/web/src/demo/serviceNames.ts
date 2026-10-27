// The fixed map of well-known services, as platform-store's service_names.rs
// holds it (step 5f ruling 3): the usual name and use, the class that decides
// Needs a look, the compliance area and the packages of the usual server. A
// unit is looked up by its base: lower case, `.service` and any `@instance`
// removed.
export type ServiceClass = "database" | "remote_admin" | "other";
export type ServiceInfo = { name: string; usual_use: string; class: ServiceClass; area?: string; packages: string[] };

const s = (names: string[], name: string, usual_use: string, packages: string[], cls: ServiceClass = "other", area?: string): [string[], ServiceInfo] =>
  [names, { name, usual_use, class: cls, packages, ...(area ? { area } : {}) }];

const SERVICES: [string[], ServiceInfo][] = [
  s(["sshd", "ssh"], "OpenSSH server", "Secure remote login", ["openssh-server", "openssh"], "other", "SSH"),
  s(["nginx"], "nginx", "Web server and proxy", ["nginx"]),
  s(["apache2", "httpd"], "Apache HTTP Server", "Web server", ["apache2", "httpd"]),
  s(["haproxy"], "HAProxy", "Load balancer", ["haproxy"]),
  s(["postgresql"], "PostgreSQL", "PostgreSQL database", ["postgresql", "postgresql-server"], "database"),
  s(["mysqld", "mysql", "mariadb"], "MySQL or MariaDB", "MySQL or MariaDB database", ["mysql-server", "mariadb-server", "mysql-community-server"], "database"),
  s(["mongod", "mongodb"], "MongoDB", "MongoDB database", ["mongodb-org-server", "mongodb-server"], "database"),
  s(["redis", "redis-server"], "Redis", "Redis database", ["redis", "redis-server"], "database"),
  s(["memcached"], "Memcached", "Memcached cache", ["memcached"], "database"),
  s(["elasticsearch"], "Elasticsearch", "Elasticsearch database", ["elasticsearch"], "database"),
  s(["cassandra"], "Cassandra", "Cassandra database", ["cassandra"], "database"),
  s(["docker"], "Docker", "Container engine", ["docker-ce", "docker.io", "moby-engine"]),
  s(["containerd"], "containerd", "Container runtime", ["containerd", "containerd.io"]),
  s(["kubelet"], "kubelet", "Kubernetes node agent", ["kubelet"]),
  s(["libvirtd"], "libvirt", "Virtual machine manager", ["libvirt-daemon", "libvirt-bin"]),
  s(["crond", "cron"], "cron", "Scheduled jobs", ["cronie", "cron"]),
  s(["atd"], "at", "One-off scheduled jobs", ["at"]),
  s(["rsyslog", "rsyslogd"], "rsyslog", "System logging", ["rsyslog"]),
  s(["auditd"], "Linux audit", "Audit logging", ["audit", "auditd"]),
  s(["chronyd", "chrony"], "chrony", "Time sync", ["chrony"]),
  s(["ntpd", "ntp"], "ntpd", "Time sync", ["ntp", "ntpsec"]),
  s(["systemd-timesyncd"], "systemd-timesyncd", "Time sync", ["systemd-timesyncd"]),
  s(["named", "bind9"], "BIND", "Name server", ["bind", "bind9"]),
  s(["unbound"], "Unbound", "Name resolver", ["unbound"]),
  s(["dnsmasq"], "dnsmasq", "DNS and DHCP", ["dnsmasq"]),
  s(["smb", "smbd"], "Samba", "Windows file sharing", ["samba", "samba-common-bin"]),
  s(["nmb", "nmbd"], "Samba names", "Windows name service", ["samba", "samba-common-bin"]),
  s(["nfs-server", "nfs-kernel-server"], "NFS server", "Network file sharing", ["nfs-utils", "nfs-kernel-server"]),
  s(["rpcbind"], "rpcbind", "Remote procedure calls", ["rpcbind"]),
  s(["cups", "cupsd"], "CUPS", "Printing", ["cups"]),
  s(["avahi-daemon"], "Avahi", "Local network discovery (mDNS)", ["avahi", "avahi-daemon"]),
  s(["bluetooth"], "Bluetooth", "Bluetooth devices", ["bluez"]),
  s(["firewalld"], "firewalld", "Host firewall", ["firewalld"]),
  s(["fail2ban"], "Fail2ban", "Blocks repeated failed logins", ["fail2ban"]),
  s(["networkmanager"], "NetworkManager", "Network configuration", ["NetworkManager", "network-manager"]),
  s(["postfix"], "Postfix", "Mail server", ["postfix"]),
  s(["exim4", "exim"], "Exim", "Mail server", ["exim4", "exim"]),
  s(["sendmail"], "Sendmail", "Mail server", ["sendmail"]),
  s(["dovecot"], "Dovecot", "Mail access (IMAP, POP3)", ["dovecot", "dovecot-core"]),
  s(["vsftpd"], "vsftpd", "File transfer (FTP)", ["vsftpd"]),
  s(["snmpd"], "SNMP agent", "Device monitoring", ["net-snmp", "snmpd"]),
  s(["sssd"], "SSSD", "Directory logins", ["sssd"]),
  s(["tailscaled"], "Tailscale", "VPN", ["tailscale"]),
  s(["telnet", "telnetd", "telnet.socket"], "Telnet server", "Unencrypted remote login", ["telnetd", "telnet-server"], "remote_admin"),
  s(["xrdp"], "xrdp", "Remote desktop (RDP)", ["xrdp"], "remote_admin"),
  s(["vncserver", "tigervnc", "x11vnc"], "VNC server", "Remote desktop", ["tigervnc-server", "x11vnc"], "remote_admin"),
];

/** The base of a unit: lower case, `.service` and any `@instance` removed. */
export const baseOf = (unit: string): string => {
  const lower = unit.toLowerCase();
  return lower.endsWith(".service") ? (lower.slice(0, -".service".length).split("@")[0] ?? "") : lower;
};
/** What the map knows about a unit, by its base. */
export const serviceInfo = (unit: string): ServiceInfo | undefined => SERVICES.find(([names]) => names.includes(baseOf(unit)))?.[1];
/** Installed-package names (lower case) that count as "from a package" for a unit. */
export const candidates = (unit: string): string[] => [...new Set([baseOf(unit), ...(serviceInfo(unit)?.packages ?? []).map((p) => p.toLowerCase())])];
/** Bases whose name or usual use contains `needle` (any case). */
export const basesNamed = (needle: string): string[] => {
  const n = needle.toLowerCase();
  return SERVICES.filter(([, i]) => i.name.toLowerCase().includes(n) || i.usual_use.toLowerCase().includes(n)).flatMap(([names]) => names);
};
