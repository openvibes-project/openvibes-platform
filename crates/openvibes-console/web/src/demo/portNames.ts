// The fixed map of well-known ports, as platform-store's port_names.rs holds it
// (step 5e ruling 9): the usual name and use, the class that decides Needs a
// look, the compliance area and the packages of the usual server.
export type PortClass = "database" | "remote_admin" | "other";
export type PortInfo = { name: string; usual_use: string; class: PortClass; area?: string; packages?: string[] };

const p = (protocol: string, port: number, name: string, usual_use: string, cls: PortClass = "other"): [string, PortInfo] =>
  [`${protocol}/${port}`, { name, usual_use, class: cls }];

const MAP = new Map<string, PortInfo>([
  p("tcp", 21, "FTP", "File transfer"),
  ["tcp/22", { name: "SSH", usual_use: "Secure remote login", class: "other", area: "SSH", packages: ["openssh-server", "openssh"] }],
  p("tcp", 23, "Telnet", "Unencrypted remote login", "remote_admin"),
  p("tcp", 25, "SMTP", "Mail delivery between servers"),
  p("tcp", 53, "DNS", "Name lookups"), p("udp", 53, "DNS", "Name lookups"),
  p("tcp", 80, "HTTP", "Web pages"), p("tcp", 110, "POP3", "Mail download"),
  p("tcp", 111, "RPC", "Remote procedure calls (rpcbind)"), p("udp", 123, "NTP", "Time sync"),
  p("udp", 137, "NetBIOS name", "Windows name service"), p("udp", 138, "NetBIOS datagram", "Windows file sharing"),
  p("tcp", 139, "NetBIOS session", "Windows file sharing"), p("tcp", 143, "IMAP", "Mail access"),
  p("udp", 161, "SNMP", "Device monitoring"), p("tcp", 389, "LDAP", "Directory lookups"),
  p("tcp", 443, "HTTPS", "Encrypted web pages"), p("tcp", 445, "SMB", "Windows file sharing"),
  p("tcp", 465, "SMTPS", "Encrypted mail submission"), p("tcp", 587, "Submission", "Mail submission"),
  p("tcp", 631, "IPP", "Printing (CUPS)"), p("tcp", 636, "LDAPS", "Encrypted directory lookups"),
  p("tcp", 993, "IMAPS", "Encrypted mail access"), p("tcp", 995, "POP3S", "Encrypted mail download"),
  p("tcp", 1433, "SQL Server", "Microsoft SQL Server database", "database"), p("tcp", 1521, "Oracle", "Oracle database", "database"),
  p("tcp", 2049, "NFS", "Network file sharing"), p("tcp", 2375, "Docker", "Docker API without encryption", "remote_admin"),
  p("tcp", 2376, "Docker TLS", "Docker API"), p("tcp", 3306, "MySQL", "MySQL or MariaDB database", "database"),
  p("tcp", 3389, "RDP", "Windows remote desktop", "remote_admin"), p("tcp", 5432, "PostgreSQL", "PostgreSQL database", "database"),
  p("tcp", 5900, "VNC", "Remote desktop", "remote_admin"), p("tcp", 5984, "CouchDB", "CouchDB database", "database"),
  p("tcp", 5985, "WinRM", "Windows remote management", "remote_admin"), p("tcp", 5986, "WinRM TLS", "Windows remote management", "remote_admin"),
  p("tcp", 6379, "Redis", "Redis database", "database"), p("tcp", 8080, "HTTP alternate", "Web pages and proxies"),
  p("tcp", 8443, "HTTPS alternate", "Encrypted web pages"), p("tcp", 9042, "Cassandra", "Cassandra database", "database"),
  p("tcp", 9200, "Elasticsearch", "Elasticsearch database", "database"), p("tcp", 11211, "Memcached", "Memcached cache", "database"),
  p("tcp", 27017, "MongoDB", "MongoDB database", "database"),
]);

/** What the map knows about a port, by key (`tcp/22`). */
export const portInfo = (key: string): PortInfo | undefined => MAP.get(key);
/** Keys whose name or usual use contains `needle` (any case). */
export const keysNamed = (needle: string): string[] => {
  const n = needle.toLowerCase();
  return [...MAP].filter(([, i]) => i.name.toLowerCase().includes(n) || i.usual_use.toLowerCase().includes(n)).map(([k]) => k);
};
