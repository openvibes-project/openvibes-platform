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
  evidence: string;
  hitRate: number;
};

const RULES: readonly DemoRule[] = [
  { ruleSetId: "hardening-ssh", ruleId: "SSH-001", severity: "critical", message: "SSH permits root login with a password", evidence: "sshd_config: PermitRootLogin yes", hitRate: 0.05 },
  { ruleSetId: "hardening-ssh", ruleId: "SSH-002", severity: "high", message: "SSH allows password authentication", evidence: "sshd_config: PasswordAuthentication yes", hitRate: 0.22 },
  { ruleSetId: "hardening-ssh", ruleId: "SSH-004", severity: "medium", message: "SSH uses a weak MAC algorithm", evidence: "sshd -T: macs hmac-sha1", hitRate: 0.12 },
  { ruleSetId: "baseline-linux", ruleId: "LNX-010", severity: "critical", message: "World-writable file in /etc", evidence: "/etc/cron.d/backup mode 0666", hitRate: 0.03 },
  { ruleSetId: "baseline-linux", ruleId: "LNX-014", severity: "high", message: "Host firewall is disabled", evidence: "firewalld.service inactive", hitRate: 0.16 },
  { ruleSetId: "baseline-linux", ruleId: "LNX-021", severity: "high", message: "Unexpected SUID binary", evidence: "/usr/local/bin/helper mode 4755", hitRate: 0.04 },
  { ruleSetId: "baseline-linux", ruleId: "LNX-030", severity: "medium", message: "Automatic security updates are off", evidence: "dnf-automatic.timer disabled", hitRate: 0.35 },
  { ruleSetId: "baseline-linux", ruleId: "LNX-033", severity: "medium", message: "SELinux is permissive", evidence: "getenforce: Permissive", hitRate: 0.1 },
  { ruleSetId: "baseline-linux", ruleId: "LNX-041", severity: "low", message: "Core dumps are enabled for SUID programs", evidence: "fs.suid_dumpable = 2", hitRate: 0.18 },
  { ruleSetId: "baseline-linux", ruleId: "LNX-052", severity: "low", message: "Time synchronisation is not configured", evidence: "chronyd.service inactive", hitRate: 0.07 },
  { ruleSetId: "baseline-linux", ruleId: "LNX-060", severity: "high", message: "Listening service bound to all interfaces", evidence: "0.0.0.0:6379 redis-server", hitRate: 0.06 },
  { ruleSetId: "cis-fedora", ruleId: "CIS-1.1.2", severity: "medium", message: "/tmp is not a separate partition", evidence: "findmnt /tmp: not mounted", hitRate: 0.4 },
  { ruleSetId: "cis-fedora", ruleId: "CIS-5.2.1", severity: "low", message: "Password expiry longer than 365 days", evidence: "PASS_MAX_DAYS 99999", hitRate: 0.5 },
  { ruleSetId: "cis-fedora", ruleId: "CIS-4.1.1", severity: "medium", message: "Audit daemon is not running", evidence: "auditd.service inactive", hitRate: 0.14 },
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
        scan_id: `scan-${agent.id}-${Math.floor(now / DAY)}`,
        authenticated: agent.status !== "imported",
        origin: agent.status === "imported" ? "import" : "online",
        first_observed_at: iso(first),
        last_observed_at: iso(agent.last_seen_at ? Date.parse(agent.last_seen_at) : first),
        received_at: iso(agent.last_seen_at ? Date.parse(agent.last_seen_at) : first),
      });
      const state = random() < 0.72 ? "open" : pick(["investigating", "mitigated", "accepted_risk", "false_positive"]);
      triage.set(`${agent.id}|${rule.ruleSetId}|${rule.ruleId}`, {
        state, version: 1, rule_version: 3,
        assigned_to: state === "investigating" ? "analyst" : null,
        note: state === "accepted_risk" ? "Isolated lab network; revisit next quarter." : null,
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
      });
    }
  }

  const people = [
    ["u-admin", "admin", "Alex Admin"], ["u-sam", "sam", "Sam Analyst"], ["u-ola", "ola", "Ola Operator"],
    ["u-vic", "vic", "Vic Viewer"], ["u-lab", "lab-ops", "Lab operator"],
  ] as const;
  const access: AccessInventory = {
    roles: [
      { role_id: "viewer", display_name: "Viewer", builtin: true, permissions: ["agents.read", "findings.read", "vulnerabilities.read"] },
      { role_id: "analyst", display_name: "Analyst", builtin: true, permissions: ["agents.read", "findings.read", "vulnerabilities.read", "findings.triage", "assistant.use"] },
      { role_id: "operator", display_name: "Operator", builtin: true, permissions: ["agents.read", "agents.revoke", "findings.read", "vulnerabilities.read", "tokens.read", "tokens.create", "tokens.revoke", "rules.upload"] },
      { role_id: "admin", display_name: "Admin", builtin: true, permissions: ["agents.read", "agents.revoke", "findings.read", "vulnerabilities.read", "findings.triage", "tokens.read", "tokens.create", "tokens.revoke", "rules.read", "rules.upload", "audit.read", "audit.export", "audit.retention.manage", "rbac.read", "rbac.manage", "asset_groups.manage", "service_accounts.read", "service_accounts.manage", "assistant.use"] },
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
    { token_id: "tok-7f3a", label: "Office laptops", created_at: iso(now - 2 * DAY), expires_at: iso(now + 5 * DAY), max_uses: 25, uses: 9, revoked: false },
    { token_id: "tok-19c2", label: "k8s node pool", created_at: iso(now - 6 * DAY), expires_at: iso(now + 1 * DAY), max_uses: 10, uses: 10, revoked: false },
    { token_id: "tok-88e0", label: "Lab rebuild", created_at: iso(now - 20 * DAY), expires_at: iso(now - 13 * DAY), max_uses: 5, uses: 3, revoked: false },
    { token_id: "tok-02bd", label: "Leaked in a ticket", created_at: iso(now - 9 * DAY), expires_at: iso(now + 20 * DAY), max_uses: 50, uses: 1, revoked: true },
  ];

  const ruleSets: RuleSet[] = ["baseline-linux", "hardening-ssh", "cis-fedora"].map((rule_set_id, index) => ({
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
    ["user.login", "user", "console", null], ["finding.triage", "finding", "hardening-ssh/SSH-002", "finding"],
    ["enrollment_token.create", "token", "tok-7f3a", "enrollment_token"], ["agent.revoke", "agent", "agent-00047", "agent"],
    ["rule_bundle.publish", "rule_set", "baseline-linux", "rule_set"], ["access.binding.create", "binding", "b-5", "binding"],
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

  return {
    now, rules: RULES, agents, tags, certificates, findings, triage, advisories, vulnerabilities, access,
    enrollmentTokens, ruleSets, bundles, serviceAccounts, serviceTokens, audit,
    retention: { retention_days: 365, updated_at: iso(now - 90 * DAY), updated_by: "admin", version: 1 },
  };
}
