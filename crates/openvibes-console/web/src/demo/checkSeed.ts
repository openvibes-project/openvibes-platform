// Hand-made compliance checks on top of data.ts's generated findings (no
// random() draws, so the rest of the demo stays put), for the cases the
// Compliance list must show (roles 5c): hardening-linux-l1 and a site rule
// set next to baseline, a check in every area, every triage state, an
// accepted risk that expired (counts as open), an ended finding (not
// failing), assignees (one person, two, none) and checks no host fails
// (passing only). They join data.findings and data.triage, so every page
// sees them. Hosts: every third runs no hardening, hosts 1-4 and every
// fifth run the site set (data.ts).
import type { Finding, Severity, Triage } from "../api/types";

const DAY = 86_400_000;
const HOUR = 3_600_000;

/** What console_rule_meta indexes for a rule: the title and the severity. */
export type CheckMeta = { ruleSetId: string; ruleId: string; title: string; severity: Severity };
/** A current finding; an ended one (protocol P13, `ended_at`) no longer fails. */
export type DemoFinding = Finding & { ended_at?: string | null };

const HL1 = "hardening-linux-l1";
export const EXTRA_META: CheckMeta[] = [
  // openvibes-rules hardening/linux-l1: ids, titles and severities as shipped.
  { ruleSetId: HL1, ruleId: "harden.ssh.permit_root_login", title: "SSH allows root to log in with a password", severity: "high" },
  { ruleSetId: HL1, ruleId: "harden.ssh.permit_empty_passwords", title: "SSH allows empty passwords", severity: "high" },
  { ruleSetId: HL1, ruleId: "harden.net.ip_forward", title: "The host forwards IP packets", severity: "low" },
  { ruleSetId: HL1, ruleId: "harden.kernel.aslr", title: "Address space randomisation is weakened", severity: "high" },
  { ruleSetId: HL1, ruleId: "harden.files.shadow", title: "/etc/shadow is open to other users", severity: "high" },
  { ruleSetId: HL1, ruleId: "harden.files.passwd", title: "/etc/passwd or /etc/group can be changed by other users", severity: "medium" },
  { ruleSetId: HL1, ruleId: "harden.accounts.empty_password", title: "An account has an empty password", severity: "critical" },
  { ruleSetId: HL1, ruleId: "harden.lsm.selinux_off", title: "SELinux is disabled", severity: "medium" },
  { ruleSetId: HL1, ruleId: "harden.services.avahi", title: "Avahi (mDNS) is enabled", severity: "low" },
  // The site's own rule set: invented, as a site's rules are.
  { ruleSetId: "site", ruleId: "site.change_window.exceeded", title: "Change window exceeded", severity: "medium" },
  { ruleSetId: "site", ruleId: "test.canary", title: "Canary check", severity: "low" },
];

type Seed = { rule: string; set?: string; severity: Severity; hosts: {
  agent: string; days: number; state?: string; assignee?: string; until?: number; endedDaysAgo?: number }[] };

const SEEDS: Seed[] = [
  { rule: "harden.ssh.permit_root_login", severity: "high", hosts: [
    { agent: "agent-00001", days: 12, assignee: "sam" }, { agent: "agent-00002", days: 9 },
    { agent: "agent-00004", days: 20, state: "mitigated" }, { agent: "agent-00005", days: 6, state: "accepted_risk", until: 60 },
    { agent: "agent-00007", days: 3, state: "false_positive" }] },
  { rule: "harden.ssh.permit_empty_passwords", severity: "high", hosts: [
    { agent: "agent-00001", days: 5 }, { agent: "agent-00002", days: 14, state: "accepted_risk", until: -2, assignee: "ola" }] },
  { rule: "harden.net.ip_forward", severity: "low", hosts: [
    { agent: "agent-00004", days: 30 }, { agent: "agent-00005", days: 8, assignee: "sam" }, { agent: "agent-00007", days: 8, assignee: "ola" }] },
  { rule: "harden.kernel.aslr", severity: "high", hosts: [
    { agent: "agent-00001", days: 25, endedDaysAgo: 2 }, { agent: "agent-00002", days: 4 }] },
  { rule: "harden.files.shadow", severity: "high", hosts: [{ agent: "agent-00002", days: 17, state: "mitigated" }] },
  { rule: "harden.accounts.empty_password", severity: "critical", hosts: [{ agent: "agent-00001", days: 2 }] },
  { rule: "harden.lsm.selinux_off", severity: "medium", hosts: [{ agent: "agent-00004", days: 40 }] },
  { rule: "harden.services.avahi", severity: "low", hosts: [{ agent: "agent-00005", days: 11 }, { agent: "agent-00008", days: 11 }] },
  { rule: "site.change_window.exceeded", set: "site", severity: "medium", hosts: [{ agent: "agent-00001", days: 7, assignee: "sam" }, { agent: "agent-00004", days: 7 }] },
  { rule: "test.canary", set: "site", severity: "low", hosts: [{ agent: "agent-00002", days: 1 }] },
];

/** Adds the seeded findings (only on hosts that report) and their triage. */
export function seedChecks(now: number, hostname: (agent: string) => string | null | undefined, findings: DemoFinding[], triage: Map<string, Triage>) {
  const iso = (ms: number) => new Date(ms).toISOString();
  const meta = new Map(EXTRA_META.map((m) => [m.ruleId, m]));
  for (const s of SEEDS) {
    const set = s.set ?? HL1;
    const title = meta.get(s.rule)?.title ?? s.rule;
    for (const h of s.hosts) {
      const name = hostname(h.agent);
      if (name === undefined) continue;
      const last = iso(now - (h.endedDaysAgo ?? 0) * DAY - 5 * 60_000);
      findings.push({
        id: `finding-${findings.length + 1}`, agent_id: h.agent, hostname: name, rule_set_id: set, rule_id: s.rule, rule_version: 3,
        severity: s.severity, confidence: 90, message: title, evidence: [s.rule],
        detection: {
          observed_at_unix_ms: now - 5 * 60_000, rule_set_version: set === "site" ? 10 : 4, preimage_sha256: "c".repeat(64), truncated: false,
          inputs: [{ key: s.rule, status: "summarized", value: null, item_count: 1 }], steps: [{ expression: `facts['${s.rule}']`, result: true }],
        },
        scan_id: `scan-${h.agent}-${Math.floor(now / DAY)}`, authenticated: true, origin: "online",
        first_observed_at: iso(now - h.days * DAY), last_observed_at: last, received_at: last,
        ended_at: h.endedDaysAgo == null ? null : iso(now - h.endedDaysAgo * DAY + HOUR),
      });
      if (h.state || h.assignee) {
        triage.set(`${h.agent}|${set}|${s.rule}`, {
          state: h.state ?? "open", version: 1, rule_version: 3, assigned_to: h.assignee ?? null,
          note: h.state === "accepted_risk" ? "Isolated lab network; revisit next quarter." : h.state ? "Handled outside the console." : null,
          accepted_until: h.until == null ? null : iso(now + h.until * DAY),
        });
      }
    }
  }
}
