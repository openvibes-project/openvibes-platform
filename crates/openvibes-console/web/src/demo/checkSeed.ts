// Hand-made compliance checks on top of data.ts's generated findings (no
// random() draws, so the rest of the demo stays put), for the cases the
// Compliance list must show (roles 5c): hardening-linux-l1 and a site rule
// set next to baseline, a check in every area, every triage state, an
// accepted risk that expired (counts as open), an ended finding (not
// failing), assignees (one person, two, none) and checks no host fails
// (passing only). The findings here are the list's only; their triage is
// in data.triage like the rest. Hosts: every third runs no hardening
// (data.ts), every fifth runs the site set (checkList.ts).
import type { Severity, Triage } from "../api/types";

const DAY = 86_400_000;
const HOUR = 3_600_000;

/** What console_rule_meta indexes for a rule: the title and the severity. */
export type CheckMeta = { ruleSetId: string; ruleId: string; title: string; severity: Severity };
/** A current finding the list counts; ended ones no longer fail. */
export type CheckFinding = {
  agent_id: string; rule_set_id: string; rule_id: string; severity: Severity;
  first_observed_at: string; last_observed_at: string; ended_at: string | null;
};

const HL1 = "hardening-linux-l1";
export const EXTRA_META: CheckMeta[] = [
  { ruleSetId: HL1, ruleId: "harden.ssh.permit_root_login", title: "SSH allows root login", severity: "critical" },
  { ruleSetId: HL1, ruleId: "harden.ssh.permit_empty_passwords", title: "SSH allows empty passwords", severity: "high" },
  { ruleSetId: HL1, ruleId: "harden.net.ip_forward", title: "IP forwarding is on", severity: "medium" },
  { ruleSetId: HL1, ruleId: "harden.kernel.aslr", title: "Address space randomisation is off", severity: "medium" },
  { ruleSetId: HL1, ruleId: "harden.files.shadow_perms", title: "/etc/shadow is readable by others", severity: "high" },
  { ruleSetId: HL1, ruleId: "harden.files.passwd_perms", title: "/etc/passwd is writable by others", severity: "high" },
  { ruleSetId: HL1, ruleId: "harden.accounts.no_empty_passwords", title: "An account has an empty password", severity: "critical" },
  { ruleSetId: HL1, ruleId: "harden.lsm.selinux_enforcing", title: "SELinux is not enforcing", severity: "medium" },
  { ruleSetId: HL1, ruleId: "harden.services.cups_disabled", title: "The print service is running", severity: "low" },
  { ruleSetId: "site", ruleId: "site.change_window.exceeded", title: "Change window exceeded", severity: "medium" },
  { ruleSetId: "site", ruleId: "test.canary", title: "Canary check", severity: "low" },
];

type Seed = { rule: string; set?: string; severity: Severity; hosts: {
  agent: string; days: number; state?: string; assignee?: string; until?: number; endedDaysAgo?: number }[] };

const SEEDS: Seed[] = [
  { rule: "harden.ssh.permit_root_login", severity: "critical", hosts: [
    { agent: "agent-00001", days: 12, assignee: "sam" }, { agent: "agent-00002", days: 9 },
    { agent: "agent-00004", days: 20, state: "mitigated" }, { agent: "agent-00005", days: 6, state: "accepted_risk", until: 60 },
    { agent: "agent-00007", days: 3, state: "false_positive" }] },
  { rule: "harden.ssh.permit_empty_passwords", severity: "high", hosts: [
    { agent: "agent-00001", days: 5 }, { agent: "agent-00002", days: 14, state: "accepted_risk", until: -2, assignee: "ola" }] },
  { rule: "harden.net.ip_forward", severity: "medium", hosts: [
    { agent: "agent-00004", days: 30 }, { agent: "agent-00005", days: 8, assignee: "sam" }, { agent: "agent-00007", days: 8, assignee: "ola" }] },
  { rule: "harden.kernel.aslr", severity: "medium", hosts: [
    { agent: "agent-00001", days: 25, endedDaysAgo: 2 }, { agent: "agent-00002", days: 4 }] },
  { rule: "harden.files.shadow_perms", severity: "high", hosts: [{ agent: "agent-00002", days: 17, state: "mitigated" }] },
  { rule: "harden.accounts.no_empty_passwords", severity: "critical", hosts: [{ agent: "agent-00001", days: 2 }] },
  { rule: "harden.lsm.selinux_enforcing", severity: "medium", hosts: [{ agent: "agent-00004", days: 40 }] },
  { rule: "harden.services.cups_disabled", severity: "low", hosts: [{ agent: "agent-00005", days: 11 }, { agent: "agent-00008", days: 11 }] },
  { rule: "site.change_window.exceeded", set: "site", severity: "medium", hosts: [{ agent: "agent-00001", days: 7, assignee: "sam" }, { agent: "agent-00004", days: 7 }] },
  { rule: "test.canary", set: "site", severity: "low", hosts: [{ agent: "agent-00002", days: 1 }] },
];

/** Adds the seeded findings (only on hosts that report) and their triage. */
export function seedChecks(now: number, reports: (agent: string) => boolean, findings: CheckFinding[], triage: Map<string, Triage>) {
  const iso = (ms: number) => new Date(ms).toISOString();
  for (const s of SEEDS) {
    const set = s.set ?? HL1;
    for (const h of s.hosts) {
      if (!reports(h.agent)) continue;
      findings.push({
        agent_id: h.agent, rule_set_id: set, rule_id: s.rule, severity: s.severity, first_observed_at: iso(now - h.days * DAY),
        last_observed_at: iso(now - (h.endedDaysAgo ?? 0) * DAY - 5 * 60_000), ended_at: h.endedDaysAgo == null ? null : iso(now - h.endedDaysAgo * DAY + HOUR),
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
