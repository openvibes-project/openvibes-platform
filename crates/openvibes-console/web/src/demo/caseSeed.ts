// The cases the demo starts with (see cases.ts for the store and its rules).
import type { CaseKind } from "../panels/cases";
import type { CaseState } from "./cases";
import type { DemoData } from "./data";

type Body = Record<string, unknown>;
type StoredEvent = CaseState["events"][number];

/** Cases the demo starts with, over objects that exist in the demo data. */
export function seedCases(data: DemoData): CaseState {
  const minutes = (ago: number) => new Date(data.now - ago * 60_000).toISOString();
  const state: CaseState = { v: 2, next_number: 101, next_event: 1, cases: [], items: [], events: [] };
  const host = (id: string) => data.agents.find((a) => a.id === id);
  const short = (id: string) => (host(id)?.hostname ?? id).split(".")[0] ?? id;
  const findingOf = (f: { agent_id: string; rule_set_id: string; rule_id: string }) => `${f.agent_id}/${f.rule_set_id}/${f.rule_id}`;
  const triageOf = (f: { agent_id: string; rule_set_id: string; rule_id: string }) => data.triage.get(`${f.agent_id}|${f.rule_set_id}|${f.rule_id}`)?.state;

  type Spec = {
    title: string; severity: string; status: string; assignee?: string; openedBy: string; openedAgo: number;
    items: { kind: CaseKind; ref: string; agent_id: string | null; by: string; ago: number; outcome?: string; note?: string }[];
    timeline: { ago: number; actor: string; kind: string; body?: string; detail?: Body }[];
    ending?: { resolution: string; note: string; ago: number; until?: string };
  };
  const add = (spec: Spec) => {
    const caseId = crypto.randomUUID();
    const number = state.next_number;
    state.next_number += 1;
    const closedCase = spec.ending !== undefined;
    const events: Omit<StoredEvent, "event_id">[] = [];
    const event = (ago: number, actor: string | null, kind: string, body: string | null, detail: Body) =>
      events.push({ case_id: caseId, at: minutes(ago), actor_user_id: actor, kind, body, detail });
    event(spec.openedAgo, spec.openedBy, "created", null, { severity: spec.severity });
    if (spec.assignee) event(spec.openedAgo, spec.openedBy, "assigned", null, { from: null, to: spec.assignee.replace("u-", "") });
    for (const item of spec.items) {
      const itemId = crypto.randomUUID();
      state.items.push({
        item_id: itemId, case_id: caseId, kind: item.kind, ref: item.ref, agent_id: item.agent_id, active: !closedCase,
        outcome: item.outcome ?? null, outcome_note: item.note ?? null, added_by_user_id: item.by, added_at: minutes(item.ago),
      });
      event(item.ago, item.by, "item_added", null, { item_id: itemId, item_kind: item.kind, item_ref: item.ref, item_agent_id: item.agent_id });
      if (item.outcome) event(Math.max(0, item.ago - 20), item.by, "item_outcome", item.note ?? null, { item_id: itemId, item_kind: item.kind, item_ref: item.ref, item_agent_id: item.agent_id, from: null, to: item.outcome });
    }
    for (const t of spec.timeline) event(t.ago, t.actor, t.kind, t.body ?? null, t.detail ?? {});
    if (spec.ending) event(spec.ending.ago, spec.assignee ?? spec.openedBy, "resolved", spec.ending.note, { resolution: spec.ending.resolution, accepted_until: spec.ending.until ?? null });
    events.sort((a, b) => a.at.localeCompare(b.at));
    for (const e of events) { state.events.push({ ...e, event_id: state.next_event }); state.next_event += 1; }
    const last = events[events.length - 1]?.at ?? minutes(spec.openedAgo);
    state.cases.push({
      case_id: caseId, number, title: spec.title, status: spec.status, resolution: spec.ending?.resolution ?? null, resolution_note: spec.ending?.note ?? null,
      accepted_until: spec.ending?.until ?? null, severity: spec.severity, assignee_user_id: spec.assignee ?? null, opened_by_user_id: spec.openedBy,
      created_at: minutes(spec.openedAgo), updated_at: last, closed_at: spec.ending ? minutes(spec.ending.ago) : null,
      version: 1 + events.filter((e) => ["status", "assigned", "severity", "resolved"].includes(e.kind)).length,
    });
  };

  // The oldest case, closed: a finding fixed on a host (evidence gone) and one that is expected there.
  const fixed = data.findings.find((f) => triageOf(f) === "mitigated");
  const sibling = fixed && data.findings.find((f) => f.agent_id === fixed.agent_id && f !== fixed);
  if (fixed) {
    add({
      title: `Clean up: ${fixed.message.toLowerCase()} on ${short(fixed.agent_id)}`, severity: "medium", status: "closed", assignee: "u-sam", openedBy: "u-sam", openedAgo: 9 * 1440,
      items: [
        { kind: "host", ref: fixed.agent_id, agent_id: fixed.agent_id, by: "u-sam", ago: 9 * 1440 - 5 },
        { kind: "compliance_finding", ref: findingOf(fixed), agent_id: fixed.agent_id, by: "u-sam", ago: 9 * 1440 - 6, outcome: "resolved" },
        ...(sibling ? [{ kind: "compliance_finding" as const, ref: findingOf(sibling), agent_id: sibling.agent_id, by: "u-sam", ago: 9 * 1440 - 7, outcome: "false_positive", note: "Expected on this image; the owner confirmed." }] : []),
      ],
      timeline: [
        { ago: 8 * 1440, actor: "u-sam", kind: "note", body: "The config management change is merged and rolled out; waiting for the next scan to confirm." },
        { ago: 7 * 1440, actor: "u-sam", kind: "status", detail: { from: "open", to: "investigating" } },
      ],
      ending: { resolution: "mitigated", note: "Fixed through configuration management; the agent no longer reports it.", ago: 3 * 1440 },
    });
  }

  // An exploited advisory on several hosts: a vulnerability case, in progress.
  const exploited = data.vulnerabilities.filter((v) => v.exploited);
  const byAdvisory = new Map<string, typeof exploited>();
  for (const v of exploited) byAdvisory.set(v.advisory_id, [...(byAdvisory.get(v.advisory_id) ?? []), v]);
  const hot = [...byAdvisory.values()].sort((a, b) => b.length - a.length)[0]?.slice(0, 3);
  if (hot && hot[0]) {
    const pkg = (hot[0].packages as { name?: string }[])[0]?.name;
    const lab = hot.find((v) => (v.hostname ?? "").includes(".lab."));
    add({
      title: `${hot[0].title.replace(/ security update$/, "")}: known exploited on ${hot.length} hosts`, severity: "critical", status: "investigating",
      assignee: "u-sam", openedBy: "u-admin", openedAgo: 2 * 1440,
      items: [
        ...hot.map((v, index) => ({
          kind: "vulnerability" as const, ref: `${v.agent_id}/${v.advisory_id}`, agent_id: v.agent_id, by: "u-admin", ago: 2 * 1440 - index,
          ...(v === lab ? { outcome: "accepted_risk", note: "Lab host, not reachable from outside; patch with the next rebuild." } : {}),
        })),
        ...(pkg ? [{ kind: "software" as const, ref: `rpm/${pkg}`, agent_id: null, by: "u-sam", ago: 2 * 1440 - 30 }] : []),
      ],
      timeline: [
        { ago: 2 * 1440 - 40, actor: "u-sam", kind: "status", detail: { from: "open", to: "investigating" } },
        { ago: 26 * 60, actor: "u-sam", kind: "note", body: "CISA lists it as exploited. The vendor has no fixed build yet; checking whether we can turn off the affected feature in the meantime." },
        { ago: 5 * 60, actor: "u-admin", kind: "note", body: "Security asked for a status on Thursday." },
      ],
    });
  }

  // SSH, the host it runs on, an alarm and a finding: the investigation the spec describes.
  const sshAlarm = [...data.alarms].sort((a, b) => (a.severity === "critical" ? 0 : 1) - (b.severity === "critical" ? 0 : 1))
    .find((a) => data.findings.some((f) => f.agent_id === a.agent_id && f.rule_id === "port.ssh.exposed"));
  const sshFinding = sshAlarm && data.findings.find((f) => f.agent_id === sshAlarm.agent_id && f.rule_id === "port.ssh.exposed");
  if (sshAlarm && sshFinding) {
    add({
      title: `Shell started by a service on ${short(sshAlarm.agent_id)}, SSH open to the network`, severity: "critical", status: "investigating",
      assignee: "u-admin", openedBy: "u-sam", openedAgo: 3 * 60,
      items: [
        { kind: "host", ref: sshAlarm.agent_id, agent_id: sshAlarm.agent_id, by: "u-sam", ago: 175 },
        { kind: "alarm", ref: sshAlarm.id, agent_id: sshAlarm.agent_id, by: "u-sam", ago: 170 },
        { kind: "compliance_finding", ref: findingOf(sshFinding), agent_id: sshFinding.agent_id, by: "u-sam", ago: 160 },
      ],
      timeline: [
        { ago: 150, actor: "u-sam", kind: "status", detail: { from: "open", to: "investigating" } },
        { ago: 140, actor: "u-sam", kind: "note", body: "SSH is reachable from the network on this host and the alarm fired 20 minutes after a login from 203.0.113.9. Pulling the auth log." },
        { ago: 45, actor: "u-admin", kind: "note", body: "Auth log shows 40 failed logins for one account, then a success. Treating as hostile until we know more." },
      ],
    });
  }

  // Two web servers starting shells: opened, nobody on it yet.
  const shells = data.alarms.filter((a) => a.message === "A web server started a shell" && a.id !== sshAlarm?.id).slice(0, 2);
  if (shells.length > 0) {
    add({
      title: `Web servers starting shells (${shells.map((a) => short(a.agent_id)).join(", ")})`, severity: "high", status: "open", openedBy: "u-sam", openedAgo: 40,
      items: shells.map((a, index) => ({ kind: "alarm" as const, ref: a.id, agent_id: a.agent_id, by: "u-sam", ago: 38 - index })),
      timeline: [{ ago: 12, actor: "u-sam", kind: "note", body: "One of them is a health check script; the other has a longer command line. Needs a look." }],
    });
  }
  return state;
}
