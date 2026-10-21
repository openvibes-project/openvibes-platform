// An alarm's page above the fold (GET /api/v1/alarms/{id}/summary), answered
// as alarms/summary.rs and the store's alarm_summary.rs answer it: the alarm
// in the alarms.read reach or 404; its siblings (same host, rule set, rule,
// program and parent) as the commands seen, most starts first; the last 24
// hours of their starts; the Related card; each action by its permission on
// the host (roles 5a, user decisions 1 and 2, rulings 6–9).
import type { AlarmSummaryPage } from "../../api/types";
import type { createCaseStore } from "../cases";
import type { DemoContext } from "../context";
import { json, problem, severityRank } from "../http";
import { alarmRows } from "./alarmList";
import { topVulnerabilities } from "./hostSummary";

const HOUR = 3_600_000;
const rank = (severity: string) => severityRank[severity] ?? 9;

export function registerAlarmSummaryRoute(ctx: DemoContext & { cases: ReturnType<typeof createCaseStore> }) {
  const { data, route, reaches, now } = ctx;
  route("GET", "/api/v1/alarms/{id}/summary", "alarms.read", ({ id = "" }) => {
    const alarm = data.alarms.find((a) => a.id === id && reaches("alarms.read", a.agent_id));
    const notFound = problem(404, "alarm_not_found", "Alarm not found");
    if (!alarm) return notFound;
    const rows = alarmRows(ctx);
    const row = rows.find((r) => r.row.id === Number(id))?.row;
    if (!row) return notFound;
    const here = (p: Parameters<typeof reaches>[0]) => reaches(p, alarm.agent_id);
    const onHost = data.alarms.filter((a) => a.agent_id === alarm.agent_id);
    const siblings = onHost.filter((a) => a.rule_set_id === alarm.rule_set_id && a.rule_id === alarm.rule_id
      && a.exe === alarm.exe && a.parent_exe === alarm.parent_exe)
      .sort((a, b) => b.count - a.count || Number(a.id) - Number(b.id));
    const caseOf = new Map(rows.map((r) => [String(r.row.id), r.row.case]));
    // Demo alarms carry no per-hour history: each one's count stands in as
    // the starts of the hour it was last seen, as ingest records a new alarm.
    const start = Math.floor(now / HOUR) * HOUR - 23 * HOUR;
    const hourly = Array.from({ length: 24 }, () => 0);
    for (const s of siblings) {
      const slot = Math.floor((Math.floor(Date.parse(s.last_seen) / HOUR) * HOUR - start) / HOUR);
      if (slot >= 0 && slot < 24) hourly[slot] = (hourly[slot] ?? 0) + s.count;
    }
    const others = onHost.filter((a) => a.id !== alarm.id && a.state === "open")
      .sort((a, b) => rank(a.severity) - rank(b.severity) || b.last_seen.localeCompare(a.last_seen) || Number(b.id) - Number(a.id));
    const elsewhere = data.alarms.filter((a) => a.agent_id !== alarm.agent_id && a.rule_set_id === alarm.rule_set_id && a.rule_id === alarm.rule_id
      && a.state === "open" && a.suppressed_by === null && reaches("alarms.read", a.agent_id));
    const triage = here("alarms.triage");
    const body: AlarmSummaryPage = {
      alarm: {
        ...row, confidence: alarm.confidence, rule_set_version: alarm.rule_set_version, rule_version: alarm.rule_version,
        // The schema types these as free-form objects.
        process: alarm.process as unknown as AlarmSummaryPage["alarm"]["process"],
        ancestors: alarm.ancestors as unknown as AlarmSummaryPage["alarm"]["ancestors"],
        received_at: alarm.received_at, triage: alarm.triage,
      },
      tiles: {
        starts: siblings.reduce((n, s) => n + s.count, 0), different_commands: siblings.length,
        first_seen: siblings.map((s) => s.first_seen).sort((a, b) => a.localeCompare(b))[0] ?? alarm.first_seen, confidence: alarm.confidence,
      },
      // The demo's rules are all indexed, titled by their message (as GET /alarms/{id}/rule answers).
      rule: { title: alarm.message, message: alarm.message, explain: null, check: null, techniques: row.techniques },
      commands: siblings.map((s) => ({
        id: Number(s.id), args: s.process.args, count: s.count, first_seen: s.first_seen, last_seen: s.last_seen, state: s.state,
        suppressed_by: s.suppressed_by === null ? null : Number(s.suppressed_by), case: caseOf.get(s.id) ?? null,
      })),
      hourly,
      related: {
        host_alarms: {
          items: others.slice(0, 5).map((a) => ({ id: Number(a.id), rule_id: a.rule_id, message: a.message, severity: a.severity, last_seen: a.last_seen })),
          total: others.length,
        },
        host_vulnerabilities: here("vulnerabilities.read") ? topVulnerabilities(ctx, alarm.agent_id) : null,
        same_rule_elsewhere: { hosts: new Set(elsewhere.map((a) => a.agent_id)).size, open: elsewhere.length },
      },
      can: {
        triage, assign: triage && here("cases.assign"), suppress: here("alarms.suppress"), add_to_case: here("cases.write"),
        ask: here("assistant.use"), export: here("alarms.export"),
      },
    };
    return json(body);
  });
}
