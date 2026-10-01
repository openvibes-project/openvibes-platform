// Threat alarms (P14): process starts that matched a rule, newest first,
// and the suppressions that quiet them.
import { useMemo } from "react";

import { ApiError, invalidate, request, useAllPages, useResource } from "../api/client";
import type { AlarmSummary, AlarmSuppression } from "../api/types";
import { nav, useLocation } from "../app/nav";
import { useSession } from "../app/session";
import { Ago, Empty, ErrorBox, Loading, SeverityBadge, TriageBadge } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { severityOrder } from "../ui/format";
import { Confirm } from "../ui/panel";
import { matches } from "../ui/table";
import { toast } from "../ui/toast";
import { ViewHeader } from "../ui/ViewHeader";

const active = new Set(["open", "investigating"]);

/** `parent → program`, by base name, the way an analyst reads it. */
export function lineage(alarm: Pick<AlarmSummary, "exe" | "parent_exe">): string {
  const base = (path: string) => path.split("/").pop() || path;
  return alarm.parent_exe ? `${base(alarm.parent_exe)} → ${base(alarm.exe)}` : base(alarm.exe);
}

/** What the list shows: active and unsuppressed unless asked, then the filters. */
export function selectAlarms(all: readonly AlarmSummary[], params: URLSearchParams): AlarmSummary[] {
  const resolved = params.get("state") === "all";
  const suppressed = params.get("suppressed") === "true";
  const severity = params.get("severity");
  const q = params.get("q") ?? "";
  return all.filter((a) => (resolved || active.has(a.state)) && (suppressed || !a.suppressed_by)
    && (!severity || a.severity === severity)
    && matches([a.message, a.rule_id, a.hostname ?? a.agent_id, a.exe, a.parent_exe ?? ""], q));
}

export const quietScopes = [
  { scope: "host", label: "On this host", global: false },
  { scope: "program", label: "For this program, any host", global: true },
  { scope: "command", label: "For this exact command, any host", global: true },
] as const;

/** Creates a suppression derived from one alarm ("don't alarm on this again"). */
export async function quiet(alarmId: string, scope: string, note: string): Promise<void> {
  await request("POST", "/api/v1/alarm-suppressions", { alarm_id: alarmId, scope, note });
  invalidate("/api/v1/alarm");
  toast("Quieted: new matches are closed as false positives");
}

function QuietMenu({ alarm }: { alarm: AlarmSummary }) {
  const { can } = useSession();
  const scopes = quietScopes.filter((s) => can("alarms.suppress", s.global));
  if (scopes.length === 0 || alarm.suppressed_by) return null;
  return (
    <select className="select select--small" aria-label={`Quiet ${alarm.message}`} value=""
      onClick={(event) => event.stopPropagation()}
      onChange={(event) => {
        const scope = event.target.value;
        if (scope) void quiet(alarm.id, scope, "Quieted from the alarm list").catch((e: unknown) => toast(e instanceof ApiError ? e.message : "Quiet failed", true));
      }}>
      <option value="">Quiet…</option>
      {scopes.map((s) => <option key={s.scope} value={s.scope}>{s.label}</option>)}
    </select>
  );
}

export function Alarms() {
  const { params, panels } = useLocation();
  const alarms = useAllPages<AlarmSummary>("/api/v1/alarms?suppressed=true");
  const all = useMemo(() => alarms.data ?? [], [alarms.data]);
  const rows = useMemo(() => selectAlarms(all, params), [all, params]);
  const top = panels[panels.length - 1];
  const hidden = all.filter((a) => !active.has(a.state) || a.suppressed_by).length;
  const bySeverity = (s: string) => all.filter((a) => a.severity === s && active.has(a.state) && !a.suppressed_by).length;

  return (
    <div className="view">
      <ViewHeader title="Alarms" count={rows.length} total={all.length} refresh="/api/v1/alarms" placeholder="Filter by message, rule, host or program…"
        chips={[
          { label: "Include resolved", param: "state", value: "all" },
          { label: "Include suppressed", param: "suppressed", value: "true" },
          ...(["critical", "high", "medium", "low"] as const).map((s) => ({ label: s[0]?.toUpperCase() + s.slice(1), param: "severity", value: s, count: bySeverity(s) })),
        ]} />
      {alarms.error ? <div className="view-pad"><ErrorBox error={alarms.error} /></div> : alarms.loading && !alarms.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="alarm" title={all.length === 0 ? "No alarms" : "Nothing matches these filters"}>
          {all.length === 0
            ? "Alarms appear here within seconds of a matching program start. Agents report process starts only when auditd runs and \"process_events\" is in their collectors (agent.toml)."
            : hidden > 0 ? "Resolved and suppressed alarms are hidden; use the chips to include them." : "Clear a filter to see more."}
        </Empty>
      ) : (
        <DataTable label="Alarms" rows={rows} rowKey={(a) => a.id}
          onOpen={(a) => nav.open({ kind: "alarm", id: a.id }, true)}
          isOpen={(a) => top?.kind === "alarm" && top.id === a.id}
          defaultSort={{ key: "last", direction: "desc" }}
          columns={[
            { key: "severity", header: "Severity", width: "110px", sort: (a) => severityOrder[a.severity] ?? 9, render: (a) => <SeverityBadge severity={a.severity} /> },
            { key: "alarm", header: "Alarm", sort: (a) => a.message, render: (a) => <div className="cell-two"><span className="truncate">{a.message}</span><span className="mono subtle">{lineage(a)}</span></div> },
            { key: "host", header: "Host", width: "160px", hideBelow: 560, sort: (a) => a.hostname ?? a.agent_id, render: (a) => <span className="truncate">{a.hostname ?? a.agent_id}</span> },
            { key: "count", header: "Count", numeric: true, width: "80px", sort: (a) => a.count, render: (a) => <span className="num">{a.count}</span> },
            { key: "state", header: "Triage", width: "130px", hideBelow: 760, sort: (a) => a.state, render: (a) => <TriageBadge state={a.state} /> },
            { key: "last", header: "Last seen", width: "120px", hideBelow: 900, sort: (a) => a.last_seen, render: (a) => <span className="subtle"><Ago value={a.last_seen} /></span> },
            { key: "quiet", header: "Quiet", width: "120px", hideBelow: 900, render: (a) => <QuietMenu alarm={a} /> },
          ]} />
      )}
    </div>
  );
}

export function AlarmSuppressions() {
  const { can } = useSession();
  const list = useResource<{ items: AlarmSuppression[] }>("/api/v1/alarm-suppressions");
  const items = list.data?.items ?? [];
  const what = (s: AlarmSuppression) => s.scope === "host" ? `on ${s.agent_id ?? "?"}` : s.scope === "program" ? `${s.exe ?? "?"}, any host` : `${s.exe ?? "?"} with one command line, any host`;
  return (
    <div className="view">
      <ViewHeader title="Alarm suppressions" count={items.length} total={items.length} refresh="/api/v1/alarm-suppressions" />
      {list.error ? <div className="view-pad"><ErrorBox error={list.error} /></div> : list.loading && !list.data ? <Loading /> : items.length === 0 ? (
        <Empty icon="alarm" title="No suppressions">Quiet a noisy alarm from its panel or the alarm list; new matches are then closed as false positives.</Empty>
      ) : (
        <DataTable label="Alarm suppressions" rows={items} rowKey={(s) => s.id} defaultSort={{ key: "created", direction: "desc" }}
          onOpen={(s) => nav.view("/alarms", { q: s.rule_id, state: "all", suppressed: "true" })}
          columns={[
            { key: "rule", header: "Rule", sort: (s) => s.rule_id, render: (s) => <div className="cell-two"><span className="mono">{s.rule_id}</span><span className="subtle">{what(s)}</span></div> },
            { key: "note", header: "Why", hideBelow: 560, render: (s) => <span className="truncate">{s.note}</span> },
            { key: "created", header: "By", width: "180px", hideBelow: 760, sort: (s) => s.created_at, render: (s) => <span className="subtle">{s.created_by}, <Ago value={s.created_at} /></span> },
            { key: "remove", header: "Remove", width: "120px", render: (s) => can("alarms.suppress", s.scope !== "host") && (
              <Confirm danger label={`Remove? Matching alarms raise again from now on.`} onConfirm={async () => {
                await request("DELETE", `/api/v1/alarm-suppressions/${encodeURIComponent(s.id)}`);
                invalidate("/api/v1/alarm");
                toast("Suppression removed");
              }}>Remove</Confirm>
            ) },
          ]} />
      )}
    </div>
  );
}
