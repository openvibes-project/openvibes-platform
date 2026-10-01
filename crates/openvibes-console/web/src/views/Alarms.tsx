// Threat alarms (P14): process starts that matched a rule, newest first,
// and the suppressions that quiet them.
import { useMemo, useState } from "react";

import { invalidate, request, useAllPages, useResource } from "../api/client";
import type { AlarmDetail, AlarmPage, AlarmSummary, AlarmSuppression } from "../api/types";
import { nav, useLocation } from "../app/nav";
import { useSession } from "../app/session";
import { Ago, Empty, ErrorBox, Loading, SeverityBadge, TriageBadge } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { severityOrder } from "../ui/format";
import { Confirm } from "../ui/panel";
import { matches } from "../ui/table";
import { toast } from "../ui/toast";
import { ViewHeader } from "../ui/ViewHeader";

/** Alarms fetched per "Load more" (the API's page size). */
const PAGE = 100;

/** `parent → program`, by base name, the way an analyst reads it. */
export function lineage(alarm: Pick<AlarmSummary, "exe" | "parent_exe">): string {
  const base = (path: string) => path.split("/").pop() || path;
  return alarm.parent_exe ? `${base(alarm.parent_exe)} → ${base(alarm.exe)}` : base(alarm.exe);
}

/** The API query for the list's filters; the text filter stays local. */
export function alarmQuery(params: URLSearchParams): string {
  const query = new URLSearchParams();
  if (params.get("state") !== "all") query.set("state", "active");
  const severity = params.get("severity");
  if (severity) query.set("severity", severity);
  if (params.get("suppressed") === "true") query.set("suppressed", "true");
  return `/api/v1/alarms?${query.toString()}`;
}

/** The loaded alarms that match the text filter. */
export function selectAlarms(loaded: readonly AlarmSummary[], params: URLSearchParams): AlarmSummary[] {
  const q = params.get("q") ?? "";
  return loaded.filter((a) => matches([a.message, a.rule_id, a.hostname ?? a.agent_id, a.exe, a.parent_exe ?? ""], q));
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

/** From the list: closes this alarm as a false positive (through the
 * workflow's steps) and then quiets new ones, both with the user's note. */
async function closeAndQuiet(alarmId: string, scope: string, note: string): Promise<void> {
  const path = `/api/v1/alarms/${encodeURIComponent(alarmId)}`;
  let alarm = await request<AlarmDetail>("GET", path);
  const step = async (state: string, withNote: boolean) => {
    await request("PUT", `${path}/triage`, { state, note: withNote ? note : null, assigned_to: alarm.triage.assigned_to ?? null, accepted_until: null },
      { "if-match": `"${alarm.triage.version}"` });
    alarm = await request<AlarmDetail>("GET", path);
  };
  if (alarm.triage.state === "open") await step("investigating", false);
  if (alarm.triage.state === "investigating") await step("false_positive", true);
  await quiet(alarmId, scope, note);
}

function QuietMenu({ alarm }: { alarm: AlarmSummary }) {
  const { can } = useSession();
  const [scope, setScope] = useState("");
  const scopes = quietScopes.filter((s) => can("alarms.suppress", s.global));
  if (scopes.length === 0 || alarm.suppressed_by) return null;
  const chosen = quietScopes.find((s) => s.scope === scope);
  const what = scope === "host" ? `on ${alarm.hostname ?? alarm.agent_id}` : scope === "program" ? `${alarm.exe} on every host` : `this exact ${alarm.exe} command on every host`;
  // Choosing a scope does nothing by itself (arrow keys change a closed
  // select); only the confirmation acts, and it names what it quiets.
  return (
    <div className="row" onClick={(event) => event.stopPropagation()}>
      <select className="select select--small" aria-label={`Quiet ${alarm.message}`} value={scope} onChange={(event) => setScope(event.target.value)}>
        <option value="">Quiet…</option>
        {scopes.map((s) => <option key={s.scope} value={s.scope}>{s.label}</option>)}
      </select>
      {chosen && (
        <Confirm danger label={`Close this alarm as a false positive and quiet ${what}?`} reason="Why (saved as the note)"
          onConfirm={async (note) => { await closeAndQuiet(alarm.id, scope, note); setScope(""); }}>Quiet</Confirm>
      )}
    </div>
  );
}

export function Alarms() {
  const { params, panels } = useLocation();
  // Alarms are per occurrence and can run to thousands: the newest pages
  // only, filtered on the server, more on request.
  // ponytail: Load more refetches from the first page (useAllPages); keep
  // the cursor and append if people page deep.
  const [max, setMax] = useState(PAGE);
  const path = alarmQuery(params);
  const alarms = useAllPages<AlarmSummary>(path, max);
  const loaded = useMemo(() => alarms.data ?? [], [alarms.data]);
  const rows = useMemo(() => selectAlarms(loaded, params), [loaded, params]);
  const top = panels[panels.length - 1];
  // An empty filtered page: does any alarm exist at all? If not, the
  // empty state explains how to turn alarms on, not the chips.
  const any = useResource<AlarmPage>(alarms.data && loaded.length === 0 ? "/api/v1/alarms?suppressed=true&limit=1" : null);
  const none = loaded.length === 0 && any.data !== undefined && any.data.items.length === 0;

  return (
    <div className="view">
      <ViewHeader title="Alarms" count={rows.length} total={loaded.length} refresh="/api/v1/alarms" placeholder="Filter by message, rule, host or program…"
        chips={[
          { label: "Include resolved", param: "state", value: "all" },
          { label: "Include suppressed", param: "suppressed", value: "true" },
          ...(["critical", "high", "medium", "low"] as const).map((s) => ({ label: s[0]?.toUpperCase() + s.slice(1), param: "severity", value: s })),
        ]} />
      {alarms.error ? <div className="view-pad"><ErrorBox error={alarms.error} /></div> : alarms.loading && !alarms.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="alarm" title={none ? "No alarms" : "Nothing matches these filters"}>
          {none
            ? "Alarms appear here within seconds of a matching program start. Agents report process starts only when auditd runs and \"process_events\" is in their collectors (agent.toml)."
            : "Resolved and suppressed alarms are hidden unless their chips are on; clear a filter to see more."}
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
            { key: "quiet", header: "Quiet", width: "200px", hideBelow: 900, render: (a) => <QuietMenu alarm={a} /> },
          ]} />
      )}
      {loaded.length >= max && (
        <div className="view-pad"><button type="button" className="button" onClick={() => setMax((m) => m + PAGE)}>Load {PAGE} more</button></div>
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
