// One detail template for an alarm, a compliance finding and a
// vulnerability (triage v2, spec 2026-10-10-bulk-triage §5): the summary
// with its actions, then tabs. The Hosts tab is a real table with
// selection and the bulk bar; History lists the triage changes.
import { type ReactNode, useMemo, useState } from "react";

import { useResource } from "../api/client";
import { Ago, Empty, ErrorBox, Loading, ObjectLink, TriageBadge } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { triageLabel } from "../ui/format";
import { Segmented } from "../ui/Segmented";
import { useSelection } from "../ui/selection";
import type { BulkItem, BulkKind } from "./bulk";
import { BulkBar } from "./BulkBar";
import { CaseBadge } from "./CaseBadge";
import { triageStates } from "./triage";

export type Tab = { key: string; label: string; body: ReactNode };

/** The summary (with its actions) stays; one tab shows below it. `tab`
 * and `onTab` let the panel switch tabs itself (a host's "Evidence"). */
export function TriageDetail({ summary, tabs, tab: shown, onTab }: Readonly<{ summary: ReactNode; tabs: Tab[]; tab?: string; onTab?: (tab: string) => void }>) {
  const [own, setOwn] = useState(tabs[0]?.key ?? "");
  const tab = shown ?? own;
  const setTab = onTab ?? setOwn;
  return (
    <>
      <div className="panel-body stack">{summary}</div>
      <div className="detail-tabs">
        <Segmented label="Detail" value={tab} onChange={setTab} options={tabs.map((t) => ({ value: t.key, label: t.label }))} />
      </div>
      <div className="detail-tab">{tabs.find((t) => t.key === tab)?.body}</div>
    </>
  );
}

/** One host's row in a finding's or an advisory's Hosts tab. */
export type HostRow = {
  agent_id: string; hostname: string | null; triage_state: string; assigned_to: string | null;
  seen: string; extra?: ReactNode;
};

/** The hosts, filterable by state, selectable, with the bulk bar for the
 * selected ones; it pages ("Show more") and is never cut off (#239). */
export function HostsTab({ kind, hosts, item, cases, title, severity }: Readonly<{
  kind: BulkKind; hosts: HostRow[]; item: (agentId: string) => BulkItem; cases: Map<string, number[]>;
  title: string; severity: string;
}>) {
  const [filter, setFilter] = useState("all");
  const rows = useMemo(() => hosts.filter((h) => filter === "all" || h.triage_state === filter), [hosts, filter]);
  const [selected, setSelected] = useSelection(filter);
  const counts = (state: string) => hosts.filter((h) => h.triage_state === state).length;
  return (
    <>
      <fieldset className="row row--wrap detail-tab__filters" aria-label="Show hosts by triage state">
        {(["all", ...triageStates] as const).map((value) => {
          const n = value === "all" ? hosts.length : counts(value);
          if (value !== "all" && n === 0) return null;
          return (
            <button key={value} type="button" className="chip" aria-pressed={filter === value} onClick={() => setFilter(value)}>
              {value === "all" ? "All" : triageLabel[value]} <span className="chip__count">{n}</span>
            </button>
          );
        })}
      </fieldset>
      {rows.length === 0 ? <Empty title="No hosts in this state" /> : (
        <DataTable compact label="Hosts" rows={rows} rowKey={(h) => h.agent_id} selection={{ selected, onChange: setSelected }}
          onOpen={() => undefined} defaultSort={{ key: "state", direction: "asc" }}
          columns={[
            { key: "host", header: "Host", sort: (h) => h.hostname ?? h.agent_id, render: (h) => (
              <span className="row"><ObjectLink to={{ kind: "agent", id: h.agent_id }}>{h.hostname ?? h.agent_id}</ObjectLink>{h.extra}</span>) },
            { key: "state", header: "State", width: "130px", sort: (h) => triageStates.indexOf(h.triage_state as never), render: (h) => <TriageBadge state={h.triage_state} /> },
            { key: "assignee", header: "Assignee", width: "110px", hideBelow: 380, sort: (h) => h.assigned_to ?? "", render: (h) => <span className={h.assigned_to ? "truncate" : "subtle"}>{h.assigned_to ?? "—"}</span> },
            { key: "case", header: "Case", width: "80px", hideBelow: 560, render: (h) => <CaseBadge numbers={cases.get(h.agent_id)} /> },
            { key: "seen", header: "Last seen", width: "110px", hideBelow: 640, sort: (h) => h.seen, render: (h) => <span className="subtle"><Ago value={h.seen} /></span> },
          ]} />
      )}
      <BulkBar kind={kind} noun={selected.size === 1 ? "host" : "hosts"} count={selected.size} onClear={() => setSelected(new Set())}
        items={() => [...selected].map(item)} newCase={() => ({ title: `${title} on ${selected.size} hosts`, severity })} />
    </>
  );
}

type Event = { agent_id: string; hostname?: string | null; from_state?: string | null; to_state: string; note?: string | null; changed_at: string; changed_by: string };

/** The triage changes, newest first: who, when, from and to, the note. */
export function HistoryTab({ query, showHost }: Readonly<{ query: string; showHost: boolean }>) {
  const history = useResource<{ items: Event[] }>(`/api/v1/triage-history?${query}`);
  if (history.error) return <div className="panel-body"><ErrorBox error={history.error} /></div>;
  if (!history.data) return <Loading rows={3} />;
  if (history.data.items.length === 0) return <Empty title="No triage changes yet" />;
  return (
    <ol className="list list--plain detail-history">
      {history.data.items.map((e, index) => (
        <li key={`${e.changed_at}-${index}`} className="list__row list__row--static">
          <div className="stack">
            <span>
              {e.from_state ? <><TriageBadge state={e.from_state} /> → </> : null}<TriageBadge state={e.to_state} />
              {showHost && <span className="subtle"> on {e.hostname ?? e.agent_id}</span>}
            </span>
            {e.note && <span>{e.note}</span>}
            <span className="subtle">{e.changed_by} · <Ago value={e.changed_at} /></span>
          </div>
        </li>
      ))}
    </ol>
  );
}
