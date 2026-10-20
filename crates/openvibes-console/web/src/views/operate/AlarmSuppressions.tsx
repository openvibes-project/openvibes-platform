// Alarm suppressions: the program and command rules that quiet new alarms.
import { invalidate, request, useResource } from "../../api/client";
import type { AlarmSuppression } from "../../api/types";
import { nav } from "../../app/nav";
import { DataTable } from "../../ui/DataTable";
import { ViewHeader } from "../../ui/ViewHeader";
import { Ago, Empty, ErrorBox, Loading } from "../../ui/bits";
import { Confirm } from "../../ui/panel";
import { toast } from "../../ui/toast";

export function AlarmSuppressions() {
  const list = useResource<{ items: AlarmSuppression[] }>("/api/v1/alarm-suppressions");
  const items = list.data?.items ?? [];
  // ponytail: interim rows until Task 7 builds screen 14 with approvals.
  const where = (s: AlarmSuppression) => s.where.kind === "host" ? `on ${s.where.hostname ?? s.where.agent_id ?? "?"}` : s.where.kind === "group" ? `on ${s.where.group_name ?? "a deleted group"}` : "any host";
  const what = (s: AlarmSuppression) => s.what === "host" ? where(s) : s.what === "command" ? `${s.exe ?? "?"} with one command line, ${where(s)}` : `${s.exe ?? "?"}, ${where(s)}`;
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
            { key: "note", header: "Why", hideBelow: 560, render: (s) => <span className="truncate">{s.reason}</span> },
            { key: "created", header: "By", width: "180px", hideBelow: 760, sort: (s) => s.requested_at, render: (s) => <span className="subtle">{s.requested_by}, {s.status}, <Ago value={s.requested_at} /></span> },
            { key: "remove", header: "Remove", width: "120px", render: (s) => s.can_remove && (
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
