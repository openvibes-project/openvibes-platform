// Alarm suppressions: the program and command rules that quiet new alarms.
import { invalidate, request, useResource } from "../../api/client";
import type { AlarmSuppression } from "../../api/types";
import { nav } from "../../app/nav";
import { useSession } from "../../app/session";
import { DataTable } from "../../ui/DataTable";
import { ViewHeader } from "../../ui/ViewHeader";
import { Ago, Empty, ErrorBox, Loading } from "../../ui/bits";
import { Confirm } from "../../ui/panel";
import { toast } from "../../ui/toast";

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
            { key: "remove", header: "Remove", width: "120px", render: (s) => can("alarms.suppress") && (
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
