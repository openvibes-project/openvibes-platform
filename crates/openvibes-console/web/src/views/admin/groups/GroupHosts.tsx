// The "Hosts in this group" card: the member hosts the viewer can see, with a
// filter, their address, labels, last contact and open problems.
import { useState } from "react";

import type { GroupHost } from "../../../api/types";
import { Ago, ObjectLink } from "../../../ui/bits";
import { Icon } from "../../../ui/Icon";
import { SortHeader, sortBy, useSort } from "../../../ui/DataTable";
import { matches, type SortValue } from "../../../ui/table";
import { Card } from "../../../ui/detail/DetailPage";
import { Problems } from "./badges";

const SORTS: Record<string, (h: GroupHost) => SortValue> = {
  host: (h) => h.hostname ?? h.agent_id, address: (h) => h.last_address, seen: (h) => h.last_seen_at, problems: (h) => h.open_alarms,
};

export function GroupHosts({ hosts }: { hosts: readonly GroupHost[] }) {
  const [query, setQuery] = useState("");
  const sort = useSort();
  const rows = sortBy(hosts.filter((h) => matches([h.hostname, h.agent_id, h.distribution, h.last_address, ...h.labels], query)), SORTS, sort);
  const title = <>Hosts in this group <span className="subtle num group-page__count">{hosts.length}</span></>;
  const filter = (
    <label className="search group-hosts__filter">
      <Icon name="search" size={15} />
      <span className="sr-only">Filter hosts</span>
      <input className="input" type="search" placeholder="Filter hosts…" value={query} onChange={(e) => setQuery(e.target.value)} />
    </label>
  );
  return (
    <Card title={title} aside={filter} flush>
      <div className="table-wrap group-hosts">
        <table className="table" aria-label="Hosts in this group">
          <thead><tr><SortHeader sort={sort} column="host" style={{ width: 220 }}>Host</SortHeader><SortHeader sort={sort} column="address" style={{ width: 130 }}>IP address</SortHeader>
            <th>Labels</th><SortHeader sort={sort} column="seen" style={{ width: 110 }}>Last seen</SortHeader><SortHeader sort={sort} column="problems" style={{ width: 200 }}>Open problems</SortHeader></tr></thead>
          <tbody>
            {rows.length === 0 && <tr><td colSpan={5} className="subtle">No host matches yet.</td></tr>}
            {rows.map((h) => (
              <tr key={h.agent_id}>
                <td><div className="cell-two"><ObjectLink to={{ kind: "agent", id: h.agent_id }} className="mono">{h.hostname ?? h.agent_id}</ObjectLink><span className="subtle">{h.distribution ?? " "}</span><span className="subtle">{h.why}</span></div></td>
                <td className="mono">{h.last_address ?? <span className="subtle">Unknown</span>}</td>
                <td><span className="row row--wrap group-hosts__labels">{h.labels.map((l) => <span key={l} className="chip group-hosts__label">{l}</span>)}</span></td>
                <td><span className={h.online ? undefined : "warn-text"}>{h.last_seen_at ? <Ago value={h.last_seen_at} /> : "Never"}</span></td>
                <td><Problems alarms={h.open_alarms} critical={h.critical} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
