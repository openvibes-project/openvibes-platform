// The "Hosts in this group" card: the member hosts the viewer can see, with a
// filter, their address, labels, last contact and open problems.
import { useState } from "react";

import type { GroupHost } from "../../../api/types";
import { Ago, ObjectLink } from "../../../ui/bits";
import { Icon } from "../../../ui/Icon";
import { matches } from "../../../ui/table";
import { Card } from "../../../ui/detail/DetailPage";
import { Problems } from "./badges";

export function GroupHosts({ hosts }: { hosts: readonly GroupHost[] }) {
  const [query, setQuery] = useState("");
  const rows = hosts.filter((h) => matches([h.hostname, h.agent_id, h.distribution, h.last_address, ...h.labels], query));
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
          <thead><tr><th style={{ width: 220 }}>Host</th><th style={{ width: 130 }}>IP address</th><th>Labels</th><th style={{ width: 110 }}>Last seen</th><th style={{ width: 200 }}>Open problems</th></tr></thead>
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
