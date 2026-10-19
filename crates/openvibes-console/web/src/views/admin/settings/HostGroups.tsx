// Settings › Host groups (approved screen 9): automatic, rule and manual
// groups apart, each with its membership, hosts, open problems and reach.
import { useMemo } from "react";

import { useResource } from "../../../api/client";
import type { HostGroup } from "../../../api/types";
import { nav, useLocation } from "../../../app/nav";
import { useSession } from "../../../app/session";
import { DataTable } from "../../../ui/DataTable";
import { Icon } from "../../../ui/Icon";
import { ViewHeader } from "../../../ui/ViewHeader";
import { Empty, ErrorBox, Loading } from "../../../ui/bits";
import { matches } from "../../../ui/table";
import { KindBadge, Problems } from "../groups/badges";
import { hostsLabel, membershipText } from "../groups/groupState";

const RANK: Record<HostGroup["kind"], number> = { automatic: 0, rule: 1, manual: 2 };

export function HostGroups() {
  const { params } = useLocation();
  const { can, canEverywhere } = useSession();
  const { data, error } = useResource<HostGroup[]>("/api/v1/host-groups");
  const seesAll = canEverywhere("hosts.read");
  const q = params.get("q") ?? "";
  const rows = useMemo(() => (data ?? []).filter((g) => matches([g.name, g.description, g.membership, g.kind, ...g.roles.map((r) => r.name)], q)), [data, q]);
  return (
    <div className="view">
      <ViewHeader title="Host groups" count={rows.length} refresh="/api/v1/host-groups" placeholder="Filter groups, rules or roles…"
        actions={can("host_groups.manage") && canEverywhere("hosts.read") && (
          <button type="button" className="button button--primary button--small" onClick={() => nav.view("/settings/host-groups/new")}><Icon name="plus" size={14} /> New group</button>
        )} />
      <p className="view-pad subtle host-groups__intro">
        <b>Automatic</b> groups are made by OpenVIBES from what agents report (OS, distribution) and appear as new kinds of hosts arrive. <b>Rule</b> groups
        are yours, built from what agents report (OS, distribution, hostname, IP address); both stay up to date by themselves. <b>Manual</b> groups hold
        hand-picked hosts and never change by themselves.
      </p>
      {error ? <div className="view-pad"><ErrorBox error={error} /></div> : !data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="access" title={q ? "Nothing matches this filter" : "No host groups yet"}>{q ? "Clear the filter to see every group." : "Automatic groups appear when the first hosts report in."}</Empty>
      ) : (
        <DataTable label="Host groups" rows={rows} rowKey={(g) => g.asset_group_id} onOpen={(g) => nav.view(`/settings/host-groups/${encodeURIComponent(g.asset_group_id)}`)}
          defaultSort={{ key: "name", direction: "asc" }}
          columns={[
            { key: "name", header: "Group", sort: (g) => `${RANK[g.kind]} ${g.name.toLowerCase()}`, render: (g) => (
              <div className="cell-two">
                <span className="row host-groups__name"><strong>{g.name}</strong><KindBadge kind={g.kind} /></span>
                <span className="subtle">{g.description || " "}</span>
              </div>
            ) },
            { key: "membership", header: "Membership", width: "380px", render: (g) => <span className={g.kind === "manual" ? "subtle" : undefined}>{membershipText(g, seesAll)}</span> },
            { key: "hosts", header: "Hosts", width: "130px", sort: (g) => g.hosts, render: (g) => (
              <div className="cell-two"><span className="num">{hostsLabel(g.hosts, seesAll)}</span><span className="subtle">{g.hosts || seesAll ? `${g.online} online` : " "}</span></div>
            ) },
            { key: "problems", header: "Open problems", width: "200px", sort: (g) => g.critical * 1e6 + g.open_alarms, render: (g) => <Problems alarms={g.open_alarms} critical={g.critical} /> },
            { key: "reach", header: "Who reaches it", width: "210px", sort: (g) => g.people, render: (g) => (
              <div className="cell-two">
                <span>{g.roles.length ? g.roles.map((r) => <span key={r.role_id} className="badge badge--accent badge--plain">{r.name}</span>) : <span className="subtle">No role yet</span>}</span>
                <span className="subtle">{g.people ? `${g.people} ${g.people === 1 ? "person" : "people"}` : "Nobody reaches it"}</span>
              </div>
            ) },
          ]} />
      )}
    </div>
  );
}
