// Settings › Access: users, their roles and the asset groups that scope them.
import { useMemo } from "react";

import { useResource } from "../../../api/client";
import type { HostGroup, PersonRow } from "../../../api/types";
import { reachLabel } from "../../../panels/admin/UserPanel";
import { nav, useLocation, useTopPanel } from "../../../app/nav";
import { useSession } from "../../../app/session";
import { DataTable } from "../../../ui/DataTable";
import { Icon } from "../../../ui/Icon";
import { ViewHeader } from "../../../ui/ViewHeader";
import { Empty, ErrorBox, Loading } from "../../../ui/bits";
import { matches } from "../../../ui/table";

export function Access() {
  const { params } = useLocation();
  const { can } = useSession();
  const inventory = useResource<PersonRow[]>("/api/v1/users");
  const groups = useResource<HostGroup[]>("/api/v1/host-groups").data ?? [];
  const top = useTopPanel();
  const data = inventory.data;
  const rows = useMemo(() => (data ?? []).filter((user) => matches([user.username, user.display_name, ...user.roles.map((r) => r.name)], params.get("q") ?? "")), [data, params]);
  return (
    <div className="view">
      <ViewHeader title="Access" count={rows.length} refresh="/api/v1/users" placeholder="Filter people or roles…"
        actions={can("access.users", true) && <button type="button" className="button button--primary button--small" onClick={() => nav.open({ kind: "user", id: "new" }, true)}><Icon name="plus" size={14} /> New user</button>} />
      {inventory.error ? <div className="view-pad"><ErrorBox error={inventory.error} /></div> : !data ? <Loading /> : (
        <>
          {rows.length === 0 ? (
            <Empty icon="access" title={data.length === 0 ? "No people" : "Nothing matches these filters"}>
              {data.length === 0 ? "Add a person with New user." : "Clear a filter to see more."}
            </Empty>
          ) : <DataTable label="People" rows={rows} rowKey={(u) => u.user_id}
            onOpen={(u) => nav.open({ kind: "user", id: u.user_id }, true)}
            isOpen={(u) => top?.kind === "user" && top.id === u.user_id}
            defaultSort={{ key: "name", direction: "asc" }}
            columns={[
              { key: "name", header: "Person", sort: (u) => u.display_name, render: (u) => <div className="cell-two"><span>{u.display_name}</span><span className="mono subtle">{u.username}</span></div> },
              { key: "roles", header: "Roles", render: (u) => <span className="row row--wrap">{u.roles.length === 0 ? <span className="subtle">None</span> : u.roles.map((r) => (
                <span key={r.role_id} className="badge badge--accent badge--plain" title={reachLabel(r)}>{r.name}</span>
              ))}</span> },
            ]} />}
          <section className="view-pad stack">
            <div className="row row--between">
              <h2 className="section-title">Asset groups</h2>
              {can("host_groups.manage", true) && <button type="button" className="button button--small" onClick={() => nav.open({ kind: "asset-group", id: "new" }, true)}><Icon name="plus" size={14} /> New group</button>}
            </div>
            <div className="group-cards">
              {groups.map((group) => (
                <button key={group.asset_group_id} type="button" className="card card__body group-card" aria-pressed={top?.kind === "asset-group" && top.id === group.asset_group_id}
                  onClick={() => nav.open({ kind: "asset-group", id: group.asset_group_id }, true)}>
                  <strong>{group.name}</strong>
                  <span className="row row--wrap" style={{ marginTop: 8 }}>{group.selectors.map((sel) => <span key={sel} className="tag">{sel}</span>)}</span>
                  <span className="subtle">{group.roles} {group.roles === 1 ? "role" : "roles"}</span>
                </button>
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
