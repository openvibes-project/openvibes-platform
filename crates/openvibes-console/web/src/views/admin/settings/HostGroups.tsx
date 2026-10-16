// Settings › Host groups: the named sets of hosts that roles and rules reach.
import { useResource } from "../../../api/client";
import type { HostGroup } from "../../../api/types";
import { nav, useTopPanel } from "../../../app/nav";
import { useSession } from "../../../app/session";
import { Icon } from "../../../ui/Icon";
import { Loading, ErrorBox } from "../../../ui/bits";

export function HostGroups() {
  const { can } = useSession();
  const top = useTopPanel();
  const { data: groups, error } = useResource<HostGroup[]>("/api/v1/host-groups");
  if (error) return <div className="view-pad"><ErrorBox error={error} /></div>;
  if (!groups) return <Loading />;
  return (
    <section className="view-pad stack">
      <div className="row row--between">
        <h2 className="section-title">Host groups</h2>
        {can("host_groups.manage") && <button type="button" className="button button--small" onClick={() => nav.open({ kind: "asset-group", id: "new" }, true)}><Icon name="plus" size={14} /> New group</button>}
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
  );
}
