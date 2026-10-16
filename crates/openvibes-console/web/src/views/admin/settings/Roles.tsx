// Settings › Roles: every role (templates are not roles), Administrator first.
import { useMemo } from "react";

import { useResource } from "../../../api/client";
import type { Role } from "../../../api/types";
import { nav, useLocation } from "../../../app/nav";
import { useSession } from "../../../app/session";
import { DataTable } from "../../../ui/DataTable";
import { Icon } from "../../../ui/Icon";
import { ViewHeader } from "../../../ui/ViewHeader";
import { Empty, ErrorBox, Loading } from "../../../ui/bits";
import { matches } from "../../../ui/table";
import { hostsSummary } from "../roles/roleState";

export function Roles() {
  const { params } = useLocation();
  const { can } = useSession();
  const { data, error } = useResource<Role[]>("/api/v1/roles");
  const q = params.get("q") ?? "";
  const rows = useMemo(() => (data ?? []).filter((r) => matches([r.name, r.description, hostsSummary(r.reach)], q)), [data, q]);
  return (
    <div className="view">
      <ViewHeader title="Roles" count={rows.length} refresh="/api/v1/roles" placeholder="Filter roles…"
        actions={can("access.roles") && <button type="button" className="button button--primary button--small" onClick={() => nav.view("/settings/roles/new")}><Icon name="plus" size={14} /> New role</button>} />
      {error ? <div className="view-pad"><ErrorBox error={error} /></div> : !data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="access" title="Nothing matches this filter">Clear the filter to see every role.</Empty>
      ) : (
        <DataTable label="Roles" rows={rows} rowKey={(r) => r.role_id} onOpen={(r) => nav.view(`/settings/roles/${encodeURIComponent(r.role_id)}`)}
          defaultSort={{ key: "name", direction: "asc" }}
          columns={[
            // Administrator sorts first.
            { key: "name", header: "Role", sort: (r) => `${r.builtin ? 0 : 1} ${r.name}`, render: (r) => (
              <div className="cell-two">
                <span>{r.name}{r.builtin && <> <span className="badge badge--plain">Protected</span></>}</span>
                <span className="subtle">{r.description || " "}</span>
              </div>
            ) },
            { key: "hosts", header: "Hosts", width: "220px", sort: (r) => hostsSummary(r.reach), render: (r) => <span className={r.reach.kind === "none" ? "subtle" : undefined}>{hostsSummary(r.reach)}</span> },
            { key: "permissions", header: "Permissions", numeric: true, width: "140px", sort: (r) => (r.builtin ? Infinity : r.permissions.length), render: (r) => (r.builtin ? "Every permission" : r.permissions.length) },
            { key: "members", header: "People", numeric: true, width: "100px", sort: (r) => r.members, render: (r) => r.members },
          ]} />
      )}
    </div>
  );
}
