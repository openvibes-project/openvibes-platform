// Settings › People: everyone inside the viewer's share, each role with where
// it applies, how they sign in, status and last sign-in (approved screen 6).
import { useMemo, useState } from "react";

import { useResource } from "../../../api/client";
import type { PersonRow } from "../../../api/types";
import { nav, useLocation } from "../../../app/nav";
import { useSession } from "../../../app/session";
import { DataTable } from "../../../ui/DataTable";
import { Icon } from "../../../ui/Icon";
import { ViewHeader } from "../../../ui/ViewHeader";
import { Ago, Empty, ErrorBox, Loading } from "../../../ui/bits";
import { matches } from "../../../ui/table";
import { NewPersonDialog } from "../people/NewPersonDialog";
import { signsIn } from "../people/people";
import { hostsSummary } from "../roles/roleState";

export function People() {
  const { params } = useLocation();
  const { can } = useSession();
  const [adding, setAdding] = useState(false);
  const { data, error } = useResource<PersonRow[]>("/api/v1/users");
  const q = params.get("q") ?? "";
  const rows = useMemo(() => (data ?? []).filter((p) => matches([p.username, p.display_name, p.email, ...p.roles.map((r) => r.name)], q)), [data, q]);
  return (
    <div className="view">
      <ViewHeader title="People" count={rows.length} refresh="/api/v1/users" placeholder="Filter people or roles…"
        actions={can("access.users") && <button type="button" className="button button--primary button--small" onClick={() => setAdding(true)}><Icon name="plus" size={14} /> New person</button>} />
      {adding && <NewPersonDialog onClose={() => setAdding(false)} />}
      {error ? <div className="view-pad"><ErrorBox error={error} /></div> : !data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="access" title={data.length === 0 ? "No people" : "Nothing matches these filters"}>
          {data.length === 0 ? "Add a person with New person." : "Clear a filter to see more."}
        </Empty>
      ) : (
        <DataTable label="People" rows={rows} rowKey={(p) => p.user_id} onOpen={(p) => nav.view(`/settings/people/${encodeURIComponent(p.user_id)}`)}
          defaultSort={{ key: "name", direction: "asc" }}
          columns={[
            { key: "name", header: "Person", sort: (p) => p.display_name, render: (p) => <div className="cell-two"><span>{p.display_name}</span><span className="mono subtle">{p.username}</span></div> },
            { key: "roles", header: "Roles", render: (p) => <span className="row row--wrap people-roles">{p.roles.length === 0 ? <span className="subtle">No roles</span> : p.roles.map((r) => (
              <span key={r.role_id} className="badge badge--accent badge--plain">{r.name}<span className="people-roles__where"> · {hostsSummary(r.reach)}</span></span>
            ))}</span> },
            { key: "signs-in", header: "Signs in with", width: "150px", sort: (p) => signsIn(p.auth_source), render: (p) => <span className="subtle">{signsIn(p.auth_source)}</span> },
            { key: "status", header: "Status", width: "110px", sort: (p) => Number(!p.enabled), render: (p) => <span className={p.enabled ? "badge badge--ok" : "badge badge--plain"}>{p.enabled ? "Active" : "Disabled"}</span> },
            { key: "seen", header: "Last sign-in", width: "140px", sort: (p) => p.last_sign_in_at ?? "", render: (p) => (p.last_sign_in_at ? <Ago value={p.last_sign_in_at} /> : <span className="subtle">Never</span>) },
          ]} />
      )}
    </div>
  );
}
