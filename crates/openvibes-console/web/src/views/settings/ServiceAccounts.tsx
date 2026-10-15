// Settings › Service accounts: API identities and their tokens.
import { useResource } from "../../api/client";
import type { ServiceAccount } from "../../api/types";
import { nav, useTopPanel } from "../../app/nav";
import { useSession } from "../../app/session";
import { DataTable } from "../../ui/DataTable";
import { Icon } from "../../ui/Icon";
import { ViewHeader } from "../../ui/ViewHeader";
import { Empty, ErrorBox, Loading } from "../../ui/bits";

export function ServiceAccounts() {
  const { can } = useSession();
  const canManage = can("service_accounts.manage", true);
  const accounts = useResource<{ items: ServiceAccount[] }>("/api/v1/service-accounts");
  const top = useTopPanel();
  const rows = accounts.data?.items ?? [];
  return (
    <div className="view">
      <ViewHeader title="Service accounts" count={rows.length} refresh="/api/v1/service-accounts"
        actions={canManage && (
          <button type="button" className="button button--primary" onClick={() => nav.open({ kind: "service-account", id: "new" }, true)}><Icon name="plus" size={15} /> New account</button>
        )} />
      {accounts.error ? <div className="view-pad"><ErrorBox error={accounts.error} /></div> : !accounts.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="service" title="No service accounts">
          {canManage ? "Create one for integrations that need API access." : "An administrator can create one for integrations that need API access."}
        </Empty>
      ) : (
        <DataTable label="Service accounts" rows={rows} rowKey={(a) => a.service_account_id}
          onOpen={(a) => nav.open({ kind: "service-account", id: a.service_account_id }, true)}
          isOpen={(a) => top?.kind === "service-account" && top.id === a.service_account_id}
          defaultSort={{ key: "name", direction: "asc" }}
          columns={[
            { key: "name", header: "Name", sort: (a) => a.name, render: (a) => <div className="cell-two"><span>{a.name}</span><span className="mono subtle">{a.service_account_id}</span></div> },
            { key: "roles", header: "Roles", render: (a) => <span className="row">{a.role_ids.map((r) => <span key={r} className="badge badge--accent badge--plain">{r}</span>)}</span> },
            { key: "tokens", header: "Active tokens", numeric: true, width: "120px", sort: (a) => a.active_tokens, render: (a) => <span className="num">{a.active_tokens}</span> },
            { key: "state", header: "State", width: "110px", sort: (a) => a.enabled, render: (a) => <span className={`badge badge--${a.enabled ? "ok" : "plain"}`}>{a.enabled ? "Enabled" : "Disabled"}</span> },
          ]} />
      )}
    </div>
  );
}
