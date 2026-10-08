// The operate and administer lists: enrollment tokens, rule sets, access,
// service accounts and the audit log. Same table + panel pattern as the
// investigate views.
import { useMemo } from "react";

import { isDemo, useAllPages, useResource } from "../api/client";
import type { AccessInventory, AgentCommand, AuditEvent, AuditRetention, EnrollmentToken, RuleSet, ServiceAccount } from "../api/types";
import { nav, useLocation } from "../app/nav";
import { useSession } from "../app/session";
import { tokenState, tokenUsable } from "../panels/tokens";
import { Ago, Empty, ErrorBox, Loading } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { auditSince, within } from "../ui/format";
import { Icon } from "../ui/Icon";
import { matches } from "../ui/table";
import { toast } from "../ui/toast";
import { ViewHeader } from "../ui/ViewHeader";
import { selectAudit } from "./rows";

/** The demo has no server to export from: build the same columns in the browser. */
function downloadCsv(events: readonly AuditEvent[]) {
  const cell = (value: string | null | undefined) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  const lines = [["at", "action", "actor", "target", "result"].join(","), ...events.map((e) => [e.at, e.action, e.actor, e.target, e.result].map(cell).join(","))];
  const url = URL.createObjectURL(new Blob([`${lines.join("\n")}\n`], { type: "text/csv" }));
  const link = Object.assign(document.createElement("a"), { href: url, download: "openvibes-audit-demo.csv" });
  link.click();
  URL.revokeObjectURL(url);
}

/** The demo has no platform to build the install package from. */
function downloadDemoPackage() {
  const url = URL.createObjectURL(new Blob(["#!/bin/sh\n# Demo: the real package carries the platform's fleet token.\n"], { type: "text/x-shellscript" }));
  const link = Object.assign(document.createElement("a"), { href: url, download: "openvibes-agent-install.sh" });
  link.click();
  URL.revokeObjectURL(url);
}

function useTop() {
  const { panels } = useLocation();
  return panels[panels.length - 1];
}

export function Enrollment() {
  const { can } = useSession();
  const { params } = useLocation();
  const tokens = useResource<{ items: EnrollmentToken[] }>("/api/v1/enrollment-tokens");
  const top = useTop();
  const all = tokens.data?.items ?? [];
  // Expired, used-up and revoked tokens pile up (each short-lived token
  // stays listed), so only the ones a host can still use show by default.
  const showAll = params.get("all") === "true";
  const hidden = all.filter((t) => !tokenUsable(t)).length;
  const rows = all.filter((t) => (showAll || tokenUsable(t)) && matches([t.label, t.token_id], params.get("q") ?? ""));
  return (
    <div className="view">
      <ViewHeader title="Enrollment" count={rows.length} refresh="/api/v1/enrollment-tokens" placeholder="Filter tokens…"
        chips={[{ label: "Show expired and revoked", param: "all", value: "true", count: hidden }]}
        actions={can("tokens.create", true) && (<>
          <button type="button" className="button button--primary" onClick={() => nav.open({ kind: "enrollment-token", id: "new" }, true)}><Icon name="plus" size={15} /> New token</button>
        </>)} />
      {can("tokens.create", true) && all.some((t) => t.standing && !t.revoked) && <AddHost />}
      {tokens.error ? <div className="view-pad"><ErrorBox error={tokens.error} /></div> : !tokens.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="enrollment" title={all.length === 0 ? "No enrollment tokens" : "No usable enrollment tokens"}>
          {all.length === 0 ? "Create one to let new hosts enroll." : `${hidden} expired or revoked ${hidden === 1 ? "token is" : "tokens are"} hidden. Run openvibes-admin agent command to create the standing token.`}
        </Empty>
      ) : (
        <DataTable label="Enrollment tokens" rows={rows} rowKey={(t) => t.token_id}
          onOpen={(t) => nav.open({ kind: "enrollment-token", id: t.token_id }, true)}
          isOpen={(t) => top?.kind === "enrollment-token" && top.id === t.token_id}
          defaultSort={{ key: "created", direction: "desc" }}
          columns={[
            { key: "label", header: "Label", sort: (t) => t.label, render: (t) => <div className="cell-two"><span>{t.label ?? "Unlabelled"}</span><span className="mono subtle">{t.token_id}</span></div> },
            { key: "state", header: "State", width: "110px", sort: (t) => tokenState(t).label, render: (t) => { const s = tokenState(t); return <span className={`badge badge--${s.tone}`}>{s.label}</span>; } },
            { key: "uses", header: "Uses", width: "110px", sort: (t) => (t.standing ? 0 : t.uses / t.max_uses), render: (t) => t.standing
              ? <span className="num subtle">{t.uses} / no limit</span>
              : <span className="row"><span className="meter"><span style={{ width: `${Math.min(100, (t.uses / t.max_uses) * 100)}%` }} /></span><span className="num subtle">{t.uses}/{t.max_uses}</span></span> },
            { key: "expires", header: "Expires", width: "130px", sort: (t) => (t.standing ? "9999" : t.expires_at), render: (t) => <span className="subtle">{t.standing ? "Never" : <Ago value={t.expires_at} />}</span> },
            { key: "created", header: "Created", width: "130px", hideBelow: 800, sort: (t) => t.created_at, render: (t) => <span className="subtle"><Ago value={t.created_at} /></span> },
          ]} />
      )}
    </div>
  );
}

export function RuleSets() {
  const { can } = useSession();
  const sets = useResource<{ items: RuleSet[] }>("/api/v1/rule-sets");
  const top = useTop();
  const rows = sets.data?.items ?? [];
  return (
    <div className="view">
      <ViewHeader title="Rule sets" count={rows.length} refresh="/api/v1/rule-sets"
        actions={can("rules.upload", true) && (
          <button type="button" className="button button--primary" onClick={() => nav.open({ kind: "rule-bundle", id: "new" }, true)}><Icon name="plus" size={15} /> Publish bundle</button>
        )} />
      {sets.error ? <div className="view-pad"><ErrorBox error={sets.error} /></div> : !sets.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="rules" title="No rule sets">Publish a signed bundle with openvibes-admin to start.</Empty>
      ) : (
        <DataTable label="Rule sets" rows={rows} rowKey={(s) => s.rule_set_id}
          onOpen={(s) => nav.open({ kind: "rule-set", id: s.rule_set_id }, true)}
          isOpen={(s) => top?.kind === "rule-set" && top.id === s.rule_set_id}
          defaultSort={{ key: "id", direction: "asc" }}
          columns={[
            { key: "id", header: "Rule set", sort: (s) => s.rule_set_id, render: (s) => <span className="mono">{s.rule_set_id}</span> },
            { key: "version", header: "Version", numeric: true, width: "90px", sort: (s) => s.current_version, render: (s) => <span className="num">{s.current_version ?? "—"}</span> },
            { key: "key", header: "Signed by", width: "130px", sort: (s) => s.current_issuer_key_id, render: (s) => <span className="mono subtle">{s.current_issuer_key_id ?? "—"}</span> },
            { key: "expires", header: "Expires", width: "130px", sort: (s) => s.current_expires_at_ms, render: (s) => <span className={within(s.current_expires_at_ms, 7 * 86_400_000) ? "warn-text" : "subtle"}><Ago value={s.current_expires_at_ms} /></span> },
            { key: "state", header: "State", width: "140px", render: (s) => s.current_signer_removed ? <span className="badge badge--bad">Signer removed</span> : s.retired ? <span className="badge">Retired</span> : <span className="badge badge--ok">Active</span> },
          ]} />
      )}
    </div>
  );
}

export function Access() {
  const { params } = useLocation();
  const { can } = useSession();
  const inventory = useResource<AccessInventory>("/api/v1/access-control");
  const top = useTop();
  const data = inventory.data;
  const rows = useMemo(() => (data?.users ?? []).map((user) => ({
    ...user,
    bindings: (data?.bindings ?? []).filter((b) => b.user_id === user.user_id),
  })).filter((user) => matches([user.username, user.display_name, ...user.bindings.map((b) => b.role_id)], params.get("q") ?? "")), [data, params]);
  return (
    <div className="view">
      <ViewHeader title="Access" count={rows.length} refresh="/api/v1/access-control" placeholder="Filter people or roles…"
        actions={can("rbac.manage", true) && <button type="button" className="button button--primary button--small" onClick={() => nav.open({ kind: "user", id: "new" }, true)}><Icon name="plus" size={14} /> New user</button>} />
      {inventory.error ? <div className="view-pad"><ErrorBox error={inventory.error} /></div> : !data ? <Loading /> : (
        <>
          {rows.length === 0 ? (
            <Empty icon="access" title={data.users.length === 0 ? "No people" : "Nothing matches these filters"}>
              {data.users.length === 0 ? "Add a person with New user." : "Clear a filter to see more."}
            </Empty>
          ) : <DataTable label="People" rows={rows} rowKey={(u) => u.user_id}
            onOpen={(u) => nav.open({ kind: "user", id: u.user_id }, true)}
            isOpen={(u) => top?.kind === "user" && top.id === u.user_id}
            defaultSort={{ key: "name", direction: "asc" }}
            columns={[
              { key: "name", header: "Person", sort: (u) => u.display_name, render: (u) => <div className="cell-two"><span>{u.display_name}</span><span className="mono subtle">{u.username}</span></div> },
              { key: "roles", header: "Roles", render: (u) => <span className="row row--wrap">{u.bindings.length === 0 ? <span className="subtle">None</span> : u.bindings.map((b) => (
                <span key={b.binding_id} className="badge badge--accent badge--plain">{data.roles.find((r) => r.role_id === b.role_id)?.display_name ?? b.role_id}{b.asset_group_name ? ` · ${b.asset_group_name}` : ""}</span>
              ))}</span> },
            ]} />}
          <section className="view-pad stack">
            <div className="row row--between">
              <h2 className="section-title">Asset groups</h2>
              {can("asset_groups.manage", true) && <button type="button" className="button button--small" onClick={() => nav.open({ kind: "asset-group", id: "new" }, true)}><Icon name="plus" size={14} /> New group</button>}
            </div>
            <div className="group-cards">
              {data.asset_groups.map((group) => (
                <button key={group.asset_group_id} type="button" className="card card__body group-card" aria-pressed={top?.kind === "asset-group" && top.id === group.asset_group_id}
                  onClick={() => nav.open({ kind: "asset-group", id: group.asset_group_id }, true)}>
                  <strong>{group.name}</strong>
                  <span className="row row--wrap" style={{ marginTop: 8 }}>{group.selectors.map((sel) => <span key={sel} className="tag">{sel}</span>)}</span>
                  <span className="subtle">{data.bindings.filter((b) => b.asset_group_id === group.asset_group_id).length} role grants</span>
                </button>
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  );
}

export function ServiceAccounts() {
  const { can } = useSession();
  const canManage = can("service_accounts.manage", true);
  const accounts = useResource<{ items: ServiceAccount[] }>("/api/v1/service-accounts");
  const top = useTop();
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

export function Audit() {
  const { can } = useSession();
  const { params } = useLocation();
  const since = auditSince(params);
  const page = useAllPages<AuditEvent>(`/api/v1/audit-events?since=${encodeURIComponent(since)}`, 1000);
  const retention = useResource<AuditRetention>("/api/v1/audit-retention");
  const top = useTop();
  const rows = selectAudit(page.data ?? [], params);
  return (
    <div className="view">
      <ViewHeader title="Audit log" count={rows.length} refresh="/api/v1/audit" placeholder="Filter by action, person or target…"
        chips={[
          { label: "Failures", param: "result", value: "failure" },
          ...[1, 7, 365].map((days) => ({ label: days === 1 ? "Last day" : `Last ${days} days`, param: "range", value: String(days) })),
        ]}
        actions={<>
          {retention.data && <button type="button" className="button button--ghost" onClick={() => nav.open({ kind: "audit-retention", id: "policy" }, true)} title="Retention policy"><Icon name="clock" size={15} /> Kept {retention.data.retention_days} days</button>}
          {can("audit.export", true) && (isDemo()
            ? <button type="button" className="button" onClick={() => downloadCsv(rows)}><Icon name="download" size={15} /> Export CSV</button>
            : <a className="button" href={`/api/v1/audit-export.csv?since=${encodeURIComponent(since)}`} download><Icon name="download" size={15} /> Export CSV</a>)}
        </>} />
      {page.error ? <div className="view-pad"><ErrorBox error={page.error} /></div> : !page.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="audit" title={page.data.length === 0 ? "No audit events in this range" : "Nothing matches these filters"}>
          {page.data.length === 0 ? "Actions recorded by the platform appear here." : "Clear a filter to see more."}
        </Empty>
      ) : (
        <DataTable label="Audit events" compact rows={rows} rowKey={(e) => e.id}
          onOpen={(e) => nav.open({ kind: "audit-event", id: e.id }, true)}
          isOpen={(e) => top?.kind === "audit-event" && top.id === e.id}
          defaultSort={{ key: "at", direction: "desc" }}
          columns={[
            { key: "at", header: "When", width: "130px", sort: (e) => e.at, render: (e) => <span className="subtle"><Ago value={e.at} /></span> },
            { key: "action", header: "Action", sort: (e) => e.action, render: (e) => <span className="mono">{e.action}</span> },
            { key: "actor", header: "Who", width: "140px", sort: (e) => e.actor, render: (e) => e.actor },
            { key: "target", header: "Target", hideBelow: 800, sort: (e) => e.target, render: (e) => <span className="mono subtle truncate">{e.target ?? "—"}</span> },
            { key: "result", header: "Result", width: "100px", sort: (e) => e.result, render: (e) => <span className={`badge badge--${e.result === "success" ? "ok" : "bad"}`}>{e.result}</span> },
          ]} />
      )}
    </div>
  );
}

/** How to add a host: the install package, or the one-line command to copy
 * (install walkthrough, 2026-10-08: hosts are added from the console). Both
 * carry the standing token. The command is copied, not shown: it is long and
 * holds the token. */
function AddHost() {
  const command = useResource<AgentCommand>("/api/v1/agent-command");
  const text = command.data?.command;
  return (
    <section className="view-pad stack" aria-labelledby="add-host">
      <h2 id="add-host" className="section-title">Add a host</h2>
      <p className="subtle">Run either as root on the new host. Both carry the standing token: anyone with it can enroll a host.</p>
      {command.error && <ErrorBox error={command.error} />}
      <div className="row row--wrap">
        {isDemo()
          ? <button type="button" className="button" onClick={downloadDemoPackage} title="A script to copy to the host and run with sudo"><Icon name="download" size={15} /> Install package</button>
          : <a className="button" href="/api/v1/agent-package" download title="A script to copy to the host and run with sudo"><Icon name="download" size={15} /> Install package</a>}
        <button type="button" className="button" disabled={!text} title="A one-line command to paste into a root shell on the host"
          onClick={() => { if (text) { void navigator.clipboard?.writeText(text); toast("Install command copied"); } }}>
          <Icon name="copy" size={15} /> Copy CLI install
        </button>
      </div>
    </section>
  );
}
