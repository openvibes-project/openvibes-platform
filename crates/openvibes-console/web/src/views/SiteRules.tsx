// The site's own rules: compliance (findings) rules and alarm rules the
// operator writes here. Saved rules are drafts; publishing is a later step.
import { type ReactNode, useState } from "react";

import { ApiError, invalidate, request, useResource } from "../api/client";
import type { DraftChanges, PublishedDrafts, RuleDraft, SiteFleet } from "../api/types";
import { nav, useLocation } from "../app/nav";
import { useSession } from "../app/session";
import { Ago, Empty, ErrorBox, Loading, SeverityBadge } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { Icon } from "../ui/Icon";
import { toast } from "../ui/toast";
import { ViewHeader } from "../ui/ViewHeader";

function useTop() {
  const { panels } = useLocation();
  return panels[panels.length - 1];
}

export const SITE_SETS = [
  { id: "site", title: "Compliance rules", what: "Checked on every scan; a match is a finding under Compliance." },
  { id: "site-alarms", title: "Alarm rules", what: "Checked on every process start of the programs a rule names; a match raises an alarm." },
] as const;

function SetTable({ set, intro }: { set: (typeof SITE_SETS)[number]; intro: ReactNode }) {
  const drafts = useResource<{ items: RuleDraft[] }>(`/api/v1/rule-drafts/${set.id}`);
  const top = useTop();
  const rows = drafts.data?.items ?? [];
  return (
    <section className="view-section">
      <div className="row">
        <h2 className="grow">{set.title}</h2>
        <button type="button" className="button button--small" onClick={() => nav.open({ kind: "site-rule", id: `${set.id}/new` }, true)}><Icon name="plus" size={14} /> New rule</button>
      </div>
      <p className="subtle">{intro}</p>
      {drafts.error ? <ErrorBox error={drafts.error} /> : !drafts.data ? <Loading rows={2} /> : rows.length === 0 ? (
        <Empty icon="rules" title="No rules yet">Write the first rule with New rule.</Empty>
      ) : (
        <DataTable label={set.title} rows={rows} rowKey={(r) => r.rule_id}
          onOpen={(r) => nav.open({ kind: "site-rule", id: `${set.id}/${r.rule_id}` }, true)}
          isOpen={(r) => top?.kind === "site-rule" && top.id === `${set.id}/${r.rule_id}`}
          defaultSort={{ key: "id", direction: "asc" }}
          columns={[
            { key: "id", header: "Rule", sort: (r) => r.rule_id, render: (r) => <div className="cell-two"><span>{r.title}</span><span className="mono subtle">{r.rule_id}</span></div> },
            { key: "severity", header: "Severity", width: "110px", render: (r) => <SeverityBadge severity={r.severity} /> },
            { key: "version", header: "Version", numeric: true, width: "90px", sort: (r) => r.version, render: (r) => <span className="num">{r.version}</span> },
            { key: "saved", header: "Saved", width: "130px", hideBelow: 800, sort: (r) => r.updated_at, render: (r) => <span className="subtle"><Ago value={r.updated_at} /></span> },
          ]} />
      )}
    </section>
  );
}


function Publish({ set }: { set: (typeof SITE_SETS)[number] }) {
  const { can } = useSession();
  const changes = useResource<DraftChanges>(`/api/v1/rule-drafts/${set.id}/changes`);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const data = changes.data;
  const pending = data ? data.added.length + data.changed.length + data.removed.length : 0;
  const publish = () => {
    setBusy(true);
    setError(undefined);
    request<PublishedDrafts>("POST", `/api/v1/rule-drafts/${set.id}/publish`, { password })
      .then((done) => {
        setPassword("");
        invalidate(`/api/v1/rule-drafts/${set.id}`);
        invalidate("/api/v1/rule-sets");
        toast(`${set.title} published as version ${done.version}`);
      })
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : "Could not publish"))
      .finally(() => setBusy(false));
  };
  const list = (label: string, ids: string[]) => ids.length > 0 && <li><strong>{label}:</strong> <span className="mono">{ids.join(", ")}</span></li>;
  return (
    <section className="view-section">
      <h2>Publish {set.title.toLowerCase()}</h2>
      {changes.error ? <ErrorBox error={changes.error} /> : !data ? <Loading rows={1} /> : (
        <>
          <p className="subtle">{data.published_version === null || data.published_version === undefined ? "Nothing is published yet." : `Version ${data.published_version} is published.`}</p>
          {pending === 0 ? <p className="subtle">{data.unchanged === 0 ? "Write a rule, then publish it here." : "The drafts match what is published."}</p> : (
            <ul className="plain">{list("Added", data.added)}{list("Changed", data.changed)}{list("Removed", data.removed)}</ul>
          )}
          {can("rules.upload", true) ? (
            <form className="row" onSubmit={(event) => { event.preventDefault(); publish(); }}>
              <label className="field grow">Your password, to sign<input className="input" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} disabled={pending === 0} /></label>
              <button className="button button--primary" type="submit" disabled={busy || pending === 0 || password === ""}>Publish</button>
            </form>
          ) : <p className="subtle">Publishing needs the rules.upload permission.</p>}
          {error && <p className="confirm__error" role="alert">{error}</p>}
        </>
      )}
    </section>
  );
}

const STATE_TEXT: Record<string, string> = { current: "Current", behind: "Behind", refused: "Refused the bundle", missing: "Not in agent.toml" };

function Fleet() {
  const fleet = useResource<SiteFleet>("/api/v1/site-rules/fleet");
  const data = fleet.data;
  const lacking = data ? data.sets.reduce((sum, set) => sum + set.missing, 0) : 0;
  return (
    <section className="view-section">
      <h2>Hosts</h2>
      {fleet.error ? <ErrorBox error={fleet.error} /> : !data ? <Loading rows={2} /> : (
        <>
          <ul className="plain">
            {data.sets.map((set) => (
              <li key={set.rule_set_id}>
                <strong>{set.rule_set_id === "site" ? "Compliance rules" : "Alarm rules"}:</strong>{" "}
                {set.published_version === null || set.published_version === undefined ? "nothing published yet. " : `version ${set.published_version}. `}
                {set.current} current, {set.behind} behind, {set.refused} refused, {set.missing} not set up.
              </li>
            ))}
          </ul>
          {data.not_reporting > 0 && <p className="subtle">{data.not_reporting} hosts haven't sent a health report yet and are not counted.</p>}
          {data.hosts.length > 0 && (
            <DataTable label="Hosts without the current site rules" rows={data.hosts} rowKey={(h) => h.agent_id}
              onOpen={(h) => nav.open({ kind: "agent", id: h.agent_id }, true)}
              columns={[
                { key: "host", header: "Host", render: (h) => <div className="cell-two"><span>{h.hostname ?? h.agent_id}</span><span className="mono subtle">{h.agent_id}</span></div> },
                { key: "site", header: "Compliance", width: "170px", render: (h) => STATE_TEXT[h.site] ?? h.site },
                { key: "alarms", header: "Alarms", width: "170px", render: (h) => STATE_TEXT[h.site_alarms] ?? h.site_alarms },
              ]} />
          )}
          {data.hosts_truncated && <p className="subtle">Showing the first {data.hosts.length} hosts.</p>}
          {lacking > 0 && data.paste && (
            <div className="stack">
              <p className="subtle">A host marked "Not in agent.toml" needs these lines added to its <span className="mono">/etc/openvibes-agent/agent.toml</span>, then the agent restarted. Hosts installed from now on get them at install.</p>
              <div className="row">
                <pre className="code grow" tabIndex={0} aria-label="agent.toml lines">{data.paste}</pre>
                <button type="button" className="icon-button" aria-label="Copy the agent.toml lines" onClick={() => { void navigator.clipboard?.writeText(data.paste ?? ""); toast("Copied"); }}><Icon name="copy" size={16} /></button>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}

export function SiteRules() {
  return (
    <div className="view">
      <ViewHeader title="Site rules" />
      <div className="view-pad stack">
        <div className="callout"><Icon name="help" size={16} /><span>Rules saved here are drafts. They reach hosts only once you publish the set: the rule signer signs it after you type your password again.</span></div>
        {SITE_SETS.map((set) => (
          <div key={set.id} className="stack"><SetTable set={set} intro={set.what} /><Publish set={set} /></div>
        ))}
        <Fleet />
      </div>
    </div>
  );
}
