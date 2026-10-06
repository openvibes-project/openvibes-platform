// The site's own rules: compliance (findings) rules and alarm rules the
// operator writes here. Saved rules are drafts; publishing is a later step.
import type { ReactNode } from "react";

import { useResource } from "../api/client";
import type { RuleDraft } from "../api/types";
import { nav, useLocation } from "../app/nav";
import { Ago, Empty, ErrorBox, Loading, SeverityBadge } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { Icon } from "../ui/Icon";
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

export function SiteRules() {
  return (
    <div className="view">
      <ViewHeader title="Site rules" />
      <div className="view-pad stack">
        <div className="callout"><Icon name="help" size={16} /><span>Rules saved here are drafts. They reach hosts only once the set is signed and published, which is not part of this screen yet.</span></div>
        {SITE_SETS.map((set) => <SetTable key={set.id} set={set} intro={set.what} />)}
      </div>
    </div>
  );
}
