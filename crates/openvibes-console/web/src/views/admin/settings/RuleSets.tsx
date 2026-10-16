// Settings › Rule sets: published sets, where each runs, and its state.
import { useResource } from "../../../api/client";
import type { RuleSet, RuleSetAssignments } from "../../../api/types";
import { nav, useTopPanel } from "../../../app/nav";
import { useSession } from "../../../app/session";
import { ruleSetRows, runsOn } from "../../../panels/rules/ruleAssignment";
import { DataTable } from "../../../ui/DataTable";
import { Icon } from "../../../ui/Icon";
import { ViewHeader } from "../../../ui/ViewHeader";
import { Ago, Empty, ErrorBox, Loading } from "../../../ui/bits";
import { within } from "../../../ui/format";

export function RuleSets() {
  const { can } = useSession();
  const sets = useResource<{ items: RuleSet[] }>("/api/v1/rule-sets");
  const assignments = useResource<RuleSetAssignments>("/api/v1/rule-set-assignments");
  const top = useTopPanel();
  const rows = ruleSetRows(sets.data?.items ?? [], assignments.data?.items ?? []);
  const error = sets.error ?? assignments.error;
  const loaded = sets.data && assignments.data;
  return (
    <div className="view">
      <ViewHeader title="Rule sets" count={rows.length} refresh="/api/v1/rule-set"
        actions={can("rules.publish", true) && (
          <button type="button" className="button button--primary" onClick={() => nav.open({ kind: "rule-bundle", id: "new" }, true)}><Icon name="plus" size={15} /> Publish bundle</button>
        )} />
      {error ? <div className="view-pad"><ErrorBox error={error} /></div> : !loaded ? <Loading /> : rows.length === 0 ? (
        <Empty icon="rules" title="No rule sets">Publish a signed bundle with openvibes-admin to start.</Empty>
      ) : (
        <DataTable label="Rule sets" rows={rows} rowKey={(r) => r.rule_set_id}
          onOpen={(r) => nav.open({ kind: "rule-set", id: r.rule_set_id }, true)}
          isOpen={(r) => top?.kind === "rule-set" && top.id === r.rule_set_id}
          defaultSort={{ key: "id", direction: "asc" }}
          columns={[
            { key: "id", header: "Rule set", sort: (r) => r.rule_set_id, render: (r) => <span className="mono nowrap">{r.rule_set_id}</span> },
            { key: "version", header: "Version", numeric: true, width: "90px", sort: (r) => r.set?.current_version, render: (r) => r.set ? <span className="num">{r.set.current_version ?? "—"}</span> : <span className="subtle">—</span> },
            { key: "key", header: "Signed by", width: "130px", sort: (r) => r.set?.current_issuer_key_id, render: (r) => <span className={r.set ? "mono subtle" : "subtle"}>{r.set?.current_issuer_key_id ?? "—"}</span> },
            { key: "expires", header: "Expires", width: "130px", sort: (r) => r.set?.current_expires_at_ms, render: (r) => r.set ? <span className={within(r.set.current_expires_at_ms, 7 * 86_400_000) ? "warn-text" : "subtle"}><Ago value={r.set.current_expires_at_ms} /></span> : <span className="subtle">—</span> },
            { key: "runs", header: "Runs on", width: "170px", render: (r) => { const where = runsOn(r.rule_set_id, r.assignment); return <span className="nowrap">{where.text}{where.more && <span className="subtle"> {where.more}</span>}</span>; } },
            { key: "state", header: "State", width: "140px", render: (r) => r.set?.current_signer_removed ? <span className="badge badge--bad">Signer removed</span>
              : r.set?.retired ? <span className="badge">Retired</span>
              : r.assignment && !r.assignment.published ? <span className="badge badge--plain">Not published</span>
              : <span className="badge badge--ok">Active</span> },
          ]} />
      )}
    </div>
  );
}
