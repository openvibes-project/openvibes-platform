// The cards of a host's page (approved screen 17): Details, Protection,
// Rule sets and Certificates on the left; the top three open alarms,
// failing checks and vulnerabilities (the left menu's order, #118), and the software, ports and services
// summary on the right. Each reads the host's summary; Rule sets and the
// hardening row keep their own routes (plan ruling 10).
import { type ReactNode, useState } from "react";

import { type ApiError, useResource } from "../../../api/client";
import type { Agent, AgentDetail, HostRuleSetAssignments, HostSummary, RuleSet } from "../../../api/types";
import { hostPath } from "../../../app/location";
import { viewLink } from "../../../app/nav";
import { useSession } from "../../../app/session";
import { readsRules } from "../../../panels/rules/ruleAssignment";
import { AddToCase } from "../../../panels/cases/AddToCase";
import { vulnerabilityRef } from "../../../panels/cases/cases";
import { Ago, Empty, ErrorBox, Loading, ObjectLink, SeverityBadge, StatusBadge } from "../../../ui/bits";
import { Card } from "../../../ui/detail/DetailPage";
import { date } from "../../../ui/format";
import { Icon } from "../../../ui/Icon";
import { toast } from "../../../ui/toast";
import { HardeningRows, NotAssigned, hostAssignmentsPath } from "./HostHardening";

type Host = HostSummary["host"];

/** "Show all 12 vulnerabilities", to the full list it counts. */
const ShowAll = ({ n, what, view, params }: { n: number; what: string; view: string; params?: Record<string, string> }) =>
  <a className="detail-more" {...viewLink(view, params)}>Show all {n.toLocaleString()} {what}</a>;

/** The system as the host reports it: "Debian 12", else its os-release id and version. */
export const systemName = (host: Host) => host.os.distribution ?? ([host.os.id, host.os.version].filter(Boolean).join(" ") || null);

export function DetailsCard({ host }: { host: Host }) {
  return (
    <Card title="Details">
      <dl className="kv person-page__kv">
        <dt>Host name</dt><dd>{host.hostname ?? "—"}</dd>
        <dt>Agent ID</dt><dd className="mono">{host.id}</dd>
        {systemName(host) && <><dt>System</dt><dd>{systemName(host)}</dd></>}
        {host.running_kernel && <><dt>Running kernel</dt><dd className="mono">{host.running_kernel}</dd></>}
        {host.address && <><dt>IP address</dt><dd className="mono">{host.address}</dd></>}
        {host.scanner_version && <><dt>Agent</dt><dd>{host.scanner_version}{host.agent_older && <span className="warn-text"> (older than the latest release)</span>}</dd></>}
        {host.inventory_at && <><dt>Software as of</dt><dd><Ago value={host.inventory_at} /></dd></>}
        <dt>Status</dt><dd><StatusBadge status={host.status} /></dd>
        <dt>Enrolled</dt><dd>{date(host.enrolled_at)}</dd>
        {host.revoked_at && <><dt>Revoked</dt><dd>{date(host.revoked_at)}</dd></>}
        <dt>Capabilities</dt><dd className="row row--wrap">{host.capabilities.length ? host.capabilities.map((c) => <span key={c} className="tag">{c}</span>) : "—"}</dd>
      </dl>
    </Card>
  );
}

/** On and from which source, or off: why, and the command that fixes it. */
export function ThreatAlarms({ alarms }: { alarms: NonNullable<HostSummary["protection"]["threat_alarms"]> }) {
  if (alarms.state === "on") return <>On <span className="subtle">({alarms.source === "ebpf" ? "eBPF" : "audit"})</span></>;
  const command = alarms.command;
  return (
    <div className="stack">
      <span className={alarms.fault ? "warn-text" : undefined}>Off: {alarms.text}</span>
      {alarms.fix && <span className="subtle">To fix: {alarms.fix}</span>}
      {command && <div className="row">
        <pre className="code code--wrap grow" tabIndex={0} aria-label="Command to run on the host">{command}</pre>
        <button type="button" className="icon-button" aria-label="Copy the command" onClick={() => { void navigator.clipboard?.writeText(command); toast("Copied"); }}><Icon name="copy" size={16} /></button>
      </div>}
    </div>
  );
}

// The harmless pipeline test (spec 2026-10-09-test-triggers-design.md): run
// `openvibes-test alarm|finding` on the host and watch this line change.
export function ProtectionCard({ summary, agent }: { summary: HostSummary; agent: Agent | undefined }) {
  const { threat_alarms: alarms, last_test: test } = summary.protection;
  const imported = summary.host.status === "imported";
  const seen = (at: string | null | undefined) => at ? <span className="badge badge--ok">OK <Ago value={at} /></span> : <span className="subtle">Not seen yet</span>;
  return (
    <Card title="Protection">
      <div className="stack">
        <dl className="kv person-page__kv">
          {alarms && <><dt>Threat alarms</dt><dd><ThreatAlarms alarms={alarms} /></dd></>}
          {!imported && agent && <HardeningRows agent={agent} />}
          {!imported && <><dt>Last test</dt><dd className="stack"><span>Alarm {seen(test.alarm_at)}</span><span>Finding {seen(test.finding_at)}</span></dd></>}
        </dl>
        {!imported && <p className="subtle">Check this host end to end: run <code className="mono">openvibes-test alarm</code> (seconds) or <code className="mono">openvibes-test finding</code> (until the next scan) on it, as any user. Test alarms close themselves.</p>}
      </div>
    </Card>
  );
}

/** What an agent holds of each rule set, against what the platform has published. */
export function RuleSetsCard({ agent, error }: { agent: Agent | undefined; error?: ApiError | undefined }) {
  const { can } = useSession();
  const published = useResource<{ items: RuleSet[] }>(agent && readsRules(can) ? "/api/v1/rule-sets" : null);
  const host = useResource<HostRuleSetAssignments>(agent ? hostAssignmentsPath(agent) : null);
  if (!agent) return <Card title="Rule sets">{error ? <ErrorBox error={error} /> : <Loading rows={2} />}</Card>;
  const decided = new Map((host.data?.items ?? []).map((item) => [item.rule_set_id, item]));
  const current = new Map((published.data?.items ?? []).map((set) => [set.rule_set_id, set.current_version ?? null]));
  const sets = agent.rule_sets;
  return (
    <Card title="Rule sets">
      {sets.length === 0 ? (
        <p className="subtle">{agent.rule_sets_at ? "This agent reports no rule sets." : "This agent has not reported its rule sets yet. Agents report them in their health, which older versions do not send."}</p>
      ) : (
        <ul className="list list--plain" aria-label="Rule sets on this host">
          {sets.map((set) => {
            const latest = current.get(set.id);
            const behind = set.version != null && latest != null && set.version < latest;
            const d = decided.get(set.id);
            return (
              <li key={set.id} className="list__row list__row--static">
                <span className="mono">{set.id}</span>
                <span className="grow" />
                {set.state === "not_assigned" ? <NotAssigned text={!d || d.enabled ? null : d.group ? `off for ${d.group}` : "off by default"} /> : <>
                  {set.version == null ? <span className="badge badge--warn badge--plain">no bundle yet</span> : <span className="mono subtle nowrap">v{set.version}</span>}
                  {behind && <span className="badge badge--warn badge--plain" title={`Published: v${latest}`}>behind v{latest}</span>}
                  {set.refused && <span className="badge badge--critical badge--plain" title="The agent refused the last bundle it was given">refused: {set.refused.replaceAll("_", " ")}</span>}
                  {set.expires_at_ms != null && <span className="subtle nowrap">expires {date(new Date(set.expires_at_ms).toISOString())}</span>}
                </>}
              </li>
            );
          })}
        </ul>
      )}
      {agent.rule_sets_at && <p className="subtle">Reported <Ago value={agent.rule_sets_at} />.</p>}
    </Card>
  );
}

/** The five newest from the summary; "Show all n" lists every one from the
 * agent's record, which holds the 100 newest, so past 100 it says so. */
export function CertificatesCard({ summary, agent }: { summary: HostSummary; agent: AgentDetail | undefined }) {
  const [all, setAll] = useState(false);
  const total = summary.certificate_count;
  const certificates = all && agent ? agent.certificates : summary.certificates;
  const more = agent && agent.certificates.length < total ? `Show the ${agent.certificates.length.toLocaleString()} newest of ${total.toLocaleString()}` : `Show all ${total.toLocaleString()}`;
  return (
    <Card title="Certificates" aside={total > summary.certificates.length && agent && (
      <button type="button" className="link-button detail-more" aria-expanded={all} onClick={() => setAll(!all)}>{all ? "Show the newest 5" : more}</button>
    )}>
      {certificates.length === 0 ? <p className="subtle">None</p> : (
        <ul className="list list--plain" aria-label="Certificates">
          {certificates.map((c, index) => (
            <li key={c.serial} className="list__row list__row--static">
              <span className="mono truncate">{c.serial}</span>
              <span className="grow" />
              <span className="subtle nowrap">until {date(c.not_after)}</span>
              {index === 0 && <span className="badge badge--ok">Current</span>}
            </li>
          ))}
        </ul>
      )}
      {total > certificates.length && <p className="subtle">The {certificates.length} newest of {total.toLocaleString()}.</p>}
    </Card>
  );
}

/** The header of the add-to-case column, read by screen readers only. */
const CASE = "Add to case";

/** A top-three card: its title with the count, Show all n, and a table. */
function TopCard({ title, total, more, empty, head, children }: { title: string; total: number; more: ReactNode; empty: string; head: readonly string[]; children: ReactNode }) {
  return (
    <Card flush title={<>{title} <span className="subtle num">{total.toLocaleString()}</span></>} aside={total > 0 ? more : undefined}>
      {total === 0 ? <Empty title={empty} /> : (
        <div className="table-wrap"><table className="table table--compact" aria-label={title}>
          <thead><tr>{head.map((h) => <th key={h}>{h === CASE ? <span className="sr-only">{h}</span> : h}</th>)}</tr></thead>
          <tbody>{children}</tbody>
        </table></div>
      )}
    </Card>
  );
}

export function TopCards({ summary }: { summary: HostSummary }) {
  const { top_alarms: alarms, top_vulnerabilities: vulns, top_failing: failing, can } = summary;
  const q = { host: summary.host.id };
  return (
    <>
      {alarms && (
        <TopCard title="Open alarms" total={alarms.total} empty="No open alarms" head={["Alarm", "Severity", "Last seen"]}
          more={<ShowAll n={alarms.total} what="alarms" view="/alarms" params={q} />}>
          {alarms.items.map((a) => (
            <tr key={a.id}>
              <td><ObjectLink to={{ kind: "alarm", id: String(a.id) }}>{a.message}</ObjectLink></td>
              <td><SeverityBadge severity={a.severity} /></td>
              <td className="subtle"><Ago value={a.last_seen} /></td>
            </tr>
          ))}
        </TopCard>
      )}
      {failing && (
        <TopCard title="Compliance failing" total={failing.total} empty={summary.tiles.compliance_stale ? "No report in the last day" : "No failing checks"} head={["Check", "Rule set", "Severity"]}
          more={<ShowAll n={failing.total} what="checks" view="/compliance" params={q} />}>
          {failing.items.map((f) => (
            <tr key={`${f.rule_set_id}/${f.rule_id}`}>
              <td><ObjectLink to={{ kind: "finding", id: `${f.rule_set_id}/${f.rule_id}` }}>{f.message}</ObjectLink></td>
              <td className="mono subtle">{f.rule_set_id}</td>
              <td><SeverityBadge severity={f.severity} /></td>
            </tr>
          ))}
        </TopCard>
      )}
      {vulns && (
        <TopCard title="Vulnerabilities" total={vulns.total} empty="No open vulnerabilities" head={can.add_to_case ? ["Advisory", "Severity", CASE] : ["Advisory", "Severity"]}
          more={<ShowAll n={vulns.total} what="vulnerabilities" view="/vulnerabilities" params={q} />}>
          {vulns.items.map((v) => (
            <tr key={v.advisory}>
              <td><span className="row" title={v.title}><ObjectLink to={{ kind: "advisory", id: v.advisory }}>{v.advisory}</ObjectLink>
                {v.exploited && <span className="badge badge--critical badge--plain" title="Known to be exploited"><Icon name="flame" size={12} /> Exploited</span>}</span></td>
              <td><SeverityBadge severity={v.severity} /></td>
              {can.add_to_case && <td className="num"><AddToCase compact kind="vulnerability" id={vulnerabilityRef(summary.host.id, v.advisory)} label={v.advisory} /></td>}
            </tr>
          ))}
        </TopCard>
      )}
    </>
  );
}

export function InventoryCard({ summary }: { summary: HostSummary }) {
  const { packages, listening_ports: ports, exposed_ports: exposed, services } = summary.inventory;
  const at = (sub: string) => `${hostPath(summary.host.id)}/${sub}`;
  return (
    <Card title="Software, ports and services">
      <div className="host-inventory">
        <div className="stack"><strong>{packages.toLocaleString()} packages</strong><ShowAll n={packages} what="packages" view={at("software")} /></div>
        <div className="stack"><strong>{ports.toLocaleString()} open ports</strong>{exposed > 0 && <span className="subtle">{exposed.toLocaleString()} reachable from outside</span>}<ShowAll n={ports} what="ports" view={at("ports")} /></div>
        <div className="stack"><strong>{services.toLocaleString()} services</strong><ShowAll n={services} what="services" view={at("services")} /></div>
      </div>
    </Card>
  );
}
