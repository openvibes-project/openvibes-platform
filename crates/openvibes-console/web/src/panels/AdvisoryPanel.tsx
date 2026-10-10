// An advisory in the one detail template (triage v2): the summary (what
// fixes it, acting on every open host), then Hosts (triage per host),
// Evidence (how it was matched, its CVEs) and History.
import { useResource } from "../api/client";
import type { AdvisoryDetail, Vulnerability } from "../api/types";
import { useProvideTitle } from "../app/titles";
import { ConfidenceBar, ErrorBox, Loading, SeverityBadge } from "../ui/bits";
import { date, pct } from "../ui/format";
import { Icon } from "../ui/Icon";
import { useSession } from "../app/session";
import { PanelHeader, Section } from "../ui/panel";
import { AddToCase } from "./AddToCase";
import { BulkBar } from "./BulkBar";
import { useHostCaseBadges } from "./CaseBadge";
import { vulnerabilityRef } from "./cases";
import { HistoryTab, type HostRow, HostsTab, TriageDetail } from "./TriageDetail";

type Pkg = { name?: unknown; installed?: unknown; fixed?: unknown };

export function packagesOf(item: Vulnerability): Pkg[] {
  return Array.isArray(item.packages) ? (item.packages as unknown[]).filter((p): p is Pkg => typeof p === "object" && p !== null) : [];
}

export function fixState(item: Vulnerability): { label: string; tone: string } {
  if (item.fixed_at) return { label: "Fixed", tone: "ok" };
  if (item.reboot_needed) return { label: "Reboot needed", tone: "warn" };
  const packages = packagesOf(item);
  if (packages.length > 0 && packages.every((p) => p.fixed == null)) return { label: "No fix yet", tone: "plain" };
  return { label: "Fix available", tone: "accent" };
}

function cvssTone(score: number | null | undefined) {
  if (score == null) return "plain";
  return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
}

export function AdvisoryPanel({ id }: { id: string }) {
  const { can } = useSession();
  const detail = useResource<AdvisoryDetail>(`/api/v1/vulnerabilities/advisories/${encodeURIComponent(id)}`);
  const cases = useHostCaseBadges("vulnerability", id);
  useProvideTitle({ kind: "advisory", id }, detail.data?.hosts.items[0]?.title);
  if (detail.error) return <div className="panel-body"><ErrorBox error={detail.error} /></div>;
  if (!detail.data) return <Loading />;
  const all = detail.data.hosts.items;
  const first = all[0];
  const packages = first ? packagesOf(first) : [];
  const reboot = all.filter((host) => host.reboot_needed).length;
  const open = all.filter((host) => host.triage_state === "open");
  // NVD CPE matches are possible matches, not distribution findings: no
  // triage or cases for them.
  const triageable = !id.startsWith("CPE:");
  const title = first?.title ?? id;
  const hosts: HostRow[] = all.map((host) => {
    const state = fixState(host);
    return {
      agent_id: host.agent_id, hostname: host.hostname ?? null, triage_state: host.triage_state, assigned_to: host.assigned_to ?? null, seen: host.first_seen_at,
      extra: <>
        <span className={`badge badge--${state.tone} badge--plain`}>{state.label}</span>
        {can("cases.manage") && triageable && <AddToCase compact kind="vulnerability" id={vulnerabilityRef(host.agent_id, host.advisory_id)} label={`${host.title} on ${host.hostname ?? host.agent_id}`} />}
      </>,
    };
  });

  const summary = <>
    {first?.kev_due && (
      <div className="callout callout--bad"><Icon name="clock" size={16} /><span>Known exploited: CISA asks for remediation by <strong>{date(first.kev_due)}</strong>.</span></div>
    )}
    <p className="subtle">{open.length.toLocaleString()} open of {all.length.toLocaleString()}{detail.data.hosts.more_available ? "+" : ""} hosts{reboot > 0 && ` · ${reboot} only need a reboot`}</p>
    {packages.length > 0 && (
      <Section title="What to do">
        <ul className="list list--plain">
          {packages.map((pkg) => (
            <li key={String(pkg.name)} className="list__row list__row--static">
              <Icon name="package" size={15} />
              <strong>{String(pkg.name ?? "package")}</strong>
              <span className="mono subtle">{String(pkg.installed ?? "?")}</span>
              <Icon name="chevronRight" size={14} />
              {pkg.fixed == null ? <span className="subtle">no fixed version yet</span> : <span className="mono">{String(pkg.fixed)}</span>}
            </li>
          ))}
        </ul>
      </Section>
    )}
    {triageable && open.length > 0 && (
      <BulkBar inline kind="vulnerabilities" noun={open.length === 1 ? "open host" : "open hosts"} count={open.length} onClear={() => undefined}
        items={() => open.map((host) => ({ advisory_id: id, agent_id: host.agent_id }))}
        newCase={() => ({ title, severity: first?.severity })} />
    )}
  </>;

  const evidence = (
    <div className="panel-body stack">
      {first && (
        <Section title="How this was matched">
          <div className="stack">
            <ConfidenceBar value={first.confidence} wide />
            <p className="muted">{first.match_basis}</p>
            <p className="subtle">Source <span className="mono">{first.source}</span> · method <span className="mono">{first.match_method}</span></p>
          </div>
        </Section>
      )}
      <Section title={`CVEs (${detail.data.cves.length})`}>
        <div className="stack">
          {detail.data.cves.map((cve) => (
            <article key={cve.cve_id} className="cve">
              <div className="row row--between">
                <a className="mono" href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} target="_blank" rel="noreferrer noopener">{cve.cve_id}</a>
                <div className="row">
                  {cve.kev && <span className="badge badge--critical badge--plain">KEV</span>}
                  {cve.euvd_exploited && <span className="badge badge--bad badge--plain">EUVD exploited</span>}
                </div>
              </div>
              {cve.description && <p className="muted">{cve.description}</p>}
              <div className="cve__scores">
                <div><span className="subtle">CVSS {cve.cvss_version ?? ""}</span><span className={`badge badge--${cvssTone(cve.cvss_score)} badge--plain num`}>{cve.cvss_score?.toFixed(1) ?? "—"}</span></div>
                <div><span className="subtle">EPSS</span><span className="row"><span className="meter"><span style={{ width: `${Math.round((cve.epss ?? 0) * 100)}%` }} /></span><span className="num">{pct(cve.epss)}</span></span></div>
                <div><span className="subtle">Weakness</span><span className="mono">{cve.cwe.join(", ") || "—"}</span></div>
              </div>
            </article>
          ))}
        </div>
      </Section>
    </div>
  );

  return (
    <>
      <PanelHeader
        icon="vulnerabilities" kind="Advisory" title={title}
        subtitle={<span className="mono subtle">{id}</span>}
        badges={<>
          {first && <SeverityBadge severity={first.severity} />}
          {first?.exploited && <span className="badge badge--critical"><Icon name="flame" size={12} /> Known exploited</span>}
          {first?.ransomware && <span className="badge badge--critical badge--plain">Used by ransomware</span>}
          <span className="badge badge--plain">{all.length} hosts</span>
        </>}
        askAbout={{ ref: { kind: "advisory", id }, label: title }}
        actions={first?.url && <a className="button button--small" href={first.url} target="_blank" rel="noreferrer noopener"><Icon name="external" size={14} /> Vendor advisory</a>}
      />
      <TriageDetail summary={summary} tabs={[
        { key: "hosts", label: `Hosts (${all.length.toLocaleString()})`, body: <>
          {detail.data.hosts.more_available && <p className="view-note">Showing the first {all.length.toLocaleString()} hosts.</p>}
          <HostsTab key={id} kind="vulnerabilities" hosts={hosts} cases={cases} title={title} severity={first?.severity ?? "low"}
            item={(agentId) => ({ advisory_id: id, agent_id: agentId })} />
        </> },
        { key: "evidence", label: "Evidence", body: evidence },
        { key: "history", label: "History", body: <HistoryTab showHost query={`kind=vulnerability&advisory_id=${encodeURIComponent(id)}`} /> },
      ]} />
    </>
  );
}
