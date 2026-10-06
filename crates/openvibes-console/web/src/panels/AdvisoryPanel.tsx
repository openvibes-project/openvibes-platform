// An advisory: what it fixes (CVEs with CVSS, EPSS, KEV), which package
// versions fix it, and every host in scope that still needs it.
import { useResource } from "../api/client";
import type { AdvisoryDetail, Vulnerability } from "../api/types";
import { useProvideTitle } from "../app/titles";
import { Ago, ConfidenceBar, Empty, ErrorBox, Loading, ObjectLink, SeverityBadge } from "../ui/bits";
import { date, pct } from "../ui/format";
import { Icon } from "../ui/Icon";
import { useSession } from "../app/session";
import { PanelHeader, Section } from "../ui/panel";
import { AddToCase } from "./AddToCase";
import { vulnerabilityRef } from "./cases";

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
  useProvideTitle({ kind: "advisory", id }, detail.data?.hosts.items[0]?.title);
  if (detail.error) return <div className="panel-body"><ErrorBox error={detail.error} /></div>;
  if (!detail.data) return <Loading />;
  const hosts = detail.data.hosts.items;
  const first = hosts[0];
  const packages = first ? packagesOf(first) : [];
  const reboot = hosts.filter((host) => host.reboot_needed).length;

  return (
    <>
      <PanelHeader
        icon="vulnerabilities" kind="Advisory" title={first?.title ?? id}
        subtitle={<span className="mono subtle">{id}</span>}
        badges={<>
          {first && <SeverityBadge severity={first.severity} />}
          {first?.exploited && <span className="badge badge--critical"><Icon name="flame" size={12} /> Known exploited</span>}
          {first?.ransomware && <span className="badge badge--critical badge--plain">Used by ransomware</span>}
          <span className="badge badge--plain">{hosts.length} hosts</span>
        </>}
        askAbout={{ ref: { kind: "advisory", id }, label: first?.title ?? id }}
        actions={first?.url && <a className="button button--small" href={first.url} target="_blank" rel="noreferrer noopener"><Icon name="external" size={14} /> Vendor advisory</a>}
      />
      <div className="panel-body stack">
        {first?.kev_due && (
          <div className="callout callout--bad"><Icon name="clock" size={16} /><span>Known exploited: CISA asks for remediation by <strong>{date(first.kev_due)}</strong>.</span></div>
        )}
        {packages.length > 0 && (
          <Section title="Fix">
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
            {reboot > 0 && <p className="subtle">{reboot} of {hosts.length} hosts have the fix installed and only need a reboot.</p>}
          </Section>
        )}
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
      <Section title="Affected hosts" flush>
        {hosts.length === 0 ? <Empty title="No host in your scope needs this" /> : (
          <table className="table table--compact">
            <thead><tr><th>Host</th><th>State</th><th className="hide-narrow">Since</th></tr></thead>
            <tbody>
              {hosts.map((host) => {
                const state = fixState(host);
                return (
                  <tr key={host.agent_id}>
                    <td><span className="row"><ObjectLink to={{ kind: "agent", id: host.agent_id }}>{host.hostname ?? host.agent_id}</ObjectLink>{can("cases.manage") && <AddToCase compact kind="vulnerability" id={vulnerabilityRef(host.agent_id, host.advisory_id)} label={`${host.title} on ${host.hostname ?? host.agent_id}`} />}</span></td>
                    <td><span className={`badge badge--${state.tone} badge--plain`}>{state.label}</span></td>
                    <td className="subtle hide-narrow"><Ago value={host.first_seen_at} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Section>
    </>
  );
}
