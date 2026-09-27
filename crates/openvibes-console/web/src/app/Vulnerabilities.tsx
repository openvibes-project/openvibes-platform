import { useEffect, useState } from "react";
import type { components } from "../api/generated";

type Summary = components["schemas"]["VulnerabilitySummary"];
type Page = components["schemas"]["VulnerabilityPage"];
type Advisory = components["schemas"]["VulnerabilityAdvisoryDetail"];

export function useData<T>(url: string, seeded: boolean): { data?: T; error?: string; status?: number | undefined } {
  const [state, setState] = useState<{ url: string; data?: T; error?: string; status?: number | undefined }>({ url: "" });
  useEffect(() => {
    const controller = new AbortController();
    if (!url) return () => controller.abort();
    const headers = new Headers({ Accept: "application/json" });
    if (seeded) {
      headers.set("X-OpenVIBES-Dev-Persona", localStorage.getItem("openvibes.dev.persona") ?? "analyst");
      headers.set("X-OpenVIBES-Dev-Mode", localStorage.getItem("openvibes.dev.mode") ?? "mixed");
    }
    void fetch(url, { headers, signal: controller.signal }).then(async (response) => {
      if (!response.ok) {
        const problem = await response.json() as { title?: string; field_errors?: { message: string }[] };
        const detail = problem.field_errors?.map((item) => item.message).join(" ");
        throw Object.assign(new Error([problem.title ?? "Data could not be loaded.", detail].filter(Boolean).join(" ")), { status: response.status });
      }
      return await response.json() as T;
    }).then((data) => setState({ url, data })).catch((error: unknown) => {
      if (!controller.signal.aborted) {
        const detail = typeof error === "object" && error !== null ? error as { message?: string; status?: number } : {};
        setState({ url, error: detail.message ?? "Read failed.", status: detail.status });
      }
    });
    return () => controller.abort();
  }, [url, seeded]);
  return state.url === url ? state : {};
}

function dateLabel(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function VulnerabilitiesPage({ seeded = false }: { seeded?: boolean }) {
  const params = new URLSearchParams(typeof window === "undefined" ? "" : window.location.search);
  const host = params.get("host") ?? "";
  const advisory = params.get("advisory") ?? "";
  const severity = params.get("severity") ?? "";
  const cve = params.get("cve") ?? "";
  const fixed = params.get("fixed") ?? "false";
  const exploited = params.get("exploited") ?? "";
  const rebootNeeded = params.get("reboot_needed") ?? "";
  const query = new URLSearchParams();
  if (host) query.set("host", host);
  if (advisory) query.set("advisory", advisory);
  if (severity) query.set("severity", severity);
  if (cve) query.set("cve", cve);
  if (fixed === "true") query.set("fixed", "true");
  if (exploited) query.set("exploited", exploited);
  if (rebootNeeded) query.set("reboot_needed", rebootNeeded);
  const summary = useData<Summary>("/api/v1/vulnerabilities/summary", seeded);
  const list = useData<Page>(`/api/v1/vulnerabilities${query.size ? `?${query}` : ""}`, seeded);
  const details = useData<Advisory>(advisory ? `/api/v1/vulnerabilities/advisories/${encodeURIComponent(advisory)}` : "", seeded);
  return <section aria-labelledby="vulnerabilities-title">
    <div className="read-card__heading"><div><p className="eyebrow">Exposure review</p><h2 id="vulnerabilities-title">Vulnerabilities</h2><p>Open host and advisory matches, ranked by exploitation evidence, EPSS, severity, and age.</p></div></div>
    {summary.error ? <section className="read-card" role="alert"><h2>{summary.status === 401 ? "Session expired" : "Data unavailable"}</h2><p>{summary.error}</p></section> : summary.data && <div className="summary-grid" aria-label="Vulnerability summary">
      {summary.data.by_severity.map((entry) => <a className="summary-card" key={entry.severity} href={`/vulnerabilities?severity=${entry.severity}&reboot_needed=false`}><span>{entry.severity}</span><strong>{entry.count.toLocaleString()}</strong></a>)}
      <a className="summary-card" href="/vulnerabilities?exploited=true&reboot_needed=false"><span>Exploited</span><strong>{summary.data.exploited.toLocaleString()}</strong></a>
      <article className="summary-card"><span>No fix</span><strong>{summary.data.no_fix.toLocaleString()}</strong></article>
      <a className="summary-card" href="/vulnerabilities?reboot_needed=true"><span>Reboot needed</span><strong>{summary.data.reboot_hosts.toLocaleString()}</strong></a>
      <article className="summary-card"><span>Affected hosts</span><strong>{summary.data.hosts.toLocaleString()}</strong></article>
    </div>}
    <form className="filter-form" action="/vulnerabilities" method="get"><label>Host name or ID<input name="host" defaultValue={host} maxLength={256} /></label><label>Advisory<input name="advisory" defaultValue={advisory} maxLength={128} /></label><label>Severity<select name="severity" defaultValue={severity}><option value="">All severities</option><option value="critical">Critical</option><option value="important">Important</option><option value="moderate">Moderate</option><option value="low">Low</option><option value="unrated">Unrated</option></select></label><label>CVE<input name="cve" defaultValue={cve} maxLength={64} /></label><label>State<select name="fixed" defaultValue={fixed}><option value="false">Open</option><option value="true">Fixed</option></select></label><label>Exploited<select name="exploited" defaultValue={exploited}><option value="">Any</option><option value="true">Yes</option><option value="false">No</option></select></label><label>Reboot needed<select name="reboot_needed" defaultValue={rebootNeeded}><option value="">Any</option><option value="true">Yes</option><option value="false">No</option></select></label><button type="submit">Apply filters</button>{(host || advisory || severity || cve || fixed === "true" || exploited || rebootNeeded) && <a className="button-link" href="/vulnerabilities">Clear</a>}</form>
    {advisory && details.data && <section className="read-card" aria-labelledby="advisory-details"><h3 id="advisory-details">CVE enrichment for {advisory}</h3>{details.data.cves.length === 0 ? <p>No CVE enrichment is available for this advisory.</p> : <ul>{details.data.cves.map((cve) => <li key={cve.cve_id}><strong>{cve.cve_id}</strong>{cve.cvss_score != null ? ` · CVSS ${cve.cvss_score} (${cve.cvss_version ?? "NVD"})` : ""}{cve.kev ? " · CISA KEV" : ""}{cve.euvd_exploited ? ` · EUVD ${cve.euvd_exploited}` : ""}{cve.epss != null ? ` · EPSS ${(cve.epss * 100).toFixed(1)}%` : ""}{cve.description && <p>{cve.description}</p>}</li>)}</ul>}</section>}
    {list.error ? <section className="read-card" role="alert"><h2>{list.status === 401 ? "Session expired" : "Data unavailable"}</h2><p>{list.error}</p></section> : !list.data ? <p role="status" className="read-state">Loading vulnerability matches…</p> : list.data.items.length === 0 ? <p className="read-state">No open vulnerability matches for this view.</p> : <>
      <div className="table-scroll"><table className="data-table"><thead><tr><th scope="col">Advisory</th><th scope="col">Severity / priority</th><th scope="col">Host</th><th scope="col">Packages</th><th scope="col">State</th><th scope="col">First seen</th></tr></thead><tbody>{list.data.items.map((item, index) => <tr key={`${item.agent_id}:${item.advisory_id}`}>
        <th scope="row"><a href={`/vulnerabilities?${new URLSearchParams({ ...(host ? { host } : {}), advisory: item.advisory_id }).toString()}`}>{item.advisory_id}</a><span className="table-subtext">{item.title}</span><span className="table-subtext">{item.cves.join(", ") || "No CVE listed"}</span></th>
        <td>{item.severity}{item.exploited ? " · exploited" : ""}{item.epss != null ? ` · EPSS ${(item.epss * 100).toFixed(1)}%` : ""}<span className="table-subtext">Priority {index + 1}{item.kev ? " · CISA KEV" : ""}{item.euvd ? " · EUVD" : ""}{item.ransomware ? " · ransomware" : ""}</span></td>
        <td><a href={`/vulnerabilities?host=${encodeURIComponent(item.agent_id)}`}>{item.hostname ?? item.agent_id}</a>{item.agent_id.startsWith("import.") && <span className="table-subtext">Imported · installation {item.agent_id.slice(7)}</span>}</td>
        <td><code>{Array.isArray(item.packages) ? item.packages.map((pkg) => typeof pkg === "object" && pkg !== null ? `${String(pkg.name ?? "package")} ${String(pkg.installed ?? "")}${pkg.fixed ? ` → ${String(pkg.fixed)}` : ""}` : "package").join(", ") : "Package details unavailable"}</code></td>
        <td>{item.fixed_at ? `Fixed ${dateLabel(item.fixed_at)}` : item.reboot_needed ? "Fix installed · reboot needed" : Array.isArray(item.packages) && item.packages.length > 0 && item.packages.every((pkg) => typeof pkg === "object" && pkg !== null && (pkg as Record<string, unknown>).fixed == null) ? "Open · no fix available" : "Open · fix available"}</td>
        <td><time dateTime={item.first_seen_at}>{dateLabel(item.first_seen_at)}</time></td>
      </tr>)}</tbody></table></div>
      {list.data.more_available && <p className="read-state">The prioritized API result is bounded to the first 100 matches. Narrow by host, advisory, severity, or CVE to review more.</p>}
      <p className="read-state">Generated {dateLabel(list.data.generated_at)}. A host label is descriptive; use its ID when names are shared.</p>
    </>}
  </section>;
}
