// A CVE's own facts as the server reads them from cve_enrichment (the list
// row and the page take them per CVE, not from the covering advisory, which
// may name several CVEs): exploited (KEV or EUVD), the KEV due date, CVSS
// and EPSS. Null for a key that is an advisory without CVEs.
import type { Cve } from "../../api/types";

export function cveFacts(advisories: readonly { cves: readonly Cve[] }[], key: string, pairs: readonly { kev_due?: string | null }[]) {
  const cve = advisories.flatMap((a) => a.cves).find((c) => c.cve_id === key);
  if (!cve) return null;
  // The demo keeps the KEV date per pair; it is this CVE's only when the CVE is on KEV.
  const due = cve.kev ? pairs.flatMap((p) => (p.kev_due ? [p.kev_due.slice(0, 10)] : [])).sort()[0] ?? null : null;
  return {
    exploited: cve.kev || cve.euvd_exploited != null, due, cvss: cve.cvss_score ?? null, epss: cve.epss ?? null,
    epss_percentile: cve.epss == null ? null : Math.min(0.999, cve.epss * 1.6),
  };
}
