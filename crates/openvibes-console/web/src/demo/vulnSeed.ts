// Hand-made vulnerabilities on top of data.ts's generated ones (no random()
// draws, so the rest of the demo stays put), for the cases the
// Vulnerabilities list and page must show (roles 5b): a CVE covered by a
// Fedora and a Debian advisory, a Fedora advisory naming two CVEs, a fixed
// (resolved) pair and a mitigated one, KEV due dates overdue, within 30 days
// and later, assignees (one person, two, none) and a lower-confidence CPE
// match. Hosts: n % 4 is 0 for Fedora, 1 for Debian, 2 for Ubuntu.
import type { Cve, Vulnerability } from "../api/types";

type Pkg = { name: string; installed: string; fixed: string | null };
type Seed = {
  id: string; title: string; severity: Vulnerability["severity"]; url: string; source: string; cves: Cve[];
  pkg: Pkg; due: number | null; confidence: number; method: string; basis: string;
  hosts: { agent: string; state?: string; assignee?: string; fixedDaysAgo?: number }[];
};

const DAY = 86_400_000;

const cve = (cve_id: string, cvss: number, epss: number, kev: boolean, description: string, now: number): Cve => ({
  cve_id, cvss_score: cvss, cvss_version: "3.1", cwe: ["CWE-787"], description, epss,
  euvd_exploited: kev ? new Date(now - 20 * DAY).toISOString() : null, kev,
});

function seeds(now: number): Seed[] {
  const tls = cve("CVE-2026-20037", 9.8, 0.879, true, "A flaw in openssl's TLS 1.3 handshake lets a remote attacker corrupt memory.", now);
  const timing = cve("CVE-2026-20051", 5.3, 0.008, false, "A timing side channel in openssl's RSA decryption may disclose key material.", now);
  const socks = cve("CVE-2026-20042", 8.6, 0.631, true, "A heap overflow in curl's SOCKS5 proxy handshake.", now);
  const smuggling = cve("CVE-2026-20112", 7.5, 0.12, false, "Request smuggling in nginx with HTTP/2.", now);
  const fedora = "Fedora's own security advisory names this package; the installed version is older than the fixed one.";
  const debian = "Debian's security advisory names this package; the installed version is older than the fixed one.";
  return [
    { id: "FEDORA-2026-5b1e0c11", title: "openssl security update", severity: "critical", url: "https://bodhi.fedoraproject.org/updates/FEDORA-2026-5b1e0c11",
      source: "fedora-44-x86_64", cves: [tls, timing], pkg: { name: "openssl", installed: "3.2.2-3.fc44", fixed: "3.2.2-6.fc44" },
      due: now - 3 * DAY, confidence: 98, method: "distribution-advisory", basis: fedora,
      hosts: [{ agent: "agent-00004", assignee: "sam" }, { agent: "agent-00008", assignee: "ola" }, { agent: "agent-00012", state: "mitigated" }] },
    { id: "DSA-5891-1", title: "openssl security update", severity: "important", url: "https://www.debian.org/security/2026/dsa-5891",
      source: "debian-12-amd64", cves: [tls], pkg: { name: "openssl", installed: "3.0.14-1~deb12u2", fixed: "3.0.15-1~deb12u1" },
      due: now - 3 * DAY, confidence: 98, method: "distribution-advisory", basis: debian,
      hosts: [{ agent: "agent-00001", assignee: "sam" }, { agent: "agent-00005" }, { agent: "agent-00009", fixedDaysAgo: 2 }] },
    { id: "DSA-5900-1", title: "curl security update", severity: "important", url: "https://www.debian.org/security/2026/dsa-5900",
      source: "debian-12-amd64", cves: [socks], pkg: { name: "curl", installed: "7.88.1-10+deb12u7", fixed: "7.88.1-10+deb12u8" },
      due: now + 60 * DAY, confidence: 98, method: "distribution-advisory", basis: debian,
      hosts: [{ agent: "agent-00001", assignee: "sam" }, { agent: "agent-00005", assignee: "sam" }] },
    { id: "CPE:CVE-2026-20112:nginx", title: "nginx: request smuggling with HTTP/2", severity: "important", url: "https://nvd.nist.gov/vuln/detail/CVE-2026-20112",
      source: "nvd-cpe", cves: [smuggling], pkg: { name: "nginx", installed: "1.24.0-2ubuntu7", fixed: null },
      due: null, confidence: 60, method: "cpe-range", basis: "Matched from NVD's upstream version ranges, not a distribution advisory.",
      hosts: [{ agent: "agent-00002" }, { agent: "agent-00006" }] },
  ];
}

/** Adds the seeded advisories and their pairs (only on hosts that report). */
export function seedVulnerabilities(now: number, hostname: (agent: string) => string | null | undefined,
  advisories: { id: string; title: string; severity: Vulnerability["severity"]; packages: Pkg[]; cves: Cve[]; hitRate: number; kernel: boolean }[],
  vulnerabilities: Vulnerability[]) {
  const iso = (ms: number) => new Date(ms).toISOString();
  for (const s of seeds(now)) {
    advisories.push({ id: s.id, title: s.title, severity: s.severity, packages: [s.pkg], cves: s.cves, hitRate: 0, kernel: false });
    const first = s.cves[0];
    const kev = s.cves.some((c) => c.kev);
    for (const h of s.hosts) {
      const name = hostname(h.agent);
      if (name === undefined) continue;
      vulnerabilities.push({
        advisory_id: s.id, agent_id: h.agent, hostname: name, title: s.title, severity: s.severity, url: s.url,
        cves: s.cves.map((c) => c.cve_id), cvss: first?.cvss_score ?? null, epss: first?.epss ?? null,
        epss_percentile: first?.epss == null ? null : Math.min(0.999, first.epss * 1.1),
        kev, kev_due: kev && s.due != null ? iso(s.due) : null, euvd: kev, exploited: kev, ransomware: false, reboot_needed: false,
        packages: [s.pkg], first_seen_at: iso(now - 9 * DAY), fixed_at: h.fixedDaysAgo == null ? null : iso(now - h.fixedDaysAgo * DAY),
        source: s.source, match_method: s.method, confidence: s.confidence, match_basis: s.basis,
        triage_state: h.state ?? "open", triage_version: h.state ? 1 : 0, assigned_to: h.assignee ?? null,
      });
    }
  }
}
