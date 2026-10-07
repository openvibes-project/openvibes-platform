// The count catalogue; ids and permissions must equal the server's CATALOGUE
// (crates/openvibes-console/src/metrics.rs), which catalogue.test.ts enforces.
// No DOM imports here so tests can read it.
// A cross-kind entry has no view of its own: only its parts navigate.
type Entry = {
  label: string; permissions: string[]; view?: [string, Record<string, string>]; parts?: [string, string][];
};
const defs = {
  "all.open.critical": { label: "Critical", permissions: ["alarms.read","vulnerabilities.read","compliance.read"], parts: [["alarm", "alarms.active.critical"], ["vulnerability", "vulns.open.critical"], ["compliance", "compliance.open.critical"]] },
  "all.open.high": { label: "High", permissions: ["alarms.read","vulnerabilities.read","compliance.read"], parts: [["alarm", "alarms.active.high"], ["vulnerability", "vulns.open.high"], ["compliance", "compliance.open.high"]] },
  "alarms.active": { label: "Active alarms", permissions: ["alarms.read"], view: ["/alarms", {}] },
  "alarms.active.critical": { label: "Active critical alarms", permissions: ["alarms.read"], view: ["/alarms", { severity: "critical" }] },
  "alarms.active.high": { label: "Active high alarms", permissions: ["alarms.read"], view: ["/alarms", { severity: "high" }] },
  "alarms.active.medium": { label: "Active medium alarms", permissions: ["alarms.read"], view: ["/alarms", { severity: "medium" }] },
  "alarms.active.low": { label: "Active low alarms", permissions: ["alarms.read"], view: ["/alarms", { severity: "low" }] },
  "vulns.open.critical": { label: "Open critical vulnerabilities", permissions: ["vulnerabilities.read"], view: ["/vulnerabilities", { severity: "critical" }] },
  "vulns.open.high": { label: "Open high vulnerabilities", permissions: ["vulnerabilities.read"], view: ["/vulnerabilities", { severity: "important" }] },
  "vulns.open.medium": { label: "Open medium vulnerabilities", permissions: ["vulnerabilities.read"], view: ["/vulnerabilities", { severity: "moderate" }] },
  "vulns.open.low": { label: "Open low vulnerabilities", permissions: ["vulnerabilities.read"], view: ["/vulnerabilities", { severity: "low" }] },
  "vulns.exploited": { label: "Exploited vulnerabilities", permissions: ["vulnerabilities.read"], view: ["/vulnerabilities", { exploited: "true" }] },
  "vulns.no_fix": { label: "No fix yet", permissions: ["vulnerabilities.read"], view: ["/vulnerabilities", { nofix: "true" }] },
  "vulns.reboot_hosts": { label: "Hosts needing a reboot", permissions: ["vulnerabilities.read"], view: ["/vulnerabilities", { reboot: "true" }] },
  "compliance.open.critical": { label: "Open critical compliance findings", permissions: ["compliance.read"], view: ["/compliance", { severity: "critical" }] },
  "compliance.open.high": { label: "Open high compliance findings", permissions: ["compliance.read"], view: ["/compliance", { severity: "high" }] },
  "compliance.open.medium": { label: "Open medium compliance findings", permissions: ["compliance.read"], view: ["/compliance", { severity: "medium" }] },
  "compliance.open.low": { label: "Open low compliance findings", permissions: ["compliance.read"], view: ["/compliance", { severity: "low" }] },
  "agents.active": { label: "Hosts online", permissions: ["agents.read"], view: ["/agents", { status: "active" }] },
  "agents.stale": { label: "Stale hosts", permissions: ["agents.read"], view: ["/agents", { status: "stale" }] },
  "agents.revoked": { label: "Revoked hosts", permissions: ["agents.read"], view: ["/agents", { status: "revoked" }] },
} satisfies Record<string, Entry>;
export const METRICS: Record<keyof typeof defs, Entry> = defs;
export type Metric = keyof typeof defs;
export const METRIC_KEYS = Object.keys(defs) as Metric[];

/** Fine print for one part of a cross-kind count: "1 vulnerability", "0 alarms". */
export function partText(kind: string, n: number): string {
  const word = kind === "vulnerability" ? (n === 1 ? "vulnerability" : "vulnerabilities") : kind === "alarm" && n !== 1 ? "alarms" : kind;
  return `${n} ${word}`;
}
