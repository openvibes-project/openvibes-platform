// The count catalogue; ids and permissions must equal the server's CATALOGUE
// (crates/openvibes-console/src/metrics.rs), which catalogue.test.ts enforces.
// No DOM imports here so tests can read it.
// A cross-kind entry has no view of its own: only its parts navigate.
import { count } from "../ui/format";
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
  return `${count(n)} ${word}`;
}

/** Change between the first and last point of the shown period; null under two points. */
export function delta(points: { day: string; value: number }[]): string | null {
  const first = points[0];
  const last = points.at(-1);
  if (!first || !last || points.length < 2) return null;
  const d = last.value - first.value;
  return d === 0 ? "no change" : `${d < 0 ? "−" : "+"}${count(Math.abs(d))}`;
}

/** A count needs every permission of its kinds. */
export const permitted = (id: Metric, can: (permission: string) => boolean) => METRICS[id].permissions.every(can);

export const TREND_DAYS = [0, 7, 30, 90] as const;
/** The trend period a tile asks for; anything unknown means off. */
export const trendDays = (v: unknown): (typeof TREND_DAYS)[number] => TREND_DAYS.find((d) => d === v) ?? 0;

/** "vs 12 d ago" when the history starts later than the trend period asks (new install, gaps); else null. */
export function deltaSince(points: { day: string }[], trend: number, now = Date.now()): string | null {
  const first = points[0];
  if (!first || points.length < 2) return null;
  const ago = Math.round((Math.floor(now / 86_400_000) * 86_400_000 - Date.parse(first.day)) / 86_400_000);
  return ago < trend - 1 ? `vs ${ago} d ago` : null;
}

export const GRAPH_MAX_LINES = 4;
/** The counts a graph draws: catalogue ids only, no repeats, at most four; one default if none. */
export function graphMetrics(config: Record<string, unknown>): Metric[] {
  const raw = Array.isArray(config.metrics) ? config.metrics : [];
  const ids = [...new Set(raw.filter((m): m is Metric => typeof m === "string" && m in METRICS))].slice(0, GRAPH_MAX_LINES);
  return ids.length ? ids : ["alarms.active"];
}
