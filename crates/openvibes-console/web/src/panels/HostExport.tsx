// Export one host to CSV (#119): the user picks the sections, the browser
// fetches them through the same scoped API the Host page uses, and saves
// one file with a `section` column. Nothing new on the server.
import { useState } from "react";

import { request } from "../api/client";
import type { Agent, AlarmSummary, Finding, HostPackage, HostServices, Vulnerability } from "../api/types";
import { useSession } from "../app/session";
import { downloadCsv } from "../ui/csv";
import { Icon } from "../ui/Icon";
import { toast } from "../ui/toast";

type Section = "details" | "findings" | "alarms" | "vulnerabilities" | "software" | "ports" | "services";
type Row = [Section, string, string, string, string, string];

const LABELS: Record<Section, string> = {
  details: "Details", findings: "Findings", alarms: "Alarms", vulnerabilities: "Vulnerabilities",
  software: "Software", ports: "Ports", services: "Services",
};
const PERMISSION: Partial<Record<Section, "findings.read" | "alarms.read" | "vulnerabilities.read">> = {
  findings: "findings.read", alarms: "alarms.read", vulnerabilities: "vulnerabilities.read",
};
/** At most this many rows per section: a runaway list never freezes the tab. */
const CAP = 10_000;

/** Every page of a cursor-paged list, up to CAP items. */
async function all<T>(path: string): Promise<T[]> {
  const items: T[] = [];
  let cursor: string | null | undefined = null;
  do {
    const separator = path.includes("?") ? "&" : "?";
    const page: { items: T[]; next_cursor?: string | null } = await request("GET", `${path}${separator}limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
    items.push(...page.items);
    cursor = page.next_cursor;
  } while (cursor && items.length < CAP);
  return items.slice(0, CAP);
}

async function rows(agent: Agent, sections: readonly Section[]): Promise<Row[]> {
  const id = encodeURIComponent(agent.id);
  const out: Row[] = [];
  for (const section of sections) {
    if (section === "details") {
      for (const [key, value] of [["host name", agent.hostname], ["agent id", agent.id], ["status", agent.status], ["agent version", agent.scanner_version],
        ["system", [agent.os_id, agent.os_version].filter(Boolean).join(" ")], ["running kernel", agent.running_kernel], ["enrolled", agent.enrolled_at], ["last contact", agent.last_seen_at]] as const) {
        out.push(["details", key, String(value ?? ""), "", "", ""]);
      }
    } else if (section === "findings") {
      for (const f of (await all<Finding>("/api/v1/findings/latest")).filter((f) => f.agent_id === agent.id)) {
        out.push(["findings", f.message, `${f.rule_set_id}/${f.rule_id}`, "", f.severity, f.last_observed_at]);
      }
    } else if (section === "alarms") {
      for (const a of await all<AlarmSummary>(`/api/v1/alarms?agent_id=${id}&state=all&suppressed=true`)) {
        out.push(["alarms", a.message, a.exe, a.state, a.severity, `${a.count}× · last ${a.last_seen}`]);
      }
    } else if (section === "vulnerabilities") {
      for (const v of await all<Vulnerability>(`/api/v1/vulnerabilities?host=${id}`)) {
        out.push(["vulnerabilities", v.title, `${v.advisory_id}${v.cves.length ? ` (${v.cves.join(" ")})` : ""}`, v.fixed_at ? "fixed" : "open", v.severity, v.exploited ? "known exploited" : ""]);
      }
    } else if (section === "software") {
      for (const p of await all<HostPackage>(`/api/v1/agents/${id}/packages`)) {
        out.push(["software", p.name, `${p.version}${p.release ? `-${p.release}` : ""}`, p.arch, "", p.fixable_vulnerable ? "fix available" : ""]);
      }
    } else {
      const report = await request<HostServices>("GET", `/api/v1/agents/${id}/services`);
      if (section === "ports") {
        for (const l of report.listeners) out.push(["ports", `${l.port}/${l.protocol}`, l.address, l.exposed ? "exposed" : "local", "", [l.service, l.program].filter(Boolean).join(" · ")]);
      } else {
        for (const s of report.services) out.push(["services", s.unit, s.programs.join(" "), s.run_as ?? "", "", `${s.processes} processes`]);
      }
    }
  }
  return out;
}

/** The Host page's Export button and its section picker. */
export function HostExport({ agent }: { agent: Agent }) {
  const { can } = useSession();
  const allowed = (Object.keys(LABELS) as Section[]).filter((s) => !PERMISSION[s] || can(PERMISSION[s]));
  const [open, setOpen] = useState(false);
  const [picked, setPicked] = useState<Section[]>(allowed);
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    try {
      const data = await rows(agent, allowed.filter((s) => picked.includes(s)));
      const day = new Date().toISOString().slice(0, 10);
      downloadCsv(`openvibes-${agent.hostname ?? agent.id}-${day}.csv`, [["section", "name", "detail", "state", "severity", "extra"], ...data]);
      setOpen(false);
    } catch {
      toast("The export failed; try again", true);
    } finally {
      setBusy(false);
    }
  };
  if (!open) return <button type="button" className="button" onClick={() => setOpen(true)}><Icon name="download" size={14} /> Export</button>;
  return (
    <div className="stack export-picker" role="group" aria-label="Export this host">
      {allowed.map((s) => (
        <label key={s} className="row"><input type="checkbox" checked={picked.includes(s)} onChange={() => setPicked((p) => p.includes(s) ? p.filter((x) => x !== s) : [...p, s])} /> {LABELS[s]}</label>
      ))}
      <div className="row">
        <button type="button" className="button button--primary" disabled={busy || picked.length === 0} onClick={() => void save()}>{busy ? "Exporting…" : "Download CSV"}</button>
        <button type="button" className="button" onClick={() => setOpen(false)}>Cancel</button>
      </div>
    </div>
  );
}
