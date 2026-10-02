import { useResource } from "../api/client";
import type { HostServices } from "../api/types";
import { Ago, Empty, ErrorBox, Loading } from "../ui/bits";
import { Icon } from "../ui/Icon";

const REFUSED: Record<string, string> = {
  too_large: "over 512 KiB",
  invalid: "not a valid report",
  wrong_agent: "sent with another agent's id",
};

const TRUNCATED_NOTE = "The host has more than one report can carry (4,096 listeners, 2,048 services, 512 KiB); the agent cut the lists to those limits.";

const OWNERS_NOTE = "Some owners are not visible to the agent. Admins can opt in to exact program names on this host (see the agent's owners.conf).";

/** One host's open ports or running services (Assets v2), from its last report. */
export function HostServicesTab({ id, show }: { id: string; show: "ports" | "services" }) {
  const report = useResource<HostServices>(`/api/v1/agents/${encodeURIComponent(id)}/services`);
  if (report.error) return <div className="panel-body"><ErrorBox error={report.error} /></div>;
  if (report.loading && !report.data) return <div className="panel-body"><Loading rows={4} /></div>;
  const data = report.data;
  // Ingest refused the last report: say so, or the lists look current.
  const refused = data?.refused && data.refused_at ? (
    <div className="callout callout--warn" role="status"><Icon name="alert" size={16} /><span>Last report refused <Ago value={data.refused_at} />: {REFUSED[data.refused] ?? data.refused}.{data.reported_at ? " These lists are from the report before." : null}</span></div>
  ) : null;
  if (!data?.reported_at) {
    return <div className="panel-body stack">{refused}<Empty title="Not reported yet">Agents report open ports and running services about an hour after they start, once upgraded.</Empty></div>;
  }
  return (
    <div className="panel-body stack">
      {refused}
      <p className="subtle">As of <Ago value={data.reported_at} />{show === "ports" && data.owners === "partial" ? <> · <span title={OWNERS_NOTE}>some owners not visible</span></> : null}{data.truncated ? <> · <span title={TRUNCATED_NOTE}>some {show === "ports" ? "ports" : "services"} not listed</span></> : null}</p>
      {show === "ports" ? (
        data.listeners.length === 0 ? <Empty title="No open ports" /> : (
          <div className="table-wrap"><table className="table table--compact" aria-label="Open ports">
            <thead><tr><th>Port</th><th className="hide-narrow">Address</th><th>Service</th><th className="hide-narrow">Program</th></tr></thead>
            <tbody>
              {data.listeners.map((l) => (
                <tr key={`${l.protocol}/${l.address}/${l.port}`}>
                  <td className="mono nowrap">{l.port}/{l.protocol}{l.exposed && <> <span className="badge badge--warn badge--plain">exposed</span></>}</td>
                  <td className="mono hide-narrow">{l.address}</td>
                  <td className="mono">{l.service ?? "—"}</td>
                  <td className="mono hide-narrow">{l.program ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )
      ) : (
        data.services.length === 0 ? <Empty title="No services reported" /> : (
          <div className="table-wrap"><table className="table table--compact" aria-label="Running services">
            <thead><tr><th>Service</th><th className="hide-narrow">Programs</th><th>Processes</th><th>Runs as</th></tr></thead>
            <tbody>
              {data.services.map((s) => (
                <tr key={s.unit}>
                  <td className="mono">{s.unit}</td>
                  <td className="mono hide-narrow">{s.programs.join(", ") || "—"}</td>
                  <td className="num">{s.processes}</td>
                  <td className="mono">{s.run_as ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )
      )}
    </div>
  );
}
