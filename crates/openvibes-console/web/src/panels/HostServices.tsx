import { useResource } from "../api/client";
import type { HostServices } from "../api/types";
import { Ago, Empty, ErrorBox, Loading } from "../ui/bits";

const OWNERS_NOTE = "Some owners are not visible to the agent. Admins can opt in to exact program names on this host (see the agent's owners.conf).";

/** One host's open ports or running services (Assets v2), from its last report. */
export function HostServicesTab({ id, show }: { id: string; show: "ports" | "services" }) {
  const report = useResource<HostServices>(`/api/v1/agents/${encodeURIComponent(id)}/services`);
  if (report.error) return <div className="panel-body"><ErrorBox error={report.error} /></div>;
  if (report.loading && !report.data) return <div className="panel-body"><Loading rows={4} /></div>;
  const data = report.data;
  if (!data?.reported_at) {
    return <div className="panel-body"><Empty title="Not reported yet">Agents from 0.3 on report open ports and running services about an hour after they start.</Empty></div>;
  }
  return (
    <div className="panel-body stack">
      <p className="subtle">As of <Ago value={data.reported_at} />{show === "ports" && data.owners === "partial" ? <> · <span title={OWNERS_NOTE}>some owners not visible</span></> : null}</p>
      {show === "ports" ? (
        data.listeners.length === 0 ? <Empty title="No open ports" /> : (
          <div className="table-wrap"><table className="table table--compact" aria-label="Open ports">
            <thead><tr><th>Port</th><th>Address</th><th>Service</th><th>Program</th></tr></thead>
            <tbody>
              {data.listeners.map((l) => (
                <tr key={`${l.protocol}/${l.address}/${l.port}`}>
                  <td className="mono nowrap">{l.port}/{l.protocol}{l.exposed && <> <span className="badge badge--warn badge--plain">exposed</span></>}</td>
                  <td className="mono">{l.address}</td>
                  <td className="mono">{l.service ?? "—"}</td>
                  <td className="mono">{l.program ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )
      ) : (
        data.services.length === 0 ? <Empty title="No services reported" /> : (
          <div className="table-wrap"><table className="table table--compact" aria-label="Running services">
            <thead><tr><th>Service</th><th>Programs</th><th>Processes</th><th>Runs as</th></tr></thead>
            <tbody>
              {data.services.map((s) => (
                <tr key={s.unit}>
                  <td className="mono">{s.unit}</td>
                  <td className="mono">{s.programs.join(", ") || "—"}</td>
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
