import { useResource } from "../../../api/client";
import { portPath } from "../../../app/location";
import { viewLink } from "../../../app/nav";
import type { HostServices } from "../../../api/types";
import { Ago, Empty, ErrorBox, Loading } from "../../../ui/bits";
import { SortHeader, sortBy, useSort } from "../../../ui/DataTable";
import { Icon } from "../../../ui/Icon";
import type { SortValue } from "../../../ui/table";

const REFUSED: Record<string, string> = {
  too_large: "over 512 KiB",
  invalid: "not a valid report",
  wrong_agent: "sent with another agent's id",
};

const TRUNCATED_NOTE = "The host has more than one report can carry (4,096 listeners, 2,048 services, 512 KiB); the agent cut the lists to those limits.";

const OWNERS_NOTE = "Some owners are not visible to the agent. Admins can opt in to exact program names on this host (see the agent's owners.conf).";

type Listener = HostServices["listeners"][number];
type Service = HostServices["services"][number];
// The report's order (exposed first, then port; by unit) until a header is chosen.
const PORT_SORTS: Record<string, (l: Listener) => SortValue> = {
  port: (l) => l.port, address: (l) => l.address, service: (l) => l.service, program: (l) => l.program,
};
const SERVICE_SORTS: Record<string, (s: Service) => SortValue> = { service: (s) => s.unit, processes: (s) => s.processes, user: (s) => s.run_as };

/** One host's open ports or running services (Assets v2), from its last report. */
export function HostServicesTab({ id, show }: { id: string; show: "ports" | "services" }) {
  const report = useResource<HostServices>(`/api/v1/agents/${encodeURIComponent(id)}/services`);
  const sort = useSort();
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
            <thead><tr><SortHeader sort={sort} column="port" style={{ width: "15%" }}>Port</SortHeader><SortHeader sort={sort} column="address" className="hide-narrow" style={{ width: "25%" }}>Address</SortHeader>
              <SortHeader sort={sort} column="service" style={{ width: "30%" }}>Service</SortHeader><SortHeader sort={sort} column="program" className="hide-narrow" style={{ width: "30%" }}>Program</SortHeader></tr></thead>
            <tbody>
              {sortBy(data.listeners, PORT_SORTS, sort).map((l) => (
                <tr key={`${l.protocol}/${l.address}/${l.port}`}>
                  <td className="mono nowrap"><a {...viewLink(portPath(l.protocol, l.port))}>{l.port}/{l.protocol}</a>{l.exposed && <> <span className="badge badge--warn badge--plain">exposed</span></>}</td>
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
            <thead><tr><SortHeader sort={sort} column="service" style={{ width: "30%" }}>Service</SortHeader><th className="hide-narrow" style={{ width: "30%" }}>Programs</th>
              <SortHeader sort={sort} column="processes" style={{ width: "20%" }}>Processes</SortHeader><SortHeader sort={sort} column="user" style={{ width: "20%" }}>Runs as</SortHeader></tr></thead>
            <tbody>
              {sortBy(data.services, SERVICE_SORTS, sort).map((s) => (
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
