// One port or one service unit across the fleet (Assets v2): the visible
// hosts that have it, linking to their Host page. Hosts are paged like a
// package's; the panel shows the first page.
import { useResource } from "../api/client";
import type { PortDetail, UnitDetail } from "../api/types";
import { useProvideTitle } from "../app/titles";
import { Ago, Empty, ErrorBox, Loading, ObjectLink } from "../ui/bits";
import { PanelHeader, Section } from "../ui/panel";
import { ShowMore, useMoreHosts } from "./MoreHosts";

/** `tcp/443` → ["tcp", "443"]. */
export function splitPortId(id: string): [string, string] {
  const split = id.indexOf("/");
  return split < 0 ? ["tcp", id] : [id.slice(0, split), id.slice(split + 1)];
}

export function PortPanel({ id }: { id: string }) {
  const [protocol, port] = splitPortId(id);
  const path = `/api/v1/ports/${encodeURIComponent(protocol)}/${encodeURIComponent(port)}`;
  const detail = useResource<PortDetail>(path);
  const page = useMoreHosts(path, detail.data);
  useProvideTitle({ kind: "port", id }, `${port}/${protocol}`);
  if (detail.error) return <div className="panel-body"><ErrorBox error={detail.error} /></div>;
  if (!detail.data) return <Loading />;
  const data = detail.data;
  return (
    <>
      <PanelHeader icon="activity" kind="Port" title={<span className="mono">{data.port}/{data.protocol}</span>}
        badges={<span className="badge badge--plain">{page.hosts.length}{page.more ? "+" : ""} hosts</span>} />
      <div className="panel-body stack">
        <Section title="Hosts listening on it" flush>
          {page.hosts.length === 0 ? <Empty title="No host in your scope listens on it" /> : (
            <ul className="list" aria-label="Hosts listening on this port">
              {page.hosts.map((h) => (
                <li key={`${h.agent_id}/${h.address}`}>
                  <ObjectLink to={{ kind: "agent", id: h.agent_id }} className="list__row">
                    <span className="cell-two grow">
                      <span>{h.hostname ?? h.agent_id}</span>
                      <span className="subtle"><span className="mono">{h.address}</span> · <span className="mono">{h.service ?? h.program ?? "owner not visible"}</span> · <Ago value={h.last_seen_at} /></span>
                    </span>
                    {h.exposed && <span className="badge badge--warn badge--plain">exposed</span>}
                  </ObjectLink>
                </li>
              ))}
            </ul>
          )}
          <ShowMore shown={page.hosts.length} {...page} />
        </Section>
      </div>
    </>
  );
}

export function UnitPanel({ id }: { id: string }) {
  const path = `/api/v1/services/${encodeURIComponent(id)}`;
  const detail = useResource<UnitDetail>(path);
  const page = useMoreHosts(path, detail.data);
  useProvideTitle({ kind: "unit", id }, id);
  if (detail.error) return <div className="panel-body"><ErrorBox error={detail.error} /></div>;
  if (!detail.data) return <Loading />;
  const data = detail.data;
  return (
    <>
      <PanelHeader icon="layers" kind="Service" title={<span className="mono">{data.unit}</span>}
        badges={<span className="badge badge--plain">{page.hosts.length}{page.more ? "+" : ""} hosts</span>} />
      <div className="panel-body stack">
        <Section title="Hosts running it" flush>
          {page.hosts.length === 0 ? <Empty title="No host in your scope runs it" /> : (
            <ul className="list" aria-label="Hosts running this service">
              {page.hosts.map((h) => (
                <li key={h.agent_id}>
                  <ObjectLink to={{ kind: "agent", id: h.agent_id }} className="list__row">
                    <span className="cell-two grow">
                      <span>{h.hostname ?? h.agent_id}</span>
                      <span className="subtle"><span className="mono">{h.programs.join(", ") || "—"}</span> as <span className="mono">{h.run_as ?? "?"}</span> · <Ago value={h.last_seen_at} /></span>
                    </span>
                    <span className="num nowrap subtle">{h.processes} {h.processes === 1 ? "process" : "processes"}</span>
                  </ObjectLink>
                </li>
              ))}
            </ul>
          )}
          <ShowMore shown={page.hosts.length} {...page} />
        </Section>
      </div>
    </>
  );
}
