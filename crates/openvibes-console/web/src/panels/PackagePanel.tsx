// One package across the fleet (Assets v1): the versions in use with how
// many hosts run each, and the hosts themselves.
import { useResource } from "../api/client";
import type { SoftwareDetail } from "../api/types";
import { useProvideTitle } from "../app/titles";
import { Icon } from "../ui/Icon";
import { Ago, Empty, ErrorBox, Loading, ObjectLink, SeverityBadge } from "../ui/bits";
import { pct } from "../ui/format";
import { PanelHeader, Section } from "../ui/panel";
import { ShowMore, useMoreHosts } from "./MoreHosts";

/** `manager/name` → [manager, name]; the name may itself contain "/". */
export function splitPackageId(id: string): [string, string] {
  const split = id.indexOf("/");
  return split < 0 ? ["", id] : [id.slice(0, split), id.slice(split + 1)];
}

function fullVersion(v: { epoch: number; version: string; release: string }): string {
  return `${v.epoch ? `${v.epoch}:` : ""}${v.version}${v.release ? `-${v.release}` : ""}`;
}

export function PackagePanel({ id }: { id: string }) {
  const [manager, name] = splitPackageId(id);
  const path = `/api/v1/software/${encodeURIComponent(manager)}/${encodeURIComponent(name)}`;
  const detail = useResource<SoftwareDetail>(path);
  const page = useMoreHosts(path, detail.data);
  useProvideTitle({ kind: "package", id }, name);
  if (detail.error) return <div className="panel-body"><ErrorBox error={detail.error} /></div>;
  if (!detail.data) return <Loading />;
  const data = detail.data;
  const hosts = data.versions.reduce((sum, v) => sum + v.hosts, 0);
  return (
    <>
      <PanelHeader icon="package" kind={`Software · ${manager}`} title={<span className="mono">{name}</span>}
        badges={<><span className="badge badge--plain">{hosts} hosts</span><span className="badge badge--plain">{data.versions.length} {data.versions.length === 1 ? "version" : "versions"}</span></>} />
      <div className="panel-body stack">
        <Section title={`Versions in use (${data.versions.length})`}>
          <ul className="list list--plain" aria-label="Versions in use">
            {data.versions.map((v) => (
              <li key={`${fullVersion(v)}.${v.arch}`} className="list__row list__row--static">
                <span className="cell-two grow">
                  <span className="mono truncate">{fullVersion(v)} <span className="subtle">{v.arch}</span></span>
                  <span className="subtle">{hosts > 0 ? Math.round((v.hosts / hosts) * 100) : 0}% of hosts</span>
                </span>
                {v.advisories > 0 && <span className="badge badge--bad badge--plain">{v.advisories} {v.advisories === 1 ? "advisory" : "advisories"}</span>}
                {v.fixable_vulnerable_hosts > 0 && <span className="badge badge--warn badge--plain">fix available</span>}
                <span className="num nowrap">{v.hosts} hosts</span>
              </li>
            ))}
          </ul>
        </Section>
        <Section title={`Vulnerabilities (${data.advisories.length})`} flush>
          {data.advisories.length === 0 ? <Empty title="No open advisories on this package" /> : (
            <ul className="list" aria-label="Open advisories">
              {data.advisories.map((a) => (
                <li key={a.advisory_id}>
                  <ObjectLink to={{ kind: "advisory", id: a.advisory_id }} className="list__row">
                    <span className="cell-two grow">
                      <span className="truncate">{a.advisory_id} <span className="subtle">{a.title}</span></span>
                      <span className="subtle">
                        {a.cves.slice(0, 3).join(", ")}{a.cves.length > 3 ? ` +${a.cves.length - 3}` : ""}
                        {a.epss != null && ` · EPSS ${pct(a.epss)}`}{a.cvss != null && ` · CVSS ${a.cvss.toFixed(1)}`}
                        {" · "}{a.fixed_in ? <>fixed in <span className="mono">{a.fixed_in}</span></> : "no fix yet"}
                      </span>
                    </span>
                    {a.exploited && <span className="badge badge--critical badge--plain" title="Known to be exploited"><Icon name="flame" size={12} /> Exploited</span>}
                    <SeverityBadge severity={a.severity} />
                    <span className="num nowrap">{a.hosts} {a.hosts === 1 ? "host" : "hosts"}</span>
                  </ObjectLink>
                </li>
              ))}
            </ul>
          )}
        </Section>
        <Section title="Hosts" flush>
          {page.hosts.length === 0 ? <Empty title="No host in your scope has it" /> : (
            <ul className="list" aria-label="Hosts that have it">
              {page.hosts.map((host) => (
                <li key={`${host.agent_id}.${host.version}.${host.arch}`}>
                  <ObjectLink to={{ kind: "agent", id: host.agent_id }} className="list__row">
                    <span className="cell-two grow">
                      <span>{host.hostname ?? host.agent_id}</span>
                      <span className="subtle"><span className="mono">{host.version}</span> · <Ago value={host.last_seen_at} /></span>
                    </span>
                    {host.fixable_vulnerable && <span className="badge badge--warn badge--plain">fix available</span>}
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
