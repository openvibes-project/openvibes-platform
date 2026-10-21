// A host's software, open ports or running services at full width
// (`/hosts/{id}/software|ports|services`, plan ruling 9): the per-host
// tables the panel's tabs showed, reached from the host's page.
import { useState } from "react";

import { useAllPages, useResource } from "../../../api/client";
import type { HostPackage, HostSummary } from "../../../api/types";
import { hostPath } from "../../../app/location";
import { viewLink } from "../../../app/nav";
import { useProvideTitle } from "../../../app/titles";
import { Empty, ErrorBox, Loading, ObjectLink } from "../../../ui/bits";
import { packageId } from "../Software";
import { HostServicesTab } from "./HostServices";
import { NoSuchHost, summaryPath } from "./HostPage";

export const SUB_PAGES = { software: "Software", ports: "Open ports", services: "Services" } as const;
export type SubPage = keyof typeof SUB_PAGES;

/** The host's installed software (Assets v1), filtered on the server. */
export function SoftwareTab({ id }: { id: string }) {
  const [q, setQ] = useState("");
  const [fixable, setFixable] = useState(false);
  const [max, setMax] = useState(200);
  const query = new URLSearchParams();
  if (q.trim()) query.set("q", q.trim());
  if (fixable) query.set("fixable", "true");
  const packages = useAllPages<HostPackage>(`/api/v1/agents/${encodeURIComponent(id)}/packages?${query.toString()}`, max);
  const items = packages.data ?? [];
  return (
    <div className="panel-body stack">
      <div className="row row--wrap">
        <input className="input grow" value={q} onChange={(event) => { setQ(event.target.value); setMax(200); }} placeholder="Filter by package name…" aria-label="Filter installed software" />
        <label className="row"><input type="checkbox" className="checkbox" checked={fixable} onChange={(event) => setFixable(event.target.checked)} /> Fix available</label>
      </div>
      {packages.error ? <ErrorBox error={packages.error} /> : packages.loading && !packages.data ? <Loading rows={4} /> : items.length === 0 ? (
        <Empty title={q || fixable ? "Nothing matches" : "No software reported"}>{q || fixable ? null : "The agent reports its packages shortly after it enrolls."}</Empty>
      ) : (
        <ul className="list" aria-label="Installed software">
          {items.map((pkg) => (
            <li key={`${pkg.manager}/${pkg.name}/${pkg.version}/${pkg.release}/${pkg.arch}`}>
              <ObjectLink to={{ kind: "package", id: packageId(pkg) }} className="list__row">
                <span className="mono grow truncate">{pkg.name}</span>
                <span className="mono subtle nowrap">{pkg.version}{pkg.release ? `-${pkg.release}` : ""}</span>
                {pkg.fixable_vulnerable && <span className="badge badge--warn badge--plain">fix available</span>}
              </ObjectLink>
            </li>
          ))}
        </ul>
      )}
      {items.length >= max && <button type="button" className="button" onClick={() => setMax((m) => m + 200)}>Show more</button>}
    </div>
  );
}

export function HostSubPage({ id, page }: { id: string; page: SubPage }) {
  const summary = useResource<HostSummary>(summaryPath(id));
  const name = summary.data?.host.hostname ?? id;
  useProvideTitle({ kind: "agent", id }, summary.data?.host.hostname ?? undefined);
  if (summary.error?.status === 404) return <NoSuchHost />;
  return (
    <div className="view host-sub-page">
      <div className="view-pad person-page__crumb subtle">
        <a {...viewLink("/hosts")}>Hosts</a> › <a {...viewLink(hostPath(id))}>{name}</a>
      </div>
      <header className="view-pad host-sub-page__head">
        <h1>{SUB_PAGES[page]} <span className="subtle">on <span className="mono">{name}</span></span></h1>
        <nav className="row" aria-label="This host's lists">
          {(Object.keys(SUB_PAGES) as SubPage[]).map((p) => (
            <a key={p} className="chip" aria-current={p === page ? "page" : undefined} {...viewLink(`${hostPath(id)}/${p}`)}>{SUB_PAGES[p]}</a>
          ))}
        </nav>
      </header>
      {summary.error ? <div className="view-pad"><ErrorBox error={summary.error} /></div>
        : page === "software" ? <SoftwareTab id={id} /> : <HostServicesTab id={id} show={page} />}
    </div>
  );
}
