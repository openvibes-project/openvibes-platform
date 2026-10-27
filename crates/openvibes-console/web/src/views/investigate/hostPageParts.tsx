// The pieces the port and service pages share (a host-centred page: Details,
// By group, Recent changes, Hosts, Related). Each page keeps its own wording
// and passes it in.
import type { ReactNode } from "react";

import { useResource } from "../../api/client";
import { checkPath } from "../../app/location";
import { nav, useLocation, viewLink } from "../../app/nav";
import { Ago, Empty, ErrorBox, Loading, ObjectLink, SeverityBadge } from "../../ui/bits";
import { Card } from "../../ui/detail/DetailPage";
import { SegmentChips } from "../../ui/detail/SegmentChips";
import { plural } from "../../ui/format";
import { PAGE } from "../../ui/list/filters";
import { Pager } from "./Hosts";

const DAY = 86_400_000;
export const PAGE_SIZE = 50;

/** A host's last services report is stale after a day (the step-4 rule). */
export const stale = (reportedAt: string | null | undefined, now = Date.now()) => reportedAt != null && now - Date.parse(reportedAt) > DAY;

/** The URL's `segment` among a page's segments; anything unknown is the first (All). */
export const segmentIn = <S extends string>(segments: readonly S[], value: string | null): S => segments.find((s) => s === value) ?? (segments[0] as S);

/** The By group card: a meter per group of how many of its hosts have it. */
export function GroupMeters({ groups, empty, listLabel, meterLabel }: {
  groups: readonly { group_id: string; name: string; count: number; of: number }[];
  empty: string;
  listLabel: string;
  meterLabel: string;
}) {
  return (
    <Card title="By group">
      {groups.length === 0 ? <p className="subtle">{empty}</p> : (
        <ul className="list list--plain" aria-label={listLabel}>
          {groups.map((g) => (
            <li key={g.group_id} className="list__row list__row--static stack" style={{ alignItems: "stretch" }}>
              <span className="row row--between">
                <a className="object-link" {...viewLink("/hosts", { group: g.group_id })}>{g.name}</a>
                <span className="num subtle">{g.count.toLocaleString()} of {g.of.toLocaleString()}</span>
              </span>
              <span className="meter meter--wide" role="meter" aria-label={`${g.name}: ${g.count} of ${g.of} hosts ${meterLabel}`} aria-valuemin={0} aria-valuemax={g.of} aria-valuenow={g.count}>
                <span style={{ width: `${g.of ? Math.round((100 * g.count) / g.of) : 0}%` }} />
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** The Recent changes card; `text` says what each kind of change means. */
export function ChangeList({ changes, text }: {
  changes: readonly { at: string; agent_id: string; hostname?: string | null; change: string }[];
  text: Record<string, string>;
}) {
  return (
    <Card title="Recent changes">
      {changes.length === 0 ? <Empty title="No change in the last 90 days" /> : (
        <ul className="list list--plain" aria-label="Changes, newest first">
          {changes.map((c, i) => (
            <li key={`${c.at}:${c.agent_id}:${c.change}:${i}`} className="list__row list__row--static stack" style={{ alignItems: "flex-start" }}>
              <span><ObjectLink to={{ kind: "agent", id: c.agent_id }}>{c.hostname ?? c.agent_id}</ObjectLink> {text[c.change] ?? c.change}</span>
              <span className="subtle"><Ago value={c.at} /></span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** The Hosts card: the segment chips, the paged table and its states; `hostsUrl` builds the route for a query. */
export function HostsPanel<Row extends { agent_id: string }, S extends string>({ hostsUrl, segments, labels, chipsLabel, fallback, emptyAll, table }: {
  hostsUrl: (query: string) => string;
  segments: readonly S[];
  labels: Record<S, string>;
  chipsLabel: string;
  fallback: number;
  emptyAll: string;
  table: (rows: readonly Row[]) => ReactNode;
}) {
  const { params } = useLocation();
  const segment = segmentIn(segments, params.get("segment"));
  const offset = Math.max(0, Number(params.get(PAGE)) || 0);
  const hosts = useResource<{ items: Row[]; total: number; segments: Record<string, number> }>(hostsUrl(`?segment=${segment}&offset=${offset}&limit=${PAGE_SIZE}`));
  const data = hosts.data;
  const counts = data?.segments;
  return (
    <Card id="hosts" flush title={<>Hosts <span className="subtle num">{(counts?.["all"] ?? fallback).toLocaleString()}</span></>}
      aside={<SegmentChips label={chipsLabel} value={segment} onChange={(s) => nav.setParams({ segment: s === segments[0] ? null : s, [PAGE]: null })}
        options={segments.map((s) => ({ key: s, label: labels[s], count: counts?.[s] ?? 0 }))} />}>
      {hosts.error ? <div className="person-card__body"><ErrorBox error={hosts.error} /></div> : !data ? <Loading rows={3} /> : data.items.length === 0
        ? <Empty title={segment === segments[0] ? emptyAll : `No ${labels[segment].toLowerCase()} hosts`} />
        : table(data.items)}
      {data && <Pager offset={offset} shown={data.items.length} total={data.total} />}
    </Card>
  );
}

/** The table's first and last cells, the same on both pages. */
export function HostCell({ row }: { row: { agent_id: string; hostname?: string | null; os?: string | null; ip?: string | null } }) {
  return (
    <td><div className="cell-two"><ObjectLink to={{ kind: "agent", id: row.agent_id }} className="object-link mono">{row.hostname ?? row.agent_id}</ObjectLink>
      <span className="subtle">{[row.os, row.ip].filter(Boolean).join(" · ")}</span></div></td>
  );
}
export function ReportedCell({ at }: { at: string | null | undefined }) {
  return <td className={stale(at) ? "text-warn" : "subtle"}><Ago value={at} {...(stale(at) ? { hint: "More than a day ago" } : {})} /></td>;
}

/** The Related sections that read the same on both pages. */
export function failingChecks(compliance: {
  total: number; area?: string | null;
  items: readonly { rule_set_id: string; rule_id: string; severity: string; title: string; hosts: number }[];
}) {
  return {
    label: "Failing checks",
    value: compliance.total === 0 ? <span className="subtle">None</span> : (
      <ul className="list list--plain" aria-label="Failing checks">
        {compliance.items.map((c) => (
          <li key={`${c.rule_set_id}/${c.rule_id}`} className="list__row list__row--static">
            <SeverityBadge severity={c.severity} /><a className="object-link truncate" {...viewLink(checkPath(c.rule_set_id, c.rule_id))}>{c.title}</a>
            <span className="grow" /><span className="subtle nowrap">{plural(c.hosts, "host")}</span>
          </li>
        ))}
        {compliance.total > compliance.items.length && (
          <li><a className="object-link" {...viewLink("/compliance", compliance.area ? { area: compliance.area } : undefined)}>{(compliance.total - compliance.items.length).toLocaleString()} more</a></li>
        )}
      </ul>
    ),
  };
}
export function openVulnerabilities(packages: readonly { package: string; advisories: number; hosts: number }[]) {
  return {
    label: "Vulnerabilities",
    value: (
      <ul className="list list--plain" aria-label="Open vulnerabilities by package">
        {packages.map((v) => (
          <li key={v.package} className="list__row list__row--static">
            <a className="object-link mono" {...viewLink("/vulnerabilities", { package: v.package })}>{v.package}</a>
            <span className="grow" /><span className="subtle nowrap">{v.advisories.toLocaleString()} open on {plural(v.hosts, "host")}</span>
          </li>
        ))}
      </ul>
    ),
  };
}
export function openAlarms(label: string, notCollected: string | false, alarms: { open: number; hosts: number }) {
  return { label, value: notCollected ? <span className="subtle">{notCollected}</span> : alarms.open === 0 ? <span className="subtle">None open</span> : <>{plural(alarms.open, "alarm")} on {plural(alarms.hosts, "host")}</> };
}
