// The shell the Ports and Services lists share: header with the count and
// Refresh, the filter bar, the last page kept on screen while the next
// loads, and the empty and error states. Each list passes its own wording
// and its table.
import { type ReactNode, useEffect, useState } from "react";

import { invalidate, useResource } from "../../api/client";
import { useLocation } from "../../app/nav";
import { Empty, ErrorBox, Loading } from "../../ui/bits";
import type { Column } from "../../ui/DataTable";
import { plural } from "../../ui/format";
import { Icon, type IconName } from "../../ui/Icon";
import { FilterBar } from "../../ui/list/FilterBar";
import { type ListFilter, PAGE, hasFilters } from "../../ui/list/filters";
import { importBrowserViews, useHiddenColumns } from "../../ui/list/savedViews";
import { SummaryLine } from "../../ui/list/SummaryLine";
import { useHostName } from "../lists/HostChip";

const PAGE_SIZE = 50;

/** The API query for a list's URL: only the parameters in `keys` (the API refuses anything else). */
export function listApiQuery(params: URLSearchParams, keys: readonly string[]): string {
  const query = new URLSearchParams();
  for (const key of keys) {
    const value = params.get(key);
    if (value) query.set(key, value);
  }
  query.set("limit", String(PAGE_SIZE));
  return query.toString();
}

/** Chip values from the server's counts, labelled by `labels` (the value itself when unknown). */
export const named = (labels: Record<string, string>) => (c: { value: string; count: number }) => ({ value: c.value, label: labels[c.value] ?? c.value, count: c.count });

/** The Group chip's values, and the Host chip that shows only while a host is set. */
export const groupValues = (groups: readonly { value: string; name: string; count: number }[] | undefined) => (groups ?? []).map((g) => ({ value: g.value, label: g.name, count: g.count }));
export const hostFilter = (set: { host: string | null; hostName: string | undefined }, total: number | undefined): ListFilter => (
  { param: "host", label: "Host", chipOnly: true, values: set.host ? [{ value: set.host, label: set.hostName ?? set.host, count: total ?? 0 }] : [] }
);

export const dash = (text: string) => <span className="subtle" title={text}><span aria-hidden="true">—</span><span className="sr-only">{text}</span></span>;

/** "+2 hosts" / "−1 host" / "No change" (ruling 8). */
export function Week({ row }: { row: { week_added: number; week_removed: number } }) {
  if (row.week_added === 0 && row.week_removed === 0) return <span className="subtle">No change</span>;
  return (
    <span className="row nowrap" style={{ gap: 6 }}>
      {row.week_added > 0 && <span className="num">+{plural(row.week_added, "host")}</span>}
      {row.week_removed > 0 && <span className="num subtle">−{plural(row.week_removed, "host")}</span>}
    </span>
  );
}

/** The first reason a row needs a look, and how many more there are. */
export function LookCell({ look, labels }: { look: readonly string[]; labels: Record<string, string> }) {
  const [first, ...rest] = look;
  return first === undefined ? dash("Nothing to look at") : (
    <span className="row"><span className="badge badge--warn badge--plain">{labels[first] ?? first}</span>{rest.length > 0 && <span className="subtle" title={rest.map((c) => labels[c] ?? c).join(", ")}>+{rest.length}</span>}</span>
  );
}

/** "from 1 host's last report" / "from 4 hosts' last reports". */
export const reportedTail = (hosts: number) => (hosts === 1 ? "from 1 host's last report" : `from ${hosts.toLocaleString()} hosts' last reports`);

/** The summary line over a list's table. */
export const ListSummary = ({ parts, hosts }: { parts: { count: number; text: string }[]; hosts: number }) => (
  <div className="view-pad host-summary"><SummaryLine parts={parts} tail={reportedTail(hosts)} /></div>
);

export function ListScreen<L extends { total: number }>({ page, title, listPath, query, icon, noun, search, columns, filters, legacyQuery, body }: {
  /** The page's key for saved views and hidden columns ("ports"). */
  page: string;
  title: string;
  /** The list route without its query ("/api/v1/port-list"). */
  listPath: string;
  query: (params: URLSearchParams) => string;
  icon: IconName;
  /** "port" / "service": the empty states read "No {noun} matches these filters". */
  noun: string;
  search: { label: string; placeholder: string };
  columns: ReadonlyArray<{ key: string; label: string; fixed?: boolean }>;
  filters: (list: L | undefined, set: { host: string | null; hostName: string | undefined }) => ListFilter[];
  /** Turns a view saved in this browser before saved views lived on the console into a query. */
  legacyQuery: (query: string) => string;
  body: (list: L, hidden: readonly string[], offset: number) => ReactNode;
}) {
  const { params } = useLocation();
  const list = useResource<L>(`${listPath}?${query(params)}`);
  const hidden = useHiddenColumns(page);
  const host = params.get("host");
  const hostName = useHostName(host);
  // The last page stays on screen (and its counts in the chips) while the next loads.
  const [kept, setKept] = useState<L>();
  if (list.data && list.data !== kept) setKept(list.data);
  const data = list.data ?? kept;
  useEffect(() => { void importBrowserViews(page, `openvibes.v2.views./${page}`, legacyQuery); }, [page, legacyQuery]);

  return (
    <div className="view">
      <header className="view-header">
        <div className="view-header__top">
          <div className="view-header__title">
            <h1>{title}</h1>
            {data && <span className="view-header__count num">{data.total.toLocaleString()}</span>}
          </div>
          <button type="button" className="icon-button" title="Refresh" aria-label="Refresh" onClick={() => invalidate(listPath)}>
            <Icon name="refresh" size={16} />
          </button>
        </div>
        <FilterBar page={page} label={search.label} placeholder={search.placeholder} filters={filters(data, { host, hostName })} columns={columns} />
      </header>
      {list.error ? <div className="view-pad"><ErrorBox error={list.error} /></div> : !data ? <Loading /> : data.total === 0 ? (
        hasFilters(params)
          ? <Empty icon={icon} title={`No ${noun} matches these filters`}>Clear a filter to see more.</Empty>
          : <Empty icon={icon} title={`No ${noun}s reported yet`}>Agents report open ports and running services about an hour after they start.</Empty>
      ) : body(data, hidden ?? [], Math.max(0, Number(params.get(PAGE)) || 0))}
    </div>
  );
}

export type { Column };
