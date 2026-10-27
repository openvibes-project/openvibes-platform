// The shell the Ports and Services lists share: header with the count and
// Refresh, the filter bar, the last page kept on screen while the next
// loads, and the empty and error states. Each list passes its own wording
// and its table.
import { type ReactNode, useEffect, useState } from "react";

import { invalidate, useResource } from "../../api/client";
import { useLocation } from "../../app/nav";
import { Empty, ErrorBox, Loading } from "../../ui/bits";
import type { Column } from "../../ui/DataTable";
import { Icon, type IconName } from "../../ui/Icon";
import { FilterBar } from "../../ui/list/FilterBar";
import { type ListFilter, PAGE, hasFilters } from "../../ui/list/filters";
import { importBrowserViews, useHiddenColumns } from "../../ui/list/savedViews";
import { SummaryLine } from "../../ui/list/SummaryLine";
import { useHostName } from "../lists/HostChip";

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
