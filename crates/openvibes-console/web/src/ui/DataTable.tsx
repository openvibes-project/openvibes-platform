// The one table every view uses: sortable headers (sort kept in the URL),
// keyboard navigation (j/k or arrows, Enter opens, x selects), the row
// open in the inspector highlighted, optional selection for bulk actions,
// and incremental rendering so large lists stay fast.
import { type CSSProperties, type KeyboardEvent, type ReactNode, useEffect, useMemo, useRef, useState } from "react";

import { nav, useLocation } from "../app/nav";
import { Icon } from "./Icon";
import { PAGE } from "./list/filters";
import { MAX_SELECTION, selectAll, selectRange } from "./selection";
import { type Direction, type SortValue, sortRows, tableIgnoresKey } from "./table";

export type Column<T> = {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  sort?: (row: T) => SortValue;
  numeric?: boolean;
  width?: string;
  hideBelow?: number;
};

type Props<T> = {
  rows: readonly T[];
  columns: readonly Column<T>[];
  rowKey: (row: T) => string;
  onOpen: (row: T) => void;
  isOpen?: (row: T) => boolean;
  defaultSort?: { key: string; direction: Direction };
  selection?: { selected: ReadonlySet<string>; onChange: (next: Set<string>) => void };
  label: string;
  compact?: boolean;
  /** The rows come sorted by the server (the sort is still set in the URL). */
  serverSort?: boolean;
  /** The rows are one page of a server-paged list: selecting is per page, never "all matching". */
  serverPaged?: boolean;
};

const STEP = 150;

type SortDefault = { key: string; direction: Direction };
/** A table's sort as the URL keeps it (one sortable table per page). */
export type Sort = { key: string | undefined; direction: Direction };

export function useSort(fallback?: SortDefault): Sort {
  const { params } = useLocation();
  return { key: params.get("sort") ?? fallback?.key, direction: (params.get("dir") as Direction | null) ?? fallback?.direction ?? "asc" };
}

/** Sort by `key`: again flips the direction; Severity starts with the most severe, every other column from A or the smallest. */
export function setSort(sort: Sort, key: string) {
  const direction = key === sort.key ? (sort.direction === "asc" ? "desc" : "asc") : key === "severity" ? "desc" : "asc";
  nav.setParams({ sort: key, dir: direction, [PAGE]: null });
}

/** `rows` in `sort`'s order, by its key in `by`; as they came when no header is chosen. */
export function sortBy<T>(rows: readonly T[], by: Record<string, (row: T) => SortValue>, sort: Sort): readonly T[] {
  const key = by[sort.key ?? ""];
  return key ? sortRows(rows, key, sort.direction) : rows;
}

/** The query string a server-sorted route takes: `&sort=…&dir=…`, or nothing for its default. */
export const sortQuery = (sort: Sort) => (sort.key ? `&sort=${encodeURIComponent(sort.key)}&dir=${sort.direction}` : "");

/** A sortable column's header, as every table shows it. */
export function SortHeader({ sort, column, children, className, style }: {
  sort: Sort; column: string; children: ReactNode; className?: string | undefined; style?: CSSProperties | undefined;
}) {
  const on = sort.key === column;
  return (
    <th className={className} style={style} aria-sort={on ? (sort.direction === "asc" ? "ascending" : "descending") : undefined}>
      <button type="button" onClick={() => setSort(sort, column)}>
        {children}
        {on && <Icon name={sort.direction === "asc" ? "chevronUp" : "chevronDown"} size={14} />}
      </button>
    </th>
  );
}

export function DataTable<T>({ rows, columns, rowKey, onOpen, isOpen, defaultSort, selection, label, compact, serverSort, serverPaged }: Props<T>) {
  const sort = useSort(defaultSort);
  const { key: sortKey, direction } = sort;
  const column = columns.find((candidate) => candidate.key === sortKey && candidate.sort);
  const sorted = useMemo(() => (column?.sort && !serverSort ? sortRows(rows, column.sort, direction) : [...rows]), [rows, column, direction, serverSort]);
  const [shown, setShown] = useState(STEP);
  const [cursor, setCursor] = useState(-1);
  const keyboard = useRef(false);
  const body = useRef<HTMLTableSectionElement>(null);
  const [width, setWidth] = useState(1200);
  const wrap = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!wrap.current) return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry?.contentRect.width ?? 1200));
    observer.observe(wrap.current);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!keyboard.current) return;
    keyboard.current = false;
    body.current?.querySelector<HTMLElement>(`tr[data-index="${cursor}"]`)?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  const visibleColumns = columns.filter((candidate) => !candidate.hideBelow || width >= candidate.hideBelow);
  const last = useRef(-1);
  const toggle = (key: string, index: number, shift = false) => {
    if (!selection) return;
    const on = !selection.selected.has(key);
    if (shift && last.current >= 0) {
      selection.onChange(selectRange(sorted.map(rowKey), last.current, index, selection.selected, on));
    } else {
      const next = new Set(selection.selected);
      if (on) next.add(key); else next.delete(key);
      selection.onChange(next);
    }
    last.current = index;
  };
  // The header box selects the rows on screen; a bar then offers every row
  // the filter matches (spec §3).
  const onScreen = sorted.slice(0, shown);
  const pageSelected = selection !== undefined && onScreen.length > 0 && onScreen.every((row) => selection.selected.has(rowKey(row)));
  const everySelected = selection !== undefined && sorted.length > 0 && selection.selected.size >= Math.min(sorted.length, MAX_SELECTION) && pageSelected;

  const onKeyDown = (event: KeyboardEvent) => {
    if (tableIgnoresKey(event.target as HTMLElement, event.key)) return;
    const max = Math.min(sorted.length, shown) - 1;
    keyboard.current = true;
    if (event.key === "j" || event.key === "ArrowDown") { event.preventDefault(); setCursor((c) => Math.min(max, c + 1)); }
    else if (event.key === "k" || event.key === "ArrowUp") { event.preventDefault(); setCursor((c) => Math.max(0, c - 1)); }
    else if (event.key === "Enter" && cursor >= 0) { const row = sorted[cursor]; if (row) onOpen(row); }
    else if (event.key === "x" && cursor >= 0) { const row = sorted[cursor]; if (row) toggle(rowKey(row), cursor); }
  };

  return (
    <div className="table-wrap" ref={wrap}>
      {selection && pageSelected && serverPaged && (
        <output className="select-all-bar">All {onScreen.length.toLocaleString()} on this page are selected.</output>
      )}
      {selection && pageSelected && !serverPaged && sorted.length > onScreen.length && (
        <output className="select-all-bar">
          {everySelected
            ? <>All {Math.min(sorted.length, MAX_SELECTION).toLocaleString()} matching this filter are selected{sorted.length > MAX_SELECTION && ` (the first ${MAX_SELECTION.toLocaleString()}; narrow the filter for the rest)`}. </>
            : <>{onScreen.length.toLocaleString()} on screen selected. </>}
          {everySelected
            ? <button type="button" className="link-button" onClick={() => selection.onChange(new Set())}>Clear</button>
            : <button type="button" className="link-button" onClick={() => selection.onChange(selectAll(sorted.map(rowKey)))}>
                Select all {Math.min(sorted.length, MAX_SELECTION).toLocaleString()} matching this filter</button>}
        </output>
      )}
      <table className={compact ? "table table--compact" : "table"} aria-label={label} tabIndex={0} onKeyDown={onKeyDown}>
        <thead>
          <tr>
            {selection && (
              <th className="check">
                <input type="checkbox" className="checkbox" aria-label="Select the rows on screen" checked={pageSelected}
                  onChange={() => selection.onChange(pageSelected ? new Set() : new Set(onScreen.map(rowKey)))} />
              </th>
            )}
            {visibleColumns.map((candidate) => {
              const className = candidate.numeric ? "num" : undefined;
              const style = candidate.width ? { width: candidate.width } : undefined;
              return candidate.sort
                ? <SortHeader key={candidate.key} sort={sort} column={candidate.key} className={className} style={style}>{candidate.header}</SortHeader>
                : <th key={candidate.key} className={className} style={style}>{candidate.header}</th>;
            })}
          </tr>
        </thead>
        <tbody ref={body}>
          {sorted.slice(0, shown).map((row, index) => {
            const key = rowKey(row);
            return (
              <tr key={key} data-index={index} data-cursor={index === cursor || undefined}
                aria-selected={isOpen?.(row) || selection?.selected.has(key) || undefined}
                onClick={(event) => { if (!(event.target as HTMLElement).closest("a,button,input,select,form,.sel,dialog")) { setCursor(index); onOpen(row); } }}>
                {selection && (
                  <td className="check">
                    <input type="checkbox" className="checkbox" aria-label="Select row" checked={selection.selected.has(key)}
                      onChange={(event) => toggle(key, index, (event.nativeEvent as MouseEvent).shiftKey)} />
                  </td>
                )}
                {visibleColumns.map((candidate) => (
                  <td key={candidate.key} className={candidate.numeric ? "num" : undefined}>{candidate.render(row)}</td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
      {sorted.length > shown && (
        <div className="table-more">
          <button type="button" className="button" onClick={() => setShown((current) => current + STEP * 2)}>
            Show more ({(sorted.length - shown).toLocaleString()} left)
          </button>
        </div>
      )}
    </div>
  );
}
