// The one table every view uses: sortable headers (sort kept in the URL),
// keyboard navigation (j/k or arrows, Enter opens, x selects), the row
// open in the inspector highlighted, optional selection for bulk actions,
// and incremental rendering so large lists stay fast.
import { type KeyboardEvent, type ReactNode, useEffect, useMemo, useRef, useState } from "react";

import { nav, useLocation } from "../app/nav";
import { Icon } from "./Icon";
import { type Direction, type SortValue, sortRows } from "./table";

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
};

const STEP = 150;

export function DataTable<T>({ rows, columns, rowKey, onOpen, isOpen, defaultSort, selection, label, compact }: Props<T>) {
  const { params } = useLocation();
  const sortKey = params.get("sort") ?? defaultSort?.key;
  const direction: Direction = (params.get("dir") as Direction | null) ?? defaultSort?.direction ?? "asc";
  const column = columns.find((candidate) => candidate.key === sortKey && candidate.sort);
  const sorted = useMemo(() => (column?.sort ? sortRows(rows, column.sort, direction) : [...rows]), [rows, column, direction]);
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
  const setSort = (key: string) => {
    const nextDirection = key === sortKey ? (direction === "asc" ? "desc" : "asc") : "asc";
    nav.setParams({ sort: key, dir: nextDirection });
  };
  const toggle = (key: string) => {
    if (!selection) return;
    const next = new Set(selection.selected);
    if (next.has(key)) next.delete(key); else next.add(key);
    selection.onChange(next);
  };
  const allSelected = selection !== undefined && sorted.length > 0 && sorted.every((row) => selection.selected.has(rowKey(row)));

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.target instanceof HTMLInputElement) return;
    const max = Math.min(sorted.length, shown) - 1;
    keyboard.current = true;
    if (event.key === "j" || event.key === "ArrowDown") { event.preventDefault(); setCursor((c) => Math.min(max, c + 1)); }
    else if (event.key === "k" || event.key === "ArrowUp") { event.preventDefault(); setCursor((c) => Math.max(0, c - 1)); }
    else if (event.key === "Enter" && cursor >= 0) { const row = sorted[cursor]; if (row) onOpen(row); }
    else if (event.key === "x" && cursor >= 0) { const row = sorted[cursor]; if (row) toggle(rowKey(row)); }
  };

  return (
    <div className="table-wrap" ref={wrap}>
      <table className={compact ? "table table--compact" : "table"} aria-label={label} tabIndex={0} onKeyDown={onKeyDown}>
        <thead>
          <tr>
            {selection && (
              <th className="check">
                <input type="checkbox" aria-label="Select all" checked={allSelected}
                  onChange={() => selection.onChange(allSelected ? new Set() : new Set(sorted.map(rowKey)))} />
              </th>
            )}
            {visibleColumns.map((candidate) => (
              <th key={candidate.key} className={candidate.numeric ? "num" : undefined} style={candidate.width ? { width: candidate.width } : undefined}
                aria-sort={candidate.key === sortKey ? (direction === "asc" ? "ascending" : "descending") : undefined}>
                {candidate.sort ? (
                  <button type="button" onClick={() => setSort(candidate.key)}>
                    {candidate.header}
                    {candidate.key === sortKey && <Icon name={direction === "asc" ? "chevronUp" : "chevronDown"} size={14} />}
                  </button>
                ) : candidate.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody ref={body}>
          {sorted.slice(0, shown).map((row, index) => {
            const key = rowKey(row);
            return (
              <tr key={key} data-index={index} data-cursor={index === cursor || undefined}
                aria-selected={isOpen?.(row) || selection?.selected.has(key) || undefined}
                onClick={(event) => { if (!(event.target as HTMLElement).closest("a,button,input,select,form")) { setCursor(index); onOpen(row); } }}>
                {selection && (
                  <td className="check">
                    <input type="checkbox" aria-label="Select row" checked={selection.selected.has(key)} onChange={() => toggle(key)} />
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
