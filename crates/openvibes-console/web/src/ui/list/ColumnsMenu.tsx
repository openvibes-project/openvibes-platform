// The Columns menu of a list: a checkbox per column, the first (Host)
// always shown. Each change is saved for the person at once.
import { useEffect, useId, useRef, useState } from "react";

import { apiMessage } from "../../api/client";
import { Icon } from "../Icon";
import { toast } from "../toast";
import { columnSaver } from "./savedViews";

/** `fixed`: never hidden (the first column always is). */
export type ListColumn = { key: string; label: string; fixed?: boolean };

/** The checkboxes; the first column and `fixed` ones cannot be hidden. Until the person's columns load (`hidden` undefined) none can change. */
export function ColumnList({ columns, hidden, onToggle }: { columns: readonly ListColumn[]; hidden: readonly string[] | undefined; onToggle: (key: string) => void }) {
  return (
    <fieldset className="columns-menu__list">
      <legend className="sr-only">Shown columns</legend>
      {columns.map((c, i) => {
        const fixed = i === 0 || c.fixed === true;
        return (
          <label key={c.key} className="columns-menu__row" title={fixed ? `The ${c.label} column can't be hidden` : undefined}>
            <input type="checkbox" className="checkbox" checked={fixed || !hidden?.includes(c.key)} disabled={fixed || hidden === undefined}
              onChange={() => onToggle(c.key)} /> <span>{c.label}</span>
          </label>
        );
      })}
    </fieldset>
  );
}

export function ColumnsMenu({ page, columns, hidden }: { page: string; columns: readonly ListColumn[]; hidden: readonly string[] | undefined }) {
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState<string[]>();
  const [save] = useState(() => columnSaver(page, setPending, (e) => toast(apiMessage(e, "The columns could not be saved."), true)));
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const id = useId();
  const close = (restore: boolean) => { setOpen(false); if (restore) button.current?.focus(); };
  useEffect(() => {
    if (!open) return;
    root.current?.querySelector<HTMLInputElement>("input:not(:disabled)")?.focus();
    const away = (event: PointerEvent) => { if (!root.current?.contains(event.target as Node)) setOpen(false); };
    document.addEventListener("pointerdown", away);
    return () => document.removeEventListener("pointerdown", away);
  }, [open]);
  const toggle = (key: string) => { if (hidden) save(hidden, key); };
  return (
    <div className="sel columns-menu" ref={root}
      onKeyDown={(event) => { if (event.key === "Escape" && open) { event.stopPropagation(); close(true); } }}
      onBlur={(event) => { if (open && !root.current?.contains(event.relatedTarget as Node | null)) setOpen(false); }}>
      <button ref={button} type="button" className="button button--small" aria-expanded={open} aria-controls={open ? id : undefined}
        onClick={() => setOpen(!open)}>
        <Icon name="list" size={14} /> Columns
      </button>
      {open && <div className="sel__popup columns-menu__popup" id={id}><ColumnList columns={columns} hidden={pending ?? hidden} onToggle={toggle} /></div>}
    </div>
  );
}
