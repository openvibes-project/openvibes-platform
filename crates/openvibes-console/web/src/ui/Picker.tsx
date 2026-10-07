// A searchable single-choice list, for choices too long for a native
// <select> (the browser draws that popup itself, so it cannot be themed).
import { useEffect, useId, useMemo, useRef, useState } from "react";

import { Icon } from "./Icon";
import { matches } from "./table";

export type PickerOption = { value: string; label: string };

export function Picker({ options, value, onChange, placeholder, label }: {
  options: readonly PickerOption[];
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  label: string;
}) {
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState("");
  const [active, setActive] = useState(0);
  const root = useRef<HTMLDivElement>(null);
  const listId = useId();
  const shown = useMemo(() => options.filter((option) => matches([option.label], filter)), [options, filter]);
  const selected = options.find((option) => option.value === value);

  useEffect(() => {
    if (!open) return;
    const away = (event: PointerEvent) => { if (!root.current?.contains(event.target as Node)) setOpen(false); };
    document.addEventListener("pointerdown", away);
    return () => document.removeEventListener("pointerdown", away);
  }, [open]);
  useEffect(() => {
    if (open) root.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [open, active]);

  const choose = (next: string) => {
    onChange(next);
    setOpen(false);
    setFilter("");
  };
  const close = () => { setOpen(false); setFilter(""); };
  const onKey = (event: React.KeyboardEvent) => {
    if (event.key === "ArrowDown") { event.preventDefault(); setActive((i) => Math.min(i + 1, shown.length - 1)); }
    else if (event.key === "ArrowUp") { event.preventDefault(); setActive((i) => Math.max(i - 1, 0)); }
    else if (event.key === "Enter") { event.preventDefault(); const option = shown[active]; if (option) choose(option.value); }
    else if (event.key === "Escape") { event.stopPropagation(); close(); }
  };

  return (
    <div className="picker" ref={root}>
      <button type="button" className="select picker__button" aria-haspopup="listbox" aria-expanded={open} aria-label={label}
        onClick={() => { setOpen(!open); setActive(Math.max(0, options.findIndex((option) => option.value === value))); }}>
        <span className={selected ? "picker__value" : "picker__value subtle"}>{selected?.label ?? placeholder}</span>
        <Icon name="chevronDown" size={14} />
      </button>
      {open && (
        <div className="picker__popup" onKeyDown={onKey}>
          <div className="search">
            <Icon name="search" size={14} />
            <input className="input" autoFocus value={filter} placeholder="Filter…" aria-label={`Filter ${label}`} autoComplete="off" spellCheck={false}
              role="combobox" aria-expanded="true" aria-controls={listId} aria-activedescendant={shown[active] ? `${listId}-${active}` : undefined}
              onChange={(event) => { setFilter(event.target.value); setActive(0); }} />
          </div>
          <ul className="picker__list" role="listbox" id={listId} aria-label={label}>
            {shown.length === 0 && <li className="picker__empty subtle">No match</li>}
            {shown.map((option, index) => (
              <li key={option.value} id={`${listId}-${index}`} data-index={index} role="option" aria-selected={option.value === value}
                className={index === active ? "picker__option picker__option--active" : "picker__option"}
                tabIndex={-1} onPointerEnter={() => setActive(index)} onClick={() => choose(option.value)}
                onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); choose(option.value); } }}>
                <span>{option.label}</span>
                {option.value === value && <Icon name="check" size={14} />}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
