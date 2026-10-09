// The console's own dropdown: grouped options, search once the list is long,
// full keyboard use. Native <select> popups are drawn by the browser and
// cannot be themed, so the console never uses them.
import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties, KeyboardEvent } from "react";

import { Icon } from "./Icon";
import {
  SEARCH_ABOVE, enabledCount, filterSections, firstEnabled, placement, step, toSections,
  type SelectGroup, type SelectOption,
} from "./select";

export type { SelectGroup, SelectOption } from "./select";

// Only one Select is open at a time: opening registers its closer here.
let closeCurrent: (() => void) | null = null;

export function Select({ label, value, onChange, options, placeholder, unknownLabel = (v) => v, small, disabled }: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: SelectOption[] | SelectGroup[];
  placeholder?: string;
  unknownLabel?: (value: string) => string;
  small?: boolean;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState("");
  const [active, setActive] = useState(0);
  const [box, setBox] = useState<CSSProperties>();
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const listId = useId();

  const sections = useMemo(() => toSections(options), [options]);
  const known = sections.some((s) => s.options.some((o) => o.value === value));
  const unknown = !!value && !known;
  const searchable = enabledCount(sections) > SEARCH_ABOVE;
  const shown = useMemo(() => {
    const filtered = filterSections(sections, filter);
    return unknown && !filter ? [{ options: [{ value, label: unknownLabel(value) }] }, ...filtered] : filtered;
  }, [sections, filter, unknown, value, unknownLabel]);
  const flat = useMemo(() => shown.flatMap((s) => s.options), [shown]);
  const selectedLabel = unknown ? unknownLabel(value) : sections.flatMap((s) => s.options).find((o) => o.value === value)?.label;

  const close = (restoreFocus = false) => {
    setOpen(false);
    setFilter("");
    if (restoreFocus) button.current?.focus();
  };
  const openWith = (query = "") => {
    closeCurrent?.();
    setFilter(query);
    const index = flat.findIndex((o) => o.value === value);
    setActive(query ? 0 : index >= 0 ? index : Math.max(0, firstEnabled(flat)));
    setOpen(true);
  };

  const place = () => {
    if (!button.current) return;
    setBox({ position: "fixed", ...placement(button.current.getBoundingClientRect(), { width: window.innerWidth, height: window.innerHeight }) });
  };
  // Measured on open, then followed on scroll and resize (the popup is fixed, so it must track its button).
  useLayoutEffect(() => { if (open) place(); }, [open]);

  useEffect(() => {
    if (!open) return;
    const mine = () => close();
    closeCurrent = mine;
    const away = (event: PointerEvent) => { if (!root.current?.contains(event.target as Node)) close(); };
    const scrolled = (event: Event) => { if (!root.current?.contains(event.target as Node)) place(); };
    document.addEventListener("pointerdown", away);
    window.addEventListener("scroll", scrolled, true);
    window.addEventListener("resize", place);
    return () => {
      if (closeCurrent === mine) closeCurrent = null;
      document.removeEventListener("pointerdown", away);
      window.removeEventListener("scroll", scrolled, true);
      window.removeEventListener("resize", place);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    (searchable ? root.current?.querySelector("input") : listRef.current)?.focus({ preventScroll: true });
  }, [open, searchable]);
  useEffect(() => {
    if (open) root.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView?.({ block: "nearest" });
  }, [open, active]);

  const choose = (option: SelectOption) => {
    if (option.disabled) return;
    if (!(unknown && option.value === value)) onChange(option.value);
    close(true);
  };
  const onKey = (event: KeyboardEvent) => {
    if (event.key === "ArrowDown") { event.preventDefault(); setActive((i) => step(flat, i, 1)); }
    else if (event.key === "ArrowUp") { event.preventDefault(); setActive((i) => step(flat, i, -1)); }
    else if (event.key === "Enter") { event.preventDefault(); if (flat[active]) choose(flat[active]); }
    else if (event.key === "Escape") { event.stopPropagation(); close(true); }
    else if (event.key === "Tab") close();
  };
  const onButtonKey = (event: KeyboardEvent) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") { event.preventDefault(); openWith(); }
    else if (searchable && event.key.length === 1 && event.key !== " " && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      openWith(event.key);
    }
  };

  const activeId = flat[active] ? `${listId}-${active}` : undefined;
  const starts = shown.map((_, s) => shown.slice(0, s).reduce((n, x) => n + x.options.length, 0));
  return (
    <div className="sel" ref={root}>
      <button type="button" ref={button} className={small ? "select select--small sel__button" : "select sel__button"} role="combobox"
        aria-haspopup="listbox" aria-expanded={open} aria-controls={open ? listId : undefined} aria-label={label} disabled={disabled}
        onClick={() => (open ? close() : openWith())} onKeyDown={onButtonKey}>
        <span className={selectedLabel ? "sel__value" : "sel__value subtle"}>{selectedLabel ?? placeholder ?? ""}</span>
        <Icon name="chevronDown" size={14} />
      </button>
      {open && (
        <div className="sel__popup" style={box} onKeyDown={onKey}>
          {searchable && (
            <div className="search">
              <Icon name="search" size={14} />
              <input className="input" value={filter} placeholder="Filter…" aria-label={`Filter ${label}`} autoComplete="off" spellCheck={false}
                aria-controls={listId} aria-activedescendant={activeId}
                onChange={(event) => { setFilter(event.target.value); setActive(Math.max(0, firstEnabled(filterSections(sections, event.target.value).flatMap((s) => s.options)))); }} />
            </div>
          )}
          <div className="sel__list" role="listbox" id={listId} aria-label={label} ref={listRef} tabIndex={searchable ? -1 : 0}
            aria-activedescendant={searchable ? undefined : activeId} style={box?.maxHeight ? { maxHeight: Math.min(260, Number(box.maxHeight) - (searchable ? 48 : 12)) } : undefined}>
            {flat.length === 0 && <div className="sel__empty subtle">No match</div>}
            {shown.map((section, s) => {
              const rows = section.options.map((option, k) => {
                const i = (starts[s] ?? 0) + k;
                const selected = option.value === value;
                return (
                  <div key={option.value} id={`${listId}-${i}`} data-index={i} role="option" aria-selected={selected} aria-disabled={option.disabled || undefined}
                    className={i === active ? "sel__option sel__option--active" : "sel__option"}
                    onPointerEnter={() => { if (!option.disabled) setActive(i); }} onClick={() => choose(option)}>
                    <span>{option.label}</span>
                    {selected && <Icon name="check" size={14} />}
                  </div>
                );
              });
              return section.group ? (
                <div key={`g${s}`} role="group" aria-label={section.group}>
                  <div className="sel__group" aria-hidden="true">{section.group}</div>
                  {rows}
                </div>
              ) : <div key={`s${s}`} role="presentation">{rows}</div>;
            })}
          </div>
        </div>
      )}
    </div>
  );
}
