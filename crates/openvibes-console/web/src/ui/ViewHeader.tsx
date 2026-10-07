// Header of every list view: title and count, the text filter (`q` in the
// URL, focused with "/"), quick-filter chips, and saved views, which store
// the current filters and sort per viewer so each person shapes their own.
import { type ReactNode, useEffect, useRef, useState } from "react";

import { invalidate } from "../api/client";
import { nav, useLocation } from "../app/nav";
import { Icon } from "./Icon";

type Saved = { name: string; query: string };
const storageKey = (view: string) => `openvibes.v2.views.${view}`;

function readSaved(view: string): Saved[] {
  try {
    let raw = localStorage.getItem(storageKey(view));
    // Saved views from before the compliance rename (2026-10), copied once.
    if (raw === null && view === "/compliance") {
      raw = localStorage.getItem(storageKey("/findings"));
      if (raw !== null) localStorage.setItem(storageKey(view), raw);
    }
    const parsed = JSON.parse(raw ?? "[]") as unknown;
    return Array.isArray(parsed) ? parsed.filter((item): item is Saved => typeof item?.name === "string" && typeof item?.query === "string") : [];
  } catch {
    return [];
  }
}

function writeSaved(view: string, saved: Saved[]) {
  try {
    localStorage.setItem(storageKey(view), JSON.stringify(saved));
  } catch {
    // Saved views are a convenience; without storage they last until reload.
  }
}

export type Chip = { label: string; param: string; value: string; count?: number | undefined };

type Props = {
  title: string;
  count?: number | undefined;
  total?: number | undefined;
  placeholder?: string;
  chips?: readonly Chip[];
  actions?: ReactNode;
  refresh?: string;
};

export function ViewHeader({ title, count, total, placeholder = "Filter…", chips = [], actions, refresh }: Props) {
  const { view, params } = useLocation();
  const [saved, setSaved] = useState(() => readSaved(view));
  const [naming, setNaming] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const current = new URLSearchParams(params);
  current.sort();
  const currentQuery = current.toString();

  useEffect(() => {
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (event.key !== "/" || event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement) return;
      event.preventDefault();
      input.current?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const apply = (query: string) => {
    const next = new URLSearchParams(query);
    const changes: Record<string, string | null> = {};
    for (const key of params.keys()) changes[key] = null;
    for (const [key, value] of next) changes[key] = value;
    nav.setParams(changes);
  };
  const save = (name: string) => {
    const next = [...saved.filter((item) => item.name !== name), { name, query: currentQuery }];
    setSaved(next);
    writeSaved(view, next);
    setNaming(false);
  };
  const remove = (name: string) => {
    const next = saved.filter((item) => item.name !== name);
    setSaved(next);
    writeSaved(view, next);
  };

  return (
    <header className="view-header">
      <div className="view-header__top">
        <div className="view-header__title">
          <h1>{title}</h1>
          {count !== undefined && (
            <span className="view-header__count num">
              {count.toLocaleString()}{total !== undefined && total !== count ? ` of ${total.toLocaleString()}` : ""}
            </span>
          )}
        </div>
        <div className="row">
          {actions}
          {refresh && (
            <button type="button" className="icon-button" title="Refresh" aria-label="Refresh" onClick={() => invalidate(refresh)}>
              <Icon name="refresh" size={16} />
            </button>
          )}
        </div>
      </div>
      <div className="view-header__tools">
        <label className="search view-header__search">
          <Icon name="search" size={15} />
          <span className="sr-only">Filter {title.toLowerCase()}</span>
          <input ref={input} className="input" type="search" placeholder={placeholder} value={params.get("q") ?? ""}
            onChange={(event) => nav.setParams({ q: event.target.value })} />
          <span className="kbd view-header__kbd" aria-hidden="true">/</span>
        </label>
        {chips.length > 0 && (
          <div className="row row--wrap" role="group" aria-label="Quick filters">
            {chips.map((chip) => {
              const active = params.get(chip.param) === chip.value;
              return (
                <button key={`${chip.param}=${chip.value}`} type="button" className="chip" aria-pressed={active}
                  onClick={() => nav.setParams({ [chip.param]: active ? null : chip.value })}>
                  {chip.label}
                  {chip.count !== undefined && <span className="chip__count">{chip.count.toLocaleString()}</span>}
                </button>
              );
            })}
          </div>
        )}
        <div className="saved-views row">
          {saved.map((item) => (
            <span key={item.name} className={`saved-view${item.query === currentQuery ? " saved-view--active" : ""}`}>
              <button type="button" onClick={() => apply(item.query)}>{item.name}</button>
              <button type="button" aria-label={`Delete saved view ${item.name}`} onClick={() => remove(item.name)}><Icon name="close" size={12} /></button>
            </span>
          ))}
          {naming ? (
            <form onSubmit={(event) => { event.preventDefault(); const name = new FormData(event.currentTarget).get("name"); if (typeof name === "string" && name.trim()) save(name.trim()); }}>
              <input name="name" className="input input--tiny" autoFocus placeholder="View name" aria-label="Saved view name"
                onBlur={() => setNaming(false)} onKeyDown={(event) => { if (event.key === "Escape") setNaming(false); }} />
            </form>
          ) : (
            currentQuery !== "" && !saved.some((item) => item.query === currentQuery) && (
              <button type="button" className="button button--ghost button--small" onClick={() => setNaming(true)}>
                <Icon name="pin" size={14} /> Save view
              </button>
            )
          )}
        </div>
      </div>
    </header>
  );
}
