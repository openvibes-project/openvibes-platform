// The filter bar of a list page (approved screen 16): the search (`q` in
// the URL, focused with "/"), a chip per filter that lists its values with
// counts, a chosen value as a chip with ×, the person's saved views, and on
// the right Clear all, Save view and Columns. Everything it sets is in the
// URL; saved views and hidden columns are kept by the console per person.
import { useEffect, useId, useRef, useState } from "react";

import { apiMessage } from "../../api/client";
import type { SavedView } from "../../api/types";
import { nav, useLocation } from "../../app/nav";
import { Icon } from "../Icon";
import { Select } from "../Select";
import { toast } from "../toast";
import { ColumnsMenu, type ListColumn } from "./ColumnsMenu";
import { type ListFilter, PAGE, applyViewChanges, chosenFilters, clearAllChanges, debounce, hasFilters, valueOptions, viewQuery } from "./filters";
import { deleteView, saveView, useHiddenColumns, useSavedViews } from "./savedViews";

type Props = {
  /** The list page the console keeps views and columns for, such as `hosts`. */
  page: string;
  /** The search field's accessible name, such as "Search hosts". */
  label: string;
  placeholder?: string;
  filters: readonly ListFilter[];
  /** The list's columns, Host first; without them there is no Columns menu. */
  columns?: readonly ListColumn[];
};

export function FilterBar(props: Props) {
  const { params } = useLocation();
  const views = useSavedViews(props.page);
  const hidden = useHiddenColumns(props.page);
  return <FilterBarBody {...props} params={params} views={views} hidden={hidden} />;
}

/** Naming a new view; a refusal is announced and tied to the field. */
export function SaveViewForm({ error, onSave, onCancel }: { error?: string | undefined; onSave: (name: string) => void; onCancel: () => void }) {
  const errorId = useId();
  return (
    <form className="row filter-bar__name" onSubmit={(event) => {
      event.preventDefault();
      const name = String(new FormData(event.currentTarget).get("name") ?? "").trim();
      if (name) onSave(name);
    }}>
      <input name="name" className="input input--tiny" autoFocus maxLength={60} placeholder="View name" aria-label="View name"
        aria-invalid={error ? true : undefined} aria-describedby={error ? errorId : undefined}
        onKeyDown={(event) => { if (event.key === "Escape") { event.stopPropagation(); onCancel(); } }} />
      <button type="submit" className="button button--primary button--small">Save</button>
      <button type="button" className="button button--ghost button--small" onClick={onCancel}>Cancel</button>
      {error && <span id={errorId} role="alert" className="filter-bar__error">{error}</span>}
    </form>
  );
}

/** A saved view: applies on click; × asks before deleting. */
export function SavedViewChip({ view, active, confirming, onApply, onAsk, onDelete, onCancel }: {
  view: SavedView; active: boolean; confirming: boolean; onApply: () => void; onAsk: () => void; onDelete: () => void; onCancel: () => void;
}) {
  if (confirming) {
    return (
      <span className="saved-view saved-view--confirm" role="group" aria-label={`Delete the view ${view.name}`}
        onKeyDown={(event) => { if (event.key === "Escape") { event.stopPropagation(); onCancel(); } }}>
        <span className="saved-view__ask">Delete the view “{view.name}”?</span>
        <button type="button" className="saved-view__delete" onClick={onDelete}>Delete</button>
        <button type="button" autoFocus onClick={onCancel}>Cancel</button>
      </span>
    );
  }
  return (
    <span className={`saved-view${active ? " saved-view--active" : ""}`}>
      <button type="button" aria-pressed={active} onClick={onApply}>{view.name}</button>
      <button type="button" aria-label={`Delete saved view ${view.name}`} onClick={onAsk}><Icon name="close" size={12} /></button>
    </span>
  );
}

export function FilterBarBody({ page, label, placeholder = "Search…", filters, columns = [], params, views, hidden }: Props & {
  params: URLSearchParams; views: readonly SavedView[]; hidden: readonly string[] | undefined;
}) {
  const [naming, setNaming] = useState(false);
  const [error, setError] = useState<string>();
  const [confirming, setConfirming] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  // The search reaches the URL 250 ms after the last key (at once on Enter
  // or leaving the field); until then the field shows what was typed. Only
  // onto this list's own URL: leaving the page drops a search not yet sent.
  const [typed, setTyped] = useState<string>();
  const [search] = useState(() => {
    const view = nav.location.view;
    return debounce((q: string) => {
      if (nav.location.view !== view) return;
      nav.setParams({ q, [PAGE]: null });
      setTyped((t) => (t === q ? undefined : t));
    }, 250);
  });
  useEffect(() => () => search.cancel(), [search]);
  // What gets focus once the chip it names is drawn again (a chip turns into its chosen form and back).
  const refocus = useRef<string | null>(null);
  const focusIn = (key: string, selector: string) => (el: HTMLElement | null) => {
    if (el && refocus.current === key) { refocus.current = null; el.querySelector<HTMLElement>(selector)?.focus(); }
  };

  useEffect(() => {
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (event.key !== "/" || event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement) return;
      event.preventDefault();
      input.current?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const current = viewQuery(params);
  const filtered = hasFilters(params);
  const chosen = new Map(chosenFilters(filters, params).map((c) => [c.param, c.text]));
  const set = (param: string, value: string | null) => { refocus.current = param; nav.setParams({ [param]: value, [PAGE]: null }); };
  const replace = (changes: Record<string, string | null>) => { search.cancel(); setTyped(undefined); nav.setParams(changes); };
  const stopNaming = () => { setNaming(false); setError(undefined); refocus.current = "save"; };
  const save = (name: string) => {
    saveView(page, name, current).then(() => { refocus.current = "views"; setNaming(false); setError(undefined); toast(`View “${name}” saved`); },
      (e: unknown) => setError(apiMessage(e, "The view could not be saved.")));
  };
  const remove = (view: SavedView) => {
    deleteView(page, view.id).then(() => {
      // Focus goes to the views left, or to the search when none is.
      if (views.length > 1) refocus.current = "views"; else input.current?.focus();
      setConfirming(null); toast(`View “${view.name}” deleted`); },
      (e: unknown) => toast(apiMessage(e, "The view could not be deleted."), true));
  };

  return (
    <div className="filter-bar">
      <label className="search filter-bar__search">
        <Icon name="search" size={15} />
        <span className="sr-only">{label}</span>
        <input ref={input} className="input" type="search" placeholder={placeholder} value={typed ?? params.get("q") ?? ""}
          onChange={(event) => { setTyped(event.target.value); search.set(event.target.value); }}
          onKeyDown={(event) => { if (event.key === "Enter") search.flush(); }} onBlur={() => search.flush()} />
        <span className="kbd view-header__kbd" aria-hidden="true">/</span>
      </label>
      {filters.length > 0 && (
        <div className="row row--wrap filter-bar__chips" role="group" aria-label="Filters">
          {filters.map((f) => {
            const text = chosen.get(f.param);
            return (
              <span key={`${f.param}:${text !== undefined}`} ref={focusIn(f.param, "button")} className="filter-bar__chip">
                {text !== undefined ? (
                  <span className="chip filter-chip">{text}
                    <button type="button" className="filter-chip__remove" aria-label={`Remove filter ${text}`} onClick={() => set(f.param, null)}>
                      <Icon name="close" size={12} />
                    </button>
                  </span>
                ) : (
                  <Select button label={f.label} placeholder={f.label} value="" options={valueOptions(f)} onChange={(v) => set(f.param, v)} />
                )}
              </span>
            );
          })}
        </div>
      )}
      {views.length > 0 && (
        <div className="row row--wrap filter-bar__views" role="group" aria-label="Saved views" tabIndex={-1}
          ref={(el) => { if (el && refocus.current === "views") { refocus.current = null; el.focus(); } }}>
          {views.map((v) => (
            <span key={`${v.id}:${confirming === v.id}`} ref={focusIn(`view:${v.id}`, "button:last-of-type")}>
              <SavedViewChip view={v} active={v.query === current} confirming={confirming === v.id}
                onApply={() => replace(applyViewChanges(params, v.query, filters))} onAsk={() => setConfirming(v.id)}
                onDelete={() => remove(v)} onCancel={() => { refocus.current = `view:${v.id}`; setConfirming(null); }} />
            </span>
          ))}
        </div>
      )}
      <div className="row filter-bar__end">
        {filtered && <button type="button" className="button button--ghost button--small" onClick={() => replace(clearAllChanges(params))}>Clear all</button>}
        {naming ? <SaveViewForm error={error} onSave={save} onCancel={stopNaming} /> : (
          filtered && !views.some((v) => v.query === current) && (
            <button type="button" className="button button--small" onClick={() => setNaming(true)}
              ref={(el) => { if (el && refocus.current === "save") { refocus.current = null; el.focus(); } }}>
              <Icon name="pin" size={14} /> Save view
            </button>
          )
        )}
        {columns.length > 0 && <ColumnsMenu page={page} columns={columns} hidden={hidden} />}
      </div>
    </div>
  );
}
