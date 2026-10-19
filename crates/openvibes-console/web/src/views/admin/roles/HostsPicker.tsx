// Step "Hosts": a search over host groups with "All hosts" first; chosen ones
// show as chips with ×. All hosts clears the groups; nothing chosen is "No hosts".
// A search field plus a list of toggle buttons (Tab moves through them), not a combobox.
import { useRef, useState } from "react";

import type { HostGroup } from "../../../api/types";
import { Icon } from "../../../ui/Icon";
import { matches } from "../../../ui/table";
import type { Action, Reach } from "./roleState";

const ALL = "All hosts";

function note(reach: Reach): string {
  if (reach.kind === "all") return "Its host permissions apply to every host, now and later.";
  if (reach.kind === "groups") return `Its host permissions apply only to hosts in ${reach.groups.length === 1 ? "this group" : "these groups"}.`;
  return "Its host permissions apply nowhere until you choose hosts. Search for groups, or choose All hosts. Platform permissions work either way.";
}

export function HostsPicker({ reach, groups, dispatch, readOnly }: { reach: Reach; groups: readonly HostGroup[]; dispatch: (action: Action) => void; readOnly: boolean }) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const chosen = reach.kind === "groups" ? reach.groups : [];
  const isChosen = (id: string) => chosen.some((g) => g.asset_group_id === id);
  const options = [{ id: "", name: ALL }, ...groups.map((g) => ({ id: g.asset_group_id, name: g.name }))].filter((o) => matches([o.name], query));
  const pick = (id: string, name: string) => {
    dispatch(id ? { type: "group", group: { asset_group_id: id, name } } : { type: "allHosts" });
    setQuery("");
    // Closed after each pick, so it never covers the bar below; click, type or ArrowDown reopens it.
    setOpen(false);
    input.current?.focus();
  };
  const chips = reach.kind === "all" ? [{ id: "", name: ALL }] : chosen.map((g) => ({ id: g.asset_group_id, name: g.name }));
  return (
    <div className="stack hosts-picker">
      {!readOnly && (
        <div className="hosts-picker__search" onBlur={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) setOpen(false); }}
          onKeyDown={(e) => { if (e.key === "Escape") setOpen(false); }}>
          <label className="search">
            <Icon name="search" size={15} />
            <span className="sr-only">Search host groups</span>
            <input ref={input} className="input" type="search" placeholder="Search host groups, or choose All hosts" value={query} autoComplete="off"
              onFocus={() => setOpen(true)} onClick={() => setOpen(true)} onChange={(e) => { setQuery(e.target.value); setOpen(true); }}
              onKeyDown={(e) => { if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); } }} />
          </label>
          {open && (
            <div className="sel__popup hosts-picker__popup">
              <div className="sel__list" role="group" aria-label="Host groups">
                {options.length === 0 && <div className="sel__empty subtle">No group matches</div>}
                {options.map((o) => {
                  const selected = o.id ? isChosen(o.id) : reach.kind === "all";
                  return (
                    <button key={o.id || "all"} type="button" aria-pressed={selected} className="sel__option hosts-picker__option"
                      onMouseDown={(e) => e.preventDefault()} onClick={() => pick(o.id, o.name)}>
                      <span className="sel__label">{o.name}</span>
                      {selected && <Icon name="check" size={14} />}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
      {chips.length > 0 && (
        <div className="row row--wrap">
          {chips.map((c) => (
            <span key={c.id || "all"} className="chip hosts-picker__chip">
              {c.name}
              {!readOnly && <button type="button" className="icon-button" aria-label={`Remove ${c.name}`} title={`Remove ${c.name}`} onClick={() => pick(c.id, c.name)}><Icon name="close" size={12} /></button>}
            </span>
          ))}
        </div>
      )}
      <p className="subtle hosts-picker__note">{note(reach)}</p>
    </div>
  );
}
