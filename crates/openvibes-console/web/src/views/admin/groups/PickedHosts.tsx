// The "Hosts picked by hand" card's body: the picked hosts as chips, and in
// edit mode a × on each and a search to add more.
import { useState } from "react";

import { useAllPages } from "../../../api/client";
import type { Agent } from "../../../api/types";
import { Icon } from "../../../ui/Icon";
import { matches } from "../../../ui/table";
import type { Action, Draft } from "./groupState";

const SHOWN = 8;

/** Search over the active hosts (filtered here: /agents takes no text query). */
function AddHost({ draft, dispatch }: { draft: Draft; dispatch: (a: Action) => void }) {
  const [query, setQuery] = useState("");
  // ponytail: loads up to 2000 active hosts once per edit; a server-side search when fleets outgrow it.
  const agents = useAllPages<Agent>("/api/v1/agents?state=active");
  const picked = new Set(draft.picked.map((h) => h.agent_id));
  const found = query.trim()
    ? (agents.data ?? []).filter((a) => !picked.has(a.id) && matches([a.hostname, a.id], query)).slice(0, SHOWN)
    : [];
  return (
    <div className="picked-hosts__search">
      <label className="search">
        <Icon name="search" size={15} />
        <span className="sr-only">Search hosts to add</span>
        <input className="input" type="search" placeholder="Search hosts to add" value={query} autoComplete="off" onChange={(e) => setQuery(e.target.value)} />
      </label>
      {query.trim() && (
        <div className="sel__list picked-hosts__results" role="group" aria-label="Hosts to add">
          {found.length === 0 && <div className="sel__empty subtle">{agents.data ? "No host matches" : "Loading hosts…"}</div>}
          {found.map((a) => (
            <button key={a.id} type="button" className="sel__option" onClick={() => { dispatch({ type: "pick", host: { agent_id: a.id, hostname: a.hostname ?? a.id } }); setQuery(""); }}>
              <span className="sel__label mono">{a.hostname ?? a.id}</span><Icon name="plus" size={14} />
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function PickedHosts({ draft, dispatch, editing, empty }: { draft: Draft; dispatch: (a: Action) => void; editing: boolean; empty: string }) {
  return (
    <div className="stack picked-hosts">
      <span className="subtle">Hosts picked by hand. New hosts are never added by themselves.</span>
      <div className="row row--wrap">
        {draft.picked.length === 0 && <span className="subtle">{empty}</span>}
        {draft.picked.map((h) => (
          <span key={h.agent_id} className="chip picked-hosts__chip" aria-pressed="true">
            <span className="mono">{h.hostname}</span>
            {editing && <button type="button" className="icon-button" aria-label={`Remove ${h.hostname}`} title={`Remove ${h.hostname}`} onClick={() => dispatch({ type: "unpick", agent_id: h.agent_id })}><Icon name="close" size={12} /></button>}
          </span>
        ))}
      </div>
      {editing && <AddHost draft={draft} dispatch={dispatch} />}
    </div>
  );
}
