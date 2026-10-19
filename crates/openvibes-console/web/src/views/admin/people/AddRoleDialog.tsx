// "+ Add role" on the person page (approved screen 8): a search by name over
// the roles the person does not hold, each with where it applies and how many
// permissions it has. Roles outside the viewer's share are not offered.
// A search field plus a list of buttons (Tab moves through them), like HostsPicker.
import { useState } from "react";

import { useResource } from "../../../api/client";
import type { Role } from "../../../api/types";
import { useSession } from "../../../app/session";
import { Icon } from "../../../ui/Icon";
import { matches } from "../../../ui/table";
import { countLabel, hostsSummary } from "../roles/roleState";
import { fitsShare } from "./people";

export function AddRoleDialog({ held, onAdd, onClose }: { held: readonly Role[]; onAdd: (role: Role) => void; onClose: (refocus: boolean) => void }) {
  const { session } = useSession();
  const roles = useResource<Role[]>("/api/v1/roles").data ?? [];
  const [query, setQuery] = useState("");
  const options = roles.filter((r) => !held.some((h) => h.role_id === r.role_id) && fitsShare(session?.capabilities ?? [], r) && matches([r.name], query));
  return (
    <div className="hosts-picker__search" onBlur={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) onClose(false); }}
      onKeyDown={(e) => { if (e.key === "Escape") { e.stopPropagation(); onClose(true); } }}>
      <label className="search">
        <Icon name="search" size={15} />
        <span className="sr-only">Add a role</span>
        <input className="input" type="search" autoFocus placeholder="Add a role: search by name" value={query} autoComplete="off" onChange={(e) => setQuery(e.target.value)} />
      </label>
      <div className="sel__popup hosts-picker__popup">
        <div className="sel__list" role="group" aria-label="Roles to add">
          {options.length === 0 && <div className="sel__empty subtle">No other role matches</div>}
          {options.map((r) => (
            <button key={r.role_id} type="button" className="sel__option hosts-picker__option" onMouseDown={(e) => e.preventDefault()} onClick={() => onAdd(r)}>
              <span className="sel__label">{r.name} <span className="subtle">· {hostsSummary(r.reach)} · {r.builtin ? "every permission" : countLabel(r.permissions.length)}</span></span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
