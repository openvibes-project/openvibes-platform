// The `host` filter of the Alarms, Compliance and Vulnerabilities views
// (plan ruling 9): set by a host page's tiles and "Show all n", shown as a
// removable chip "Host: web-01 ×".
import { useResource } from "../../api/client";
import type { Agent } from "../../api/types";
import { nav } from "../../app/nav";
import { useSession } from "../../app/session";
import { Icon } from "../../ui/Icon";

export function HostChip({ id }: { id: string | null }) {
  const { can } = useSession();
  // The name when this person may read the host; its id otherwise.
  const agent = useResource<Agent>(id && can("hosts.read") ? `/api/v1/agents/${encodeURIComponent(id)}` : null);
  if (!id) return null;
  const text = `Host: ${agent.data?.hostname ?? id}`;
  return (
    <span className="chip filter-chip">{text}
      <button type="button" className="filter-chip__remove" aria-label={`Remove filter ${text}`} onClick={() => nav.setParams({ host: null, window: null })}>
        <Icon name="close" size={12} />
      </button>
    </span>
  );
}
