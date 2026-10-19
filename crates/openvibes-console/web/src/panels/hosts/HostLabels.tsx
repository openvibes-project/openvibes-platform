// The host's "Groups and labels" card (approved screen 17): the groups it is in, and its labels.
import { useState } from "react";

import { ApiError, invalidate, request, useResource } from "../../api/client";
import type { HostGroup } from "../../api/types";
import { useSession } from "../../app/session";
import { Icon } from "../../ui/Icon";
import { ErrorBox, Loading } from "../../ui/bits";
import { Section } from "../../ui/panel";
import { KindBadge } from "../../views/admin/groups/badges";
import { link } from "../../views/admin/groups/groupApi";

/** The server's cap on labels per host. */
export const MAX_LABELS = 32;

type GroupRef = { asset_group_id: string; name: string; kind: HostGroup["kind"] };
type View = { labels: string[]; groups: GroupRef[] };

/** The label to add: trimmed, or undefined when it is empty or already there. */
export const nextLabel = (labels: readonly string[], input: string): string | undefined => {
  const label = input.trim();
  return label && !labels.includes(label) ? label : undefined;
};

/** The server's invalid_label words (labels.rs). */
export const INVALID_LABEL = "Use 1 to 64 characters, without control characters, and not . or ..";
/** "." and ".." cannot travel as a path segment, so they are refused before sending. */
export const refusedLabel = (label: string): string | undefined => (label === "." || label === ".." ? INVALID_LABEL : undefined);

const labelsPath = (id: string) => `/api/v1/hosts/${encodeURIComponent(id)}/labels`;
/** PUT is idempotent: adding a label already there succeeds. */
export const addRequest = (id: string, label: string) => ({ method: "PUT", path: `${labelsPath(id)}/${encodeURIComponent(label)}` }) as const;
export const removeRequest = (id: string, label: string) => ({ method: "DELETE", path: `${labelsPath(id)}/${encodeURIComponent(label)}` }) as const;

export function labelError(e: unknown): string {
  if (e instanceof ApiError && e.code === "too_many_labels") return `A host can have at most ${MAX_LABELS} labels. Remove one first.`;
  if (e instanceof ApiError && e.code === "invalid_label") return e.message;
  return "The label could not be saved.";
}

export function LabelsCard({ labels, groups, editable, error, busy = false, onAdd, onRemove }: {
  labels: readonly string[]; groups: readonly GroupRef[]; editable: boolean; error: string | undefined; busy?: boolean;
  onAdd: (label: string) => Promise<boolean> | undefined; onRemove: (label: string) => void;
}) {
  const [draft, setDraft] = useState("");
  return (
    <Section title="Groups and labels">
      <div className="stack">
        <div className="row row--wrap" aria-label="Groups">
          {groups.length === 0 && <span className="subtle">In no group</span>}
          {groups.map((g) => (
            <a key={g.asset_group_id} className="chip" {...link(`/settings/host-groups/${encodeURIComponent(g.asset_group_id)}`)}>{g.name} <KindBadge kind={g.kind} /></a>
          ))}
        </div>
        <div className="row row--wrap" aria-label="Labels">
          {labels.length === 0 && <span className="subtle">No labels</span>}
          {labels.map((l) => (
            <span key={l} className="chip">{l}
              {editable && <button type="button" className="icon-button" aria-label={`Remove label ${l}`} disabled={busy} title={`Remove label ${l}`} onClick={() => onRemove(l)}><Icon name="close" size={12} /></button>}
            </span>
          ))}
        </div>
        {editable && (
          <input className="input" aria-label="Add a label" placeholder="Add a label" value={draft} disabled={busy} onChange={(e) => setDraft(e.target.value)}
            onKeyDown={async (e) => {
              if (e.key !== "Enter") return;
              e.preventDefault();
              const label = nextLabel(labels, draft);
              if (!label) { setDraft(""); return; }
              // The text stays when the add fails.
              if ((await onAdd(label)) !== false) setDraft("");
            }} />
        )}
        {error && <p className="warn-text" role="alert">{error}</p>}
        <p className="subtle">For filtering and finding hosts. Labels never change who can see a host.</p>
      </div>
    </Section>
  );
}

export function HostLabels({ id }: { id: string }) {
  const { can } = useSession();
  const path = labelsPath(id);
  const view = useResource<View>(path);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const change = async ({ method, path: url }: { method: string; path: string }): Promise<boolean> => {
    setError(undefined);
    setBusy(true);
    try {
      await request(method, url);
      invalidate(path);
      invalidate("/api/v1/host-groups");
      return true;
    } catch (e) { setError(labelError(e)); return false; } finally { setBusy(false); }
  };
  if (view.error) return <Section title="Groups and labels"><ErrorBox error={view.error} /></Section>;
  if (!view.data) return <Loading rows={2} />;
  return (
    <LabelsCard labels={view.data.labels} groups={view.data.groups} editable={can("hosts.label")} error={error} busy={busy}
      onAdd={(label) => {
        const refused = refusedLabel(label);
        if (!refused) return change(addRequest(id, label));
        setError(refused);
        return Promise.resolve(false);
      }}
      onRemove={(label) => void change(removeRequest(id, label))} />
  );
}
