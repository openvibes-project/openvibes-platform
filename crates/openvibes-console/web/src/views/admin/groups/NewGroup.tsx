// A new group (/settings/host-groups/new, or ?from={id} for Duplicate…): name,
// description, Rule or Manual, then the same editor and preview as the group page.
import { useReducer, useState } from "react";

import { useAllPages, useResource } from "../../../api/client";
import type { GroupHost, HostGroupDetail } from "../../../api/types";
import { nav, useLocation } from "../../../app/nav";
import { ErrorBox, Loading } from "../../../ui/bits";
import { Icon } from "../../../ui/Icon";
import { Segmented } from "../../../ui/Segmented";
import { toast } from "../../../ui/toast";
import { Card } from "../../../ui/detail/DetailPage";
import { PreviewNote } from "./badges";
import { MAX_PICKED, groupPath, link, picks, refreshGroups, saveGroup, toList, usePreview, useWriteAccess } from "./groupApi";
import { type Draft, type Kind, blankDraft, createBody, fromGroup, previewBody, reduce, refusal } from "./groupState";
import { PickedHosts } from "./PickedHosts";
import { RuleEditor } from "./RuleEditor";

export function NewGroup() {
  const from = useLocation().params.get("from");
  const source = useResource<HostGroupDetail>(from ? groupPath(from) : null);
  const manual = source.data?.kind === "manual";
  // Only a manual group's picks are copied; a rule copies its conditions.
  const hosts = useAllPages<GroupHost>(from && manual ? `${groupPath(from)}/hosts` : null, MAX_PICKED, "agent_id");
  if (!from) return <NewGroupForm initial={blankDraft("rule")} />;
  const failed = source.error ?? hosts.error;
  if (failed) return <div className="view-pad"><ErrorBox error={failed} /></div>;
  if (!source.data || (manual && !hosts.data)) return <Loading />;
  const loaded = hosts.data ?? [];
  const copy = fromGroup(source.data, manual ? picks(loaded) : []);
  // A copy missing some picks would quietly be a different group.
  const short = manual && loaded.length < source.data.picked
    ? `Only ${loaded.length} of ${source.data.picked} picked hosts could be loaded, so this group cannot be duplicated. Reload the page to try again.` : undefined;
  return <NewGroupForm initial={{ ...copy, name: `${copy.name} (copy)` }} short={short} />;
}

export function NewGroupForm({ initial, short }: { initial: Draft; short?: string | undefined }) {
  const write = useWriteAccess();
  const [draft, dispatch] = useReducer(reduce, initial);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const body = previewBody(draft);
  const preview = usePreview("/api/v1/host-groups/preview", body);
  const blocked = write.reason ?? short;
  const ready = !!draft.name.trim() && body !== undefined && !blocked;
  const create = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const saved = await saveGroup("new", createBody(draft));
      refreshGroups();
      toast("Group created");
      nav.view(`/settings/host-groups/${encodeURIComponent(saved.asset_group_id)}`);
    } catch (e) {
      setError(refusal(e, "The group could not be created.").message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="view person-page group-page">
      <div className="view-pad person-page__crumb subtle"><a {...link("/settings")}>Settings</a> › <a {...link("/settings", { tab: "host-groups" })}>Host groups</a></div>
      <header className="person-page__head"><div className="stack grow person-page__title"><h1>New group</h1></div></header>
      {(error ?? blocked) && <div className="callout callout--bad person-page__error" role="alert"><Icon name="alert" size={16} /><span>{error ?? blocked}</span></div>}
      <div className="stack group-page__new">
        <Card title="Details">
          <div className="stack group-page__fields">
            <label className="field">Name<input className="input" required maxLength={128} value={draft.name} onChange={(e) => dispatch({ type: "name", name: e.target.value })} /></label>
            <label className="field">Description<textarea className="textarea" maxLength={500} rows={2} value={draft.description} onChange={(e) => dispatch({ type: "description", description: e.target.value })} /></label>
            <Segmented<Kind> label="Kind" value={draft.kind} onChange={(kind) => dispatch({ type: "kind", kind })}
              options={[{ value: "rule", label: "Rule" }, { value: "manual", label: "Manual" }]} />
          </div>
        </Card>
        <Card title={draft.kind === "manual" ? "Hosts picked by hand" : "Rule"}>
          <div className="stack group-page__membership">
            {draft.kind === "manual" ? <PickedHosts draft={draft} dispatch={dispatch} editing empty="No hosts yet" /> : <RuleEditor draft={draft} dispatch={dispatch} editing />}
            <PreviewNote preview={preview} />
            <div className="row">
              <button type="button" className="button button--primary button--small" disabled={!ready || busy}
                title={draft.name.trim() ? undefined : "Give it a name first"} onClick={() => void create()}>{busy ? "Creating…" : "Create group"}</button>
              <button type="button" className="button button--small" onClick={toList}>Cancel</button>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
