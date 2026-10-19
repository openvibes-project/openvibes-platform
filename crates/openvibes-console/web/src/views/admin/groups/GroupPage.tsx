// A host group's page (/settings/host-groups/{id}; approved screens 10, 10b
// and 10c) in the shared layout: Details, Who reaches it and Recent changes
// on the left; the rule or the hosts picked by hand, then the member hosts, on
// the right. Edit changes the name, description and membership in place, with
// a preview of who would join or leave before Save.
import { useId, useReducer, useState } from "react";

import { invalidate, useAllPages, useResource } from "../../../api/client";
import type { GroupHost, HostGroupDetail, PersonRow, Role } from "../../../api/types";
import { nav } from "../../../app/nav";
import { useSession } from "../../../app/session";
import { auditActionLabel } from "../../../ui/auditActions";
import { ErrorBox, Loading } from "../../../ui/bits";
import { ago, plural } from "../../../ui/format";
import { Icon } from "../../../ui/Icon";
import { MenuButton } from "../../../ui/Menu";
import { toast } from "../../../ui/toast";
import { Card } from "../people/PersonPage";
import { initials } from "../people/people";
import { KindBadge, PreviewNote, Problems } from "./badges";
import { DeleteGroup } from "./DeleteGroup";
import { MAX_PICKED, groupPath, link, picks, refreshGroups, saveGroup, usePreview, useWriteAccess } from "./groupApi";
import { GroupHosts } from "./GroupHosts";
import { type Action, type Draft, fromGroup, hostsLabel, isDirty, membershipChanged, membershipText, patchBody, previewBody, rebase, reduce, refusal } from "./groupState";
import { PickedHosts } from "./PickedHosts";
import { RuleEditor } from "./RuleEditor";

const KIND_WORDS = { automatic: "Automatic: made by OpenVIBES", rule: "Rule: stays up to date", manual: "Manual: hand-picked" } as const;
const DISCARD = "Discard your changes to this group?";

/** "4 hosts · 3 online · …"; "online" is left out when the viewer sees none of the hosts. */
export function reachLine(group: HostGroupDetail, seesAll: boolean): string {
  const online = group.hosts || seesAll ? ` · ${group.online} online` : "";
  return `${hostsLabel(group.hosts, seesAll)}${online} · used by ${plural(group.roles.length, "role")} · ${
    group.people === 1 ? "1 person reaches it" : `${group.people} people reach it`}`;
}

export function GroupPage({ groupId }: { groupId: string }) {
  const { can } = useSession();
  const group = useResource<HostGroupDetail>(groupPath(groupId));
  // A manual group's hosts are its picks, all of which a save sends back: load as many as the server allows.
  // ponytail: a rule group's table stops at 2000 hosts; page it when groups grow past that.
  const max = group.data?.kind === "manual" ? MAX_PICKED : 2000;
  const hosts = useAllPages<GroupHost>(group.data ? `${groupPath(groupId)}/hosts` : null, max, "agent_id");
  // People and roles name the actors and fill Who reaches it; without access.read, ids and names only.
  const people = useResource<PersonRow[]>(can("access.read") ? "/api/v1/users" : null);
  const roles = useResource<Role[]>(can("access.read") ? "/api/v1/roles" : null);
  const failed = group.error ?? hosts.error;
  if (failed) return <div className="view-pad"><ErrorBox error={failed} /></div>;
  if (!group.data || !hosts.data) return <Loading />;
  const names = new Map((people.data ?? []).map((p) => [p.user_id, p.display_name]));
  return <GroupBody group={group.data} hosts={hosts.data} names={names} people={people.data} roles={roles.data} />;
}

export function GroupBody({ group, hosts, names, people, roles, initial }: {
  group: HostGroupDetail; hosts: readonly GroupHost[]; names: ReadonlyMap<string, string>; people?: readonly PersonRow[] | undefined; roles?: readonly Role[] | undefined;
  /** Opens in edit mode with this draft (tests). */
  initial?: Draft;
}) {
  const { session, canEverywhere } = useSession();
  const write = useWriteAccess();
  const seesAll = canEverywhere("hosts.read");
  const base = fromGroup(group, group.kind === "manual" ? picks(hosts) : []);
  const baseKey = `${group.version}|${base.picked.map((h) => h.agent_id).join()}`;
  const [editing, setEditing] = useState(initial !== undefined);
  const [draft, dispatch] = useReducer(reduce, initial ?? base);
  // What editing started from. When the group reloads (a stale save), the
  // user's own changes move onto the reload and the rest comes from it.
  const [editBase, setEditBase] = useState({ key: baseKey, draft: base });
  if (editBase.key !== baseKey) {
    setEditBase({ key: baseKey, draft: base });
    if (editing) dispatch({ type: "reset", draft: rebase(draft, editBase.draft, base) });
  }
  // Every pick must be loaded before picks can be edited: a save sends them all back.
  const picksShort = group.kind === "manual" && hosts.length < group.picked
    ? `Only ${hosts.length} of ${group.picked} picked hosts could be loaded, so the picks cannot be changed here. Reload the page to try again.` : undefined;
  const reasonId = useId();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const path = groupPath(group.asset_group_id);
  const changed = editing && membershipChanged(draft, base);
  const preview = usePreview(`${path}/preview`, changed ? previewBody(draft) : undefined);
  // The audit actor is a user id; "openvibes" made the automatic groups.
  const who = (id: string | null | undefined) =>
    (!id ? "someone" : id === session?.principal.id ? "you" : id === "openvibes" ? "OpenVIBES" : names.get(id) ?? id);

  const edit = (action?: Action) => {
    setError(undefined);
    setEditBase({ key: baseKey, draft: base });
    dispatch({ type: "reset", draft: action ? reduce(base, action) : base });
    setEditing(true);
  };
  const stop = () => {
    if (isDirty(draft, base) && !window.confirm(DISCARD)) return;
    setError(undefined);
    setEditing(false);
  };
  const save = async () => {
    const body = patchBody(draft, base, group.version);
    if (Object.keys(body).length === 1) { setEditing(false); return; }
    setBusy(true);
    setError(undefined);
    try {
      await saveGroup(group.asset_group_id, body);
      refreshGroups();
      toast("Saved · recorded in the audit log");
      setEditing(false);
    } catch (e) {
      // Stale: the group reloads underneath and the edit stays, to be saved again.
      const { message, reload } = refusal(e, "The group could not be saved.");
      setError(message);
      if (reload) invalidate(path);
    } finally {
      setBusy(false);
    }
  };

  const shown = editing ? draft : base;
  const off = write.reason ? { disabled: true, title: write.reason, "aria-describedby": reasonId } : {};
  const roleInfo = (roleId: string) => ({
    permissions: roles?.find((r) => r.role_id === roleId)?.permissions.length,
    holders: (people ?? []).filter((p) => p.enabled && p.roles.some((r) => r.role_id === roleId)).map((p) => p.display_name),
  });

  return (
    <div className="view person-page group-page">
      <div className="view-pad person-page__crumb subtle"><a {...link("/settings")}>Settings</a> › <a {...link("/settings", { tab: "host-groups" })}>Host groups</a></div>
      <header className="person-page__head">
        <span className="group-page__icon" aria-hidden="true"><Icon name="layers" size={22} /></span>
        <div className="stack grow person-page__title">
          <div className="row"><h1>{group.name}</h1><KindBadge kind={group.kind} /></div>
          <span className="subtle">{reachLine(group, seesAll)}</span>
        </div>
        {write.show && (
          <div className="row person-page__actions">
            <button type="button" className="button" {...off} onClick={() => (editing ? stop() : edit())}>{editing ? "Stop editing" : "Edit"}</button>
            <span title={write.reason}>
              <MenuButton label="More actions" icon="more" compact disabled={!!write.reason}
                items={[{ value: "duplicate", label: "Duplicate…" }, { value: "delete", label: "Delete group…" }]}
                onPick={(v) => (v === "delete" ? setDeleting(true) : nav.view("/settings/host-groups/new", { from: group.asset_group_id }))} />
            </span>
          </div>
        )}
      </header>
      {write.show && write.reason && <p id={reasonId} className="subtle group-page__reason">{write.reason}.</p>}
      {error && <div className="callout callout--bad person-page__error" role="alert"><Icon name="alert" size={16} /><span>{error}</span></div>}
      {deleting && <DeleteGroup group={group} onClose={() => setDeleting(false)} />}
      <div className="person-page__cols">
        <div className="stack person-page__col">
          <Card title="Details">
            {editing ? (
              <div className="stack group-page__fields">
                <label className="field">Name<input className="input" required maxLength={128} value={draft.name} onChange={(e) => dispatch({ type: "name", name: e.target.value })} /></label>
                <label className="field">Description<textarea className="textarea" maxLength={500} rows={3} value={draft.description} onChange={(e) => dispatch({ type: "description", description: e.target.value })} /></label>
              </div>
            ) : group.description ? <p className="group-page__desc">{group.description}</p> : null}
            <dl className="kv person-page__kv">
              <dt>Kind</dt><dd>{KIND_WORDS[group.kind]}</dd>
              <dt>Membership</dt><dd>{membershipText(group, seesAll)}</dd>
              <dt>Open problems</dt><dd><Problems alarms={group.open_alarms} critical={group.critical} /></dd>
              <dt>Changed</dt><dd>{group.changed_at ? `${ago(group.changed_at)} by ${who(group.changed_by)}` : "Never by hand"}</dd>
            </dl>
          </Card>
          <Card title="Who reaches it">
            {group.roles.length === 0 ? <p className="subtle person-page__none">No role uses this group yet. Choose it in a role's Hosts.</p> : (
              <div className="stack group-page__roles">
                {group.roles.map((r) => {
                  const info = roleInfo(r.role_id);
                  return (
                    <div key={r.role_id} className="stack group-page__role">
                      <div className="row row--between">
                        <a {...link(`/settings/roles/${encodeURIComponent(r.role_id)}`)}><strong>{r.name}</strong></a>
                        {info.permissions !== undefined && <span className="subtle num">{plural(info.permissions, "permission")}</span>}
                      </div>
                      {info.holders.length > 0 && (
                        <div className="row row--wrap">{info.holders.map((n) => <span key={n} className="chip group-page__person"><span className="group-page__initials" aria-hidden="true">{initials(n)}</span>{n}</span>)}</div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
          <Card title="Recent changes" aside={<a {...link("/audit", { q: group.asset_group_id })}>Audit log</a>}>
            {group.recent.length === 0 ? <p className="subtle person-page__none">Nothing recorded yet.</p> : (
              <ul className="person-page__activity">
                {group.recent.map((c) => <li key={`${c.at}|${c.action}`}><span>{auditActionLabel(c.action)}</span><span className="subtle">{who(c.actor)} · {ago(c.at)}</span></li>)}
              </ul>
            )}
          </Card>
        </div>
        <div className="stack person-page__col">
          {group.upgraded_from_tags && group.kind === "manual" && !editing && write.show && !write.reason && (
            <div className="callout group-page__note"><Icon name="info" size={16} />
              <span>This group was made from tags. You can turn it into a rule group.</span>
              <button type="button" className="button button--small" onClick={() => edit({ type: "toRule" })}>Turn into a rule</button>
            </div>
          )}
          <Card title={shown.kind === "manual" ? "Hosts picked by hand" : "Rule"} aside={editing && <span className="badge badge--accent badge--plain">Editing</span>}>
            <div className="stack group-page__membership">
              {group.kind === "automatic" && (
                <div className="callout group-page__note"><Icon name="info" size={16} />
                  <span>Made by OpenVIBES from what agents report. Editing it makes it yours: OpenVIBES won't change it again. Deleting it is remembered; it won't come back.</span>
                </div>
              )}
              {shown.kind === "manual"
                ? <PickedHosts draft={shown} dispatch={dispatch} editing={editing && !picksShort} empty={seesAll ? "No hosts yet" : "No hosts you can see"} />
                : <RuleEditor draft={shown} dispatch={dispatch} editing={editing} />}
              {editing && picksShort && <p className="subtle group-page__none" role="status">{picksShort}</p>}
              {editing && <PreviewNote preview={preview} />}
              {editing && (
                <div className="row">
                  <button type="button" className="button button--primary button--small" disabled={busy || !draft.name.trim()} onClick={() => void save()}>{busy ? "Saving…" : "Save changes"}</button>
                  <button type="button" className="button button--small" onClick={stop}>Cancel</button>
                </div>
              )}
            </div>
          </Card>
          <GroupHosts hosts={hosts} />
        </div>
      </div>
    </div>
  );
}
