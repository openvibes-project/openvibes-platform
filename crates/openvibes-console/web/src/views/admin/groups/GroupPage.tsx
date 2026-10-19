// A host group's page (/settings/host-groups/{id}; approved screens 10, 10b
// and 10c) in the shared layout: Details, Who reaches it and Recent changes
// on the left; the rule or the hosts picked by hand, then the member hosts, on
// the right. Edit changes the name, description and membership in place, with
// a preview of who would join or leave before Save.
import { type MouseEvent, useEffect, useReducer, useState } from "react";

import { invalidate, request, useAllPages, useResource } from "../../../api/client";
import type { GroupHost, HostGroup, HostGroupDetail, HostGroupPreview, PersonRow, PreviewHostGroup, Role, UpdateHostGroup, CreateHostGroup } from "../../../api/types";
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
import { KindBadge, Problems } from "./badges";
import { DeleteGroup } from "./DeleteGroup";
import { GroupHosts } from "./GroupHosts";
import { type Action, type Draft, type Picked, fromGroup, hostsLabel, membershipChanged, membershipText, patchBody, previewBody, previewParts, reduce, refusal } from "./groupState";
import { PickedHosts } from "./PickedHosts";
import { RuleEditor } from "./RuleEditor";

/** Why write controls are off for someone holding host_groups.manage (the server's 403 title). */
export const NEEDS_EVERY_HOST = "Changing host groups needs access to every host";
const KIND_WORDS = { automatic: "Automatic: made by OpenVIBES", rule: "Rule: stays up to date", manual: "Manual: hand-picked" } as const;

export const groupPath = (id: string) => `/api/v1/host-groups/${encodeURIComponent(id)}`;
export const toList = () => nav.view("/settings", { tab: "host-groups" });
/** A save or delete changes the list, the role page's group picker and rule-set switches. */
export const refreshGroups = () => { invalidate("/api/v1/host-groups"); invalidate("/api/v1/rule-set-assignments"); };

/** POST for a new group, PATCH (with the version read) for an existing one. */
export const saveGroup = (groupId: string, body: CreateHostGroup | UpdateHostGroup): Promise<HostGroup> =>
  groupId === "new" ? request<HostGroup>("POST", "/api/v1/host-groups", body) : request<HostGroup>("PATCH", groupPath(groupId), body);

export function link(view: string, params?: Record<string, string>) {
  return { href: nav.href(view, params), onClick: (e: MouseEvent) => { e.preventDefault(); nav.view(view, params); } };
}

/** Writes need host_groups.manage and hosts.read on every host: hidden without the first, off with the reason without the second. */
export function useWriteAccess(): { show: boolean; blocked: string | undefined } {
  const { can, canEverywhere } = useSession();
  return { show: can("host_groups.manage"), blocked: canEverywhere("hosts.read") ? undefined : NEEDS_EVERY_HOST };
}

/** What saving `body` would change, asked once typing pauses; undefined while unknown. */
export function usePreview(path: string, body: PreviewHostGroup | undefined): HostGroupPreview | undefined {
  const key = body ? JSON.stringify(body) : "";
  const [result, setResult] = useState<{ key: string; preview: HostGroupPreview }>();
  useEffect(() => {
    if (!key) return;
    let live = true;
    const timer = setTimeout(() => {
      request<HostGroupPreview>("POST", path, JSON.parse(key)).then((preview) => { if (live) setResult({ key, preview }); }, () => {});
    }, 400);
    return () => { live = false; clearTimeout(timer); };
  }, [path, key]);
  return result?.key === key ? result.preview : undefined;
}

/** The warn callout "If you save: +N (…), −M (…). … gain access to them."; nothing when nothing changes. */
export function PreviewNote({ preview, verb = "save" }: { preview: HostGroupPreview | undefined; verb?: "save" | "delete" }) {
  if (!preview) return null;
  const { lead, changes, people } = previewParts(preview, verb);
  if (changes.length === 0) return null;
  return (
    <div className="callout callout--warn group-page__preview" role="status">
      <Icon name="info" size={16} />
      <span>{lead}{changes.map((c, i) => <span key={c.sign}>{i ? ", " : ""}<b>{c.sign}</b> ({c.hosts})</span>)}.{people}</span>
    </div>
  );
}

const picks = (hosts: readonly GroupHost[]): Picked[] => hosts.map((h) => ({ agent_id: h.agent_id, hostname: h.hostname ?? h.agent_id }));

export function GroupPage({ groupId }: { groupId: string }) {
  const { can } = useSession();
  const group = useResource<HostGroupDetail>(groupPath(groupId));
  const hosts = useAllPages<GroupHost>(`${groupPath(groupId)}/hosts`, 2000, "agent_id");
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
  const [editing, setEditing] = useState(initial !== undefined);
  const [draft, dispatch] = useReducer(reduce, initial ?? base);
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
    dispatch({ type: "reset", draft: action ? reduce(base, action) : base });
    setEditing(true);
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
  const off = write.blocked ? { disabled: true, title: write.blocked } : {};
  const roleInfo = (roleId: string) => ({
    permissions: roles?.find((r) => r.role_id === roleId)?.permissions.length,
    holders: (people ?? []).filter((p) => p.enabled && p.roles.some((r) => r.role_id === roleId)).map((p) => p.display_name),
  });
  const reachLine = `${hostsLabel(group.hosts, seesAll)}${group.hosts || seesAll ? ` · ${group.online} online` : ""} · used by ${plural(group.roles.length, "role")} · ${
    group.people === 1 ? "1 person reaches it" : `${group.people} people reach it`}`;

  return (
    <div className="view person-page group-page">
      <div className="view-pad person-page__crumb subtle"><a {...link("/settings")}>Settings</a> › <a {...link("/settings", { tab: "host-groups" })}>Host groups</a></div>
      <header className="person-page__head">
        <span className="group-page__icon" aria-hidden="true"><Icon name="layers" size={22} /></span>
        <div className="stack grow person-page__title">
          <div className="row"><h1>{group.name}</h1><KindBadge kind={group.kind} /></div>
          <span className="subtle">{reachLine}</span>
        </div>
        {write.show && (
          <div className="row person-page__actions">
            <button type="button" className="button" {...off} onClick={() => (editing ? setEditing(false) : edit())}>{editing ? "Stop editing" : "Edit"}</button>
            <span title={write.blocked}>
              <MenuButton label="More actions" icon="more" compact disabled={!!write.blocked}
                items={[{ value: "duplicate", label: "Duplicate…" }, { value: "delete", label: "Delete group…" }]}
                onPick={(v) => (v === "delete" ? setDeleting(true) : nav.view("/settings/host-groups/new", { from: group.asset_group_id }))} />
            </span>
          </div>
        )}
      </header>
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
          {group.upgraded_from_tags && group.kind === "manual" && !editing && write.show && !write.blocked && (
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
                ? <PickedHosts draft={shown} dispatch={dispatch} editing={editing} empty={seesAll ? "No hosts yet" : "No hosts you can see"} />
                : <RuleEditor draft={shown} dispatch={dispatch} editing={editing} />}
              {editing && <PreviewNote preview={preview} />}
              {editing && (
                <div className="row">
                  <button type="button" className="button button--primary button--small" disabled={busy || !draft.name.trim()} onClick={() => void save()}>{busy ? "Saving…" : "Save changes"}</button>
                  <button type="button" className="button button--small" onClick={() => { setError(undefined); setEditing(false); }}>Cancel</button>
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
