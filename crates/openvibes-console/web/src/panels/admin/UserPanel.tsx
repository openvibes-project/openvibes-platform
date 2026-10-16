// A console user: their roles, and creating a new user.
import { useState } from "react";

import { apiMessage, invalidate, request, useResource } from "../../api/client";
import type { PersonView, Role } from "../../api/types";
import { nav } from "../../app/nav";
import { useSession } from "../../app/session";
import { SelectField } from "../../ui/Field";
import { Icon } from "../../ui/Icon";
import { Select } from "../../ui/Select";
import { Empty, ErrorBox, Loading } from "../../ui/bits";
import { PanelHeader, Section } from "../../ui/panel";
import { toast } from "../../ui/toast";

export function UserPanel({ id }: { id: string }) {
  const { can } = useSession();
  const person = useResource<PersonView>(`/api/v1/users/${encodeURIComponent(id)}`);
  const roles = useResource<Role[]>(can("access.read") ? "/api/v1/roles" : null).data ?? [];
  const [role, setRole] = useState("");
  if (person.error) return <div className="panel-body"><ErrorBox error={person.error} /></div>;
  const user = person.data;
  if (!user) return person.loading ? <Loading /> : <div className="panel-body"><Empty title="User not found" /></div>;
  const manage = can("access.grant", true);
  const change = (method: "PUT" | "DELETE", roleId: string, done: string) => {
    request(method, `/api/v1/users/${encodeURIComponent(id)}/roles/${encodeURIComponent(roleId)}`)
      .then(() => { invalidate("/api/v1/users"); toast(done); }, (e: unknown) => toast(apiMessage(e, "Failed"), true));
  };
  const effective = [...new Set(user.access.map((line) => line.permission))].sort((a, b) => a.localeCompare(b));
  return (
    <>
      <PanelHeader icon="user" kind="User" title={user.display_name} subtitle={<span className="mono subtle">{user.username}</span>} />
      <div className="panel-body stack">
        <Section title="Roles">
          {user.roles.length === 0 ? <p className="subtle">No roles: this user can sign in but see nothing.</p> : (
            <ul className="list list--plain">
              {user.roles.map((held) => (
                <li key={held.role_id} className="list__row list__row--static">
                  <span className="badge badge--accent badge--plain">{held.name}</span>
                  <span className="grow subtle">{reachLabel(held)}</span>
                  {manage && <button type="button" className="icon-button" aria-label="Remove role" onClick={() => change("DELETE", held.role_id, "Role removed")}><Icon name="close" size={14} /></button>}
                </li>
              ))}
            </ul>
          )}
          {manage && (
            <form className="row" onSubmit={(event) => { event.preventDefault(); change("PUT", role, "Role granted"); }}>
              <div className="grow"><Select label="Role" value={role} placeholder="Choose a role…" onChange={setRole} options={roles.map((r) => ({ value: r.role_id, label: r.name }))} /></div>
              <button className="button button--small" type="submit" disabled={!role}><Icon name="plus" size={14} /> Grant</button>
            </form>
          )}
        </Section>
        <Section title={`Effective permissions (${effective.length})`}>
          <div className="row row--wrap">{effective.map((permission) => <span key={permission} className="tag">{permission}</span>)}</div>
        </Section>
      </div>
    </>
  );
}

/** Where a role's host permissions apply, in words. */
export function reachLabel(role: Role): string {
  if (role.reach.kind === "all") return "all hosts";
  if (role.reach.kind === "groups") return `on ${role.reach.groups.map((g) => g.name).join(", ")}`;
  return "no hosts";
}

type CreatedUser = { user_id: string; username: string; display_name: string; role_ids: string[]; one_time_password: string };

/** A local user with a one-time password, shown once; they set their own at first sign-in (#85). */
export function NewUser() {
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const roles = useResource<Role[]>("/api/v1/roles").data ?? [];
  // No default role: least privilege is a deliberate choice.
  const [role, setRole] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<CreatedUser>();
  if (created) {
    return (
      <>
        <PanelHeader icon="user" kind="User" title={created.display_name} subtitle={`${created.username} · ${created.role_ids.map((rid) => roles.find((r) => r.role_id === rid)?.name ?? rid).join(", ")}`} />
        <div className="panel-body stack">
          <div className="callout callout--warn"><Icon name="alert" size={16} /> Copy the one-time password now. It is shown only once.</div>
          <div className="secret"><span className="grow">{created.one_time_password}</span>
            <button type="button" className="icon-button" aria-label="Copy one-time password" onClick={() => { void navigator.clipboard?.writeText(created.one_time_password); toast("Copied"); }}><Icon name="copy" size={16} /></button>
          </div>
          <p className="subtle">Give it to {created.display_name} by a private channel. At their first sign-in they choose their own password, and nothing else works until they do.</p>
          <div><button type="button" className="button" onClick={() => nav.open({ kind: "user", id: created.user_id }, true)}>Done</button></div>
        </div>
      </>
    );
  }
  return (
    <>
      <PanelHeader icon="user" kind="User" title="New user" subtitle="A local sign-in with a one-time password they replace at first sign-in." />
      <form className="panel-body stack" onSubmit={(event) => {
        event.preventDefault();
        if (busy) return;
        setBusy(true);
        setError(undefined);
        request<CreatedUser>("POST", "/api/v1/users", { username: username.trim(), display_name: displayName.trim(), role_ids: [role] })
          .then((user) => { invalidate("/api/v1/users"); setCreated(user); }, (e: unknown) => setError(apiMessage(e, "Could not create the user")))
          .finally(() => setBusy(false));
      }}>
        <label className="field">Username<input className="input mono" required maxLength={64} pattern="[A-Za-z0-9._@+\-]+" autoComplete="off" spellCheck={false} value={username} onChange={(e) => setUsername(e.target.value)} placeholder="e.g. jdoe" /></label>
        <label className="field">Display name<input className="input" required maxLength={160} value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="e.g. Jane Doe" /></label>
        <SelectField label="Role"><Select label="Role" value={role} placeholder="Choose a role…" onChange={setRole} options={roles.map((r) => ({ value: r.role_id, label: r.name }))} /></SelectField>
        {error && <p className="confirm__error" role="alert">{error}</p>}
        <div><button className="button button--primary" type="submit" disabled={busy || !role}><Icon name="plus" size={15} /> {busy ? "Creating…" : "Create user"}</button></div>
      </form>
    </>
  );
}
