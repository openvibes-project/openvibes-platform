// A console user: their roles, and creating a new user.
import { useState } from "react";

import { apiMessage, invalidate, request, useResource } from "../../api/client";
import type { AccessInventory } from "../../api/types";
import { nav } from "../../app/nav";
import { roles } from "../../app/roles";
import { useSession } from "../../app/session";
import { SelectField } from "../../ui/Field";
import { Icon } from "../../ui/Icon";
import { Select } from "../../ui/Select";
import { Empty, ErrorBox, Loading } from "../../ui/bits";
import { PanelHeader, Section } from "../../ui/panel";
import { toast } from "../../ui/toast";

export function UserPanel({ id }: { id: string }) {
  const { can } = useSession();
  const inventory = useResource<AccessInventory>("/api/v1/access-control");
  const [role, setRole] = useState("viewer");
  const [group, setGroup] = useState("");
  if (inventory.error) return <div className="panel-body"><ErrorBox error={inventory.error} /></div>;
  const data = inventory.data;
  const user = data?.users.find((item) => item.user_id === id);
  if (!data || !user) return inventory.loading ? <Loading /> : <div className="panel-body"><Empty title="User not found" /></div>;
  const bindings = data.bindings.filter((binding) => binding.user_id === id);
  const manage = can("rbac.manage", true);
  const effective = [...new Set(bindings.flatMap((binding) => data.roles.find((r) => r.role_id === binding.role_id)?.permissions ?? []))].sort((a, b) => a.localeCompare(b));
  return (
    <>
      <PanelHeader icon="user" kind="User" title={user.display_name} subtitle={<span className="mono subtle">{user.username}</span>} />
      <div className="panel-body stack">
        <Section title="Roles">
          {bindings.length === 0 ? <p className="subtle">No roles: this user can sign in but see nothing.</p> : (
            <ul className="list list--plain">
              {bindings.map((binding) => (
                <li key={binding.binding_id} className="list__row list__row--static">
                  <span className="badge badge--accent badge--plain">{data.roles.find((r) => r.role_id === binding.role_id)?.display_name ?? binding.role_id}</span>
                  <span className="grow subtle">{binding.asset_group_name ? `on ${binding.asset_group_name}` : "everywhere"}</span>
                  {manage && <button type="button" className="icon-button" aria-label="Remove role" onClick={() => {
                    request("DELETE", `/api/v1/access-control/bindings/${encodeURIComponent(binding.binding_id)}`)
                      .then(() => { invalidate("/api/v1/access-control"); toast("Role removed"); }, (e: unknown) => toast(apiMessage(e, "Failed"), true));
                  }}><Icon name="close" size={14} /></button>}
                </li>
              ))}
            </ul>
          )}
          {manage && (
            <form className="row" onSubmit={(event) => {
              event.preventDefault();
              request("POST", "/api/v1/access-control/bindings", { user_id: id, role_id: role, asset_group_id: group || null })
                .then(() => { invalidate("/api/v1/access-control"); toast("Role granted"); }, (e: unknown) => toast(apiMessage(e, "Failed"), true));
            }}>
              <Select label="Role" value={role} onChange={setRole} options={data.roles.map((r) => ({ value: r.role_id, label: r.display_name }))} />
              <div className="grow"><Select label="Scope" value={group} onChange={setGroup}
                options={[{ value: "", label: "Everywhere" }, ...data.asset_groups.map((g) => ({ value: g.asset_group_id, label: g.name }))]} /></div>
              <button className="button button--small" type="submit"><Icon name="plus" size={14} /> Grant</button>
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

type CreatedUser = { user_id: string; username: string; display_name: string; role_id: string; one_time_password: string };

/** A local user with a one-time password, shown once; they set their own at first sign-in (#85). */
export function NewUser() {
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState("viewer");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<CreatedUser>();
  if (created) {
    return (
      <>
        <PanelHeader icon="user" kind="User" title={created.display_name} subtitle={`${created.username} · ${roles.find(([id]) => id === created.role_id)?.[1] ?? created.role_id}`} />
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
        request<CreatedUser>("POST", "/api/v1/access-control/users", { username: username.trim(), display_name: displayName.trim(), role_id: role })
          .then((user) => { invalidate("/api/v1/access-control"); setCreated(user); }, (e: unknown) => setError(apiMessage(e, "Could not create the user")))
          .finally(() => setBusy(false));
      }}>
        <label className="field">Username<input className="input mono" required maxLength={64} pattern="[A-Za-z0-9._@+\-]+" autoComplete="off" spellCheck={false} value={username} onChange={(e) => setUsername(e.target.value)} placeholder="e.g. jdoe" /></label>
        <label className="field">Display name<input className="input" required maxLength={160} value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="e.g. Jane Doe" /></label>
        <SelectField label="Role"><Select label="Role" value={role} onChange={setRole} options={roles.map(([id, label]) => ({ value: id, label }))} /></SelectField>
        {error && <p className="confirm__error" role="alert">{error}</p>}
        <div><button className="button button--primary" type="submit" disabled={busy}><Icon name="plus" size={15} /> {busy ? "Creating…" : "Create user"}</button></div>
      </form>
    </>
  );
}
