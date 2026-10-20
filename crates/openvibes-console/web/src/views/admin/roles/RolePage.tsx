// The role page (/settings/roles/new and /settings/roles/{id}), full width:
// 1 Name and 2 Start from side by side, then Permissions (the matrix) and
// Hosts, with a sticky bar that sums up the role and saves it.
import { type ReactNode, useReducer, useState } from "react";

import { ApiError, apiMessage, invalidate, request, useResource } from "../../../api/client";
import type { HostGroup, Role, SaveRole } from "../../../api/types";
import { nav, viewLink } from "../../../app/nav";
import { CATALOGUE, TEMPLATES } from "../../../app/permissions";
import { useSession } from "../../../app/session";
import { Select } from "../../../ui/Select";
import { ErrorBox, Loading } from "../../../ui/bits";
import { Icon } from "../../../ui/Icon";
import { toast } from "../../../ui/toast";
import { HostsPicker } from "./HostsPicker";
import { InfoMark, PermissionMatrix } from "./PermissionMatrix";
import { RoleBar } from "./RoleBar";
import { BLANK, type RoleState, blank, countLabel, fromRole, hostsSummary, reduce, saveBody } from "./roleState";

const STALE = "Someone else changed this role; your edits were not saved.";
const rolePath = (id: string) => `/api/v1/roles/${encodeURIComponent(id)}`;
const toList = () => nav.view("/settings", { tab: "roles" });

/** POST for a new role, PATCH (with the version read) for an existing one. */
export const saveRole = (roleId: string, body: SaveRole): Promise<Role> =>
  roleId === "new" ? request<Role>("POST", "/api/v1/roles", body) : request<Role>("PATCH", rolePath(roleId), body);

/** What to say when a save or delete is refused, and whether the role must be reloaded (someone else saved first). */
export function refusal(error: unknown, fallback: string): { message: string; reload: boolean } {
  return error instanceof ApiError && error.code === "stale_role" ? { message: STALE, reload: true } : { message: apiMessage(error, fallback), reload: false };
}

/** Everything a save or delete can change elsewhere: the list, groups' role counts, people's roles. */
const refreshAll = () => { invalidate("/api/v1/roles"); invalidate("/api/v1/host-groups"); invalidate("/api/v1/users"); };

/** `roleId` is a role id, or "new" for a role not yet created. */
export function RolePage({ roleId }: { roleId: string }) {
  const role = useResource<Role>(roleId === "new" ? null : rolePath(roleId));
  const groups = useResource<HostGroup[]>("/api/v1/host-groups");
  const [error, setError] = useState<string>();
  const failed = role.error ?? groups.error;
  if (failed) return <div className="view-pad"><ErrorBox error={failed} /></div>;
  if ((roleId !== "new" && !role.data) || !groups.data) return <Loading />;
  // A reload after a stale save brings a new version: start again from it.
  return <RoleEditor key={role.data?.version ?? "new"} role={role.data} groups={groups.data} error={error} onError={setError} />;
}

const Step = ({ n, title, aside }: { n: number; title: ReactNode; aside?: ReactNode }) => (
  <div className="row row--between role-step">
    <h2 className="section-title role-step__title"><span className="role-step__n">{n}</span>{title}</h2>
    {aside}
  </div>
);

const link = viewLink;

export function RoleEditor({ role, groups, initial, error, onError = () => {} }: {
  role: Role | undefined; groups: readonly HostGroup[]; initial?: RoleState; error?: string | undefined; onError?: (message: string | undefined) => void;
}) {
  const { can } = useSession();
  const [state, dispatch] = useReducer(reduce, undefined, () => initial ?? (role ? fromRole(role) : blank()));
  const [busy, setBusy] = useState(false);
  const isNew = role === undefined;
  const readOnly = !!role?.builtin || !can("access.roles");
  const count = CATALOGUE.filter((p) => state.on.has(p.id)).length;
  const template = TEMPLATES.find((t) => t.name === state.startFrom);
  const k = isNew ? 1 : 0;

  const act = async (work: () => Promise<unknown>, done: string, fallback: string) => {
    setBusy(true);
    onError(undefined);
    try {
      await work();
      refreshAll();
      toast(done);
      toList();
    } catch (e) {
      const { message, reload } = refusal(e, fallback);
      onError(message);
      if (reload && role) invalidate(rolePath(role.role_id));
    } finally {
      setBusy(false);
    }
  };
  const save = () => act(() => saveRole(role?.role_id ?? "new", saveBody(state, role)), isNew ? "Role created" : "Role saved", "The role could not be saved.");
  const remove = role && !role.builtin
    ? () => { if (window.confirm(`Delete the role ${role.name}? This cannot be undone.`)) void act(() => request("DELETE", rolePath(role.role_id)), "Role deleted", "The role could not be deleted."); }
    : undefined;

  return (
    <div className="view role-page">
      <header className="view-header">
        <div className="view-header__title role-page__title">
          <span className="subtle"><a {...link("/settings")}>Settings</a> › <a {...link("/settings", { tab: "roles" })}>Roles</a></span>
          <h1>{role ? role.name : "New role"}</h1>
        </div>
      </header>
      {role && (
        <div className="callout role-page__note">
          <Icon name="info" size={16} />
          <span>{role.builtin
            ? "Administrator has every permission on all hosts and cannot be changed."
            : `${role.members} ${role.members === 1 ? "person has" : "people have"} this role. Changes apply at their next request.`}</span>
        </div>
      )}
      <div className="view-pad role-page__body">
        <div className={isNew ? "role-page__top role-page__top--two" : "role-page__top"}>
          <section className="stack role-step__body">
            <Step n={1} title="Name" />
            <input className="input role-page__name" aria-label="Name" placeholder="e.g. Windows lead" value={state.name} disabled={readOnly} maxLength={64}
              onChange={(e) => dispatch({ type: "name", name: e.target.value })} />
            <p className="subtle role-page__hint">With single sign-on, people in the identity-provider group of this name get the role.</p>
          </section>
          {isNew && (
            <section className="stack role-step__body">
              <Step n={2} title="Start from" />
              <div className="role-page__start">
                <Select label="Start from" value={state.startFrom} disabled={readOnly} onChange={(name) => dispatch({ type: "template", name })}
                  options={[{ value: BLANK, label: "Blank: no permissions", description: "No permissions; pick them yourself." },
                    ...TEMPLATES.map((t) => ({ value: t.name, label: `${t.name} template`, hint: `· ${countLabel(t.permissions.length)}`, description: t.description }))]} />
              </div>
              <p className="subtle role-page__hint">{template?.description ?? "Blank: no permissions. Pick a template to fill them in, and switch between templates to compare."}</p>
            </section>
          )}
        </div>
        <section className="stack role-step__body">
          <Step n={2 + k} title={<>Permissions <span className="subtle num role-step__count">{count} of {CATALOGUE.length}</span></>}
            aside={state.changed.size > 0 && (
              <span className="subtle role-page__legend">
                {[...state.changed.values()].includes("added") && <><span className="role-page__dot role-page__dot--added" /> added</>}
                {[...state.changed.values()].includes("removed") && <><span className="role-page__dot role-page__dot--removed" /> taken away</>}
                , compared with your previous choice
              </span>
            )} />
          {state.notice && <div className="callout role-page__notice" role="status"><Icon name="info" size={16} /><span>{state.notice}</span></div>}
          <PermissionMatrix state={state} dispatch={dispatch} readOnly={readOnly} />
          <p className="subtle role-page__foot">
            <InfoMark /> Applies to the whole platform, whatever hosts the role reaches (next to an area: the whole area). Everything else applies only to
            the hosts chosen in step {3 + k}. Turning a permission on also turns on what it needs (hover a chip to see it); turning one off turns off what depends on it.
          </p>
        </section>
        <section className="stack role-step__body">
          <Step n={3 + k} title="Hosts" />
          <HostsPicker reach={state.reach} groups={groups} dispatch={dispatch} readOnly={readOnly} />
        </section>
      </div>
      <RoleBar name={state.name} summary={`${countLabel(count)} · ${hostsSummary(state.reach)}`} error={error} isNew={isNew} readOnly={readOnly} busy={busy}
        onCancel={toList} onSave={() => void save()} onDelete={remove} />
    </div>
  );
}
