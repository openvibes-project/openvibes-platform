// A person's page (/settings/people/{id}; approved screen 7), one page, no
// tabs: the header, Details and Recent activity on the left, Roles and the
// Access they add up to on the right.
import { useRef, useState } from "react";

import { request, useResource } from "../../../api/client";
import type { PersonView } from "../../../api/types";
import { viewLink } from "../../../app/nav";
import { useSession } from "../../../app/session";
import { auditActionLabel } from "../../../ui/auditActions";
import { Ago, ErrorBox, Loading } from "../../../ui/bits";
import { Card } from "../../../ui/detail/DetailPage";
import { ago, date, plural } from "../../../ui/format";
import { Icon } from "../../../ui/Icon";
import { toast } from "../../../ui/toast";
import { countLabel, hostsSummary } from "../roles/roleState";
import { AddRoleDialog } from "./AddRoleDialog";
import { PersonMenu } from "./PersonMenu";
import { accessGroups, changeRole, initials, personActions, refreshPeople, refusal, signsIn, userPath } from "./people";

export function PersonPage({ userId }: { userId: string }) {
  const person = useResource<PersonView>(userPath(userId));
  const [error, setError] = useState<string>();
  if (person.error) return <div className="view-pad"><ErrorBox error={person.error} /></div>;
  if (!person.data) return <Loading />;
  return <PersonBody person={person.data} error={error} onError={setError} />;
}

const link = viewLink;

export function PersonBody({ person, error, onError }: { person: PersonView; error?: string | undefined; onError: (message: string | undefined) => void }) {
  const { session, can } = useSession();
  const self = session?.principal.id === person.user_id;
  const [editing, setEditing] = useState(false);
  const [adding, setAdding] = useState(false);
  // After Escape in Add role, focus goes back to the "Add role" button once it is shown again.
  const refocusAdd = useRef(false);
  const closeAdd = (refocus: boolean) => { refocusAdd.current = refocus; setAdding(false); };
  const grant = can("access.grant") && !self;
  const permissions = new Set(person.access.map((a) => a.permission)).size;
  const role = (roleId: string, give: boolean) => {
    onError(undefined);
    changeRole(person.user_id, roleId, give).then(() => toast(give ? "Role added" : "Role removed"), (e: unknown) => onError(refusal(e, "The role could not be changed.")));
  };
  return (
    <div className="view person-page">
      <div className="view-pad person-page__crumb subtle"><a {...link("/settings")}>Settings</a> › <a {...link("/settings", { tab: "people" })}>People</a></div>
      <header className="person-page__head">
        <span className="person-page__avatar" aria-hidden="true">{initials(person.display_name)}</span>
        <div className="stack grow person-page__title">
          <div className="row"><h1>{person.display_name}</h1><span className={person.enabled ? "badge badge--ok" : "badge badge--plain"}>{person.enabled ? "Active" : "Disabled"}</span></div>
          <span className="subtle">{plural(person.roles.length, "role")} · {countLabel(permissions)} · {person.last_sign_in_at ? `last signed in ${ago(person.last_sign_in_at)}` : "never signed in"}</span>
        </div>
        <div className="row person-page__actions">
          {(self || can("access.users")) && <button type="button" className="button" onClick={() => setEditing(!editing)}>{editing ? "Stop editing" : "Edit details"}</button>}
          <PersonMenu person={person} actions={personActions(person, self, can("access.users"))} onError={onError} />
        </div>
      </header>
      {error && <div className="callout callout--bad person-page__error" role="alert"><Icon name="alert" size={16} /><span>{error}</span></div>}
      <div className="person-page__cols">
        <div className="stack person-page__col">
          <Card title="Details">{editing ? <EditDetails person={person} onDone={() => setEditing(false)} /> : (
            <dl className="kv person-page__kv">
              <dt>Name</dt><dd>{person.display_name}</dd>
              <dt>Email</dt><dd>{person.email || <span className="subtle">None</span>}</dd>
              <dt>Username</dt><dd className="mono">{person.username}</dd>
              <dt>Signs in with</dt><dd>{signsIn(person.auth_source)}</dd>
              <dt>Last sign-in</dt><dd>{person.last_sign_in_at ? <Ago value={person.last_sign_in_at} /> : "Never"}</dd>
              <dt>Created</dt><dd>{date(person.created_at)}</dd>
            </dl>
          )}</Card>
          <Card title="Recent activity" aside={<a {...link("/audit", { q: person.username })}>Audit log</a>}>
            {person.recent.length === 0 ? <p className="subtle person-page__none">Nothing recorded yet.</p> : (
              <ul className="person-page__activity">
                {person.recent.map((a) => (
                  <li key={`${a.at}|${a.action}|${a.target ?? ""}`}><span>{auditActionLabel(a.action)}</span><span className="subtle">{a.target ? `${a.target} · ` : ""}{ago(a.at)}</span></li>
                ))}
              </ul>
            )}
          </Card>
        </div>
        <div className="stack person-page__col">
          <Card title={<>Roles <span className="num">{person.roles.length}</span></>}
            aside={grant && !adding && <button type="button" className="button button--primary button--small" onClick={() => setAdding(true)}
              ref={(el) => { if (el && refocusAdd.current) { refocusAdd.current = false; el.focus(); } }}><Icon name="plus" size={14} /> Add role</button>}>
            <div className="stack person-page__roles">
              {adding && <AddRoleDialog held={person.roles} onClose={closeAdd} onAdd={(r) => { closeAdd(true); role(r.role_id, true); }} />}
              {person.roles.length === 0 && <p className="subtle person-page__none">No roles yet: this person can sign in but sees nothing.</p>}
              {person.roles.map((r) => (
                <div key={r.role_id} className="person-role">
                  <div className="stack person-role__text">
                    <strong>{r.name}</strong>
                    <span className="row row--wrap subtle">Applies to <span className="chip person-role__where">{hostsSummary(r.reach)}</span> · {r.builtin ? "every permission" : countLabel(r.permissions.length)}</span>
                  </div>
                  <div className="row">
                    <a className="button button--ghost button--small" {...link(`/settings/roles/${encodeURIComponent(r.role_id)}`)}>Open role</a>
                    {grant && <button type="button" className="button button--small" onClick={() => role(r.role_id, false)}>Remove</button>}
                  </div>
                </div>
              ))}
              {self && person.roles.length > 0 && <p className="subtle person-page__none">Nobody can change their own roles.</p>}
            </div>
          </Card>
          <div className="row row--between person-page__access-head">
            <h2 className="section-title">Access <span className="num">{permissions}</span></h2>
            <span className="subtle">What these roles add up to, by where it applies.</span>
          </div>
          {person.access.length === 0 && <p className="subtle">No access: without roles this person can sign in but sees nothing.</p>}
          {accessGroups(person.access).map((g) => (
            <section key={g.key} className="card person-access">
              <div className="person-access__head"><strong>{g.title}</strong> <span className="subtle num">· {countLabel(new Set(g.lines.map((l) => l.permission)).size)}</span></div>
              <dl className="person-access__areas">
                {[...new Set(g.lines.map((l) => l.area))].map((area) => (
                  <div key={area} className="person-access__area">
                    <dt className="subtle">{area}</dt>
                    <dd className="row row--wrap">{g.lines.filter((l) => l.area === area).map((l) => (
                      <span key={`${l.permission} ${l.from_role}`} className="chip person-access__line" title={l.permission}>{l.label} · from {l.from_role}</span>
                    ))}</dd>
                  </div>
                ))}
              </dl>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}

/** Display name and email; saved with PATCH (the username never changes). */
function EditDetails({ person, onDone }: { person: PersonView; onDone: () => void }) {
  const [name, setName] = useState(person.display_name);
  const [email, setEmail] = useState(person.email ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  return (
    <form className="stack person-page__edit" onSubmit={(event) => {
      event.preventDefault();
      setBusy(true);
      setError(undefined);
      request("PATCH", userPath(person.user_id), { display_name: name.trim(), email: email.trim() })
        .then(() => { refreshPeople(); toast("Saved · recorded in the audit log"); onDone(); }, (e: unknown) => setError(refusal(e, "The details could not be saved.")))
        .finally(() => setBusy(false));
    }}>
      <label className="field">Name<input className="input" required maxLength={160} value={name} onChange={(e) => setName(e.target.value)} /></label>
      <label className="field">Email<input className="input" type="email" maxLength={254} value={email} onChange={(e) => setEmail(e.target.value)} /></label>
      <p className="subtle">Username <span className="mono">{person.username}</span> cannot change.</p>
      {error && <p className="confirm__error" role="alert">{error}</p>}
      <div className="row">
        <button type="submit" className="button button--primary button--small" disabled={busy}>{busy ? "Saving…" : "Save"}</button>
        <button type="button" className="button button--small button--ghost" onClick={onDone}>Cancel</button>
      </div>
    </form>
  );
}
