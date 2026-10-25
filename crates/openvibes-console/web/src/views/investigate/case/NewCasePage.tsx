// /cases/new (roles 5d ruling 11): the new-case form the old `case:new`
// panel showed, as a page. Also the assignee hooks and severity options the
// case page's Assign and Edit reuse.
import { type FormEvent, useState } from "react";

import { invalidate, request, useResource } from "../../../api/client";
import type { CaseDetail, CaseUser } from "../../../api/types";
import { casePath } from "../../../app/location";
import { nav, viewLink } from "../../../app/nav";
import { useSession } from "../../../app/session";
import { caseErrorText, caseNumber, severities } from "../../../panels/cases/cases";
import { SelectField } from "../../../ui/Field";
import { Icon } from "../../../ui/Icon";
import { Select } from "../../../ui/Select";
import { toast } from "../../../ui/toast";

/** The people a case can be assigned to (with `cases.assign`). */
export function useAssignees(assign: boolean): CaseUser[] {
  return useResource<{ items: CaseUser[] }>(assign ? "/api/v1/cases/assignees" : null).data?.items ?? [];
}

/** The assignable user who is the signed-in one: by id, else by username. */
export function useMe(assignees: CaseUser[]): CaseUser | undefined {
  const principal = useSession().session?.principal;
  return assignees.find((user) => user.user_id === principal?.id || (principal?.username != null && user.username === principal.username));
}

export const severityOptions = severities.map((s) => ({ value: s, label: s[0]?.toUpperCase() + s.slice(1) }));

function AssigneeSelect({ value, onChange, assignees }: { value: string; onChange: (id: string) => void; assignees: CaseUser[] }) {
  const me = useMe(assignees);
  return (
    <div className="row row--wrap">
      <div className="grow"><Select label="Assignee" value={value} onChange={onChange} unknownLabel={() => "Current assignee"}
        options={[{ value: "", label: "Unassigned" }, ...assignees.map((user) => ({ value: user.user_id, label: `${user.display_name} (${user.username})` }))]} /></div>
      {me && me.user_id !== value && <button type="button" className="button button--small" onClick={() => onChange(me.user_id)}><Icon name="user" size={14} /> Assign to me</button>}
    </div>
  );
}

export function NewCasePage() {
  const assign = useSession().can("cases.assign");
  const assignees = useAssignees(assign);
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("");
  const [assignee, setAssignee] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(undefined);
    request<CaseDetail>("POST", "/api/v1/cases", { title: title.trim(), ...(severity ? { severity } : {}), assignee_user_id: assignee || null })
      .then((created) => { invalidate("/api/v1/case"); toast(`Opened ${caseNumber(created.number)}`); nav.replace(casePath(created.case_id)); },
        (e: unknown) => setError(caseErrorText(e)))
      .finally(() => setBusy(false));
  };
  return (
    <div className="view">
      <div className="view-pad" style={{ paddingTop: 20 }}><a className="subtle" {...viewLink("/cases")}>Cases</a></div>
      <div className="view-pad stack" style={{ maxWidth: 640, paddingBottom: 40 }}>
        <h1>New case</h1>
        <p className="subtle">Add what belongs to it afterwards, or use Add to case on an alarm, compliance finding, vulnerability, host or software.</p>
        <form className="stack" onSubmit={submit}>
          <label className="field">Title<input className="input" required maxLength={120} autoFocus value={title} onChange={(event) => setTitle(event.target.value)} placeholder="e.g. Suspicious shell on web-02" /></label>
          <SelectField label="Severity">
            <Select label="Severity" value={severity} onChange={setSeverity}
              options={[{ value: "", label: "Automatic: the highest item, medium without items" }, ...severityOptions]} />
          </SelectField>
          {assign && <div className="field">Assignee<AssigneeSelect value={assignee} onChange={setAssignee} assignees={assignees} /></div>}
          {error && <p className="confirm__error" role="alert">{error}</p>}
          <div><button className="button button--primary" type="submit" disabled={busy || title.trim() === ""}><Icon name="plus" size={15} /> {busy ? "Opening…" : "Open case"}</button></div>
        </form>
      </div>
    </div>
  );
}
