// One case: its status, severity and assignee, the items it gathers (each
// opens its own panel), notes, and the timeline. Closing needs a
// resolution, a note and an outcome on every alarm, finding and
// vulnerability, so the panel shows what is still missing.
import { type FormEvent, useState } from "react";

import { invalidate, request, useResource } from "../api/client";
import type { CaseDetail, CaseItem, CaseUser } from "../api/types";
import { nav } from "../app/nav";
import { useSession } from "../app/session";
import { useProvideTitle } from "../app/titles";
import { CaseStatusBadge } from "../views/Cases";
import { Ago, ErrorBox, Loading, ObjectLink, SeverityBadge } from "../ui/bits";
import { when } from "../ui/format";
import { Icon } from "../ui/Icon";
import { Confirm, PanelHeader, Section } from "../ui/panel";
import { toast } from "../ui/toast";
import {
  CASE_KINDS, type CaseFields, type CaseKind, type CloseForm, caseErrorText, caseNumber, blockingItems, closeProblems, endingOf, eventText, isStale,
  itemPanel, kindIcon, kindLabel, localDay, needsOutcome, outcomeChoices, outcomeLabel, outcomeNeedsNote, refHint, refLabel, resolutionLabel, severities, updateBody,
} from "./cases";

/** Runs a change, tells the user why it failed, and reloads when what is on screen is out of date. */
async function attempt(change: () => Promise<unknown>, done?: string): Promise<boolean> {
  try {
    await change();
    invalidate("/api/v1/case");
    if (done) toast(done);
    return true;
  } catch (error) {
    toast(caseErrorText(error), true);
    if (isStale(error)) invalidate("/api/v1/case");
    return false;
  }
}

const casePath = (c: Pick<CaseDetail, "case_id">) => `/api/v1/cases/${encodeURIComponent(c.case_id)}`;

function useAssignees(manage: boolean): CaseUser[] {
  return useResource<{ items: CaseUser[] }>(manage ? "/api/v1/cases/assignees" : null).data?.items ?? [];
}

/** The assignable user who is the signed-in one: by id, else by username. */
function useMe(assignees: CaseUser[]): CaseUser | undefined {
  const principal = useSession().session?.principal;
  return assignees.find((user) => user.user_id === principal?.id || (principal?.username != null && user.username === principal.username));
}

function AssigneeSelect({ value, onChange, assignees }: { value: string; onChange: (id: string) => void; assignees: CaseUser[] }) {
  const me = useMe(assignees);
  return (
    <div className="row row--wrap">
      <select className="select grow" value={value} onChange={(event) => onChange(event.target.value)} aria-label="Assignee">
        <option value="">Unassigned</option>
        {assignees.map((user) => <option key={user.user_id} value={user.user_id}>{user.display_name} ({user.username})</option>)}
        {value !== "" && !assignees.some((user) => user.user_id === value) && <option value={value}>Current assignee</option>}
      </select>
      {me && me.user_id !== value && <button type="button" className="button button--small" onClick={() => onChange(me.user_id)}><Icon name="user" size={14} /> Assign to me</button>}
    </div>
  );
}

export function NewCasePanel() {
  const assignees = useAssignees(true);
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
      .then((created) => { invalidate("/api/v1/case"); toast(`Opened ${caseNumber(created.number)}`); nav.open({ kind: "case", id: created.case_id }, true); },
        (e: unknown) => setError(caseErrorText(e)))
      .finally(() => setBusy(false));
  };
  return (
    <>
      <PanelHeader icon="cases" kind="Case" title="New case" subtitle="Add what belongs to it afterwards, or use Add to case on an alarm, compliance finding, vulnerability, host or software." />
      <form className="panel-body stack" onSubmit={submit}>
        <label className="field">Title<input className="input" required maxLength={120} autoFocus value={title} onChange={(event) => setTitle(event.target.value)} placeholder="e.g. Suspicious shell on web-02" /></label>
        <label className="field">Severity
          <select className="select" value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">Automatic: the highest item, medium without items</option>
            {severities.map((s) => <option key={s} value={s}>{s[0]?.toUpperCase() + s.slice(1)}</option>)}
          </select>
        </label>
        <div className="field">Assignee<AssigneeSelect value={assignee} onChange={setAssignee} assignees={assignees} /></div>
        {error && <p className="confirm__error" role="alert">{error}</p>}
        <div><button className="button button--primary" type="submit" disabled={busy || title.trim() === ""}><Icon name="plus" size={15} /> {busy ? "Opening…" : "Open case"}</button></div>
      </form>
    </>
  );
}

export function CasePanel({ id }: { id: string }) {
  const { can } = useSession();
  const detail = useResource<CaseDetail>(`/api/v1/cases/${encodeURIComponent(id)}`);
  const c = detail.data;
  useProvideTitle({ kind: "case", id }, c ? caseNumber(c.number) : undefined);
  if (detail.error) return <div className="panel-body"><ErrorBox error={detail.error} /></div>;
  if (!c) return <Loading />;
  const manage = can("cases.manage");
  return (
    <>
      <PanelHeader
        icon="cases" kind={`Case · ${caseNumber(c.number)}`} title={c.title}
        subtitle={<span className="subtle">Opened by {c.opened_by.display_name}, <Ago value={c.created_at} /></span>}
        badges={<>
          <CaseStatusBadge status={c.status} resolution={c.resolution} />
          <SeverityBadge severity={c.severity} />
          <span className="badge badge--plain">{c.assignee ? `Assigned to ${c.assignee.display_name}` : "Unassigned"}</span>
          {c.pending_item_count > 0 && c.status !== "closed" && <span className="badge badge--warn badge--plain">{c.pending_item_count} unresolved</span>}
        </>}
      />
      <Details key={`${c.case_id}:${c.version}`} c={c} manage={manage} />
      <div className="panel-body stack">
        <ItemsSection c={c} manage={manage} />
        <Notes c={c} manage={manage} />
        <Timeline c={c} />
      </div>
    </>
  );
}

/** Title, severity, assignee and status. Remounted on each new version, so the form always starts from what is saved. */
function Details({ c, manage }: { c: CaseDetail; manage: boolean }) {
  const assignees = useAssignees(manage);
  const [draft, setDraft] = useState<CaseFields>({ title: c.title, severity: c.severity, assignee: c.assignee?.user_id ?? "" });
  const [closing, setClosing] = useState(false);
  const [busy, setBusy] = useState(false);
  const isClosed = c.status === "closed";
  const dirty = draft.title.trim() !== c.title || draft.severity !== c.severity || draft.assignee !== (c.assignee?.user_id ?? "");
  const ending = isClosed ? { resolution: c.resolution ?? "", note: c.resolution_note ?? "", accepted_until: c.accepted_until ?? null } : undefined;
  const send = async (status: string, withEnding: typeof ending, done: string) => {
    setBusy(true);
    const saved = await attempt(() => request("PUT", casePath(c), updateBody(draft, status, withEnding), { "if-match": `"${c.version}"` }), done);
    setBusy(false);
    return saved;
  };

  return (
    <div className="panel-body stack">
      {c.status === "closed" && (
        <dl className="kv">
          <dt>Resolution</dt><dd>{resolutionLabel[c.resolution ?? ""] ?? c.resolution ?? "—"}</dd>
          {c.resolution_note && <><dt>Note</dt><dd>{c.resolution_note}</dd></>}
          {c.accepted_until && <><dt>Accepted until</dt><dd>{when(c.accepted_until)}; the case reopens then</dd></>}
          {c.closed_at && <><dt>Closed</dt><dd>{when(c.closed_at)}</dd></>}
        </dl>
      )}
      {manage ? (
        <>
          <form className="stack" onSubmit={(event) => { event.preventDefault(); if (dirty && !busy) void send(c.status, ending, "Case saved"); }}>
            <label className="field">Title<input className="input" required maxLength={120} value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} /></label>
            <div className="row row--wrap">
              <label className="field">Severity
                <select className="select" value={draft.severity} onChange={(event) => setDraft({ ...draft, severity: event.target.value })}>
                  {severities.map((s) => <option key={s} value={s}>{s[0]?.toUpperCase() + s.slice(1)}</option>)}
                </select>
              </label>
              <div className="field grow">Assignee<AssigneeSelect value={draft.assignee} onChange={(assignee) => setDraft({ ...draft, assignee })} assignees={assignees} /></div>
            </div>
            <div className="row row--wrap">
              <button type="submit" className="button button--primary button--small" disabled={!dirty || busy || draft.title.trim() === ""}>{busy ? "Saving…" : "Save changes"}</button>
              {dirty && <button type="button" className="button button--small button--ghost" onClick={() => setDraft({ title: c.title, severity: c.severity, assignee: c.assignee?.user_id ?? "" })}>Discard</button>}
            </div>
          </form>
          <div className="row row--wrap" role="group" aria-label="Status">
            {c.status === "open" && <button type="button" className="button button--small" disabled={busy} onClick={() => void send("investigating", undefined, "Investigating")}>Start investigating</button>}
            {c.status === "investigating" && <button type="button" className="button button--small" disabled={busy} onClick={() => void send("open", undefined, "Back to open")}>Back to open</button>}
            {!isClosed && <button type="button" className="button button--small" aria-expanded={closing} onClick={() => setClosing((open) => !open)}>Close case…</button>}
            {isClosed && <button type="button" className="button button--small" disabled={busy} onClick={() => void send("open", undefined, "Case reopened")}>Reopen</button>}
          </div>
          {closing && !isClosed && <CloseCase c={c} busy={busy} onCancel={() => setClosing(false)}
            onClose={(form) => void send("closed", endingOf(form), "Case closed")} />}
        </>
      ) : (
        <dl className="kv">
          <dt>Severity</dt><dd><SeverityBadge severity={c.severity} /></dd>
          <dt>Assignee</dt><dd>{c.assignee?.display_name ?? "Unassigned"}</dd>
          <dt>Updated</dt><dd><Ago value={c.updated_at} /></dd>
        </dl>
      )}
    </div>
  );
}

function CloseCase({ c, busy, onClose, onCancel }: { c: CaseDetail; busy: boolean; onClose: (form: CloseForm) => void; onCancel: () => void }) {
  const [form, setForm] = useState<CloseForm>({ resolution: "", note: "", acceptedUntil: "" });
  const [tomorrow] = useState(() => localDay(new Date(Date.now() + 86_400_000)));
  const problems = closeProblems(form, c.items);
  const blocking = blockingItems(c.items);
  return (
    <div className="confirm" role="group" aria-label="Close this case">
      <p className="confirm__text"><strong>Close {caseNumber(c.number)}</strong>: say how it ended. Its items are freed for other cases.</p>
      <label className="field">Resolution
        <select className="select" value={form.resolution} onChange={(event) => setForm({ ...form, resolution: event.target.value })}>
          <option value="">Choose…</option>
          {Object.entries(resolutionLabel).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </label>
      {form.resolution === "accepted_risk" && (
        <label className="field">Accepted until<input className="input" type="date" min={tomorrow} value={form.acceptedUntil} onChange={(event) => setForm({ ...form, acceptedUntil: event.target.value })} /></label>
      )}
      <label className="field">Note<textarea className="textarea" rows={3} maxLength={4000} value={form.note} onChange={(event) => setForm({ ...form, note: event.target.value })} placeholder="Why it can close (required)" /></label>
      {blocking.length > 0 && (
        <div>
          <p className="confirm__text">Still need an outcome (set it on the item below):</p>
          <ul className="list list--plain">
            {blocking.map((item) => <li key={item.item_id} className="list__row list__row--static"><Icon name={kindIcon[item.kind as CaseKind]} size={14} /><span className="grow truncate">{item.title ?? refLabel(item.kind, item.ref)}</span></li>)}
          </ul>
        </div>
      )}
      <ul className="subtle" aria-live="polite" aria-label="What is missing">{problems.map((problem) => <li key={problem}>{problem}</li>)}</ul>
      <div className="row">
        <button type="button" className="button button--small button--primary" disabled={busy || problems.length > 0} onClick={() => onClose(form)}>{busy ? "Closing…" : "Close case"}</button>
        <button type="button" className="button button--small button--ghost" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}

function OutcomeBadge({ item }: { item: CaseItem }) {
  if (!item.outcome) return null;
  const stale = item.outcome === "resolved" && !item.evidence_gone;
  return (
    <>
      <span className={`badge badge--plain ${item.outcome === "resolved" ? "badge--ok" : item.outcome === "accepted_risk" ? "badge--info" : ""}`}>{outcomeLabel[item.outcome] ?? item.outcome}</span>
      {stale && <span className="badge badge--bad badge--plain" title="The evidence is back, so this item blocks closing until it has another outcome">Evidence is back</span>}
    </>
  );
}

function OutcomeControl({ c, item, label }: { c: CaseDetail; item: CaseItem; label: string }) {
  const [outcome, setOutcome] = useState(item.outcome ?? "");
  const [note, setNote] = useState(item.outcome_note ?? "");
  const [busy, setBusy] = useState(false);
  const changed = outcome !== (item.outcome ?? "") || (outcome !== "" && note.trim() !== (item.outcome_note ?? ""));
  const save = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    await attempt(() => request("PUT", `${casePath(c)}/items/${encodeURIComponent(item.item_id)}/outcome`, outcome === "" ? { outcome: null } : { outcome, note: note.trim() || null }), outcome === "" ? "Outcome cleared" : "Outcome saved");
    setBusy(false);
  };
  return (
    <form className="row row--wrap grow" onSubmit={(event) => void save(event)}>
      <select className="select select--small" value={outcome} aria-label={`Outcome for ${label}`} onChange={(event) => setOutcome(event.target.value)}>
        <option value="">No outcome</option>
        {outcomeChoices(item).map((choice) => (
          <option key={choice.value} value={choice.value} disabled={choice.disabled && choice.value !== item.outcome} title={choice.hint}>
            {choice.label}{choice.disabled ? " (evidence still there)" : ""}
          </option>
        ))}
      </select>
      {outcome !== "" && (
        <input className="input grow" value={note} onChange={(event) => setNote(event.target.value)} required={outcomeNeedsNote(outcome)} maxLength={4000}
          placeholder={outcomeNeedsNote(outcome) ? "Why (required)" : "Note (optional)"} aria-label={`Note for ${label}`} />
      )}
      <button type="submit" className="button button--small" disabled={busy || !changed}>{busy ? "Saving…" : outcome === "" ? "Clear" : "Save outcome"}</button>
    </form>
  );
}

function ItemRow({ c, item, manage }: { c: CaseDetail; item: CaseItem; manage: boolean }) {
  const kind = item.kind as CaseKind;
  const panel = itemPanel(item.kind, item.ref);
  const label = item.title ?? refLabel(item.kind, item.ref);
  const editable = manage && c.status !== "closed";
  return (
    <li className="case-item">
      <div className="case-item__main">
        <Icon name={kindIcon[kind] ?? "layers"} size={16} />
        <span className="case-item__title grow">{panel ? <ObjectLink to={panel}>{label}</ObjectLink> : label}</span>
        {item.severity && <SeverityBadge severity={item.severity} />}
      </div>
      <div className="case-item__meta">
        <span>{kindLabel[kind] ?? item.kind}</span>
        {item.hostname && kind !== "host" && <span>on {item.hostname}</span>}
        <OutcomeBadge item={item} />
        {needsOutcome(item) && !item.outcome && item.evidence_gone && <span className="badge badge--ok badge--plain" title="The evidence is gone, so it can be marked resolved">Evidence gone</span>}
        {needsOutcome(item) && !item.outcome && !item.evidence_gone && c.status !== "closed" && <span className="badge badge--warn badge--plain">Needs an outcome</span>}
      </div>
      {item.outcome_note && <p className="case-item__note">{item.outcome_note}</p>}
      {editable && (
        <div className="case-item__controls row row--wrap">
          {needsOutcome(item) && <OutcomeControl key={`${item.outcome}:${item.outcome_note}:${item.evidence_gone}`} c={c} item={item} label={label} />}
          <Confirm label={`Remove ${label} from this case? The timeline keeps that it was here.`}
            onConfirm={async () => {
              try {
                await request("DELETE", `${casePath(c)}/items/${encodeURIComponent(item.item_id)}`);
              } catch (error) {
                if (isStale(error)) invalidate("/api/v1/case");
                throw new Error(caseErrorText(error), { cause: error });
              }
              invalidate("/api/v1/case");
              toast("Item removed");
            }}>Remove</Confirm>
        </div>
      )}
    </li>
  );
}

function AddItem({ c }: { c: CaseDetail }) {
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<CaseKind>("host");
  const [ref, setRef] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  if (!open) return <button type="button" className="button button--small" onClick={() => setOpen(true)}><Icon name="plus" size={14} /> Add item</button>;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(undefined);
    request("POST", `${casePath(c)}/items`, { kind, ref: ref.trim() })
      .then(() => { invalidate("/api/v1/case"); toast("Item added"); setRef(""); setOpen(false); },
        (e: unknown) => { setError(caseErrorText(e)); if (isStale(e)) invalidate("/api/v1/case"); })
      .finally(() => setBusy(false));
  };
  return (
    <form className="confirm" onSubmit={submit} aria-label="Add an item">
      <p className="confirm__text">Paste the item's id. Each page's <strong>Add to case</strong> button does this for you.</p>
      <label className="field">Kind
        <select className="select" value={kind} onChange={(event) => setKind(event.target.value as CaseKind)}>
          {CASE_KINDS.map((k) => <option key={k} value={k}>{kindLabel[k]}</option>)}
        </select>
      </label>
      <label className="field">Id<input className="input mono" required autoFocus autoComplete="off" spellCheck={false} value={ref} onChange={(event) => setRef(event.target.value)} placeholder={refHint[kind]} /></label>
      {error && <p className="confirm__error" role="alert">{error}</p>}
      <div className="row">
        <button type="submit" className="button button--small button--primary" disabled={busy || ref.trim() === ""}>{busy ? "Adding…" : "Add"}</button>
        <button type="button" className="button button--small button--ghost" onClick={() => { setOpen(false); setError(undefined); }}>Cancel</button>
      </div>
    </form>
  );
}

function ItemsSection({ c, manage }: { c: CaseDetail; manage: boolean }) {
  return (
    <Section title={`Items (${c.items.length})`}>
      {c.items.length === 0 ? <p className="subtle">No items yet. Hosts, alarms, vulnerabilities, compliance findings and software can all be added.</p> : (
        <ul className="case-items" aria-label="Items">
          {c.items.map((item) => <ItemRow key={item.item_id} c={c} item={item} manage={manage} />)}
        </ul>
      )}
      {manage && c.status !== "closed" && <div><AddItem c={c} /></div>}
    </Section>
  );
}

function Notes({ c, manage }: { c: CaseDetail; manage: boolean }) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  if (!manage) return null;
  return (
    <Section title="Add a note">
      <form className="stack" onSubmit={(event) => {
        event.preventDefault();
        if (busy || text.trim() === "") return;
        setBusy(true);
        void attempt(() => request("POST", `${casePath(c)}/notes`, { body: text.trim() }), "Note added")
          .then((added) => { if (added) setText(""); }).finally(() => setBusy(false));
      }}>
        <textarea className="textarea" rows={3} maxLength={4000} value={text} onChange={(event) => setText(event.target.value)} aria-label="Note"
          placeholder="What you found or decided. Plain text, visible to everyone who can see this case." />
        <div><button type="submit" className="button button--small button--primary" disabled={busy || text.trim() === ""}>{busy ? "Adding…" : "Add note"}</button></div>
      </form>
    </Section>
  );
}

function Timeline({ c }: { c: CaseDetail }) {
  const titles = new Map(c.items.map((item) => [item.item_id, item.title ?? refLabel(item.kind, item.ref)]));
  const events = [...c.events].reverse();
  return (
    <Section title={`Timeline (${events.length})`}>
      <ol className="timeline" aria-label="Timeline, newest first">
        {events.map((event) => (
          <li key={event.event_id} className={`timeline__item${event.kind === "note" ? " timeline__item--note" : ""}`}>
            <div className="timeline__head">
              <strong>{event.actor?.display_name ?? "The platform"}</strong> {eventText(event, (itemId) => titles.get(itemId))}
              <span className="subtle"> · <Ago value={event.at} /></span>
            </div>
            {event.body && <p className="timeline__body">{event.body}</p>}
          </li>
        ))}
      </ol>
    </Section>
  );
}
