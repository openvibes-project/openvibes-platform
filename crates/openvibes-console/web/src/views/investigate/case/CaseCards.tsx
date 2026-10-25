// The cards of a case's page (approved screen 32): Details, Hosts in this
// case (each host's open problems, linking to the host page and the filtered
// lists) and Who can see it on the left; Notes and timeline (the note box at
// the top, newest first) on the right. The Items card: CaseItems.tsx.
import { useState } from "react";

import { invalidate, request } from "../../../api/client";
import type { CaseDetail, CasePageSummary } from "../../../api/types";
import { viewLink } from "../../../app/nav";
import { CaseStatusBadge } from "../../../panels/cases/CaseBadge";
import { caseErrorText, caseNumber, eventText, isStale, refLabel, resolutionLabel } from "../../../panels/cases/cases";
import { Ago, ObjectLink, SeverityBadge } from "../../../ui/bits";
import { Card } from "../../../ui/detail/DetailPage";
import { plural, when } from "../../../ui/format";
import { toast } from "../../../ui/toast";

type Page = CasePageSummary;

/** The case's API path. */
export const caseApi = (id: string) => `/api/v1/cases/${encodeURIComponent(id)}`;

/** Runs a change, tells the user why it failed, and reloads when what is on screen is out of date. */
export async function attempt(change: () => Promise<unknown>, done?: string): Promise<boolean> {
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

export function DetailsCard({ page, detail }: { page: Page; detail: CaseDetail }) {
  const { header, details: d } = page;
  return (
    <Card title="Details">
      <dl className="kv">
        <dt>Case</dt><dd className="mono">{caseNumber(header.number)}</dd>
        <dt>Title</dt><dd>{d.title}</dd>
        <dt>Severity</dt><dd><SeverityBadge severity={d.severity} /></dd>
        <dt>Status</dt><dd><CaseStatusBadge status={d.status} resolution={d.resolution} /></dd>
        <dt>Assignee</dt><dd>{header.assignee?.display_name ?? <span className="subtle">Unassigned</span>}</dd>
        <dt>Opened</dt><dd>{when(d.created_at)} by {d.opened_by.display_name}</dd>
        <dt>Updated</dt><dd><Ago value={d.updated_at} /></dd>
        {d.closed_at && <><dt>Closed</dt><dd>{when(d.closed_at)}</dd></>}
        {d.resolution && <><dt>How it ended</dt><dd>{resolutionLabel[d.resolution] ?? d.resolution}</dd></>}
        {detail.accepted_until && <><dt>Accepted until</dt><dd>{when(detail.accepted_until)}; the case reopens then</dd></>}
        {d.resolution_note && <><dt>Closing note</dt><dd style={{ whiteSpace: "pre-wrap" }}>{d.resolution_note}</dd></>}
      </dl>
    </Card>
  );
}

type Host = Page["hosts"][number];

/** A host's open problems, each a link to its list filtered to the host; unknown ones are left out. */
export function problemLinks(h: Host): { label: string; tone: string; view: string; params: Record<string, string> }[] {
  const p = h.problems;
  return [
    ...(p.alarms ? [{ label: plural(p.alarms, "open alarm"), tone: "bad", view: "/alarms", params: { host: h.agent_id } }] : []),
    ...(p.critical_vulns ? [{ label: `${p.critical_vulns.toLocaleString()} critical`, tone: "critical", view: "/vulnerabilities", params: { host: h.agent_id, severity: "critical" } }] : []),
    ...(p.failing_checks ? [{ label: plural(p.failing_checks, "failing check"), tone: "warn", view: "/compliance", params: { host: h.agent_id } }] : []),
  ];
}

export function HostsCard({ page }: { page: Page }) {
  return (
    <Card id="hosts" title={<>Hosts in this case <span className="subtle num">{page.tiles.hosts.toLocaleString()}</span></>}>
      {page.hosts.length === 0 ? <p className="subtle">No item of this case is on a host you can see.</p> : (
        <ul className="list list--plain" aria-label="Hosts in this case">
          {page.hosts.map((h) => {
            const links = problemLinks(h);
            return (
              <li key={h.agent_id} className="list__row list__row--static row row--between row--wrap">
                <span className="stack" style={{ gap: 2 }}>
                  <ObjectLink to={{ kind: "agent", id: h.agent_id }} className="object-link mono">{h.hostname ?? h.agent_id}</ObjectLink>
                  {h.os.distribution && <span className="subtle">{h.os.distribution}</span>}
                </span>
                <span className="row row--wrap">
                  {links.map((l) => <a key={l.view} className={`badge badge--${l.tone}`} {...viewLink(l.view, l.params)}>{l.label}</a>)}
                  {h.problems.compliance_stale && <span className="subtle">No compliance report in the last day</span>}
                  {links.length === 0 && !h.problems.compliance_stale && <span className="subtle">No open problems</span>}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

/** "N people", or "at least N people" when the count may leave out people who see it through hosts out of reach. */
export const peopleCount = (people: Page["people"]) => `${people.complete ? "" : "at least "}${plural(people.total, "person", "people")}`;

export function PeopleCard({ page }: { page: Page }) {
  const { people } = page;
  const names = people.names ?? [];
  const more = people.total - names.length;
  return (
    <Card title="Who can see it">
      <div className="stack">
        <p><strong>{peopleCount(people)}</strong> can see it: whoever opened it or is assigned to it, and everyone who reads cases on one of its hosts.</p>
        {names.length > 0 && (
          <ul className="list list--plain" aria-label="People who can see it">
            {names.map((u) => <li key={u.user_id} className="list__row list__row--static">{u.display_name} <span className="subtle">({u.username})</span></li>)}
          </ul>
        )}
        {names.length > 0 && more > 0 && <p className="subtle">and {more.toLocaleString()} more</p>}
      </div>
    </Card>
  );
}

/** Notes and timeline: the note box at the top (with `can.note`), then every entry, newest first. */
export function NotesCard({ detail, canNote }: { detail: CaseDetail; canNote: boolean }) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const titles = new Map(detail.items.map((item) => [item.item_id, item.title ?? refLabel(item.kind, item.ref)]));
  const events = [...detail.events].reverse();
  return (
    <Card title="Notes and timeline">
      <div className="stack">
        {canNote && (
          <form className="stack" onSubmit={(event) => {
            event.preventDefault();
            if (busy || text.trim() === "") return;
            setBusy(true);
            void attempt(() => request("POST", `${caseApi(detail.case_id)}/notes`, { body: text.trim() }), "Note added")
              .then((added) => { if (added) setText(""); }).finally(() => setBusy(false));
          }}>
            <textarea className="textarea" rows={2} maxLength={4000} value={text} onChange={(event) => setText(event.target.value)} aria-label="Note"
              placeholder="What you found or decided. Everyone who can see this case can read it." />
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <button type="submit" className="button button--small button--primary" disabled={busy || text.trim() === ""}>{busy ? "Adding…" : "Add note"}</button>
            </div>
          </form>
        )}
        <ol className="timeline" aria-label={`Timeline, newest first (${events.length})`}>
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
      </div>
    </Card>
  );
}
