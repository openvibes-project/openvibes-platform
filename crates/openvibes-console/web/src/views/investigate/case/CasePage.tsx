// A case's page (approved screen 32; roles spec §10.3, step 5d rulings
// 11-15), at /cases/{id}, replacing the case panel: a header with Edit,
// Assign ▾, Close case… and ⋯ (Export, Copy link, Reopen), four tiles (items,
// need an outcome, hosts, open for) and the cards. The summary route feeds
// the header, tiles and left column; the full detail the items and timeline.
// Ask about this is left out: the assistant takes no case reference (ruling
// 14). Old links (`?open=case:ID`, `nav.open({kind: "case"})`) come here.
import { useState } from "react";

import { request, useResource } from "../../../api/client";
import type { CaseDetail, CasePageSummary } from "../../../api/types";
import { viewLink } from "../../../app/nav";
import { useProvideTitle } from "../../../app/titles";
import { CaseStatusBadge } from "../../../panels/cases/CaseBadge";
import { blockingItems, caseNumber, closeProblems, eventText, kindLabel, type CaseKind, outcomeLabel, refLabel, updateBody } from "../../../panels/cases/cases";
import { Ago, Empty, ErrorBox, Loading, SeverityBadge } from "../../../ui/bits";
import { downloadCsv } from "../../../ui/csv";
import { DetailPage } from "../../../ui/detail/DetailPage";
import { FactTile } from "../../../ui/detail/FactTile";
import { Tile } from "../../../ui/detail/Tile";
import { date, plural } from "../../../ui/format";
import { Icon } from "../../../ui/Icon";
import { MenuButton } from "../../../ui/Menu";
import { Select } from "../../../ui/Select";
import { SelectField } from "../../../ui/Field";
import { DialogHead, Modal } from "../../admin/people/NewPersonDialog";
import { copyLink } from "../alarm/AlarmPage";
import { DetailsCard, HostsCard, NotesCard, PeopleCard, attempt, caseApi } from "./CaseCards";
import { ItemsCard } from "./CaseItems";
import { severityOptions, useAssignees, useMe } from "./NewCasePage";

type Page = CasePageSummary;

export function NoSuchCase() {
  return <div className="view"><Empty icon="cases" title="No such case">You can't see it, or the link is wrong. <a {...viewLink("/cases")}>Back to the list</a></Empty></div>;
}

export function CasePage({ id }: { id: string }) {
  const summary = useResource<Page>(`${caseApi(id)}/summary`);
  const detail = useResource<CaseDetail>(caseApi(id));
  useProvideTitle({ kind: "case", id }, summary.data ? caseNumber(summary.data.header.number) : undefined);
  const error = summary.error ?? detail.error;
  if (error?.status === 404) return <NoSuchCase />;
  if (error) return <div className="view"><div className="view-pad"><ErrorBox error={error} /></div></div>;
  if (!summary.data || !detail.data) return <div className="view"><Loading /></div>;
  return <CaseView page={summary.data} detail={detail.data} />;
}

/** "3 h", "2 days": how long a case has been (or was) open. */
export function openFor(seconds: number): string {
  const steps: [number, string][] = [[86_400, "day"], [3600, "h"], [60, "min"]];
  for (const [size, unit] of steps) if (seconds >= size) { const n = Math.floor(seconds / size); return unit === "day" ? plural(n, "day") : `${n} ${unit}`; }
  return "under a minute";
}

/** The visible items that still block closing: without an outcome, or Fixed with the evidence back. */
export const visibleBlocking = (page: Page, detail: CaseDetail) => Math.max(page.tiles.need_outcome, blockingItems(detail.items).length);

/** What still blocks closing, in words (ruling 2): the visible items without an outcome (or Fixed with the evidence back),
 * else, when close's own rule still refuses, an item the viewer can't see; never named. */
export function closeBlocker(page: Page, detail: CaseDetail): string | null {
  if (page.header.status === "closed") return null;
  const visible = visibleBlocking(page, detail);
  if (visible > 0) return `${plural(visible, "item")} still ${visible === 1 ? "needs" : "need"} an outcome`;
  return page.tiles.ready ? null : "An item you can't see still needs an outcome";
}

/** Export (ruling 15): the items and the timeline, one row each. */
export function exportRows(detail: CaseDetail): unknown[][] {
  const titles = new Map(detail.items.map((i) => [i.item_id, i.title ?? refLabel(i.kind, i.ref)]));
  return [
    ["case", "section", "at", "who", "kind", "what", "host", "severity", "outcome", "note"],
    ...detail.items.map((i) => [caseNumber(detail.number), "item", i.added_at, i.added_by.display_name, kindLabel[i.kind as CaseKind] ?? i.kind,
      i.title ?? refLabel(i.kind, i.ref), i.hostname ?? "", i.severity ?? "", i.outcome ? outcomeLabel[i.outcome] ?? i.outcome : "", i.outcome_note ?? ""]),
    ...detail.events.map((e) => [caseNumber(detail.number), "timeline", e.at, e.actor?.display_name ?? "The platform", e.kind,
      eventText(e, (itemId) => titles.get(itemId)), "", "", "", e.body ?? ""]),
  ];
}

export function CaseView({ page, detail }: { page: Page; detail: CaseDetail }) {
  const { header, tiles, details } = page;
  const blocker = closeBlocker(page, detail);
  const visible = visibleBlocking(page, detail);
  const need = header.status === "closed" ? "Closed" : tiles.ready ? "Ready to close" : blocker ?? "";
  return (
    <DetailPage
      crumb={<a {...viewLink("/cases")}>Cases</a>}
      icon={<Icon name="cases" size={20} />}
      title={<><span className="mono">{caseNumber(header.number)}</span> {header.title}</>}
      status={<><SeverityBadge severity={header.severity} /><CaseStatusBadge status={header.status} resolution={details.resolution} /></>}
      facts={[
        <>Opened by {header.opened_by.display_name} <Ago value={header.created_at} /></>,
        header.assignee ? `assigned to ${header.assignee.display_name}` : "unassigned",
        `${plural(tiles.items, "item")} on ${plural(tiles.hosts, "host")}`,
        <>updated <Ago value={details.updated_at} /></>,
      ]}
      actions={<CaseActions page={page} detail={detail} />}
      tiles={[
        <Tile key="items" label="Items" value={tiles.items} to="#items" />,
        <div key="need" className="card detail-tile" role="group" aria-label={`Need an outcome: ${visible}, ${need}`}>
          <span className={`detail-tile__value num${tiles.ready ? " ok-text" : visible > 0 ? " warn-text" : ""}`} aria-hidden="true">{visible.toLocaleString()}</span>
          <span className="detail-tile__label subtle" aria-hidden="true">Need an outcome</span>
          {need && <span className="detail-tile__note subtle" aria-hidden="true">{need}</span>}
        </div>,
        <Tile key="hosts" label="Hosts" value={tiles.hosts} to="#hosts" />,
        <FactTile key="open" label={details.closed_at ? `Was open, until ${date(details.closed_at)}` : `Open for, since ${date(header.created_at)}`} value={openFor(tiles.open_for_seconds)} />,
      ]}
      left={<>
        <DetailsCard page={page} detail={detail} />
        <HostsCard page={page} />
        <PeopleCard page={page} />
      </>}
      right={<>
        <ItemsCard detail={detail} editable={page.can.outcome} />
        <NotesCard detail={detail} canNote={page.can.note} />
      </>}
    />
  );
}

/** Sends the case's fields (the API replaces all of them) with `status`; a case that stays closed restates its closing note. */
function useSend(detail: CaseDetail) {
  const [busy, setBusy] = useState(false);
  const send = async (change: Partial<{ title: string; severity: string; assignee: string }>, status: string, done: string, closingNote?: string) => {
    const fields = { title: detail.title, severity: detail.severity, assignee: detail.assignee?.user_id ?? "", ...change };
    const note = closingNote ?? (status === "closed" ? detail.resolution_note ?? "" : undefined);
    setBusy(true);
    const ok = await attempt(() => request("PUT", caseApi(detail.case_id), updateBody(fields, status, note), { "if-match": `"${detail.version}"` }), done);
    setBusy(false);
    return ok;
  };
  return { busy, send };
}

/** ⋯: one-click status (with `can.edit`), Export (`can.export`), Copy link, Reopen (`can.reopen`). */
export function moreItems(page: Page) {
  const { can, header } = page;
  return [
    ...(can.edit && header.status === "open" ? [{ value: "investigating", label: "Start investigating" }] : []),
    ...(can.edit && header.status === "investigating" ? [{ value: "open", label: "Back to open" }] : []),
    ...(can.export ? [{ value: "export", label: "Export", description: "Its items and timeline, as CSV" }] : []),
    { value: "copy", label: "Copy link" },
    ...(can.reopen ? [{ value: "reopen", label: "Reopen" }] : []),
  ];
}

/** Edit, Assign ▾, Close case… and ⋯, each with its `can` flag. */
function CaseActions({ page, detail }: { page: Page; detail: CaseDetail }) {
  const { can, header } = page;
  const [open, setOpen] = useState<"edit" | "close" | null>(null);
  const { send } = useSend(detail);
  const more = moreItems(page);
  const pick = (value: string) => {
    if (value === "copy") void copyLink();
    else if (value === "reopen") void send({}, "open", "Case reopened");
    else if (value === "investigating") void send({}, "investigating", "Investigating");
    else if (value === "open") void send({}, "open", "Back to open");
    else downloadCsv(`openvibes-${caseNumber(header.number)}.csv`, exportRows(detail));
  };
  return (
    <>
      {can.edit && <button type="button" className="button" onClick={() => setOpen("edit")}><Icon name="pencil" size={14} /> Edit</button>}
      {can.assign && <AssignMenu detail={detail} onPick={(assignee, done) => void send({ assignee }, detail.status, done)} />}
      {can.close && <button type="button" className="button button--primary" onClick={() => setOpen("close")}>Close case…</button>}
      <MenuButton label="More actions" icon="more" compact items={more} onPick={pick} />
      {open === "edit" && <EditDialog page={page} detail={detail} onClose={() => setOpen(null)} />}
      {open === "close" && <CloseDialog page={page} detail={detail} onClose={() => setOpen(null)} />}
    </>
  );
}

function AssignMenu({ detail, onPick }: { detail: CaseDetail; onPick: (assignee: string, done: string) => void }) {
  const assignees = useAssignees(true);
  const me = useMe(assignees);
  const current = detail.assignee?.user_id ?? "";
  const items = [
    ...(me && me.user_id !== current ? [{ value: me.user_id, label: "Assign to me" }] : []),
    ...(current ? [{ value: "", label: "Unassigned" }] : []),
    ...assignees.filter((u) => u.user_id !== current && u.user_id !== me?.user_id).map((u) => ({ value: u.user_id, label: u.display_name, description: u.username })),
  ];
  return <MenuButton label="Assign" items={items} disabled={items.length === 0}
    onPick={(value) => onPick(value, value ? `Assigned to ${assignees.find((u) => u.user_id === value)?.display_name ?? "them"}` : "Unassigned")} />;
}

const STATUS_OPTIONS = [{ value: "open", label: "Open" }, { value: "investigating", label: "Investigating" }];

function EditDialog({ page, detail, onClose }: { page: Page; detail: CaseDetail; onClose: () => void }) {
  const [title, setTitle] = useState(detail.title);
  const [severity, setSeverity] = useState(detail.severity);
  const [status, setStatus] = useState(detail.status);
  const { busy, send } = useSend(detail);
  const closed = detail.status === "closed";
  const name = caseNumber(page.header.number);
  return (
    <Modal label={`Edit ${name}`} onClose={onClose}>
      <form className="bulk-dialog stack" onSubmit={(event) => {
        event.preventDefault();
        void send({ title: title.trim(), severity }, status, "Case saved").then((ok) => { if (ok) onClose(); });
      }}>
        <DialogHead title={`Edit ${name}`} onClose={onClose} />
        <label className="field">Title<input className="input" required maxLength={120} value={title} onChange={(event) => setTitle(event.target.value)} /></label>
        <SelectField label="Severity"><Select label="Severity" value={severity} onChange={setSeverity} options={severityOptions} /></SelectField>
        {!closed && <SelectField label="Status"><Select label="Status" value={status} onChange={setStatus} options={STATUS_OPTIONS} /></SelectField>}
        <div className="row">
          <button type="submit" className="button button--primary" disabled={busy || title.trim() === ""}>{busy ? "Saving…" : "Save"}</button>
          <button type="button" className="button button--ghost" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Modal>
  );
}

function CloseDialog({ page, detail, onClose }: { page: Page; detail: CaseDetail; onClose: () => void }) {
  const [note, setNote] = useState("");
  const { busy, send } = useSend(detail);
  const blocker = closeBlocker(page, detail);
  const blocking = blockingItems(detail.items);
  const name = caseNumber(page.header.number);
  return (
    <Modal label={`Close ${name}`} onClose={onClose}>
      <form className="bulk-dialog stack" onSubmit={(event) => {
        event.preventDefault();
        if (blocker || note.trim() === "") return;
        void send({}, "closed", "Case closed", note).then((ok) => { if (ok) onClose(); });
      }}>
        <DialogHead title={`Close ${name}`} onClose={onClose} />
        <p>Sum up how it ended. Each item keeps its outcome, and is freed for other cases.</p>
        <label className="field">Closing note<textarea className="textarea" rows={3} maxLength={4000} value={note} onChange={(event) => setNote(event.target.value)} placeholder="A short summary (required)" /></label>
        <ul className="list list--plain" aria-live="polite" aria-label="What is missing">
          {[...closeProblems({ note }, []), ...(blocker ? [`${blocker}. Set one on each item first.`] : [])].map((problem) => (
            <li key={problem} className="row"><Icon name="alert" size={16} className="warn-text" /><span>{problem}</span></li>
          ))}
        </ul>
        {blocking.length > 0 && (
          <ul className="list list--plain" aria-label="Items without an outcome">
            {blocking.map((item) => <li key={item.item_id} className="list__row list__row--static truncate">{item.title ?? refLabel(item.kind, item.ref)}</li>)}
          </ul>
        )}
        <div className="row">
          <button type="submit" className="button button--primary" disabled={busy || blocker !== null || note.trim() === ""}>{busy ? "Closing…" : "Close case"}</button>
          <button type="button" className="button button--ghost" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Modal>
  );
}
