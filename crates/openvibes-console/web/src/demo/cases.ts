// The demo's cases: the real API's routes, JSON shapes, status codes and
// rules (crates/openvibes-console/src/cases/, platform-store console_cases/;
// docs/components/console-cases.md), kept in memory and, in a browser, in
// localStorage like the dashboards. What an item is (its title, severity,
// whether its evidence is gone) comes from the rest of the demo through
// `CaseWorld`, so alarms, findings and vulnerabilities stay the single truth.
// The checks that need no state are in caseRules.ts, the lazy reopen in
// caseReopen.ts, the Cases list page (GET /case-list) in routes/caseList.ts.
import type { CaseDetail, CaseEvent, CaseItem, CaseSummary, CaseUser } from "../api/types";
import { EXCLUSIVE_KINDS, type CaseKind, isCaseKind } from "../panels/cases/cases";
import { reopenDue } from "./caseReopen";
import {
  type Body, type Result, badBody, closed, closingError, defaultSeverity, invalid, itemNotFound, notFound, outcomeError,
  problem, refOk, removedField, severityOk, titleOk, noteOk,
} from "./caseRules";

export { caseSeverityOf } from "./caseRules";

export type ItemFacts = { agent_id: string | null; title: string | null; severity: string | null; gone: boolean };
export type CaseWorld = {
  me: CaseUser;
  /** Everyone a case can name (opener, assignee, author). */
  people: readonly CaseUser[];
  /** User ids that hold `cases.read`, so can be assigned. */
  assignable: readonly string[];
  /** Whether the viewer's scope contains the host. */
  canSee: (agentId: string) => boolean;
  /** Whether that scope is every host (a case with no host-bound item is then visible too). */
  global: boolean;
  hostname: (agentId: string) => string | null;
  /** The object as it is now, whoever looks (the store checks the viewer's reach), or undefined when it does not exist. */
  facts: (kind: CaseKind, ref: string) => ItemFacts | undefined;
  audit: (action: string, target: string) => void;
};

export type StoredCase = {
  case_id: string; number: number; title: string; status: string; resolution: string | null; resolution_note: string | null;
  accepted_until: string | null; severity: string; assignee_user_id: string | null; opened_by_user_id: string;
  created_at: string; updated_at: string; closed_at: string | null; version: number;
};
export type StoredItem = {
  item_id: string; case_id: string; kind: CaseKind; ref: string; agent_id: string | null; active: boolean;
  outcome: string | null; outcome_note: string | null; outcome_until: string | null; added_by_user_id: string; added_at: string;
};
type StoredEvent = { event_id: number; case_id: string; at: string; actor_user_id: string | null; kind: string; body: string | null; detail: Body };
// v 3: per-item outcome_until and the five outcomes (step 5d); older stores reseed.
export type CaseState = { v: 3; next_number: number; next_event: number; cases: StoredCase[]; items: StoredItem[]; events: StoredEvent[] };
type CasePersistence = { load: () => unknown; save: (state: CaseState) => void };
/** One case the viewer sees, as the Cases list reads it. */
export type ListedCase = { c: StoredCase; visible: StoredItem[]; ready: boolean; note: { text: string; at: string } | null; opener: CaseUser; assignee: CaseUser | null };

const MAX_ITEMS = 500;
const MAX_ON_CREATE = 50;
const MAX_EVENTS = 2000;
/** A blank note is as good as none; a note is stored without the spaces around it (request.rs blank_is_absent). */
const trimmed = (value: string | null) => (value === null || value.trim() === "" ? null : value.trim());

export function createCaseStore(world: CaseWorld, seed: () => CaseState, persistence?: CasePersistence) {
  const saved = persistence?.load() as Partial<CaseState> | undefined;
  const state: CaseState = saved?.v === 3 && Array.isArray(saved.cases) && Array.isArray(saved.items) && Array.isArray(saved.events)
    && typeof saved.next_number === "number" && typeof saved.next_event === "number" ? (saved as CaseState) : seed();
  const persist = () => persistence?.save(state);
  const now = () => new Date().toISOString();
  const me = world.me.user_id;
  const person = (id: string): CaseUser => world.people.find((p) => p.user_id === id) ?? { user_id: id, username: id, display_name: id };

  /** Software is seen inside a case the viewer sees; the rest through its host. */
  const seesItem = (item: StoredItem) => item.agent_id === null || world.canSee(item.agent_id);
  const itemsOf = (c: StoredCase) => state.items.filter((i) => i.case_id === c.case_id);
  /** Opener, assignee, a host-bound item in scope, or (every host in scope) no host-bound item at all: hosts decide. */
  const sees = (c: StoredCase) => c.opened_by_user_id === me || c.assignee_user_id === me
    || itemsOf(c).some((i) => i.agent_id !== null && world.canSee(i.agent_id))
    || (world.global && !itemsOf(c).some((i) => i.agent_id !== null));
  const find = (id: string) => { const c = state.cases.find((candidate) => candidate.case_id === id); return c && sees(c) ? c : undefined; };

  const factsOf = (item: StoredItem) => world.facts(item.kind, item.ref);
  const exclusive = (item: StoredItem) => EXCLUSIVE_KINDS.has(item.kind);
  // An alarm, finding or vulnerability that no longer exists has no evidence left.
  const gone = (item: StoredItem) => factsOf(item)?.gone ?? true;
  /** Stands in the way of closing: no outcome, or resolved while the evidence is back (visibility.rs blocking_item). */
  const blocking = (i: StoredItem) => exclusive(i) && (i.outcome === null || (i.outcome === "resolved" && !gone(i)));
  const itemView = (item: StoredItem): CaseItem => {
    const facts = factsOf(item);
    return {
      item_id: item.item_id, kind: item.kind, ref: item.ref, agent_id: item.agent_id,
      hostname: item.agent_id === null ? null : world.hostname(item.agent_id), active: item.active,
      outcome: item.outcome, outcome_note: item.outcome_note, outcome_until: item.outcome_until, added_by: person(item.added_by_user_id), added_at: item.added_at,
      title: facts?.title ?? null, severity: facts?.severity ?? null, evidence_gone: exclusive(item) ? gone(item) : false,
    };
  };
  const summary = (c: StoredCase): CaseSummary => {
    const visible = itemsOf(c).filter(seesItem);
    return {
      case_id: c.case_id, number: c.number, title: c.title, status: c.status, resolution: c.resolution, accepted_until: c.accepted_until,
      severity: c.severity, assignee: c.assignee_user_id === null ? null : person(c.assignee_user_id), opened_by: person(c.opened_by_user_id),
      created_at: c.created_at, updated_at: c.updated_at, closed_at: c.closed_at, version: c.version,
      item_count: visible.length, pending_item_count: visible.filter((i) => exclusive(i) && i.outcome === null).length,
    };
  };
  const eventView = (e: StoredEvent): CaseEvent =>
    ({ event_id: e.event_id, at: e.at, actor: e.actor_user_id === null ? null : person(e.actor_user_id), kind: e.kind, body: e.body, detail: e.detail as CaseEvent["detail"] });
  const eventVisible = (e: StoredEvent) => typeof e.detail.item_agent_id !== "string" || world.canSee(e.detail.item_agent_id);
  const detail = (c: StoredCase): CaseDetail => ({
    ...summary(c), resolution_note: c.resolution_note,
    items: itemsOf(c).filter(seesItem).sort((a, b) => a.added_at.localeCompare(b.added_at)).map(itemView),
    events: state.events.filter((e) => e.case_id === c.case_id && eventVisible(e)).sort((a, b) => a.event_id - b.event_id).map(eventView),
  });
  const ok = (status: number, c: StoredCase): Result => ({ status, body: detail(c), etag: `"${c.version}"` });

  const push = (c: StoredCase, kind: string, body: string | null, extra: Body = {}, actor: string | null = me, at = now()) => {
    state.events.push({ event_id: state.next_event, case_id: c.case_id, at, actor_user_id: actor, kind, body, detail: extra });
    state.next_event += 1;
  };
  const touch = (c: StoredCase, at = now()) => { if (c.updated_at < at) c.updated_at = at; };
  const itemDetail = (item: StoredItem) => ({ item_id: item.item_id, item_kind: item.kind, item_ref: item.ref, item_agent_id: item.agent_id });

  /** The other open case that holds this exclusive item, if any. */
  const holder = (item: { kind: CaseKind; ref: string }, except: string) =>
    EXCLUSIVE_KINDS.has(item.kind) ? state.items.find((i) => i.kind === item.kind && i.ref === item.ref && i.active && i.case_id !== except) : undefined;
  /** 409 naming the other case only when the caller can see both it and the item. */
  const inCase = (other: StoredItem): Result => {
    const owner = state.cases.find((c) => c.case_id === other.case_id);
    return problem(409, "item_in_case", "The item is already in another open case", owner && sees(owner) && seesItem(other) ? { case_number: owner.number } : {});
  };

  /** Checks the item exists for the caller; a missing and a hidden one answer alike. */
  function resolve(kind: unknown, ref: unknown): Result | { kind: CaseKind; ref: string; facts: ItemFacts } {
    if (typeof kind !== "string" || !isCaseKind(kind)) return invalid("kind", "invalid_kind");
    if (typeof ref !== "string" || !refOk(kind, ref)) return invalid("ref", "invalid_ref");
    const facts = world.facts(kind, ref);
    return !facts || (facts.agent_id !== null && !world.canSee(facts.agent_id)) ? itemNotFound() : { kind, ref, facts };
  }
  const isResult = (value: unknown): value is Result => typeof value === "object" && value !== null && "status" in value;

  const insert = (c: StoredCase, item: { kind: CaseKind; ref: string; facts: ItemFacts }, at = now()): StoredItem | Result => {
    if (itemsOf(c).length >= MAX_ITEMS) return problem(422, "too_many_items", "A case holds at most 500 items");
    if (itemsOf(c).some((i) => i.kind === item.kind && i.ref === item.ref)) return problem(409, "item_already_in_case", "The item is already in this case");
    const other = holder(item, c.case_id);
    if (other) return inCase(other);
    const stored: StoredItem = {
      item_id: crypto.randomUUID(), case_id: c.case_id, kind: item.kind, ref: item.ref, agent_id: item.facts.agent_id, active: true,
      outcome: null, outcome_note: null, outcome_until: null, added_by_user_id: me, added_at: at,
    };
    state.items.push(stored);
    push(c, "item_added", null, itemDetail(stored), me, at);
    world.audit("case.item.add", c.case_id);
    return stored;
  };

  const sweep = () => {
    const changed = reopenDue({
      cases: state.cases, itemsOf, exclusive, gone, audit: world.audit,
      taken: (c) => itemsOf(c).some((i) => holder(i, c.case_id)),
      push: (c, kind, body, extra, actor) => push(c, kind, body, extra, actor),
    });
    if (changed) persist();
  };

  return {
    list(query: URLSearchParams): Result {
      sweep();
      const status = query.get("status");
      if (status !== null && !["open", "investigating", "closed", "all"].includes(status)) return problem(400, "invalid_query", "status must be open, investigating, closed or all");
      const severity = query.get("severity");
      if (severity !== null && !severityOk(severity)) return problem(400, "invalid_query", "severity must be critical, high, medium or low");
      const q = (query.get("q") ?? "").trim().toLowerCase();
      if ([...q].length > 120) return problem(400, "invalid_query", "q is at most 120 characters");
      const assignee = query.get("assignee");
      const rows = state.cases.filter((c) => sees(c)
        && (status === null ? c.status !== "closed" : status === "all" || c.status === status)
        && (severity === null || c.severity === severity)
        && (assignee === null || (assignee === "none" ? c.assignee_user_id === null : c.assignee_user_id === (assignee === "me" ? me : assignee.toLowerCase())))
        && (q === "" || c.title.toLowerCase().includes(q) || `c-${c.number}`.includes(q)))
        .sort((a, b) => b.updated_at.localeCompare(a.updated_at) || b.number - a.number);
      return { status: 200, body: rows.map(summary) };
    },

    /** Every case the viewer sees, with what the Cases list reads of it (after the reopen checks). */
    listed(): ListedCase[] {
      sweep();
      return state.cases.filter(sees).map((c) => {
        const note = state.events.filter((e) => e.case_id === c.case_id && e.kind === "note").sort((a, b) => b.event_id - a.event_id)[0];
        return {
          c, visible: itemsOf(c).filter(seesItem), ready: c.status !== "closed" && !itemsOf(c).some(blocking),
          note: note ? { text: [...(note.body ?? "")].slice(0, 120).join(""), at: note.at } : null,
          opener: person(c.opened_by_user_id), assignee: c.assignee_user_id === null ? null : person(c.assignee_user_id),
        };
      });
    },

    get(id: string): Result {
      sweep();
      const c = find(id);
      return c ? ok(200, c) : notFound();
    },

    create(body: Body): Result {
      if (typeof body.title !== "string") return badBody();
      const title = body.title.trim();
      if (!titleOk(title)) return invalid("title", "invalid_title");
      if (body.severity != null && (typeof body.severity !== "string" || !severityOk(body.severity))) return invalid("severity", "invalid_severity");
      const refs = body.items === undefined ? [] : body.items;
      if (!Array.isArray(refs)) return badBody();
      if (refs.length > MAX_ON_CREATE) return invalid("items", "too_many_items");
      const assignee = typeof body.assignee_user_id === "string" ? body.assignee_user_id.toLowerCase() : null;
      if (assignee !== null && !world.assignable.includes(assignee)) return invalid("assignee_user_id", "assignee_unavailable");
      const resolved: { kind: CaseKind; ref: string; facts: ItemFacts }[] = [];
      for (const raw of refs as Body[]) {
        const item = resolve(raw?.kind, raw?.ref);
        if (isResult(item)) return item;
        if (resolved.some((r) => r.kind === item.kind && r.ref === item.ref)) return problem(409, "item_already_in_case", "The item is already in this case");
        const other = holder(item, "");
        if (other) return inCase(other);
        resolved.push(item);
      }
      const at = now();
      const severity = typeof body.severity === "string" ? body.severity : defaultSeverity(resolved.map((r) => r.facts.severity));
      const c: StoredCase = {
        case_id: crypto.randomUUID(), number: state.next_number, title, status: "open", resolution: null, resolution_note: null, accepted_until: null,
        severity, assignee_user_id: assignee, opened_by_user_id: me, created_at: at, updated_at: at, closed_at: null, version: 1,
      };
      state.next_number += 1;
      state.cases.push(c);
      push(c, "created", null, { severity }, me, at);
      if (assignee !== null) push(c, "assigned", null, { from: null, to: person(assignee).username }, me, at);
      world.audit("case.create", c.case_id);
      for (const item of resolved) insert(c, item, at);
      persist();
      return ok(201, c);
    },

    update(id: string, body: Body, ifMatch: string | undefined): Result {
      if (ifMatch === undefined) return problem(428, "precondition_required", "If-Match is required");
      const match = /^"(\d+)"$/.exec(ifMatch);
      if (!match) return problem(400, "invalid_precondition", "If-Match must contain one quoted version");
      if (typeof body.title !== "string" || typeof body.severity !== "string" || typeof body.status !== "string") return badBody();
      const known = ["title", "severity", "status", "assignee_user_id", "closing_note", "resolution", "accepted_until"];
      if (Object.keys(body).some((key) => !known.includes(key))) return badBody();
      const optional = (value: unknown) => value === undefined || value === null ? null : typeof value === "string" ? value : false;
      const rawNote = optional(body.closing_note);
      const assigneeRaw = optional(body.assignee_user_id);
      if (rawNote === false || assigneeRaw === false) return badBody();
      // Step 5d: the case-level resolution and date are refused; `null` counts as absent.
      for (const field of ["resolution", "accepted_until"]) if (body[field] != null) return removedField(field);
      const title = body.title.trim();
      const note = trimmed(rawNote);
      const assignee = assigneeRaw === null ? null : assigneeRaw.toLowerCase();
      if (!titleOk(title)) return invalid("title", "invalid_title");
      if (!severityOk(body.severity)) return invalid("severity", "invalid_severity");
      if (!["open", "investigating", "closed"].includes(body.status)) return invalid("status", "invalid_status");
      const status = body.status;
      const wrong = closingError(status, note);
      if (wrong) return invalid(...wrong);
      sweep();
      const c = find(id);
      if (!c) return notFound();
      if (c.version !== Number(match[1])) return problem(412, "stale_case", "The case changed since you loaded it");
      const wasClosed = c.status === "closed";
      const willClose = status === "closed";
      // Nothing else about how a closed case ended changes while it stays closed.
      if (wasClosed && willClose && c.resolution_note !== note) return closed();
      const assigneeChanged = c.assignee_user_id !== assignee;
      if (assigneeChanged && assignee !== null && !world.assignable.includes(assignee)) return invalid("assignee_user_id", "assignee_unavailable");
      const fieldsChanged = c.title !== title || c.severity !== body.severity || assigneeChanged;
      if (!fieldsChanged && c.status === status) return ok(200, c);
      if (!wasClosed && willClose) {
        const standing = itemsOf(c).filter(blocking);
        if (standing.some(seesItem)) return problem(409, "items_unresolved", "Every alarm, finding and vulnerability needs an outcome before the case closes");
        if (standing.length > 0) return problem(409, "hidden_items_unresolved", "Items you cannot see still need an outcome; ask someone with access to them");
      }
      if (wasClosed && !willClose) {
        const clash = itemsOf(c).map((i) => holder(i, c.case_id)).find(Boolean);
        if (clash) return inCase(clash);
      }
      const at = now();
      const before = { severity: c.severity, status: c.status, assignee: c.assignee_user_id, resolution: c.resolution };
      // A new close sets no resolution; an old closed case keeps its own while it stays closed.
      Object.assign(c, {
        title, severity: body.severity, status, assignee_user_id: assignee, resolution_note: note,
        resolution: willClose ? c.resolution : null, accepted_until: willClose ? c.accepted_until : null,
        closed_at: willClose ? c.closed_at ?? at : null, version: c.version + 1, updated_at: at,
      });
      if (wasClosed !== willClose) for (const i of itemsOf(c)) i.active = !willClose;
      if (assigneeChanged) push(c, "assigned", null, { from: before.assignee === null ? null : person(before.assignee).username, to: assignee === null ? null : person(assignee).username }, me, at);
      if (before.severity !== body.severity) push(c, "severity", null, { from: before.severity, to: body.severity }, me, at);
      if (willClose && !wasClosed) {
        push(c, "resolved", note, {}, me, at);
        world.audit("case.close", c.case_id);
      } else if (wasClosed && !willClose) {
        push(c, "reopened", null, { reason: "manual", status, previous_resolution: before.resolution }, me, at);
        world.audit("case.reopen", c.case_id);
      } else if (before.status !== status) {
        push(c, "status", null, { from: before.status, to: status }, me, at);
      }
      if (fieldsChanged || (before.status !== status && !wasClosed && !willClose)) world.audit("case.update", c.case_id);
      persist();
      return ok(200, c);
    },

    addNote(id: string, body: Body): Result {
      if (typeof body.body !== "string") return badBody();
      if (!noteOk(body.body)) return invalid("body", "invalid_note");
      const c = find(id);
      if (!c) return notFound();
      if (state.events.filter((e) => e.case_id === c.case_id).length >= MAX_EVENTS) return problem(422, "timeline_full", "The timeline holds at most 2000 entries");
      push(c, "note", body.body);
      const event = state.events[state.events.length - 1];
      touch(c);
      world.audit("case.note", c.case_id);
      persist();
      return { status: 201, body: event && eventView(event) };
    },

    addItem(id: string, body: Body): Result {
      if (typeof body.kind !== "string" || typeof body.ref !== "string") return badBody();
      const c = find(id);
      if (!c) return notFound();
      if (c.status === "closed") return closed();
      const item = resolve(body.kind, body.ref);
      if (isResult(item)) return item;
      const stored = insert(c, item);
      if (isResult(stored)) return stored;
      touch(c);
      persist();
      return { status: 201, body: itemView(stored) };
    },

    removeItem(id: string, itemId: string): Result {
      const c = find(id);
      if (!c) return notFound();
      if (c.status === "closed") return closed();
      const item = itemsOf(c).find((i) => i.item_id === itemId && seesItem(i));
      if (!item) return itemNotFound();
      state.items.splice(state.items.indexOf(item), 1);
      push(c, "item_removed", null, itemDetail(item));
      touch(c);
      world.audit("case.item.remove", c.case_id);
      persist();
      return { status: 204 };
    },

    setOutcome(id: string, itemId: string, body: Body): Result {
      const outcome = body.outcome ?? null;
      const raw = body.note ?? null;
      const rawUntil = body.outcome_until ?? null;
      if (Object.keys(body).some((key) => !["outcome", "note", "outcome_until"].includes(key))) return badBody();
      if ((outcome !== null && typeof outcome !== "string") || (raw !== null && typeof raw !== "string") || (rawUntil !== null && typeof rawUntil !== "string")) return badBody();
      // items.rs reads the date before the store checks the rest.
      const until = rawUntil === null ? null : Date.parse(rawUntil);
      if (until !== null && Number.isNaN(until)) return invalid("outcome_until", "invalid_timestamp");
      const note = trimmed(raw);
      const wrong = outcome === null ? null : outcomeError(outcome, note, until, Date.now());
      if (wrong) return invalid(...wrong);
      const c = find(id);
      if (!c) return notFound();
      if (c.status === "closed") return closed();
      const item = itemsOf(c).find((i) => i.item_id === itemId && seesItem(i));
      if (!item) return itemNotFound();
      if (!exclusive(item)) return invalid("outcome", "outcome_not_applicable");
      if (outcome === "resolved" && !gone(item)) return problem(409, "evidence_present", "The evidence is still there; mark it false positive or accepted risk instead");
      if (item.outcome !== outcome || outcome !== null) {
        const at = until === null ? null : new Date(until).toISOString();
        push(c, "item_outcome", note, { ...itemDetail(item), from: item.outcome, to: outcome, until: at });
        item.outcome = outcome;
        item.outcome_note = outcome === null ? null : note;
        item.outcome_until = outcome === null ? null : at;
        touch(c);
        world.audit("case.item.outcome", c.case_id);
        persist();
      }
      return { status: 200, body: itemView(item) };
    },

    forItem(query: URLSearchParams): Result {
      const kind = query.get("kind");
      const ref = query.get("ref");
      if (kind === null || ref === null) return problem(400, "invalid_query", "kind and ref are required");
      if (!isCaseKind(kind)) return invalid("kind", "invalid_kind");
      if (!refOk(kind, ref)) return invalid("ref", "invalid_ref");
      const isExclusive = EXCLUSIVE_KINDS.has(kind);
      const found = state.items.filter((i) => i.kind === kind && i.ref === ref && (!isExclusive || i.active) && seesItem(i))
        .flatMap((i) => { const c = state.cases.find((candidate) => candidate.case_id === i.case_id); return c && sees(c) ? [{ c, i }] : []; })
        .sort((a, b) => b.c.updated_at.localeCompare(a.c.updated_at) || b.c.number - a.c.number).slice(0, 50);
      return { status: 200, body: { items: found.map(({ c, i }) => ({ case: summary(c), item_id: i.item_id, outcome: i.outcome })) } };
    },

    /** Items of one kind in open cases the caller can see, with the case number (the lists' badges). */
    activeItems(query: URLSearchParams): Result {
      const kind = query.get("kind");
      if (kind === null || !isCaseKind(kind) || !EXCLUSIVE_KINDS.has(kind)) return problem(400, "invalid_kind", "kind must be alarm, compliance_finding or vulnerability");
      const items = state.items.filter((i) => i.kind === kind && i.active && seesItem(i))
        .flatMap((i) => { const c = state.cases.find((candidate) => candidate.case_id === i.case_id); return c && sees(c) ? [{ ref: i.ref, case_number: c.number }] : []; });
      return { status: 200, body: { items } };
    },

    assignees(): Result {
      return { status: 200, body: { items: world.assignable.map(person) } };
    },
  };
}

export type CaseStore = ReturnType<typeof createCaseStore>;
