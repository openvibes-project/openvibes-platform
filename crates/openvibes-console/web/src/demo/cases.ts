// The demo's cases: the real API's routes, JSON shapes, status codes and
// rules (crates/openvibes-console/src/cases.rs, platform-store console_cases.rs;
// docs/components/console-cases.md), kept in memory and, in a browser, in
// localStorage like the dashboards. What an item is (its title, severity,
// whether its evidence is gone) comes from the rest of the demo through
// `CaseWorld`, so alarms, findings and vulnerabilities stay the single truth.
import type { CaseDetail, CaseEvent, CaseItem, CaseSummary, CaseUser } from "../api/types";
import { EXCLUSIVE_KINDS, type CaseKind, isCaseKind } from "../panels/cases";
import type { DemoData } from "./data";

type Result = { status: number; body?: unknown; etag?: string };
type Body = Record<string, unknown>;

export type ItemFacts = { agent_id: string | null; title: string | null; severity: string | null; gone: boolean };
export type CaseWorld = {
  me: CaseUser;
  /** Everyone a case can name (opener, assignee, author). */
  people: readonly CaseUser[];
  /** User ids that hold `cases.read`, so can be assigned. */
  assignable: readonly string[];
  /** Whether the viewer's scope contains the host. */
  canSee: (agentId: string) => boolean;
  hostname: (agentId: string) => string | null;
  /** The object as the viewer sees it now, or undefined when it does not exist for them. */
  facts: (kind: CaseKind, ref: string) => ItemFacts | undefined;
  audit: (action: string, target: string) => void;
};

type StoredCase = {
  case_id: string; number: number; title: string; status: string; resolution: string | null; resolution_note: string | null;
  accepted_until: string | null; severity: string; assignee_user_id: string | null; opened_by_user_id: string;
  created_at: string; updated_at: string; closed_at: string | null; version: number;
};
type StoredItem = {
  item_id: string; case_id: string; kind: CaseKind; ref: string; agent_id: string | null; active: boolean;
  outcome: string | null; outcome_note: string | null; added_by_user_id: string; added_at: string;
};
type StoredEvent = { event_id: number; case_id: string; at: string; actor_user_id: string | null; kind: string; body: string | null; detail: Body };
export type CaseState = { v: 1; next_number: number; next_event: number; cases: StoredCase[]; items: StoredItem[]; events: StoredEvent[] };
export type CasePersistence = { load: () => unknown; save: (state: CaseState) => void };

const MAX_ITEMS = 500;
const MAX_ON_CREATE = 50;
const MAX_EVENTS = 2000;
const messages: Record<string, string> = {
  invalid_title: "Use 1 to 120 characters, without control characters",
  invalid_severity: "Use critical, high, medium or low",
  invalid_status: "Use open, investigating or closed",
  invalid_kind: "Use alarm, finding, vulnerability, host or software",
  invalid_ref: "The id does not have the shape of this kind of item",
  too_many_items: "A case is created with at most 50 items",
  resolution_required: "A resolution is required to close a case",
  invalid_resolution: "Use mitigated, false_positive or accepted_risk",
  resolution_note_required: "A note is required to close a case",
  invalid_note: "Use 1 to 4000 characters of plain text",
  note_required: "A note is required for this outcome",
  invalid_outcome: "Use resolved, false_positive or accepted_risk",
  outcome_not_applicable: "Hosts and software need no outcome",
  accepted_until_required: "Accepted risk needs a date in the future",
  accepted_until_past: "The date must be in the future",
  accepted_until_not_allowed: "Only accepted risk has an end date",
  resolution_not_allowed: "Only a closed case has a resolution",
  invalid_timestamp: "Use an RFC 3339 time",
  assignee_unavailable: "The assignee must be an enabled user who can read cases",
};

const problem = (status: number, code: string, title: string, extra: Body = {}): Result =>
  ({ status, body: { status, code, title, request_id: "demo", ...extra } });
const invalid = (field: string, code: string): Result =>
  problem(422, "invalid_case", "The request is invalid", { field_errors: [{ field, code, message: messages[code] ?? "The value is not valid" }] });
const notFound = () => problem(404, "case_not_found", "Case not found");
const itemNotFound = () => problem(404, "item_not_found", "Item not found");
const closed = () => problem(409, "case_closed", "The case is closed; reopen it first");

const hasControl = (value: string) => [...value].some((ch) => ch < " " && ch !== "\n" && ch !== "\t");
const titleOk = (title: string) => title.length >= 1 && [...title].length <= 120 && !hasControl(title);
const noteOk = (note: string) => note.trim() !== "" && [...note].length <= 4000;
const severityOk = (severity: string) => ["critical", "high", "medium", "low"].includes(severity);
const identifier = /^[\w.:-]{1,128}$/;
const freeText = (value: string) => value.length >= 1 && value.length <= 256 && !hasControl(value);

/** The shape each kind's id has in the console's panels. */
function refOk(kind: CaseKind, ref: string): boolean {
  const [head = "", ...rest] = ref.split("/");
  switch (kind) {
    case "alarm": return /^[1-9]\d{0,17}$/.test(ref);
    case "finding": return rest.length === 2 && identifier.test(head) && (rest[0] === "" || identifier.test(rest[0] ?? "")) && identifier.test(rest[1] ?? "");
    case "vulnerability": return rest.length >= 1 && identifier.test(head) && freeText(rest.join("/"));
    case "host": return identifier.test(ref);
    case "software": return rest.length >= 1 && identifier.test(head) && freeText(rest.join("/"));
  }
}

const caseSeverityOf = (severity: string | null | undefined) =>
  ({ critical: "critical", high: "high", important: "high", medium: "medium", moderate: "medium", low: "low", info: "low", unrated: "low" } as Record<string, string>)[severity ?? ""];
const rank = (severity: string) => ["low", "medium", "high", "critical"].indexOf(severity);
const defaultSeverity = (severities: (string | null)[]) =>
  severities.map(caseSeverityOf).filter((s): s is string => s !== undefined).sort((a, b) => rank(b) - rank(a))[0] ?? "medium";

export function createCaseStore(world: CaseWorld, seed: () => CaseState, persistence?: CasePersistence) {
  const saved = persistence?.load() as Partial<CaseState> | undefined;
  const state: CaseState = saved?.v === 1 && Array.isArray(saved.cases) && Array.isArray(saved.items) && Array.isArray(saved.events)
    && typeof saved.next_number === "number" && typeof saved.next_event === "number" ? (saved as CaseState) : seed();
  const persist = () => persistence?.save(state);
  const now = () => new Date().toISOString();
  const me = world.me.user_id;
  const person = (id: string): CaseUser => world.people.find((p) => p.user_id === id) ?? { user_id: id, username: id, display_name: id };

  const seesItem = (item: StoredItem) => item.agent_id === null || world.canSee(item.agent_id);
  const itemsOf = (c: StoredCase) => state.items.filter((i) => i.case_id === c.case_id);
  /** The caller sees a case holding a visible item, or one they opened or are assigned to. */
  const sees = (c: StoredCase) => c.opened_by_user_id === me || c.assignee_user_id === me || itemsOf(c).some(seesItem);
  const find = (id: string) => { const c = state.cases.find((candidate) => candidate.case_id === id); return c && sees(c) ? c : undefined; };

  const factsOf = (item: StoredItem) => world.facts(item.kind, item.ref);
  const itemView = (item: StoredItem): CaseItem => {
    const facts = factsOf(item);
    return {
      item_id: item.item_id, kind: item.kind, ref: item.ref, agent_id: item.agent_id,
      hostname: item.agent_id === null ? null : world.hostname(item.agent_id), active: item.active,
      outcome: item.outcome, outcome_note: item.outcome_note, added_by: person(item.added_by_user_id), added_at: item.added_at,
      title: facts?.title ?? null, severity: facts?.severity ?? null,
      // An alarm, finding or vulnerability that no longer exists has no evidence left.
      evidence_gone: EXCLUSIVE_KINDS.has(item.kind) ? (facts ? facts.gone : true) : false,
    };
  };
  const summary = (c: StoredCase): CaseSummary => {
    const visible = itemsOf(c).filter(seesItem);
    return {
      case_id: c.case_id, number: c.number, title: c.title, status: c.status, resolution: c.resolution, accepted_until: c.accepted_until,
      severity: c.severity, assignee: c.assignee_user_id === null ? null : person(c.assignee_user_id), opened_by: person(c.opened_by_user_id),
      created_at: c.created_at, updated_at: c.updated_at, closed_at: c.closed_at, version: c.version,
      item_count: visible.length, pending_item_count: visible.filter((i) => EXCLUSIVE_KINDS.has(i.kind) && i.outcome === null).length,
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
  const touch = (c: StoredCase, at = now()) => { c.updated_at = at; };
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
      outcome: null, outcome_note: null, added_by_user_id: me, added_at: at,
    };
    state.items.push(stored);
    push(c, "item_added", null, itemDetail(stored), me, at);
    world.audit("case.item.add", c.case_id);
    return stored;
  };

  /** Accepted risk that has run out reopens its case, and its accepted items are decided again. */
  const sweep = () => {
    const t = Date.now();
    for (const c of state.cases) {
      if (c.status !== "closed" || c.resolution !== "accepted_risk" || c.accepted_until === null || Date.parse(c.accepted_until) > t) continue;
      if (itemsOf(c).some((i) => holder(i, c.case_id))) continue;
      Object.assign(c, { status: "open", resolution: null, resolution_note: null, accepted_until: null, closed_at: null, version: c.version + 1 });
      for (const i of itemsOf(c)) {
        i.active = true;
        if (i.outcome === "accepted_risk") { i.outcome = null; i.outcome_note = null; }
      }
      touch(c);
      push(c, "reopened", null, { reason: "accepted_risk_expired" }, null);
      world.audit("case.reopen", c.case_id);
      persist();
    }
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

    get(id: string): Result {
      sweep();
      const c = find(id);
      return c ? ok(200, c) : notFound();
    },

    create(body: Body): Result {
      if (typeof body.title !== "string") return problem(400, "invalid_request", "The request body is invalid");
      const title = body.title.trim();
      if (!titleOk(title)) return invalid("title", "invalid_title");
      if (body.severity != null && (typeof body.severity !== "string" || !severityOk(body.severity))) return invalid("severity", "invalid_severity");
      const refs = body.items === undefined ? [] : body.items;
      if (!Array.isArray(refs)) return problem(400, "invalid_request", "The request body is invalid");
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
      if (typeof body.title !== "string" || typeof body.severity !== "string" || typeof body.status !== "string") return problem(400, "invalid_request", "The request body is invalid");
      const optional = (value: unknown) => value === undefined || value === null ? null : typeof value === "string" ? value : false;
      const resolution = optional(body.resolution);
      const rawNote = optional(body.resolution_note);
      const rawUntil = optional(body.accepted_until);
      const assigneeRaw = optional(body.assignee_user_id);
      if (resolution === false || rawNote === false || rawUntil === false || assigneeRaw === false) return problem(400, "invalid_request", "The request body is invalid");
      const until = rawUntil === null ? null : Date.parse(rawUntil);
      if (until !== null && Number.isNaN(until)) return invalid("accepted_until", "invalid_timestamp");
      const title = body.title.trim();
      const note = rawNote === null || rawNote.trim() === "" ? null : rawNote;
      const assignee = assigneeRaw === null ? null : assigneeRaw.toLowerCase();
      if (!titleOk(title)) return invalid("title", "invalid_title");
      if (!severityOk(body.severity)) return invalid("severity", "invalid_severity");
      if (!["open", "investigating", "closed"].includes(body.status)) return invalid("status", "invalid_status");
      const status = body.status;
      if (status !== "closed") {
        if (resolution !== null || note !== null || until !== null) return invalid("resolution", "resolution_not_allowed");
      } else {
        if (resolution === null) return invalid("resolution", "resolution_required");
        if (!["mitigated", "false_positive", "accepted_risk"].includes(resolution)) return invalid("resolution", "invalid_resolution");
        if (note === null) return invalid("resolution_note", "resolution_note_required");
        if (!noteOk(note)) return invalid("resolution_note", "invalid_note");
        if (resolution === "accepted_risk" && until === null) return invalid("accepted_until", "accepted_until_required");
        if (resolution === "accepted_risk" && until !== null && until <= Date.now()) return invalid("accepted_until", "accepted_until_past");
        if (resolution !== "accepted_risk" && until !== null) return invalid("accepted_until", "accepted_until_not_allowed");
      }
      sweep();
      const c = find(id);
      if (!c) return notFound();
      if (c.version !== Number(match[1])) return problem(412, "stale_case", "The case changed since you loaded it");
      const wasClosed = c.status === "closed";
      const willClose = status === "closed";
      const sameEnding = c.resolution === resolution && c.resolution_note === note && (c.accepted_until === null ? null : Date.parse(c.accepted_until)) === until;
      if (wasClosed && willClose && !sameEnding) return closed();
      const assigneeChanged = c.assignee_user_id !== assignee;
      if (assigneeChanged && assignee !== null && !world.assignable.includes(assignee)) return invalid("assignee_user_id", "assignee_unavailable");
      const fieldsChanged = c.title !== title || c.severity !== body.severity || assigneeChanged;
      if (!fieldsChanged && c.status === status) return ok(200, c);
      if (!wasClosed && willClose) {
        const mine = itemsOf(c).filter((i) => EXCLUSIVE_KINDS.has(i.kind));
        const standing = (i: StoredItem) => i.outcome === null || (i.outcome === "resolved" && !(factsOf(i)?.gone ?? true));
        if (mine.some((i) => seesItem(i) && standing(i))) return problem(409, "items_unresolved", "Every alarm, finding and vulnerability needs an outcome before the case closes");
        if (mine.some((i) => !seesItem(i) && i.outcome === null)) return problem(409, "hidden_items_unresolved", "Items you cannot see still need an outcome; ask someone with access to them");
      }
      if (wasClosed && !willClose) {
        const clash = itemsOf(c).map((i) => holder(i, c.case_id)).find(Boolean);
        if (clash) return inCase(clash);
      }
      const at = now();
      const before = { severity: c.severity, status: c.status, assignee: c.assignee_user_id, resolution: c.resolution };
      Object.assign(c, {
        title, severity: body.severity, status, assignee_user_id: assignee, resolution, resolution_note: note,
        accepted_until: until === null ? null : new Date(until).toISOString(), closed_at: willClose ? c.closed_at ?? at : null,
        version: c.version + 1, updated_at: at,
      });
      if (wasClosed !== willClose) for (const i of itemsOf(c)) i.active = !willClose;
      if (assigneeChanged) push(c, "assigned", null, { from: before.assignee === null ? null : person(before.assignee).username, to: assignee === null ? null : person(assignee).username }, me, at);
      if (before.severity !== body.severity) push(c, "severity", null, { from: before.severity, to: body.severity }, me, at);
      if (willClose && !wasClosed) {
        push(c, "resolved", note, { resolution, accepted_until: c.accepted_until }, me, at);
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
      if (typeof body.body !== "string") return problem(400, "invalid_request", "The request body is invalid");
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
      if (typeof body.kind !== "string" || typeof body.ref !== "string") return problem(400, "invalid_request", "The request body is invalid");
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
      if (outcome !== null && (typeof outcome !== "string" || !["resolved", "false_positive", "accepted_risk"].includes(outcome))) return invalid("outcome", "invalid_outcome");
      const raw = body.note ?? null;
      if (raw !== null && typeof raw !== "string") return problem(400, "invalid_request", "The request body is invalid");
      const note = raw === null || raw.trim() === "" ? null : raw;
      if (outcome !== null) {
        if (note === null && outcome !== "resolved") return invalid("note", "note_required");
        if (note !== null && !noteOk(note)) return invalid("note", "invalid_note");
      }
      const c = find(id);
      if (!c) return notFound();
      if (c.status === "closed") return closed();
      const item = itemsOf(c).find((i) => i.item_id === itemId && seesItem(i));
      if (!item) return itemNotFound();
      if (!EXCLUSIVE_KINDS.has(item.kind)) return invalid("outcome", "outcome_not_applicable");
      if (outcome === "resolved" && !(factsOf(item)?.gone ?? true)) return problem(409, "evidence_present", "The evidence is still there; mark it false positive or accepted risk instead");
      if (item.outcome !== outcome || outcome !== null) {
        push(c, "item_outcome", note, { ...itemDetail(item), from: item.outcome, to: outcome });
        item.outcome = outcome;
        item.outcome_note = outcome === null ? null : note;
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
      const exclusive = EXCLUSIVE_KINDS.has(kind);
      const found = state.items.filter((i) => i.kind === kind && i.ref === ref && (!exclusive || i.active) && seesItem(i))
        .flatMap((i) => { const c = state.cases.find((candidate) => candidate.case_id === i.case_id); return c && sees(c) ? [{ c, i }] : []; })
        .sort((a, b) => b.c.updated_at.localeCompare(a.c.updated_at) || b.c.number - a.c.number).slice(0, 50);
      return { status: 200, body: { items: found.map(({ c, i }) => ({ case: summary(c), item_id: i.item_id, outcome: i.outcome })) } };
    },

    assignees(): Result {
      return { status: 200, body: { items: world.assignable.map(person) } };
    },
  };
}

/** Cases the demo starts with, over objects that exist in the demo data. */
export function seedCases(data: DemoData): CaseState {
  const minutes = (ago: number) => new Date(data.now - ago * 60_000).toISOString();
  const state: CaseState = { v: 1, next_number: 101, next_event: 1, cases: [], items: [], events: [] };
  const host = (id: string) => data.agents.find((a) => a.id === id);
  const short = (id: string) => (host(id)?.hostname ?? id).split(".")[0] ?? id;
  const findingOf = (f: { agent_id: string; rule_set_id: string; rule_id: string }) => `${f.agent_id}/${f.rule_set_id}/${f.rule_id}`;
  const triageOf = (f: { agent_id: string; rule_set_id: string; rule_id: string }) => data.triage.get(`${f.agent_id}|${f.rule_set_id}|${f.rule_id}`)?.state;

  type Spec = {
    title: string; severity: string; status: string; assignee?: string; openedBy: string; openedAgo: number;
    items: { kind: CaseKind; ref: string; agent_id: string | null; by: string; ago: number; outcome?: string; note?: string }[];
    timeline: { ago: number; actor: string; kind: string; body?: string; detail?: Body }[];
    ending?: { resolution: string; note: string; ago: number; until?: string };
  };
  const add = (spec: Spec) => {
    const caseId = crypto.randomUUID();
    const number = state.next_number;
    state.next_number += 1;
    const closedCase = spec.ending !== undefined;
    const events: Omit<StoredEvent, "event_id">[] = [];
    const event = (ago: number, actor: string | null, kind: string, body: string | null, detail: Body) =>
      events.push({ case_id: caseId, at: minutes(ago), actor_user_id: actor, kind, body, detail });
    event(spec.openedAgo, spec.openedBy, "created", null, { severity: spec.severity });
    if (spec.assignee) event(spec.openedAgo, spec.openedBy, "assigned", null, { from: null, to: spec.assignee.replace("u-", "") });
    for (const item of spec.items) {
      const itemId = crypto.randomUUID();
      state.items.push({
        item_id: itemId, case_id: caseId, kind: item.kind, ref: item.ref, agent_id: item.agent_id, active: !closedCase,
        outcome: item.outcome ?? null, outcome_note: item.note ?? null, added_by_user_id: item.by, added_at: minutes(item.ago),
      });
      event(item.ago, item.by, "item_added", null, { item_id: itemId, item_kind: item.kind, item_ref: item.ref, item_agent_id: item.agent_id });
      if (item.outcome) event(Math.max(0, item.ago - 20), item.by, "item_outcome", item.note ?? null, { item_id: itemId, item_kind: item.kind, item_ref: item.ref, item_agent_id: item.agent_id, from: null, to: item.outcome });
    }
    for (const t of spec.timeline) event(t.ago, t.actor, t.kind, t.body ?? null, t.detail ?? {});
    if (spec.ending) event(spec.ending.ago, spec.assignee ?? spec.openedBy, "resolved", spec.ending.note, { resolution: spec.ending.resolution, accepted_until: spec.ending.until ?? null });
    events.sort((a, b) => a.at.localeCompare(b.at));
    for (const e of events) { state.events.push({ ...e, event_id: state.next_event }); state.next_event += 1; }
    const last = events[events.length - 1]?.at ?? minutes(spec.openedAgo);
    state.cases.push({
      case_id: caseId, number, title: spec.title, status: spec.status, resolution: spec.ending?.resolution ?? null, resolution_note: spec.ending?.note ?? null,
      accepted_until: spec.ending?.until ?? null, severity: spec.severity, assignee_user_id: spec.assignee ?? null, opened_by_user_id: spec.openedBy,
      created_at: minutes(spec.openedAgo), updated_at: last, closed_at: spec.ending ? minutes(spec.ending.ago) : null,
      version: 1 + events.filter((e) => ["status", "assigned", "severity", "resolved"].includes(e.kind)).length,
    });
  };

  // The oldest case, closed: a finding fixed on a host (evidence gone) and one that is expected there.
  const fixed = data.findings.find((f) => triageOf(f) === "mitigated");
  const sibling = fixed && data.findings.find((f) => f.agent_id === fixed.agent_id && f !== fixed);
  if (fixed) {
    add({
      title: `Clean up: ${fixed.message.toLowerCase()} on ${short(fixed.agent_id)}`, severity: "medium", status: "closed", assignee: "u-sam", openedBy: "u-sam", openedAgo: 9 * 1440,
      items: [
        { kind: "host", ref: fixed.agent_id, agent_id: fixed.agent_id, by: "u-sam", ago: 9 * 1440 - 5 },
        { kind: "finding", ref: findingOf(fixed), agent_id: fixed.agent_id, by: "u-sam", ago: 9 * 1440 - 6, outcome: "resolved" },
        ...(sibling ? [{ kind: "finding" as const, ref: findingOf(sibling), agent_id: sibling.agent_id, by: "u-sam", ago: 9 * 1440 - 7, outcome: "false_positive", note: "Expected on this image; the owner confirmed." }] : []),
      ],
      timeline: [
        { ago: 8 * 1440, actor: "u-sam", kind: "note", body: "The config management change is merged and rolled out; waiting for the next scan to confirm." },
        { ago: 7 * 1440, actor: "u-sam", kind: "status", detail: { from: "open", to: "investigating" } },
      ],
      ending: { resolution: "mitigated", note: "Fixed through configuration management; the agent no longer reports it.", ago: 3 * 1440 },
    });
  }

  // An exploited advisory on several hosts: a vulnerability case, in progress.
  const exploited = data.vulnerabilities.filter((v) => v.exploited);
  const byAdvisory = new Map<string, typeof exploited>();
  for (const v of exploited) byAdvisory.set(v.advisory_id, [...(byAdvisory.get(v.advisory_id) ?? []), v]);
  const hot = [...byAdvisory.values()].sort((a, b) => b.length - a.length)[0]?.slice(0, 3);
  if (hot && hot[0]) {
    const pkg = (hot[0].packages as { name?: string }[])[0]?.name;
    const lab = hot.find((v) => (v.hostname ?? "").includes(".lab."));
    add({
      title: `${hot[0].title.replace(/ security update$/, "")}: known exploited on ${hot.length} hosts`, severity: "critical", status: "investigating",
      assignee: "u-sam", openedBy: "u-admin", openedAgo: 2 * 1440,
      items: [
        ...hot.map((v, index) => ({
          kind: "vulnerability" as const, ref: `${v.agent_id}/${v.advisory_id}`, agent_id: v.agent_id, by: "u-admin", ago: 2 * 1440 - index,
          ...(v === lab ? { outcome: "accepted_risk", note: "Lab host, not reachable from outside; patch with the next rebuild." } : {}),
        })),
        ...(pkg ? [{ kind: "software" as const, ref: `rpm/${pkg}`, agent_id: null, by: "u-sam", ago: 2 * 1440 - 30 }] : []),
      ],
      timeline: [
        { ago: 2 * 1440 - 40, actor: "u-sam", kind: "status", detail: { from: "open", to: "investigating" } },
        { ago: 26 * 60, actor: "u-sam", kind: "note", body: "CISA lists it as exploited. The vendor has no fixed build yet; checking whether we can turn off the affected feature in the meantime." },
        { ago: 5 * 60, actor: "u-admin", kind: "note", body: "Security asked for a status on Thursday." },
      ],
    });
  }

  // SSH, the host it runs on, an alarm and a finding: the investigation the spec describes.
  const sshAlarm = [...data.alarms].sort((a, b) => (a.severity === "critical" ? 0 : 1) - (b.severity === "critical" ? 0 : 1))
    .find((a) => data.findings.some((f) => f.agent_id === a.agent_id && f.rule_set_id === "hardening-ssh"));
  const sshFinding = sshAlarm && data.findings.find((f) => f.agent_id === sshAlarm.agent_id && f.rule_set_id === "hardening-ssh");
  if (sshAlarm && sshFinding) {
    add({
      title: `Shell started by a service and password SSH logins on ${short(sshAlarm.agent_id)}`, severity: "critical", status: "investigating",
      assignee: "u-admin", openedBy: "u-sam", openedAgo: 3 * 60,
      items: [
        { kind: "host", ref: sshAlarm.agent_id, agent_id: sshAlarm.agent_id, by: "u-sam", ago: 175 },
        { kind: "alarm", ref: sshAlarm.id, agent_id: sshAlarm.agent_id, by: "u-sam", ago: 170 },
        { kind: "finding", ref: findingOf(sshFinding), agent_id: sshFinding.agent_id, by: "u-sam", ago: 160 },
      ],
      timeline: [
        { ago: 150, actor: "u-sam", kind: "status", detail: { from: "open", to: "investigating" } },
        { ago: 140, actor: "u-sam", kind: "note", body: "SSH allows password logins on this host and the alarm fired 20 minutes after a login from 203.0.113.9. Pulling the auth log." },
        { ago: 45, actor: "u-admin", kind: "note", body: "Auth log shows 40 failed logins for one account, then a success. Treating as hostile until we know more." },
      ],
    });
  }

  // Two web servers starting shells: opened, nobody on it yet.
  const shells = data.alarms.filter((a) => a.message === "A web server started a shell" && a.id !== sshAlarm?.id).slice(0, 2);
  if (shells.length > 0) {
    add({
      title: `Web servers starting shells (${shells.map((a) => short(a.agent_id)).join(", ")})`, severity: "high", status: "open", openedBy: "u-sam", openedAgo: 40,
      items: shells.map((a, index) => ({ kind: "alarm" as const, ref: a.id, agent_id: a.agent_id, by: "u-sam", ago: 38 - index })),
      timeline: [{ ago: 12, actor: "u-sam", kind: "note", body: "One of them is a health check script; the other has a longer command line. Needs a look." }],
    });
  }
  return state;
}
