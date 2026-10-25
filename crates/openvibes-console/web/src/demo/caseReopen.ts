// The demo cases' lazy reopen checks, run before cases are listed or read,
// as console_cases/reopen.rs runs them (reopen_due), as the platform:
// a case closed before step 5d as accepted risk whose date ran out; a
// closed case with an item whose accepted risk ran out, or (closed within
// EVIDENCE_WATCH_DAYS) whose resolved evidence came back, reopens and only
// those items lose their outcome; and on a case that is not closed an
// item's run-out acceptance clears, so the case is no longer ready.
import { DAY, EVIDENCE_WATCH_DAYS } from "./caseRules";
import type { StoredCase, StoredItem } from "./cases";

export type ReopenKit = {
  cases: StoredCase[];
  itemsOf: (c: StoredCase) => StoredItem[];
  /** True when another open case holds one of the case's exclusive items. */
  taken: (c: StoredCase) => boolean;
  /** Exclusive kinds only: the evidence is gone (an object that no longer exists counts). */
  gone: (item: StoredItem) => boolean;
  exclusive: (item: StoredItem) => boolean;
  push: (c: StoredCase, kind: string, body: string | null, detail: Record<string, unknown>, actor: string | null) => void;
  audit: (action: string, target: string) => void;
};

const clear = (i: StoredItem) => { i.outcome = null; i.outcome_note = null; i.outcome_until = null; };
const ran = (i: StoredItem, now: number) => i.outcome === "accepted_risk" && i.outcome_until !== null && Date.parse(i.outcome_until) <= now;

/** Reopens one closed case as the platform; `due` are the items that lose their outcome. */
function reopen(kit: ReopenKit, c: StoredCase, reason: string, due: StoredItem[], perItem: boolean, at: string) {
  const previous = c.resolution;
  Object.assign(c, { status: "open", resolution: null, resolution_note: null, accepted_until: null, closed_at: null, version: c.version + 1, updated_at: at });
  for (const i of kit.itemsOf(c)) i.active = true;
  kit.push(c, "reopened", null, { reason, status: "open", previous_resolution: previous }, null);
  for (const i of due) {
    if (perItem) kit.push(c, "item_outcome", null, { item_id: i.item_id, item_kind: i.kind, item_ref: i.ref, item_agent_id: i.agent_id, from: i.outcome, to: null, reason }, null);
    clear(i);
  }
  kit.audit("case.reopen", c.case_id);
}

/** Runs every check; returns whether anything changed. */
export function reopenDue(kit: ReopenKit, now = Date.now()): boolean {
  const at = new Date(now).toISOString();
  let changed = false;
  for (const c of kit.cases) {
    if (c.status !== "closed" || kit.taken(c)) continue;
    const items = kit.itemsOf(c);
    if (c.resolution === "accepted_risk" && c.accepted_until !== null && Date.parse(c.accepted_until) <= now) {
      reopen(kit, c, "accepted_risk_expired", items.filter((i) => i.outcome === "accepted_risk"), false, at);
      changed = true;
      continue;
    }
    const expired = items.filter((i) => ran(i, now));
    if (expired.length > 0) {
      reopen(kit, c, "accepted_risk_expired", expired, true, at);
      changed = true;
      continue;
    }
    const recent = c.closed_at !== null && Date.parse(c.closed_at) >= now - EVIDENCE_WATCH_DAYS * DAY;
    const back = recent ? items.filter((i) => i.outcome === "resolved" && kit.exclusive(i) && !kit.gone(i)) : [];
    if (back.length > 0) {
      reopen(kit, c, "evidence_returned", back, true, at);
      changed = true;
    }
  }
  for (const c of kit.cases) {
    if (c.status === "closed") continue;
    const expired = kit.itemsOf(c).filter((i) => ran(i, now));
    if (expired.length === 0) continue;
    for (const i of expired) {
      kit.push(c, "item_outcome", null, { item_id: i.item_id, item_kind: i.kind, item_ref: i.ref, item_agent_id: i.agent_id, from: "accepted_risk", to: null, reason: "accepted_risk_expired" }, null);
      clear(i);
    }
    if (c.updated_at < at) c.updated_at = at;
    kit.audit("case.item.outcome", c.case_id);
    changed = true;
  }
  return changed;
}
