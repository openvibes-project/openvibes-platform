import { allowedStates, noteRequired } from "../../panels/triage";
import { caseSeverityOf, type CaseStore } from "../cases";
import type { DemoContext } from "../context";
import { json, problem } from "../http";

export function registerTriageRoutes(ctx: DemoContext & { cases: CaseStore }) {
  const { data, iso, actor, capabilities, alarmList, findings, vulnerabilities, triageKey, setTriage, triageProblem, addSuppression, audit, route, send, cases } = ctx;
  // Bulk triage (triage v2): the same rules as one item, applied to each;
  // what cannot change is skipped with the reason.
  type Triage = { state: string; assigned_to: string | null; note: string | null; accepted_until: string | null };
  type Target = { id: string; named: boolean; caseKind: "alarm" | "compliance_finding" | "vulnerability"; caseRef: string;
    current: () => Triage; write: (next: Triage) => void };
  type Picked = { found: Target[]; missing: string[] };
  type Skip = { id: string; reason: string };
  const text = (value: unknown) => (typeof value === "string" ? value : "");
  const auditNames = { alarms: "alarm", compliance: "finding", vulnerabilities: "vulnerability" } as const;

  const alarmTargets = (item: Record<string, unknown>, into: Picked): boolean => {
    if (typeof item.id !== "string") return false;
    const alarm = alarmList().find((a) => a.id === item.id);
    if (!alarm) { into.missing.push(item.id); return true; }
    into.found.push({ id: alarm.id, named: true, caseKind: "alarm", caseRef: alarm.id, current: () => alarm.triage,
      write: (next) => { alarm.state = next.state; alarm.triage = { ...next, version: alarm.triage.version + 1, updated_at: iso(), updated_by: actor }; } });
    return true;
  };
  const findingTargets = (item: Record<string, unknown>, into: Picked): boolean => {
    if (typeof item.rule_set_id !== "string" || typeof item.rule_id !== "string") return false;
    const agent = typeof item.agent_id === "string" ? item.agent_id : null;
    const set = item.rule_set_id === "~unknown" ? "" : item.rule_set_id;
    const rule = item.rule_id;
    const hits = findings().filter((f) => f.rule_set_id === set && f.rule_id === rule && (agent === null || f.agent_id === agent));
    if (hits.length === 0) into.missing.push(agent ? `${agent}/${set}/${rule}` : `${set}/${rule}`);
    for (const f of hits) {
      const current = (): Triage => {
        const t = data.triage.get(triageKey(f.agent_id, set, rule));
        return { state: t?.state ?? "open", assigned_to: t?.assigned_to ?? null, note: t?.note ?? null, accepted_until: t?.accepted_until ?? null };
      };
      into.found.push({ id: `${f.agent_id}/${set}/${rule}`, named: agent !== null, caseKind: "compliance_finding", caseRef: `${f.agent_id}/${set}/${rule}`, current,
        write: (next) => { setTriage(f.agent_id, set, rule, next); } });
    }
    return true;
  };
  const vulnerabilityTargets = (item: Record<string, unknown>, into: Picked): boolean => {
    if (typeof item.advisory_id !== "string") return false;
    const agent = typeof item.agent_id === "string" ? item.agent_id : null;
    const advisory = item.advisory_id;
    const hits = vulnerabilities().filter((v) => v.advisory_id === advisory && (agent === null || v.agent_id === agent));
    if (hits.length === 0) into.missing.push(agent ? `${agent}/${advisory}` : advisory);
    for (const v of hits) {
      into.found.push({ id: `${v.agent_id}/${advisory}`, named: agent !== null, caseKind: "vulnerability", caseRef: `${v.agent_id}/${advisory}`,
        current: () => ({ state: v.triage_state, assigned_to: v.assigned_to ?? null, note: null, accepted_until: null }),
        write: (next) => { v.triage_state = next.state; v.assigned_to = next.assigned_to; v.triage_version += 1; } });
    }
    return true;
  };
  const targetsOf = { alarms: alarmTargets, compliance: findingTargets, vulnerabilities: vulnerabilityTargets };

  const bulkState = (picked: Picked, body: Record<string, unknown>, note: string | null, skipped: Skip[]): number | Response => {
    const state = text(body.state);
    const fields = { state, note, accepted_until: body.accepted_until ?? null };
    if (!allowedStates(["open"]).includes(state) || (noteRequired.has(state) && !note) || triageProblem(fields)) {
      return problem(400, "invalid_triage", "Triage state, note, or expiry is invalid (closing needs a note)");
    }
    let changed = 0;
    for (const t of picked.found) {
      // A rule or advisory's closed hosts keep their decision (as the server).
      if (state !== "open" && !t.named && t.current().state !== "open") { skipped.push({ id: t.id, reason: "already closed" }); continue; }
      if (state === "open" && !t.named && t.current().state === "open") { skipped.push({ id: t.id, reason: "already open" }); continue; }
      t.write({ state, note, assigned_to: t.current().assigned_to, accepted_until: state === "accepted_risk" ? text(body.accepted_until) : null });
      changed += 1;
    }
    return changed;
  };
  const bulkAssign = (picked: Picked, body: Record<string, unknown>, skipped: Skip[]): number => {
    const assignee = typeof body.assignee === "string" ? body.assignee : null;
    let changed = 0;
    for (const t of picked.found) {
      const current = t.current();
      if (assignee !== null && triageProblem({ state: current.state, accepted_until: current.accepted_until, assigned_to: assignee })) {
        skipped.push({ id: t.id, reason: "assignee unavailable" });
        continue;
      }
      t.write({ ...current, assigned_to: assignee });
      changed += 1;
    }
    return changed;
  };
  const caseSkip: Record<string, string> = { item_in_case: "in another open case", too_many_items: "the case is full (500 items)" };
  const bulkCase = (picked: Picked, body: Record<string, unknown>, skipped: Skip[]): { changed: number; caseId: string | null } | Response => {
    let caseId = typeof body.case_id === "string" ? body.case_id : null;
    let found = picked.found;
    if (caseId === null) {
      // No empty case: items already in an open case are skipped first.
      const active = cases.activeItems(new URLSearchParams({ kind: found[0]?.caseKind ?? "alarm" })).body as { items: { ref: string }[] };
      const held = new Set(active.items.map((i) => i.ref));
      for (const t of found) if (held.has(t.caseRef)) skipped.push({ id: t.caseRef, reason: "in another open case" });
      found = found.filter((t) => !held.has(t.caseRef));
      if (found.length === 0) return { changed: 0, caseId: null };
      const severity = typeof body.new_case_severity === "string" ? { severity: caseSeverityOf(body.new_case_severity) } : {};
      const made = cases.create({ title: body.new_case_title, ...severity });
      if (made.status !== 201) return send(made);
      caseId = (made.body as { case_id: string }).case_id;
    }
    let changed = 0;
    for (const t of found) {
      const added = cases.addItem(caseId, { kind: t.caseKind, ref: t.caseRef });
      const code = (added.body as { code?: string } | undefined)?.code ?? "";
      if (added.status < 300 || code === "item_already_in_case") changed += 1;
      else if (added.status === 404 && code !== "item_not_found") return send(added);
      else skipped.push({ id: t.caseRef, reason: caseSkip[code] ?? "not found or out of scope" });
    }
    return { changed, caseId };
  };
  const bulkSuppress = (picked: Picked, note: string): number => {
    const seen = new Set<string>();
    for (const t of picked.found) {
      const alarm = alarmList().find((a) => a.id === t.id);
      const key = `${alarm?.rule_id}|${alarm?.exe}`;
      if (!alarm || seen.has(key)) continue;
      seen.add(key);
      addSuppression(alarm, "program", note);
    }
    return seen.size;
  };

  const ACTIONS = ["state", "assign", "case", "suppress"];
  for (const [kind, permission] of [["alarms", "alarms.triage"], ["compliance", "compliance.triage"], ["vulnerabilities", "vulnerabilities.triage"]] as const) {
    const has = (p: string) => capabilities.some((c) => c.permission === p);
    const allowed = (action: string) => action === "state" || action === "assign"
      || (action === "case" && has("cases.manage")) || (action === "suppress" && kind === "alarms" && has("alarms.suppress"));
    route("POST", `/api/v1/${kind}/bulk`, permission, (_, __, body) => {
      const items = Array.isArray(body.items) ? (body.items as Record<string, unknown>[]) : [];
      if (items.length === 0 || items.length > 10_000) return problem(400, "invalid_items", "Select 1 to 10,000 items");
      const action = text(body.action);
      if (!ACTIONS.includes(action)) return problem(400, "invalid_action", "Use state, assign, case or (alarms) suppress");
      if (!allowed(action)) return problem(403, "permission_denied", "Permission denied");
      const picked: Picked = { found: [], missing: [] };
      if (!items.every((item) => targetsOf[kind](item, picked))) return problem(400, "invalid_items", "An item does not fit this list");
      const skipped: Skip[] = picked.missing.map((id) => ({ id, reason: "not found or out of scope" }));
      const note = text(body.note).trim() || null;
      let changed: number | Response;
      let caseId: string | null = null;
      if (action === "state") changed = bulkState(picked, body, note, skipped);
      else if (action === "assign") changed = bulkAssign(picked, body, skipped);
      else if (action === "suppress") changed = note ? bulkSuppress(picked, note) : problem(400, "invalid_note", "A suppression needs a note");
      else {
        const filed = bulkCase(picked, body, skipped);
        if (filed instanceof Response) return filed;
        ({ changed, caseId } = filed);
      }
      if (changed instanceof Response) return changed;
      audit(`${auditNames[kind]}.bulk_triage`, `${changed} items`, kind);
      const caseNumber = caseId === null ? null : ((cases.get(caseId).body as { number?: number }).number ?? null);
      return json({ changed, skipped, case_id: caseId, case_number: caseNumber });
    });
  }
  route("PUT", "/api/v1/vulnerabilities/advisories/{advisory}/hosts/{agent}/triage", "vulnerabilities.triage", ({ advisory = "", agent = "" }, _, body, headers) => {
    const v = vulnerabilities().find((item) => item.advisory_id === decodeURIComponent(advisory) && item.agent_id === decodeURIComponent(agent));
    if (!v) return problem(404, "vulnerability_not_found", "No open vulnerability for this host and advisory");
    if (headers["if-match"] !== `"${v.triage_version}"`) return problem(412, "stale_triage", "The triage changed; reload it");
    const state = text(body.state);
    const note = typeof body.note === "string" && body.note.trim() ? body.note.trim() : null;
    if (!allowedStates(["open"]).includes(state) || (noteRequired.has(state) && !note) || triageProblem(body)) {
      return problem(400, "invalid_triage", "Triage state, note, or expiry is invalid (closing needs a note)");
    }
    v.triage_state = state;
    v.assigned_to = typeof body.assigned_to === "string" ? body.assigned_to : null;
    v.triage_version += 1;
    audit("vulnerability.triage.changed", `${v.agent_id}/${v.advisory_id}`, "vulnerability");
    return json({ state, assigned_to: v.assigned_to, note, accepted_until: typeof body.accepted_until === "string" ? body.accepted_until : null, version: v.triage_version });
  });
}
