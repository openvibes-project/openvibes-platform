import type { AlarmSuppression } from "../../api/types";
import { allowedStates, noteRequired } from "../../panels/triage/triage";
import { demoMappings, pairView } from "../attack";
import type { DemoContext } from "../context";
import { json, page, problem } from "../http";
import type { Refusal, Request, Suppressions } from "../suppressions";

export function registerAlarmRoutes(ctx: DemoContext & { suppressions: Suppressions }) {
  const { iso, actor, alarmList, triageProblem, audit, route, suppressions } = ctx;
  // Threat alarms (P14), with the server's rules: scoped like findings,
  // the findings workflow for triage.
  const summary = (alarm: ReturnType<typeof alarmList>[number]) => ({
    id: alarm.id, agent_id: alarm.agent_id, hostname: alarm.hostname, rule_set_id: alarm.rule_set_id, rule_id: alarm.rule_id,
    severity: alarm.severity, message: alarm.message, exe: alarm.exe, parent_exe: alarm.parent_exe, count: alarm.count,
    first_seen: alarm.first_seen, last_seen: alarm.last_seen, state: alarm.state, suppressed_by: alarm.suppressed_by,
  });
  route("GET", "/api/v1/alarms", "alarms.read", (_, query) => {
    const suppressed = query.get("suppressed") === "true";
    const state = query.get("state");
    const severity = query.get("severity");
    const agent = query.get("agent_id");
    const items = alarmList().filter((alarm) => (suppressed || !alarm.suppressed_by) && (!agent || alarm.agent_id === agent)
        && (!state || alarm.state === state || (state === "active" && alarm.state === "open"))
        && (!severity || alarm.severity === severity))
      .sort((a, b) => b.last_seen.localeCompare(a.last_seen)).map(summary);
    return json(page(items, query));
  });
  route("GET", "/api/v1/alarms/{id}/rule", "alarms.read", ({ id }) => {
    const alarm = alarmList().find((a) => a.id === id);
    if (!alarm) return problem(404, "alarm_not_found", "Alarm not found");
    return json({ status: "exact", rule_set_id: alarm.rule_set_id, rule_set_version: alarm.rule_set_version,
      rule: { id: alarm.rule_id, version: alarm.rule_version, title: alarm.message, expression: alarm.detection.steps[0]?.expression,
        finding_message: alarm.message, severity: alarm.severity, confidence: alarm.confidence, kind: "process_event", programs: [alarm.exe], attack: (demoMappings[alarm.rule_id] ?? []).map(pairView) } });
  });
  route("GET", "/api/v1/alarms/{id}", "alarms.read", ({ id = "" }) => {
    const alarm = alarmList().find((candidate) => candidate.id === id);
    return alarm ? json(alarm) : problem(404, "alarm_not_found", "Alarm not found");
  });
  route("PUT", "/api/v1/alarms/{id}/triage", "alarms.triage", ({ id = "" }, _, body, headers) => {
    const alarm = alarmList().find((candidate) => candidate.id === id);
    if (!alarm) return problem(404, "alarm_not_found", "Alarm not found");
    if (headers["if-match"] !== `"${alarm.triage.version}"`) return problem(412, "stale_triage", "Triage changed; reload before saving");
    const state = String(body.state ?? "");
    if (!allowedStates([alarm.state]).includes(state)) return problem(409, "invalid_transition", "Requested triage transition is not allowed");
    const note = typeof body.note === "string" && body.note.trim() ? body.note.trim() : null;
    if (noteRequired.has(state) && !note) return problem(400, "invalid_triage", "Triage state, note, or expiry is invalid");
    const invalid = triageProblem(body, "alarms.triage");
    if (invalid) return invalid;
    alarm.state = state;
    alarm.triage = { state, assigned_to: typeof body.assigned_to === "string" ? body.assigned_to : null, note,
      accepted_until: typeof body.accepted_until === "string" ? body.accepted_until : null,
      version: alarm.triage.version + 1, updated_at: iso(), updated_by: actor };
    audit("alarm.triage.changed", id, "alarm");
    return json(alarm.triage);
  });
  // Suppressions with approval (alarms/suppressions.rs, suppression_decisions.rs).
  const answer = (made: AlarmSuppression | Refusal, status = 200) => ("code" in made ? refusal(made) : json(made, status));
  route("GET", "/api/v1/alarm-suppressions", "alarms.suppressions.read", (_, query) => {
    const state = query.get("state");
    const alarmId = query.get("alarm_id");
    if (state !== null && !["waiting", "active", "rejected"].includes(state)) return invalidField("state");
    if (alarmId !== null && !/^-?\d+$/.test(alarmId)) return invalidField("alarm_id");
    return json({ items: suppressions.list(state, alarmId) });
  });
  route("GET", "/api/v1/alarm-suppressions/options", "alarms.suppress", () => json(suppressions.options()));
  route("POST", "/api/v1/alarm-suppressions", "alarms.suppress", (_, __, body) => {
    const request = requestOf(body);
    return request ? answer(suppressions.request(request), 201) : invalidField("body");
  });
  route("POST", "/api/v1/alarm-suppressions/{id}/approve", "alarms.suppressions.approve", ({ id = "" }) => answer(suppressions.decide(id, true, null)));
  route("POST", "/api/v1/alarm-suppressions/{id}/reject", "alarms.suppressions.approve", ({ id = "" }, _, body) =>
    answer(suppressions.decide(id, false, typeof body.reason === "string" ? body.reason : null)));
  route("POST", "/api/v1/alarm-suppressions/{id}/withdraw", "alarms.suppress", ({ id = "" }) => answer(suppressions.withdraw(id)));
  route("DELETE", "/api/v1/alarm-suppressions/{id}", "alarms.suppress", ({ id = "" }) => {
    const removed = suppressions.remove(id);
    return "code" in removed ? refusal(removed) : new Response(null, { status: 204 });
  });
}

const TITLES: Record<string, string> = {
  alarm_not_found: "Alarm or suppression not found", suppression_not_found: "Alarm or suppression not found",
  global_scope_required: "Only someone who reaches every host may suppress on all hosts", permission_denied: "Access is not available",
  suppression_not_waiting: "This suppression is no longer waiting", own_request: "You can't approve or reject your own request",
};
const FIELD_MESSAGES: Record<string, string> = {
  reason: "Give a reason of 1 to 4,000 characters", for: "Choose 7 days, 30 days or until removed",
  group: "The group no longer exists", command: "This alarm's command line can't be matched",
};
/** 422 naming the invalid field, as suppression_types.rs `invalid`. */
const invalidField = (field: string) => problem(422, "invalid_suppression", "Check the suppression's fields",
  { field_errors: [{ field, code: "invalid", message: FIELD_MESSAGES[field] ?? "Send alarm_id, what, where, for_days and reason" }] });
const refusal = (r: Refusal) => (r.field ? invalidField(r.field) : problem(r.status, r.code, TITLES[r.code] ?? r.code));

/** The POST body (serde, deny_unknown_fields), or null when it does not parse. */
function requestOf(body: Record<string, unknown>): Request | null {
  const keys = (o: object, allowed: string[]) => Object.keys(o).every((k) => allowed.includes(k));
  const where = body.where as Record<string, unknown> | null | undefined;
  const forDays = body.for_days ?? null;
  if (!keys(body, ["alarm_id", "what", "where", "for_days", "reason"]) || typeof body.alarm_id !== "string" || typeof body.reason !== "string"
    || (body.what !== "program" && body.what !== "command") || (forDays !== null && !Number.isInteger(forDays))
    || typeof where !== "object" || where === null) return null;
  const place = where.kind === "host" && keys(where, ["kind"]) ? { kind: "host" as const }
    : where.kind === "all" && keys(where, ["kind"]) ? { kind: "all" as const }
      : where.kind === "group" && typeof where.group_id === "string" && keys(where, ["kind", "group_id"]) ? { kind: "group" as const, group_id: where.group_id } : null;
  return place && { alarmId: body.alarm_id, what: body.what, where: place, forDays: forDays as number | null, reason: body.reason };
}
