import { allowedStates, noteRequired } from "../../panels/triage";
import { demoMappings, pairView } from "../attack";
import type { DemoContext } from "../context";
import { json, page, problem } from "../http";

export function registerAlarmRoutes(ctx: DemoContext) {
  const { data, iso, actor, capabilities, visible, alarmList, addSuppression, audit, route } = ctx;
  // Threat alarms (P14), with the server's rules: scoped like findings,
  // the findings workflow for triage, program/command suppressions only
  // for a global caller, applied to new alarms only.
  const summary = (alarm: (typeof data.alarms)[number]) => ({
    id: alarm.id, agent_id: alarm.agent_id, hostname: alarm.hostname, rule_set_id: alarm.rule_set_id, rule_id: alarm.rule_id,
    severity: alarm.severity, message: alarm.message, exe: alarm.exe, parent_exe: alarm.parent_exe, count: alarm.count,
    first_seen: alarm.first_seen, last_seen: alarm.last_seen, state: alarm.state, suppressed_by: alarm.suppressed_by,
  });
  route("GET", "/api/v1/alarms", "alarms.read", (_, query) => {
    const suppressed = query.get("suppressed") === "true";
    const state = query.get("state");
    const severity = query.get("severity");
    const items = alarmList().filter((alarm) => (suppressed || !alarm.suppressed_by)
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
    alarm.state = state;
    alarm.triage = { state, assigned_to: typeof body.assigned_to === "string" ? body.assigned_to : null, note,
      accepted_until: typeof body.accepted_until === "string" ? body.accepted_until : null,
      version: alarm.triage.version + 1, updated_at: iso(), updated_by: actor };
    audit("alarm.triage.changed", id, "alarm");
    return json(alarm.triage);
  });
  const globalSuppress = capabilities.some((c) => c.permission === "alarms.suppress" && c.scope.kind === "global");
  const suppressionVisible = (s: (typeof data.alarmSuppressions)[number]) => globalSuppress || (s.scope === "host" && !!s.agent_id && visible(s.agent_id));
  route("GET", "/api/v1/alarm-suppressions", "alarms.read", () => json({ items: data.alarmSuppressions.filter(suppressionVisible) }));
  route("POST", "/api/v1/alarm-suppressions", "alarms.suppress", (_, __, body) => {
    const scope = String(body.scope ?? "");
    const note = typeof body.note === "string" ? body.note.trim() : "";
    if (!["host", "program", "command"].includes(scope) || !note) return problem(400, "invalid_suppression", "Scope must be host, program or command, with a note");
    if (scope !== "host" && !globalSuppress) return problem(403, "global_scope_required", "Only a user with access to every host may suppress on every host");
    const alarm = alarmList().find((candidate) => candidate.id === String(body.alarm_id ?? ""));
    if (!alarm) return problem(404, "alarm_not_found", "Alarm or suppression not found");
    return json(addSuppression(alarm, scope, note), 201);
  });
  route("DELETE", "/api/v1/alarm-suppressions/{id}", "alarms.suppress", ({ id = "" }) => {
    const index = data.alarmSuppressions.findIndex((s) => s.id === id && suppressionVisible(s));
    const [removed] = index < 0 ? [] : data.alarmSuppressions.splice(index, 1);
    if (!removed) return problem(404, "alarm_not_found", "Alarm or suppression not found");
    audit("alarm.suppression.removed", id, "alarm_suppression");
    return json(removed);
  });
}
