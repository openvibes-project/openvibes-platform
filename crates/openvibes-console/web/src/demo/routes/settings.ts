// Settings: the audit log and its retention, and the assistant's internet access.
import { validDomain, validSearxngUrl } from "../../views/admin/settings/assistantRules";
import type { DemoContext } from "../context";
import { json, page, problem } from "../http";

export function registerSettingsRoutes(ctx: DemoContext) {
  const { data, iso, actor, audit, route } = ctx;
  route("GET", "/api/v1/audit-events", "audit.read", (_, query) => {
    const since = Date.parse(query.get("since") ?? "");
    if (Number.isNaN(since) || since > Date.now()) return problem(400, "invalid_query", "Audit event query parameters are invalid");
    return json(page(data.audit.filter((event) => Date.parse(event.at) >= since), query));
  });
  route("GET", "/api/v1/assistant-internet", "assistant.admin", () => json(data.assistantInternet));
  route("PUT", "/api/v1/assistant-internet", "assistant.admin", (_, __, body, headers) => {
    const match = headers["if-match"];
    if (match === undefined) return problem(428, "precondition_required", "If-Match is required");
    if (match !== `"${data.assistantInternet.version}"`) return problem(412, "stale_setting", "The setting changed; reload and try again");
    const level = Number(body.level);
    const url = typeof body.searxng_url === "string" && body.searxng_url !== "" ? body.searxng_url : null;
    const domains = Array.isArray(body.internal_domains) ? body.internal_domains.map(String) : [];
    if (![0, 1, 2].includes(level) || (level === 2 && !url) || (url !== null && !validSearxngUrl(url)) || domains.length > 50 || !domains.every(validDomain)) {
      return problem(400, "invalid_setting", "The assistant internet setting is invalid");
    }
    data.assistantInternet = { ...data.assistantInternet, level, searxng_url: url, internal_domains: domains, version: data.assistantInternet.version + 1, updated_at: iso(), updated_by: actor };
    audit("assistant.internet.changed", "assistant", "internet");
    return json(data.assistantInternet);
  });
  route("POST", "/api/v1/assistant-internet/test", "assistant.admin", () => {
    if (data.assistantInternet.level < 2) return json({ ok: false, detail: "web search is off" });
    audit("assistant.internet.lookup", "assistant", "internet");
    return json({ ok: true, detail: "5 results" });
  });
  route("GET", "/api/v1/audit-retention", "audit.read", () => json(data.retention));
  route("PUT", "/api/v1/audit-retention", "audit.retention.manage", (_, __, body, headers) => {
    const match = headers["if-match"];
    if (match === undefined) return problem(428, "precondition_required", "If-Match is required");
    if (match !== `"${data.retention.version}"`) return problem(412, "stale_policy", "The retention policy changed; reload and try again");
    const days = Number(body.retention_days);
    if (!Number.isInteger(days) || days < 1 || days > 36_500) return problem(422, "invalid_retention", "Retention must be between 1 and 36,500 days");
    data.retention = { ...data.retention, retention_days: days, version: data.retention.version + 1, updated_at: iso(), updated_by: actor };
    audit("audit.retention.update", "audit", "retention");
    return json(data.retention);
  });
}
