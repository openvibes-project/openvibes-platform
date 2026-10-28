// Settings: the general settings (settings/ in the console), the audit log and its retention, and the assistant's internet access.
import { validDomain, validSearxngUrl } from "../../views/admin/settings/assistantRules";
import type { DemoContext } from "../context";
import type { SettingChangeView, SettingView } from "../../api/types";
import { browserPersistence, json, page, problem } from "../http";

// The typed general settings, as settings/definitions.rs lists them.
const DEFINITIONS = [
  { key: "suppressions.require_approval", section: "Alarm suppressions", label: "Suppressions need approval", kind: "bool", applies: "live", default: false,
    help: "A new suppression waits until someone else who can approve on those hosts accepts it. Matching alarms keep arriving while it waits." },
  { key: "sso.remove_inactive_days", section: "Single sign-on", label: "Remove inactive single sign-on users", kind: "int", applies: "live", min: 1, max: 3650, default: 90,
    help: "Days without a sign-in before a single sign-on user is removed. Takes effect once single sign-on is set up." },
] as const;
type Stored = { value: unknown; changed_at: string; changed_by: string };
type State = { values: Record<string, Stored>; recent: SettingChangeView[] };

export function registerSettingsRoutes(ctx: DemoContext) {
  const { data, iso, actor, audit, route } = ctx;
  // Values are kept in the browser, so a reload keeps a change; what it holds is checked, as it could be anything.
  const store = browserPersistence("openvibes.v2.demo.settings");
  const fits = (def: (typeof DEFINITIONS)[number], v: unknown) =>
    def.kind === "bool" ? typeof v === "boolean" : typeof v === "number" && Number.isInteger(v) && v >= def.min && v <= def.max;
  const loaded = store?.load() as { values?: Record<string, Partial<Stored>> } | null | undefined;
  const state: State = { values: {}, recent: [] }; // Recent changes stay in memory: the audit lines they link to do too.
  for (const def of DEFINITIONS) {
    const v = loaded?.values && typeof loaded.values === "object" ? loaded.values[def.key] : undefined;
    if (v && typeof v === "object" && fits(def, v.value) && typeof v.changed_at === "string" && typeof v.changed_by === "string") state.values[def.key] = v as Stored;
  }
  const view = (def: (typeof DEFINITIONS)[number]): SettingView => {
    const stored = state.values[def.key];
    return { ...def, min: "min" in def ? def.min : null, max: "max" in def ? def.max : null, value: stored?.value ?? def.default,
      changed_at: stored?.changed_at ?? null, changed_by: stored?.changed_by ?? null };
  };
  route("GET", "/api/v1/settings", "settings.manage", () => json({ items: DEFINITIONS.map(view), recent: state.recent.slice(0, 5) }));
  route("PATCH", "/api/v1/settings/{key}", "settings.manage", (params, _, body) => {
    const def = DEFINITIONS.find((d) => d.key === params.key);
    if (!def) return problem(404, "setting_not_found", "No such setting");
    const v = body.value;
    if (v === null) {
      // Null puts the setting back to its default.
      const old = state.values[def.key]?.value ?? null;
      state.values = Object.fromEntries(Object.entries(state.values).filter(([k]) => k !== def.key));
      state.recent.unshift({ at: iso(), actor, key: def.key, old, new: null });
      state.recent.length = Math.min(state.recent.length, 5);
      store?.save({ values: state.values });
      audit("settings.changed", def.key, "setting");
      return json(view(def));
    }
    if (!fits(def, v)) {
      const message = def.kind === "bool" ? "Use true or false" : `Use a whole number from ${def.min} to ${def.max}`;
      return problem(422, "invalid_setting", "The setting value is invalid", { field_errors: [{ field: "value", code: "invalid", message }] });
    }
    const old = state.values[def.key]?.value ?? null;
    state.values[def.key] = { value: v, changed_at: iso(), changed_by: actor };
    state.recent.unshift({ at: iso(), actor, key: def.key, old, new: v });
    state.recent.length = Math.min(state.recent.length, 5);
    store?.save({ values: state.values });
    audit("settings.changed", def.key, "setting");
    return json(view(def));
  });
  route("GET", "/api/v1/audit-events", "audit.read", (_, query) => {
    const since = Date.parse(query.get("since") ?? "");
    const prefix = query.get("action_prefix");
    if (Number.isNaN(since) || since > Date.now() || (prefix !== null && !/^[a-z_.]{1,64}$/.test(prefix))) return problem(400, "invalid_query", "Audit event query parameters are invalid");
    return json(page(data.audit.filter((event) => Date.parse(event.at) >= since && event.action.startsWith(prefix ?? "")), query));
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
  /** A setting's value, for the areas it governs (console_settings). */
  return { value: (key: (typeof DEFINITIONS)[number]["key"]) => view(DEFINITIONS.find((d) => d.key === key) ?? DEFINITIONS[0]).value };
}
