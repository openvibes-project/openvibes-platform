// An in-browser implementation of the console's /api/v1 over synthetic data,
// for the GitHub Pages preview, `?demo=1` and tests. It follows the wire
// contracts (types from the OpenAPI client) and the permission model, and
// keeps mutations in memory for the life of the page.
import { createDemoContext } from "./context";
import { MAX_PAGE, problem } from "./http";
import type { Persona } from "./personas";
import { registerAccessRoutes } from "./routes/access";
import { registerAlarmListRoute } from "./routes/alarmList";
import { registerAlarmRoutes } from "./routes/alarms";
import { registerAlarmSummaryRoute } from "./routes/alarmSummary";
import { registerAssetRoutes } from "./routes/assets";
import { registerAssistantRoutes } from "./routes/assistant";
import { registerCaseRoutes } from "./routes/cases";
import { registerDashboardRoutes } from "./routes/dashboards";
import { registerFindingRoutes } from "./routes/findings";
import { registerGroupRoutes } from "./routes/groups";
import { registerHostListRoutes } from "./routes/hostList";
import { registerHostRoutes } from "./routes/hosts";
import { registerHostSummaryRoute } from "./routes/hostSummary";
import { registerListRoutes } from "./routes/lists";
import { registerMetricRoutes } from "./routes/metrics";
import { registerRoleRoutes } from "./routes/roles";
import { registerRuleRoutes } from "./routes/rules";
import { registerSessionRoutes } from "./routes/session";
import { registerSettingsRoutes } from "./routes/settings";
import { registerTriageRoutes } from "./routes/triage";
import { registerVulnerabilityRoutes } from "./routes/vulnerabilities";
import { registerVulnListRoute } from "./routes/vulnList";
import { createSuppressions } from "./suppressions";

// Each area registers its routes on the shared context. A request takes the
// first route that matches, so within an area a fixed path such as
// /cases/assignees comes before /cases/{id}.
export function createDemoServer({ persona = "admin" as Persona, now = Date.now() } = {}) {
  const ctx = createDemoContext({ persona, now });
  const { permissions, routes } = ctx;
  registerSessionRoutes(ctx);
  registerHostRoutes(ctx);
  registerHostListRoutes(ctx);
  registerHostSummaryRoute(ctx);
  registerListRoutes(ctx);
  registerFindingRoutes(ctx);
  const settings = registerSettingsRoutes(ctx);
  const suppressions = createSuppressions(ctx, () => settings.value("suppressions.require_approval") === true);
  registerAlarmRoutes({ ...ctx, suppressions });
  registerAssetRoutes(ctx);
  registerVulnerabilityRoutes(ctx);
  registerVulnListRoute(ctx);
  registerMetricRoutes(ctx);
  const roles = registerRoleRoutes(ctx);
  registerAccessRoutes({ ...ctx, roles });
  registerGroupRoutes({ ...ctx, roles, suppressions, ...registerRuleRoutes(ctx) });
  registerAssistantRoutes(ctx);
  registerDashboardRoutes(ctx);
  const cases = registerCaseRoutes(ctx);
  registerAlarmListRoute({ ...ctx, cases });
  registerAlarmSummaryRoute({ ...ctx, cases });
  registerTriageRoutes({ ...ctx, cases, suppressions });

  return {
    persona,
    /** The demo data, for tests that add to it. */
    data: ctx.data,
    async handle(method: string, url: string, body?: unknown, headers: Record<string, string> = {}): Promise<Response> {
      const parsed = new URL(url, "http://demo");
      const limit = parsed.searchParams.get("limit");
      if (limit !== null && !(Number.isInteger(Number(limit)) && Number(limit) >= 1 && Number(limit) <= MAX_PAGE)) {
        return problem(400, "invalid_pagination", "limit must be between 1 and 100");
      }
      for (const candidate of routes) {
        if (candidate.method !== method) continue;
        const match = candidate.pattern.exec(parsed.pathname);
        if (!match) continue;
        if (candidate.permission !== null && !permissions.includes(candidate.permission)) {
          return problem(403, "forbidden", "Your role does not allow this");
        }
        const params = Object.fromEntries(candidate.keys.map((key, index) => [key, decodeURIComponent(match[index + 1] ?? "")]));
        const lower = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
        return candidate.handler(params, parsed.searchParams, (body ?? {}) as Record<string, unknown>, lower);
      }
      return problem(404, "not_found", "No such endpoint");
    },
  };
}
