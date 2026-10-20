// The session, password changes and the About page.
import type { DemoContext } from "../context";
import { json, problem } from "../http";

/** The latest agent release the demo's update check reports (about/update). */
export const LATEST_AGENT_VERSION = "0.4.2";

export function registerSessionRoutes(ctx: DemoContext) {
  const { data, iso, actor, capabilities, audit, route } = ctx;
  route("GET", "/api/v1/session", null, () => json({
    principal: { id: `u-${actor}`, display_name: data.access.users.find((u) => u.username === actor)?.display_name ?? actor, username: actor },
    capabilities, csrf_token: "demo-csrf", authentication_level: "single_factor", authentication_method: "local_password",
    idle_expires_at: iso(Date.now() + 30 * 60_000), absolute_expires_at: iso(Date.now() + 12 * 3_600_000),
    password_must_change: false,
  }));
  // The demo has no real passwords: any change of at least 15 new characters succeeds.
  route("POST", "/api/v1/session/password", null, (_, __, body) => {
    const next = String(body.new_password ?? "");
    if (next.length < 15) return problem(400, "weak_password", "Use at least 15 characters for the new password");
    if (next === String(body.current_password ?? "")) return problem(400, "password_unchanged", "Choose a password different from the current one");
    audit("auth.password.changed", `u-${actor}`, "user");
    return new Response(null, { status: 204 });
  });
  route("GET", "/api/v1/about", null, () => json({ platform_version: "0.4.2", schema_version: 33, applied_schema_version: 33, database_version: "16.4", web_ui_embedded: true, platform: "linux x86_64", started_at: new Date(Date.now() - 3 * 86_400_000).toISOString(), fleet: { active: 42, online: 39, revoked: 2, newest_agent_version: "0.4.2" }, certificates: [{ role: "root", not_after: new Date(Date.now() + 3000 * 86_400_000).toISOString() }, { role: "intermediate", not_after: new Date(Date.now() + 20 * 86_400_000).toISOString() }], feeds: [{ source: "fedora-44-x86_64", advisories: 1840, last_checked_at: new Date(Date.now() - 3_600_000).toISOString(), last_changed_at: new Date(Date.now() - 86_400_000).toISOString(), failing: false }, { source: "rhel-9-x86_64", advisories: 920, last_checked_at: new Date(Date.now() - 7_200_000).toISOString(), last_changed_at: null, failing: true }] }));
  route("GET", "/api/v1/about/update", null, () => json({ state: "available", latest_version: "0.4.3", release_url: "https://github.com/openvibes-project/openvibes-platform/releases/tag/v0.4.3", latest_agent_version: LATEST_AGENT_VERSION }));
}
