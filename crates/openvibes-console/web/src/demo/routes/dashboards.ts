// Dashboards and each user's home dashboard.
import { createDashboardStore } from "../dashboards";
import type { DemoContext } from "../context";
import { browserPersistence } from "../http";

export function registerDashboardRoutes(ctx: DemoContext) {
  const { data, scoped, actor, me, permissions, route, send } = ctx;
  const dashboards = createDashboardStore(
    data.dashboards,
    (userId) => (scoped && userId === `u-${actor}` ? ["operator"] : data.access.bindings.filter((b) => b.user_id === userId).map((b) => b.role_id)),
    (userId) => data.access.users.find((u) => u.user_id === userId)?.display_name ?? userId,
    browserPersistence("openvibes.v2.demo.dashboards"),
  );
  route("GET", "/api/v1/dashboards", null, () => send(dashboards.list(me)));
  route("POST", "/api/v1/dashboards", null, (_, __, body) => send(dashboards.create(me, body)));
  route("GET", "/api/v1/dashboards/{id}", null, ({ id = "" }) => send(dashboards.get(me, id)));
  route("PUT", "/api/v1/dashboards/{id}", null, ({ id = "" }, _, body, headers) => send(dashboards.update(me, id, body, headers["if-match"])));
  route("DELETE", "/api/v1/dashboards/{id}", null, ({ id = "" }) => send(dashboards.remove(me, id)));
  route("PUT", "/api/v1/dashboards/{id}/sharing", null, ({ id = "" }, _, body) =>
    send(dashboards.share(me, id, body.role_id ?? null, permissions.includes("dashboards.share"), data.access.roles.map((r) => r.role_id))));
  route("GET", "/api/v1/me/home", null, () => send(dashboards.home(me)));
  route("PUT", "/api/v1/me/home", null, (_, __, body) => send(dashboards.setHome(me, body.dashboard_id ?? null)));
}
