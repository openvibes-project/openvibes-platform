// Dashboards: the console's home. Shows the home dashboard at "/", any
// other at /dashboards/{id}; the built-in Overview is read-only.
import { useEffect, useState } from "react";

import { ApiError, invalidate, request, useResource } from "../api/client";
import type { AgentSummary, Dashboard, DashboardPage, HomeDashboard } from "../api/types";
import { nav, useLocation } from "../app/nav";
import { useSession } from "../app/session";
import { Empty, ErrorBox, Loading } from "../ui/bits";
import { plural } from "../ui/format";
import { Icon } from "../ui/Icon";
import { Confirm } from "../ui/panel";
import { toast } from "../ui/toast";
import { greeting } from "./attention";
import { BUILTIN_ID, BUILTIN_LAYOUT, BUILTIN_NAME } from "./builtin";
import { editor, useEditor } from "./editor";
import { Grid } from "./Grid";
import type { Layout } from "./layout";

const ROLES = ["viewer", "analyst", "operator", "admin"] as const;

export function DashboardsView() {
  const { view } = useLocation();
  const home = useResource<HomeDashboard>(view === "/" ? "/api/v1/me/home" : null);
  const id = view === "/" ? home.data === undefined ? undefined : home.data.dashboard_id ?? BUILTIN_ID : decodeURIComponent(view.slice("/dashboards/".length));
  if (view === "/" && home.loading && !home.data) return <Loading />;
  return <DashboardById id={id ?? BUILTIN_ID} />;
}

function DashboardById({ id }: { id: string }) {
  const builtin = id === BUILTIN_ID;
  const stored = useResource<Dashboard>(builtin ? null : `/api/v1/dashboards/${encodeURIComponent(id)}`);
  const state = useEditor();
  // Leaving this dashboard ends its edit, but never one that started on the next page.
  useEffect(() => () => { if (editor.state().dashboard?.dashboard_id === id) editor.cancel(); }, [id]);
  useEffect(() => {
    if (!state.dirty) return;
    nav.guard(() => !editor.state().dirty || window.confirm("Leave without saving your changes?"));
    return () => nav.guard(null);
  }, [state.dirty]);
  useEffect(() => {
    if (!state.dirty) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [state.dirty]);
  if (!builtin && stored.error) {
    return (
      <div className="view view-pad">
        {stored.error.status === 404
          ? <Empty icon="overview" title="This dashboard is gone">It was deleted, or it is no longer shared with you. <button type="button" className="link-button" onClick={() => nav.view("/")}>Go home</button></Empty>
          : <ErrorBox error={stored.error} />}
      </div>
    );
  }
  if (!builtin && !stored.data) return <Loading />;
  const dashboard = stored.data;
  const editing = state.draft !== null && state.dashboard?.dashboard_id === dashboard?.dashboard_id;
  const layout: Layout = editing && state.draft ? state.draft : builtin ? BUILTIN_LAYOUT : (dashboard?.layout as unknown as Layout);
  return (
    <div className="view">
      <Header dashboard={dashboard} builtin={builtin} editing={editing} />
      {editing && state.conflict && (
        <div className="view-note" role="alert">
          <Icon name="alert" size={14} /> Someone saved this dashboard since you opened it.
          <button type="button" className="button button--small" onClick={() => void editor.reloadTheirs()}>Reload theirs</button>
          <button type="button" className="button button--small" onClick={() => void editor.saveAsCopy().then((copy) => copy && nav.view(`/dashboards/${copy.dashboard_id}`))}>Save as a copy</button>
        </div>
      )}
      {editing && state.problems.length > 0 && (
        <ul className="view-note" role="alert">{state.problems.map((p) => <li key={p.field + p.code}><code>{p.field}</code>: {p.message}</li>)}</ul>
      )}
      <Grid layout={layout} editing={editing} />
    </div>
  );
}

function Header({ dashboard, builtin, editing }: { dashboard: Dashboard | undefined; builtin: boolean; editing: boolean }) {
  const { session, can } = useSession();
  const state = useEditor();
  const home = useResource<HomeDashboard>("/api/v1/me/home");
  const agents = useResource<AgentSummary>(builtin && can("agents.read") ? "/api/v1/agents/summary" : null);
  const [menu, setMenu] = useState(false);
  const id = builtin ? null : dashboard?.dashboard_id ?? null;
  const isHome = (home.data?.dashboard_id ?? null) === id;
  const mine = dashboard?.mine === true;
  const name = session?.principal.display_name.split(" ")[0];

  const duplicate = async () => {
    const copy = await request<Dashboard>("POST", "/api/v1/dashboards", { name: `Copy of ${builtin ? BUILTIN_NAME : dashboard?.name ?? ""}`.slice(0, 80), layout: builtin ? BUILTIN_LAYOUT : dashboard?.layout });
    invalidate("/api/v1/dashboards");
    nav.view(`/dashboards/${copy.dashboard_id}`);
    editor.begin(copy);
  };
  const setHome = async () => {
    await request("PUT", "/api/v1/me/home", { dashboard_id: id });
    invalidate("/api/v1/me/home");
    toast(isHome ? "Home unchanged" : "Set as home");
  };
  const share = async (roleId: string | null) => {
    if (!dashboard) return;
    await request("PUT", `/api/v1/dashboards/${dashboard.dashboard_id}/sharing`, { role_id: roleId });
    invalidate("/api/v1/dashboards");
    toast(roleId ? `Shared with ${roleId}` : "No longer shared");
  };
  const fail = (error: unknown) => toast(error instanceof ApiError ? error.message : "That did not work", true);

  return (
    <header className="view-header dashboard-header">
      <div className="view-header__top">
        <div className="view-header__title">
          {editing ? (
            <input className="input dashboard-name" aria-label="Dashboard name" value={state.name} onChange={(e) => editor.rename(e.target.value)} maxLength={80} />
          ) : builtin ? (
            <div><h1>{greeting()}{name ? `, ${name}` : ""}</h1>
              {agents.data && <p className="muted">{plural(agents.data.active, "host")} reporting{agents.data.stale > 0 ? `, ${agents.data.stale} stale` : ""}.</p>}</div>
          ) : (
            <div><h1>{dashboard?.name}</h1>{!mine && <p className="muted">Shared by {dashboard?.owner_display_name}{dashboard?.shared_role_id ? ` with ${dashboard.shared_role_id}` : ""}</p>}
              {mine && dashboard?.shared_role_id && <p className="muted">Shared with {dashboard.shared_role_id}</p>}</div>
          )}
        </div>
        <div className="row row--wrap">
          <DashboardSwitcher current={id} />
          {!editing && (
            <button type="button" className="icon-button" aria-pressed={isHome} aria-label={isHome ? "This is your home dashboard" : "Set as home"} title="Home dashboard"
              onClick={() => void setHome().catch(fail)}><Icon name="pin" size={16} /></button>
          )}
          {editing ? (
            <>
              <button type="button" className="button" onClick={() => nav.open({ kind: "widget-gallery", id: "new" }, true)}><Icon name="plus" size={15} /> Add widget</button>
              <button type="button" className="button button--ghost" onClick={() => { if (!state.dirty || window.confirm("Discard your changes?")) { editor.cancel(); nav.closeAll(); } }}>Cancel</button>
              <button type="button" className="button button--primary" disabled={state.saving} onClick={() => void editor.save().then((saved) => { if (saved) { nav.closeAll(); toast("Dashboard saved"); } })}>
                {state.saving ? "Saving…" : "Save"}</button>
            </>
          ) : mine && dashboard ? (
            <button type="button" className="button" onClick={() => editor.begin(dashboard)}><Icon name="filter" size={15} /> Edit</button>
          ) : (
            <button type="button" className="button" onClick={() => void duplicate().catch(fail)}><Icon name="copy" size={15} /> Duplicate to edit</button>
          )}
          {!editing && (
            <div className="menu">
              <button type="button" className="icon-button" aria-haspopup="menu" aria-expanded={menu} aria-label="Dashboard menu" onClick={() => setMenu((m) => !m)}><Icon name="chevronDown" size={16} /></button>
              {menu && (
                <div className="menu__pop" role="menu" onClick={() => setMenu(false)}>
                  <button type="button" role="menuitem" className="menu__item" onClick={() => void duplicate().catch(fail)}><Icon name="copy" size={14} /> Duplicate</button>
                  {mine && dashboard && <button type="button" role="menuitem" className="menu__item" onClick={() => { editor.begin(dashboard); setTimeout(() => document.querySelector<HTMLInputElement>(".dashboard-name")?.select(), 0); }}><Icon name="filter" size={14} /> Rename</button>}
                  {mine && can("dashboards.share", true) && (
                    <div className="menu__section">
                      <div className="section-title">Share with role</div>
                      {[null, ...ROLES].map((role) => (
                        <button key={role ?? "none"} type="button" role="menuitemradio" aria-checked={(dashboard?.shared_role_id ?? null) === role} className="menu__item"
                          onClick={() => void share(role).catch(fail)}>{(dashboard?.shared_role_id ?? null) === role ? <Icon name="check" size={14} /> : <span style={{ width: 14 }} />} {role ?? "Not shared"}</button>
                      ))}
                    </div>
                  )}
                  {mine && dashboard && (
                    <Confirm danger label={`Delete "${dashboard.name}"? People it is shared with lose it too.`} onConfirm={async () => {
                      await request("DELETE", `/api/v1/dashboards/${dashboard.dashboard_id}`);
                      invalidate("/api/v1/dashboards");
                      invalidate("/api/v1/me/home");
                      nav.view("/");
                      toast("Dashboard deleted");
                    }}><Icon name="close" size={14} /> Delete</Confirm>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

function DashboardSwitcher({ current }: { current: string | null }) {
  const list = useResource<DashboardPage>("/api/v1/dashboards");
  const [open, setOpen] = useState(false);
  const items = list.data?.items ?? [];
  // Every way out of an edited dashboard asks first, before anything happens.
  const leave = () => {
    if (editor.state().dirty && !window.confirm("Leave without saving your changes?")) return false;
    editor.cancel();
    return true;
  };
  const go = (target: string) => {
    if (leave()) nav.view(`/dashboards/${target}`);
  };
  const create = async () => {
    if (!leave()) return;
    const created = await request<Dashboard>("POST", "/api/v1/dashboards", { name: "Untitled dashboard", layout: { schema: 1, widgets: [] } });
    invalidate("/api/v1/dashboards");
    nav.view(`/dashboards/${created.dashboard_id}`);
    editor.begin(created);
    nav.open({ kind: "widget-gallery", id: "new" }, true);
  };
  const group = (label: string, rows: Dashboard[]) => rows.length > 0 && (
    <div className="menu__section"><div className="section-title">{label}</div>
      {rows.map((d) => <button key={d.dashboard_id} type="button" role="menuitemradio" aria-checked={current === d.dashboard_id} className="menu__item" onClick={() => go(d.dashboard_id)}>{d.name}</button>)}</div>
  );
  return (
    <div className="menu">
      <button type="button" className="button" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}><Icon name="overview" size={15} /> Dashboards <Icon name="chevronDown" size={14} /></button>
      {open && (
        <div className="menu__pop" role="menu" onClick={() => setOpen(false)}>
          <div className="menu__section"><div className="section-title">Built-in</div>
            <button type="button" role="menuitemradio" aria-checked={current === null} className="menu__item" onClick={() => go(BUILTIN_ID)}>{BUILTIN_NAME}</button></div>
          {group("Mine", items.filter((d) => d.mine))}
          {group("Shared with me", items.filter((d) => !d.mine))}
          <button type="button" role="menuitem" className="menu__item" onClick={() => void create().catch((error: unknown) => toast(error instanceof ApiError ? error.message : "Could not create", true))}>
            <Icon name="plus" size={14} /> New dashboard</button>
        </div>
      )}
    </div>
  );
}
