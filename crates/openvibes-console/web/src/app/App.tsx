import { useEffect, useState } from "react";

import { LoginPage, SessionGate, type BrowserSession } from "./AuthPages";
import { Brand } from "../components/Brand";
import { HelpMenu } from "../components/HelpMenu";
import { SeededBanner } from "../components/SeededBanner";
import { ThemeControl } from "../components/ThemeControl";
import { AccessControlReadPage, AgentsReadPage, AuditEventsReadPage, FindingsReadPage, OverviewReadPage } from "./ReadPages";
import { canOpenPage, resolvePage, visibleNavigationGroups } from "./navigation";
import { EnrollmentPage } from "./Enrollment";
import { ServiceAccountsPage } from "./ServiceAccounts";
import { RuleSetsPage } from "./RuleSets";

type AppProps = {
  path?: string;
  seeded?: boolean;
};

function browserPath(): string {
  return typeof window === "undefined" ? "/" : window.location.pathname;
}

export function App({ path = browserPath(), seeded = false }: AppProps) {
  const [navigationCollapsed, setNavigationCollapsed] = useState(false);
  const page = resolvePage(path);
  const [session, setSession] = useState<BrowserSession>();
  const [authState, setAuthState] = useState<"checking" | "authenticated" | "unauthenticated" | "unavailable">(
    seeded ? "authenticated" : "checking",
  );
  const [logoutError, setLogoutError] = useState(false);
  const capabilities = session?.capabilities ?? [];
  const navigation = visibleNavigationGroups(capabilities, seeded);
  const pageAllowed = page !== undefined && canOpenPage(path, capabilities, seeded);

  useEffect(() => {
    document.title = path === "/login"
      ? "Sign in · OpenVIBES"
      : page === undefined ? "Page not found · OpenVIBES" : `${page.title} · OpenVIBES`;
  }, [page, path]);

  useEffect(() => {
    if (seeded || path === "/login" || page === undefined) return;
    const controller = new AbortController();
    void fetch("/api/v1/session", {
      cache: "no-store",
      credentials: "same-origin",
      signal: controller.signal,
    }).then(async (response) => {
      if (response.status === 401) {
        setSession(undefined);
        setAuthState("unauthenticated");
        return;
      }
      if (!response.ok) throw new Error("session unavailable");
      const current = await response.json() as BrowserSession;
      setSession(current);
      setAuthState("authenticated");
    }).catch(() => {
      if (!controller.signal.aborted) setAuthState("unavailable");
    });
    return () => controller.abort();
  }, [page, path, seeded]);

  async function logout() {
    if (session === undefined) return;
    setLogoutError(false);
    try {
      const response = await fetch("/auth/v1/logout", {
        method: "POST",
        cache: "no-store",
        credentials: "same-origin",
        headers: { "x-csrf-token": session.csrf_token },
      });
      if (response.status !== 204) throw new Error("logout failed");
      window.location.assign("/login");
    } catch {
      setLogoutError(true);
    }
  }

  if (path === "/login") return <LoginPage />;
  if (!seeded && page !== undefined && authState !== "authenticated") {
    return <SessionGate state={authState} />;
  }

  return (
    <div className={navigationCollapsed ? "app-shell app-shell--collapsed" : "app-shell"}>
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>

      <aside className="sidebar" aria-label="Primary navigation">
        <div className="sidebar__brand-row">
          <Brand compact={navigationCollapsed} />
          <button
            className="sidebar__collapse"
            type="button"
            aria-pressed={navigationCollapsed}
            onClick={() => setNavigationCollapsed((current) => !current)}
          >
            <span aria-hidden="true">{navigationCollapsed ? "›" : "‹"}</span>
            <span className="sr-only">
              {navigationCollapsed ? "Expand primary navigation" : "Collapse primary navigation"}
            </span>
          </button>
        </div>

        <nav id="primary-navigation" className="navigation" aria-label="Console">
          {navigation.map((group) => (
            <section className="navigation__group" key={group.label} aria-labelledby={`nav-${group.label}`}>
              <h2 id={`nav-${group.label}`} className="navigation__heading">
                {group.label}
              </h2>
              <ul className="navigation__list">
                {group.items.map((item) => (
                  <li key={item.path}>
                    <a
                      className="navigation__link"
                      href={item.path}
                      aria-current={path === item.path ? "page" : undefined}
                      aria-label={navigationCollapsed ? item.label : undefined}
                    >
                      <span className="navigation__short" aria-hidden="true">
                        {item.shortLabel}
                      </span>
                      <span className="navigation__text">{item.label}</span>
                    </a>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </nav>

        <div className="sidebar__footer">
          <span className="status-dot" aria-hidden="true" />
          <span className="sidebar__footer-text">Console shell</span>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <div>
            <span className="topbar__context">OpenVIBES</span>
            <span className="topbar__separator" aria-hidden="true">/</span>
            <span>Console</span>
          </div>
          <div className="topbar__actions">
            <ThemeControl />
            <HelpMenu />
            {!seeded && session !== undefined && <button className="topbar__logout" type="button" onClick={() => void logout()}>Sign out</button>}
          </div>
        </header>

        {logoutError && <p className="auth-inline-error" role="alert">Sign out could not be completed. Try again.</p>}
        {seeded && <SeededBanner />}

        <main id="main-content" className="main-content" tabIndex={-1}>
          {page === undefined ? (
            <section className="page page--not-found" aria-labelledby="page-title">
              <p className="eyebrow">Navigation</p>
              <h1 id="page-title">Page not found</h1>
              <p>The requested console page does not exist.</p>
              <a className="button-link" href="/">Return to Overview</a>
            </section>
          ) : !pageAllowed ? (
            <section className="page page--not-found" aria-labelledby="page-title">
              <p className="eyebrow">Access restricted</p>
              <h1 id="page-title">You do not have access to this page</h1>
              <p>Your current role does not include permission to view {page.title.toLowerCase()}.</p>
              <a className="button-link" href="/">Return to Overview</a>
            </section>
          ) : (
            <section className="page" aria-labelledby="page-title">
              <header className="page__header">
                <div>
                  <p className="eyebrow">{page.group}</p>
                  <h1 id="page-title">{page.title}</h1>
                  <p className="page__description">{page.description}</p>
                </div>
              </header>

              {path === "/" ? <OverviewReadPage seeded={seeded} /> : null}
              {path === "/agents" ? <AgentsReadPage seeded={seeded} csrfToken={session?.csrf_token} canManageTags={!seeded && session?.capabilities.some((capability) => capability.permission === "asset_groups.manage" && capability.scope.kind === "global") === true} canRevoke={!seeded && session?.capabilities.some((capability) => capability.permission === "agents.revoke") === true} /> : null}
              {path === "/enrollment" ? <EnrollmentPage csrfToken={session?.csrf_token} canRead={seeded || session?.capabilities.some((capability) => capability.permission === "tokens.read" && capability.scope.kind === "global") === true} canCreate={!seeded && session?.capabilities.some((capability) => capability.permission === "tokens.create" && capability.scope.kind === "global") === true} canRevoke={!seeded && session?.capabilities.some((capability) => capability.permission === "tokens.revoke" && capability.scope.kind === "global") === true} /> : null}
              {path === "/service-accounts" ? <ServiceAccountsPage csrfToken={session?.csrf_token} canRead={!seeded && session?.capabilities.some((capability) => capability.permission === "service_accounts.read" && capability.scope.kind === "global") === true} canManage={!seeded && session?.capabilities.some((capability) => capability.permission === "service_accounts.manage" && capability.scope.kind === "global") === true} /> : null}
              {path === "/rule-sets" ? <RuleSetsPage csrfToken={session?.csrf_token} canRead={!seeded && session?.capabilities.some((capability) => capability.permission === "rules.read" && capability.scope.kind === "global") === true} canUpload={!seeded && session?.capabilities.some((capability) => capability.permission === "rules.upload" && capability.scope.kind === "global") === true} /> : null}
              {path === "/findings" ? <FindingsReadPage seeded={seeded} csrfToken={session?.csrf_token} canTriage={!seeded && session?.capabilities.some((capability) => capability.permission === "findings.triage") === true} /> : null}
              {path === "/audit" ? <AuditEventsReadPage seeded={seeded} canExport={seeded || session?.capabilities.some((capability) => capability.permission === "audit.export" && capability.scope.kind === "global") === true} /> : null}
              {path === "/access" ? <AccessControlReadPage seeded={seeded} csrfToken={session?.csrf_token} canManage={!seeded && session?.capabilities.some((capability) => capability.permission === "rbac.manage" && capability.scope.kind === "global") === true} canManageGroups={!seeded && session?.capabilities.some((capability) => capability.permission === "asset_groups.manage" && capability.scope.kind === "global") === true} /> : null}
              {!["/", "/agents", "/enrollment", "/service-accounts", "/rule-sets", "/findings", "/audit", "/access"].includes(path) ? <div className="shell-panel">
                <div className="shell-panel__marker" aria-hidden="true">01</div>
                <div>
                  <p className="eyebrow">Interface foundation</p>
                  <h2>Workspace ready for bounded console data</h2>
                  <p>
                    This shell establishes navigation, theming, responsive structure, and accessible page
                    landmarks. Operational values appear only after their API contracts are connected.
                  </p>
                </div>
              </div> : null}
            </section>
          )}
        </main>
      </div>
    </div>
  );
}
