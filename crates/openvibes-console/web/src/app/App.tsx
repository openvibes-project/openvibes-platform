import { useEffect, useState } from "react";

import { LoginPage, SessionGate, type BrowserSession } from "./AuthPages";
import { Brand } from "../components/Brand";
import { HelpMenu } from "../components/HelpMenu";
import { SeededBanner } from "../components/SeededBanner";
import { ThemeControl } from "../components/ThemeControl";
import { AccessControlReadPage, AgentsReadPage, AuditEventsReadPage, FindingsReadPage, OverviewReadPage } from "./ReadPages";
import { navigationGroups, resolvePage } from "./navigation";

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
          {navigationGroups.map((group) => (
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
              {path === "/agents" ? <AgentsReadPage seeded={seeded} /> : null}
              {path === "/findings" ? <FindingsReadPage seeded={seeded} /> : null}
              {path === "/audit" ? <AuditEventsReadPage seeded={seeded} canExport={seeded || session?.capabilities.some((capability) => capability.permission === "audit.export" && capability.scope.kind === "global") === true} /> : null}
              {path === "/access" ? <AccessControlReadPage seeded={seeded} /> : null}
              {!["/", "/agents", "/findings", "/audit", "/access"].includes(path) ? <div className="shell-panel">
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
