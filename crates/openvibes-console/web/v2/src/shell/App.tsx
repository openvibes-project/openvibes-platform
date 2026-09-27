import { useCallback, useEffect, useMemo, useState } from "react";

import { ApiError, configureDemo, onSignedOut, request, setCsrfToken } from "../api/client";
import type { Permission, Session } from "../api/types";
import { assistant } from "../app/assistant";
import { nav, useLocation } from "../app/nav";
import { views } from "../app/registry";
import { SessionContext, allows } from "../app/session";
import type { Persona } from "../demo/server";
import { Empty } from "../ui/bits";
import { Icon } from "../ui/Icon";
import { Toasts } from "../ui/toast";
import { AssistantDock } from "./AssistantDock";
import { Rail, ShortcutHelp, TopBar } from "./Chrome";
import { CommandPalette, rememberRecent } from "./CommandPalette";
import { Inspector, WindowLayer } from "./Frames";
import { SignIn } from "./SignIn";

const personaKey = "openvibes.v2.persona";
function readPersona(): Persona {
  try {
    const value = localStorage.getItem(personaKey);
    return value === "viewer" || value === "analyst" || value === "operator" || value === "scoped_operator" ? value : "admin";
  } catch {
    return "admin";
  }
}

export function App({ demo: startDemo }: { demo: boolean }) {
  const [persona, setPersona] = useState<Persona | undefined>(() => (startDemo ? readPersona() : undefined));
  const [session, setSession] = useState<Session>();
  const [auth, setAuth] = useState<"loading" | "ok" | "signin" | "down">("loading");
  const [palette, setPalette] = useState(false);
  const [help, setHelp] = useState(false);
  const { view, panels } = useLocation();

  useEffect(() => {
    configureDemo(persona);
    request<Session>("GET", "/api/v1/session").then((current) => {
      setSession(current);
      setCsrfToken(current.csrf_token);
      setAuth("ok");
    }, (error: unknown) => setAuth(error instanceof ApiError && error.status === 401 ? "signin" : "down"));
  }, [persona]);

  useEffect(() => onSignedOut(() => setAuth("signin")), []);

  const can = useCallback((permission: Permission, global = false) => allows(session, { permission, global }), [session]);
  const canView = useCallback((path: string) => views.find((v) => v.path === path)?.access.some((a) => can(a.permission, a.global)) === true, [can]);
  const context = useMemo(() => ({ session, demo: persona !== undefined, can }), [session, persona, can]);
  const current = views.find((v) => v.path === view);
  const top = panels[panels.length - 1];

  useEffect(() => { if (top) rememberRecent(top); }, [top]);
  useEffect(() => { document.title = `${current?.label ?? "OpenVIBES"} · OpenVIBES`; }, [current]);

  useEffect(() => {
    let pending = "";
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onKey = (event: KeyboardEvent) => {
      const typing = event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement || event.target instanceof HTMLSelectElement;
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setPalette((p) => !p); return; }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "j") { event.preventDefault(); assistant.toggle(); return; }
      if (typing || event.ctrlKey || event.metaKey || event.altKey) return;
      if (event.key === "?") { setHelp(true); return; }
      const sequence = pending ? `${pending} ${event.key}` : event.key;
      const match = views.find((v) => v.keys === sequence && canView(v.path));
      if (match) { nav.view(match.path); pending = ""; return; }
      if (views.some((v) => v.keys.startsWith(`${sequence} `))) {
        pending = sequence;
        clearTimeout(timer);
        timer = setTimeout(() => { pending = ""; }, 900);
      } else pending = "";
    };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); clearTimeout(timer); };
  }, [canView]);

  const choosePersona = (next: Persona) => {
    try { localStorage.setItem(personaKey, next); } catch { /* per viewer */ }
    setAuth("loading");
    setPersona(next);
  };
  const logout = () => {
    request("POST", "/auth/v1/logout").finally(() => window.location.reload());
  };

  if (auth === "signin") return <SignIn onDemo={() => choosePersona("admin")} />;
  if (auth === "down") {
    return (
      <main className="signin">
        <div className="signin__card">
          <Empty icon="alert" title="The console is not reachable">Check that openvibes-console is running, then reload.</Empty>
          <button type="button" className="button" onClick={() => choosePersona("admin")}>Explore the demo instead</button>
        </div>
      </main>
    );
  }
  if (auth === "loading" || !session) return <div className="boot" aria-busy="true"><img src={`${import.meta.env.BASE_URL}brand/openvibes-mark.svg`} alt="" /></div>;

  const allowed = current !== undefined && canView(current.path);
  const firstAllowed = views.find((v) => canView(v.path));
  return (
    <SessionContext.Provider value={context}>
      <a className="skip-link" href="#main">Skip to content</a>
      <div className="app">
        <Rail canView={canView} />
        <div className="app__main">
          <TopBar title={current?.label ?? "Not found"} onPalette={() => setPalette(true)} onLogout={logout} persona={persona} onPersona={choosePersona} onHelp={() => setHelp(true)} />
          <div className="workspace">
            <main id="main" className="view-area" tabIndex={-1}>
              {allowed ? current.render() : (
                <Empty icon={current ? "ban" : "alert"} title={current ? "Not available with your role" : "Page not found"}>
                  {current ? "Ask an administrator for access. " : "This address does not exist. "}
                  {firstAllowed && <button type="button" className="link-button" onClick={() => nav.view(firstAllowed.path)}>Go to {firstAllowed.label}</button>}
                </Empty>
              )}
            </main>
            <Inspector />
            <AssistantDock />
          </div>
        </div>
      </div>
      <WindowLayer />
      {palette && <CommandPalette onClose={() => setPalette(false)} canView={canView} />}
      {help && <ShortcutHelp onClose={() => setHelp(false)} />}
      <Toasts />
      {persona && persona !== "admin" && (
        <div className="persona-note"><Icon name="user" size={13} /> Viewing as <strong>{persona.replace("_", " ")}</strong></div>
      )}
    </SessionContext.Provider>
  );
}
