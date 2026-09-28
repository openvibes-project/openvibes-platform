// The rail (navigation) and the top bar (title, search, assistant, theme,
// account). Both stay out of the way: the rail is icons until hovered or
// pinned, and the top bar holds only what is used on every screen.
import { useEffect, useRef, useState } from "react";

import { isDemo } from "../api/client";
import { assistant, useAssistant } from "../app/assistant";
import { nav, useLocation } from "../app/nav";
import { views } from "../app/registry";
import { useSession } from "../app/session";
import { personas, type Persona } from "../demo/personas";
import { Icon } from "../ui/Icon";
import { setDensity, setTheme, useDensity, useTheme } from "./theme";

const pinKey = "openvibes.v2.rail.pinned";

export function Rail({ canView }: { canView: (path: string) => boolean }) {
  const { view } = useLocation();
  const [pinned, setPinned] = useState(() => { try { return localStorage.getItem(pinKey) === "true"; } catch { return false; } });
  const groups = ["Investigate", "Operate", "Administer"] as const;
  const base = import.meta.env.BASE_URL;
  return (
    <nav className={pinned ? "rail rail--pinned" : "rail"} aria-label="Main">
      <a className="rail__brand" href={nav.href("/")} onClick={(event) => { event.preventDefault(); nav.view("/"); }} aria-label="OpenVIBES home">
        <img className="rail__mark" src={`${base}brand/openvibes-mark.svg`} alt="" />
        <img className="rail__wordmark rail__wordmark--light" src={`${base}brand/openvibes-wordmark-light.svg`} alt="" />
        <img className="rail__wordmark rail__wordmark--dark" src={`${base}brand/openvibes-wordmark-dark.svg`} alt="" />
      </a>
      <div className="rail__groups">
        {groups.map((group) => {
          const items = views.filter((item) => item.group === group && canView(item.path));
          if (items.length === 0) return null;
          return (
            <div key={group} className="rail__group">
              <div className="rail__heading">{group}</div>
              {items.map((item) => (
                <a key={item.path} className="rail__item" href={nav.href(item.path)} aria-current={view === item.path ? "page" : undefined}
                  onClick={(event) => { if (event.metaKey || event.ctrlKey) return; event.preventDefault(); nav.view(item.path); }}>
                  <Icon name={item.icon} size={19} />
                  <span className="rail__label">{item.label}</span>
                  <span className="rail__tip" aria-hidden="true">{item.label}</span>
                </a>
              ))}
            </div>
          );
        })}
      </div>
      <button type="button" className="rail__item rail__pin" aria-pressed={pinned} onClick={() => setPinned((p) => { try { localStorage.setItem(pinKey, String(!p)); } catch { /* per viewer */ } return !p; })}>
        <Icon name="pin" size={17} /><span className="rail__label">{pinned ? "Unpin menu" : "Keep menu open"}</span>
      </button>
    </nav>
  );
}

export function TopBar({ title, onPalette, onLogout, persona, onPersona, onHelp }: {
  title: string;
  onPalette: () => void;
  onLogout: () => void;
  persona: Persona | undefined;
  onPersona: (persona: Persona) => void;
  onHelp: () => void;
}) {
  const { session, can } = useSession();
  const { open } = useAssistant();
  const theme = useTheme();
  const density = useDensity();
  const [menu, setMenu] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!menu) return;
    const close = (event: MouseEvent) => { if (!menuRef.current?.contains(event.target as Node)) setMenu(false); };
    window.addEventListener("mousedown", close);
    return () => window.removeEventListener("mousedown", close);
  }, [menu]);
  const nextTheme = theme === "dark" ? "light" : theme === "light" ? "system" : "dark";
  const initials = (session?.principal.display_name ?? "?").split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();

  return (
    <header className="topbar">
      <div className="topbar__title">{title}</div>
      <button type="button" className="topbar__search" onClick={onPalette}>
        <Icon name="search" size={15} />
        <span className="grow">Search or jump to…</span>
        <span className="kbd">Ctrl</span><span className="kbd">K</span>
      </button>
      <div className="topbar__actions">
        {isDemo() && <span className="badge badge--warn demo-badge" title="All data is synthetic and lives in your browser">Demo data</span>}
        {can("assistant.use") && (
          <button type="button" className={open ? "button button--small assistant-toggle assistant-toggle--on" : "button button--small assistant-toggle"} aria-pressed={open} onClick={() => assistant.toggle()} title="Assistant (Ctrl+J)">
            <Icon name="sparkles" size={15} /> Assistant
          </button>
        )}
        <button type="button" className="icon-button" onClick={() => setTheme(nextTheme)} aria-label={`Theme: ${theme}. Switch to ${nextTheme}`} title={`Theme: ${theme}`}>
          <Icon name={theme === "dark" ? "moon" : theme === "light" ? "sun" : "monitor"} size={17} />
        </button>
        <button type="button" className="icon-button" onClick={onHelp} aria-label="Keyboard shortcuts" title="Keyboard shortcuts (?)"><Icon name="help" size={17} /></button>
        <div className="menu" ref={menuRef}>
          <button type="button" className="avatar" aria-haspopup="menu" aria-expanded={menu} onClick={() => setMenu((m) => !m)} aria-label="Account">{initials}</button>
          {menu && (
            <div className="menu__pop" role="menu">
              <div className="menu__who">
                <strong>{session?.principal.display_name}</strong>
                <span className="subtle">{session?.principal.username ?? session?.principal.id}</span>
              </div>
              {persona && (
                <div className="menu__section">
                  <div className="section-title">View the demo as</div>
                  {personas.map((p) => (
                    <button key={p} type="button" role="menuitemradio" aria-checked={p === persona} className="menu__item" onClick={() => { onPersona(p); setMenu(false); }}>
                      {p === persona ? <Icon name="check" size={14} /> : <span style={{ width: 14 }} />} {p.replace("_", " ")}
                    </button>
                  ))}
                </div>
              )}
              <button type="button" role="menuitemcheckbox" aria-checked={density === "compact"} className="menu__item" onClick={() => setDensity(density === "compact" ? "comfortable" : "compact")}>
                {density === "compact" ? <Icon name="check" size={14} /> : <span style={{ width: 14 }} />} Compact rows
              </button>
              {!persona && <button type="button" role="menuitem" className="menu__item" onClick={onLogout}><Icon name="logout" size={14} /> Sign out</button>}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

export const shortcuts: readonly [string, string][] = [
  ["Ctrl K", "Search and commands"],
  ["Ctrl J", "Open or close the assistant"],
  ["/", "Filter the current list"],
  ["j / k", "Move through a list"],
  ["Enter", "Open the selected row"],
  ["x", "Select the row (bulk actions)"],
  ["Esc", "Close the top panel"],
  ...views.map((view) => [view.keys, `Go to ${view.label}`] as [string, string]),
  ["?", "This list"],
];

export function ShortcutHelp({ onClose }: { onClose: () => void }) {
  return (
    <div className="palette-backdrop" onMouseDown={onClose}>
      <div className="palette shortcuts" role="dialog" aria-modal="true" aria-label="Keyboard shortcuts" onMouseDown={(event) => event.stopPropagation()}
        onKeyDown={(event) => { if (event.key === "Escape") onClose(); }}>
        <div className="row row--between shortcuts__head"><h2>Keyboard shortcuts</h2><button type="button" className="icon-button" autoFocus aria-label="Close" onClick={onClose}><Icon name="close" size={16} /></button></div>
        <dl className="shortcuts__list">
          {shortcuts.map(([keys, label]) => (
            <div key={keys + label}><dt>{keys.split(" ").map((k) => <span key={k} className="kbd">{k}</span>)}</dt><dd>{label}</dd></div>
          ))}
        </dl>
      </div>
    </div>
  );
}
