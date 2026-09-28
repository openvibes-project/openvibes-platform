import { type ReactNode, useState } from "react";

import { assistant } from "../app/assistant";
import type { PanelRef } from "../app/location";
import { useSession } from "../app/session";
import { Icon, type IconName } from "./Icon";

export function PanelHeader({ icon, kind, title, subtitle, badges, actions, askAbout }: {
  icon: IconName;
  kind: string;
  title: ReactNode;
  subtitle?: ReactNode;
  badges?: ReactNode;
  actions?: ReactNode;
  askAbout?: { ref: PanelRef; label: string };
}) {
  const { can } = useSession();
  return (
    <header className="panel-header">
      <div className="panel-header__kind"><Icon name={icon} size={14} /> {kind}</div>
      <h2 className="panel-header__title">{title}</h2>
      {subtitle && <div className="panel-header__subtitle">{subtitle}</div>}
      {badges && <div className="row row--wrap panel-header__badges">{badges}</div>}
      {(actions || (askAbout && can("assistant.use"))) && (
        <div className="row row--wrap panel-header__actions">
          {askAbout && can("assistant.use") && (
            <button type="button" className="button button--small" onClick={() => assistant.askAbout(askAbout.ref, askAbout.label)}>
              <Icon name="sparkles" size={14} /> Ask about this
            </button>
          )}
          {actions}
        </div>
      )}
    </header>
  );
}

export function Section({ title, action, children, flush }: { title: string; action?: ReactNode; children: ReactNode; flush?: boolean }) {
  return (
    <section className={flush ? "panel-section panel-section--flush" : "panel-section"}>
      <div className="panel-section__head">
        <h3 className="section-title">{title}</h3>
        {action}
      </div>
      {children}
    </section>
  );
}

export function Tabs<T extends string>({ tabs, children }: { tabs: readonly { id: T; label: string; count?: number | undefined }[]; children: (active: T) => ReactNode }) {
  const [active, setActive] = useState<T>(tabs[0]?.id as T);
  return (
    <>
      <div className="tabs" role="tablist">
        {tabs.map((tab) => (
          <button key={tab.id} type="button" role="tab" aria-selected={tab.id === active} onClick={() => setActive(tab.id)}>
            {tab.label}
            {tab.count !== undefined && <span className="tabs__count num">{tab.count.toLocaleString()}</span>}
          </button>
        ))}
      </div>
      <div role="tabpanel">{children(active)}</div>
    </>
  );
}

/** An inline confirmation (with an optional reason) instead of a modal dialog. */
export function Confirm({ label, danger, reason, onConfirm, children }: {
  label: string;
  danger?: boolean;
  reason?: string;
  onConfirm: (reason: string) => Promise<void>;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  if (!open) {
    return <button type="button" className={`button button--small${danger ? " button--danger" : ""}`} onClick={() => setOpen(true)}>{children}</button>;
  }
  return (
    <form className="confirm" onSubmit={(event) => {
      event.preventDefault();
      setBusy(true);
      setError(undefined);
      onConfirm(text.trim()).then(() => setOpen(false), (reasonError: unknown) => setError(reasonError instanceof Error ? reasonError.message : "Failed")).finally(() => setBusy(false));
    }}>
      <p className="confirm__text">{label}</p>
      {reason && <input className="input" autoFocus required placeholder={reason} value={text} onChange={(event) => setText(event.target.value)} aria-label={reason} />}
      {error && <p className="confirm__error" role="alert">{error}</p>}
      <div className="row">
        <button type="submit" className={`button button--small ${danger ? "button--danger" : "button--primary"}`} disabled={busy || (reason !== undefined && text.trim() === "")}>
          {busy ? "Working…" : "Confirm"}
        </button>
        <button type="button" className="button button--small button--ghost" onClick={() => setOpen(false)}>Cancel</button>
      </div>
    </form>
  );
}
