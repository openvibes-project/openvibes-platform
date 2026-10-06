// Small shared pieces: badges, object links, loading/empty/error states.
import type { MouseEvent, ReactNode } from "react";

import type { ApiError } from "../api/client";
import { nav } from "../app/nav";
import type { PanelRef } from "../app/location";
import { ago, triageLabel, when } from "./format";
import { Icon, type IconName } from "./Icon";

const severityText: Record<string, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low",
  important: "Important", moderate: "Moderate", unrated: "Unrated",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge--${severity}`}>{severityText[severity] ?? severity}</span>;
}

/** A 0 to 100 % bar for how sure a mapping is. */
export function ConfidenceBar({ value, wide }: { value: number; wide?: boolean }) {
  const percent = Math.max(0, Math.min(100, Math.round(value)));
  return (
    <span className="row" title={`${percent}% confidence`}>
      <span className={`meter${wide ? " meter--wide" : ""}`} role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent} aria-label="Confidence"><span style={{ width: `${percent}%` }} /></span>
      <span className="num">{percent}%</span>
    </span>
  );
}

const statusTone: Record<string, string> = { active: "ok", stale: "warn", revoked: "bad", imported: "info" };
const statusText: Record<string, string> = { active: "Online", stale: "Stale", revoked: "Revoked", imported: "Imported" };

export function StatusBadge({ status }: { status: string }) {
  return <span className={`badge badge--${statusTone[status] ?? "plain"}`}>{statusText[status] ?? status}</span>;
}

const triageTone: Record<string, string> = { open: "bad", investigating: "warn", mitigated: "ok", accepted_risk: "info", false_positive: "plain" };

export function TriageBadge({ state }: { state: string }) {
  return <span className={`badge badge--${triageTone[state] ?? "plain"}`}>{triageLabel[state] ?? state}</span>;
}

export const SAVED_HEARTBEAT_HINT = "The agent sends a heartbeat about every minute. The platform saves this time about every five minutes, so an online host can show several minutes ago.";

export function Ago({ value, hint }: { value: string | number | null | undefined; hint?: string }) {
  return <time className="nowrap" title={hint ? `${when(value)}\n${hint}` : when(value)} dateTime={typeof value === "string" ? value : undefined}>{ago(value)}</time>;
}

/** A link that opens an object in the inspector (a new stack from lists). */
export function ObjectLink({ to, children, fromList = false, className }: { to: PanelRef; children: ReactNode; fromList?: boolean; className?: string }) {
  const onClick = (event: MouseEvent) => {
    if (event.metaKey || event.ctrlKey || event.shiftKey) return;
    event.preventDefault();
    event.stopPropagation();
    nav.open(to, fromList);
  };
  const params = new URLSearchParams(nav.location.params);
  params.append("open", `${to.kind}:${to.id}`);
  return <a className={className ?? "object-link"} href={`?${params.toString()}`} onClick={onClick}>{children}</a>;
}

export function Loading({ rows = 6 }: { rows?: number }) {
  return (
    <div className="stack" style={{ padding: 16 }} aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, index) => <div key={index} className="skeleton" style={{ width: `${90 - (index % 3) * 18}%` }} />)}
    </div>
  );
}

export function Empty({ icon = "check", title, children }: { icon?: IconName; title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <Icon name={icon} size={28} />
      <h3>{title}</h3>
      {children && <p>{children}</p>}
    </div>
  );
}

export function ErrorBox({ error }: { error: ApiError }) {
  const hint = error.status === 403
    ? "Your role does not include this. An administrator can grant it under Access."
    : error.status === 0 ? "Check that the console service is running and reachable." : "Try again in a moment.";
  return (
    <div className="error-box" role="alert">
      <Icon name="alert" />
      <div><strong>{error.message}</strong><div>{hint}</div></div>
    </div>
  );
}

export function Stat({ label, value, tone, onClick, hint }: { label: string; value: ReactNode; tone?: string | undefined; onClick?: () => void; hint?: string }) {
  const body = (
    <>
      <span className="stat__label">{label}</span>
      <span className={`stat__value num${tone ? ` stat__value--${tone}` : ""}`}>{value}</span>
      {hint && <span className="stat__hint">{hint}</span>}
    </>
  );
  return onClick
    ? <button type="button" className="stat stat--link" onClick={onClick}>{body}</button>
    : <div className="stat">{body}</div>;
}
