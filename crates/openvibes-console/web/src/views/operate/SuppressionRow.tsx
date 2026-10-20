// One suppression on the Alarm suppressions page (approved screen 14): the
// command, What/Where/For chips, the quoted reason, who asked and when, what
// a waiting request would have closed, the status badge, Open alarm and the
// actions its flags allow. Every action is busy until it returns.
import { useEffect, useRef, useState } from "react";

import { apiMessage, invalidate, request } from "../../api/client";
import type { AlarmSuppression } from "../../api/types";
import { useSession } from "../../app/session";
import { type SuppressFields, SuppressDialog } from "../../panels/alarms/SuppressForm";
import { ObjectLink } from "../../ui/bits";
import { ago } from "../../ui/format";
import { Confirm } from "../../ui/panel";
import { toast } from "../../ui/toast";

const path = (id: string, action = "") => `/api/v1/alarm-suppressions/${encodeURIComponent(id)}${action}`;

/** Sends one action, then reloads the list (and with it the menu count) and recent changes. */
async function act(method: string, url: string, body?: unknown) {
  await request(method, url, body);
  invalidate("/api/v1/alarm");
  invalidate("/api/v1/audit-events");
  toast("Saved · recorded in the audit log");
}

const STATUS: Record<string, [string, string]> = {
  waiting: ["Waiting", "badge--warn"], active: ["Active", "badge--ok"], expired: ["Expired", "badge--outline"], rejected: ["Rejected", "badge--bad"],
};
const whereText = (s: AlarmSuppression) =>
  s.where.kind === "host" ? s.where.hostname ?? s.where.agent_id ?? "a host"
    : s.where.kind === "group" ? s.where.group_name ?? "a deleted group"
      : s.where.kind === "all" ? "All hosts" : "a device";
const whatText = (what: string) => what === "program" ? "Program" : what === "command" ? "Exact command" : what.charAt(0).toUpperCase() + what.slice(1);

/** The suppress form's fields from a rejected row, for "Ask again…"; a deleted group stays `group:` so the form says it is gone. */
export function again(s: AlarmSuppression): Partial<SuppressFields> {
  const where = s.where.kind === "group" ? `group:${s.where.group_id ?? ""}` : s.where.kind === "all" ? "all" : "host";
  return { ...(s.what === "command" || s.what === "program" ? { what: s.what } : {}), where, forDays: s.for_days ?? null, reason: s.reason };
}

/** The inline reject: a required reason, Reject disabled until it is given. */
export function RejectForm({ id, initial = "", onDone, onCancel }: { id: string; initial?: string; onDone: () => void; onCancel: () => void }) {
  const [reason, setReason] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const submit = () => {
    setBusy(true);
    setError(undefined);
    act("POST", path(id, "/reject"), { reason: reason.trim() }).then(onDone, (e: unknown) => { setError(apiMessage(e, "Reject failed")); setBusy(false); });
  };
  return (
    <form className="stack suppression-row__reject" onSubmit={(e) => { e.preventDefault(); if (!busy && reason.trim()) submit(); }}>
      <label className="field">Reason (required)
        <textarea className="textarea" rows={2} maxLength={4000} autoFocus value={reason} disabled={busy} onChange={(e) => setReason(e.target.value)} placeholder="Why it is rejected" />
      </label>
      {error && <p className="confirm__error" role="alert">{error}</p>}
      <div className="row">
        <button type="submit" className="button button--small button--danger" disabled={busy || !reason.trim()}>Reject</button>
        <button type="button" className="button button--small button--ghost" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

/** `focus` puts focus on the row (after it moved to another card); `onDone` reports an action, `gone` when the row leaves the page. */
export function SuppressionRow({ s, focus, onDone }: { s: AlarmSuppression; focus: boolean; onDone: (id: string, gone: boolean) => void }) {
  const { can } = useSession();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [rejecting, setRejecting] = useState(false);
  const [asking, setAsking] = useState(false);
  const self = useRef<HTMLLIElement>(null);
  const rejectButton = useRef<HTMLButtonElement>(null);
  const cancelled = useRef(false);
  useEffect(() => { if (focus) self.current?.focus(); }, [focus, s.status]);
  useEffect(() => { if (!rejecting && cancelled.current) { cancelled.current = false; rejectButton.current?.focus(); } }, [rejecting]);
  const run = (method: string, action: string, gone: boolean) => {
    setBusy(true);
    setError(undefined);
    act(method, path(s.id, action)).then(() => onDone(s.id, gone), (e: unknown) => setError(apiMessage(e, "The change failed"))).finally(() => setBusy(false));
  };
  const [label, tone] = STATUS[s.status] ?? [s.status, "badge--outline"];
  const n = s.would_close;
  const name = s.exe ?? s.rule_id;
  return (
    <li className="stack suppression-row" data-id={s.id} tabIndex={-1} ref={self}>
      <div className="row row--between">
        <span className="mono">{name}</span>
        <span className={`badge badge--plain ${tone}`}>{label}</span>
      </div>
      <div className="row suppression-row__chips">
        <span className="badge badge--outline">What: {whatText(s.what)}</span>
        <span className="badge badge--outline">Where: {whereText(s)}</span>
        <span className="badge badge--outline">For: {s.for_days ? `${s.for_days} days` : "Until removed"}</span>
      </div>
      <span>“{s.reason}”</span>
      <span className="subtle">asked by {s.requested_by} · {ago(s.requested_at)}</span>
      {s.status === "waiting" && n != null && (
        <span className="subtle">Would have closed {s.would_close_capped ? "at least " : ""}{n.toLocaleString("en-US")} {n === 1 ? "alarm" : "alarms"} in the last 7 days</span>
      )}
      {s.status === "rejected" && <span>Rejected by {s.decided_by ?? "someone"}: “{s.decision_reason ?? ""}”</span>}
      {error && <p className="confirm__error" role="alert">{error}</p>}
      {rejecting ? <RejectForm id={s.id} onDone={() => onDone(s.id, false)} onCancel={() => { cancelled.current = true; setRejecting(false); }} /> : (
        <div className="row suppression-row__actions">
          {s.alarm_id && <ObjectLink to={{ kind: "alarm", id: s.alarm_id }}>Open alarm</ObjectLink>}
          {s.can_decide && <button type="button" className="button button--small button--primary" aria-label={`Approve ${name}`} disabled={busy} onClick={() => run("POST", "/approve", false)}>Approve</button>}
          {s.can_decide && <button type="button" className="button button--small" ref={rejectButton} aria-label={`Reject… ${name}`} disabled={busy} onClick={() => setRejecting(true)}>Reject…</button>}
          {s.can_withdraw && <button type="button" className="button button--small" aria-label={`Withdraw ${name}`} disabled={busy} onClick={() => run("POST", "/withdraw", true)}>Withdraw</button>}
          {s.can_remove && (
            <Confirm danger buttonLabel={`Remove… ${name}`} label="Remove it? Matching alarms raise again from now on." onConfirm={async () => { await act("DELETE", path(s.id)); onDone(s.id, true); }}>Remove…</Confirm>
          )}
          {s.status === "rejected" && s.alarm_id && can("alarms.suppress") && <button type="button" className="button button--small" aria-label={`Ask again… ${name}`} onClick={() => setAsking(true)}>Ask again…</button>}
        </div>
      )}
      {asking && s.alarm_id && <SuppressDialog alarmId={s.alarm_id} initial={again(s)} onClose={() => setAsking(false)} />}
    </li>
  );
}
