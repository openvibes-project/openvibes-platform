// "Suppress…" (approved screen 12): stop alarming on this program or this
// exact command, on this host, a group the role reaches or all hosts, for
// 7 days, 30 days or until removed, with a required reason. With approval
// on, the request waits for someone who can approve on those hosts.
import { useState } from "react";

import { ApiError, apiMessage, invalidate, request, useResource } from "../../api/client";
import type { AlarmDetail, AlarmProcess, AlarmSummary, AlarmSuppression, AlarmSuppressionOptions } from "../../api/types";
import { useSession } from "../../app/session";
import { ErrorBox } from "../../ui/bits";
import { SelectField } from "../../ui/Field";
import { Icon } from "../../ui/Icon";
import { Segmented } from "../../ui/Segmented";
import { Select } from "../../ui/Select";
import { toast } from "../../ui/toast";
import { DialogHead, Modal } from "../../views/admin/people/NewPersonDialog";

/** The alarm a suppression is derived from. */
export type SuppressSource = { id: string; host: string; exe: string; args: string[] };
/** The form's choices; `where` is `host`, `all` or `group:<id>`. */
export type SuppressFields = { what: "program" | "command"; where: string; forDays: number | null; reason: string };

/** This host, then each group the role reaches, then all hosts when allowed. */
export function whereChoices(source: SuppressSource, options: AlarmSuppressionOptions) {
  return [
    { value: "host", label: `This host (${source.host})` },
    ...options.groups.map((g) => ({ value: `group:${g.id}`, label: g.name })),
    ...(options.all_hosts ? [{ value: "all", label: "All hosts" }] : []),
  ];
}

/** The POST /api/v1/alarm-suppressions body. */
export function bodyOf(alarmId: string, f: SuppressFields) {
  const where = f.where === "host" || f.where === "all" ? { kind: f.where } : { kind: "group", group_id: f.where.slice("group:".length) };
  return { alarm_id: alarmId, what: f.what, where, for_days: f.forDays, reason: f.reason.trim() };
}

const FOR = [{ value: "7", label: "7 days" }, { value: "30", label: "30 days" }, { value: "", label: "Until removed" }];

export function SuppressForm({ source, options, initial, onClose }: {
  source: SuppressSource; options: AlarmSuppressionOptions; initial?: Partial<SuppressFields>; onClose: () => void;
}) {
  const [fields, setFields] = useState<SuppressFields>({ what: "program", where: "host", forDays: 7, reason: "", ...initial });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const set = (patch: Partial<SuppressFields>) => setFields((f) => ({ ...f, ...patch }));
  const verb = options.require_approval ? "Request" : "Suppress";
  const submit = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const made = await request<AlarmSuppression>("POST", "/api/v1/alarm-suppressions", bodyOf(source.id, fields));
      invalidate("/api/v1/alarm");
      toast(made.status === "waiting" ? "Requested · waiting for approval" : "Suppressed · recorded in the audit log");
      onClose();
    } catch (e) {
      setError((e instanceof ApiError && e.fieldErrors?.[0]?.message) || apiMessage(e, "The suppression could not be saved"));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal label="Suppress alarms like this" onClose={onClose}>
      <form className="bulk-dialog stack" onSubmit={(e) => { e.preventDefault(); if (!busy) void submit(); }}>
        <DialogHead title="Suppress alarms like this" onClose={onClose} />
        <fieldset className="stack suppress-form" disabled={busy}>
          <SelectField label="What">
            <Segmented label="What" value={fields.what} onChange={(what) => set({ what })}
              options={[{ value: "program", label: "This program" }, { value: "command", label: "This exact command" }]} />
            <span className="mono subtle">{fields.what === "program" ? `${source.exe}, with any arguments` : [source.exe, ...source.args].join(" ")}</span>
          </SelectField>
          <SelectField label="Where">
            <Select label="Where" value={fields.where} onChange={(where) => set({ where })} options={whereChoices(source, options)} disabled={busy} />
          </SelectField>
          <SelectField label="For">
            <Segmented label="For" value={fields.forDays === null ? "" : String(fields.forDays)} onChange={(v) => set({ forDays: v === "" ? null : Number(v) })} options={FOR} />
          </SelectField>
          <label className="field">Reason (required)
            <textarea className="textarea" rows={3} maxLength={4000} value={fields.reason} onChange={(e) => set({ reason: e.target.value })} placeholder="Why these alarms are expected" />
          </label>
        </fieldset>
        {options.require_approval && (
          <div className="callout callout--warn"><Icon name="clock" size={16} /> Someone who can approve on those hosts must accept it. Until then these alarms keep arriving.</div>
        )}
        {error && <p className="confirm__error" role="alert">{error}</p>}
        <div className="row row--end">
          <button type="button" className="button button--ghost" onClick={onClose}>Cancel</button>
          <button className="button button--primary" type="submit" disabled={busy || !fields.reason.trim()}>{verb}</button>
        </div>
      </form>
    </Modal>
  );
}

/** Loads the alarm's command line and the caller's options, then the form. */
function SuppressDialog({ alarmId, onClose }: { alarmId: string; onClose: () => void }) {
  const options = useResource<AlarmSuppressionOptions>("/api/v1/alarm-suppressions/options");
  const alarm = useResource<AlarmDetail>(`/api/v1/alarms/${encodeURIComponent(alarmId)}`);
  const failed = options.error ?? alarm.error;
  if (failed) return <Modal label="Suppress alarms like this" onClose={onClose}><div className="bulk-dialog stack"><DialogHead title="Suppress alarms like this" onClose={onClose} /><ErrorBox error={failed} /></div></Modal>;
  if (!options.data || !alarm.data) return null;
  const process = alarm.data.process as unknown as AlarmProcess;
  const source = { id: alarmId, host: alarm.data.hostname ?? alarm.data.agent_id, exe: process.exe, args: process.args };
  return <SuppressForm source={source} options={options.data} onClose={onClose} />;
}

/** "Suppress…" for one alarm, for whoever holds alarms.suppress; `label` names the alarm where many are listed. */
export function SuppressButton({ alarm, label }: Readonly<{ alarm: Pick<AlarmSummary, "id" | "suppressed_by">; label?: string }>) {
  const { can } = useSession();
  const [open, setOpen] = useState(false);
  if (!can("alarms.suppress") || alarm.suppressed_by) return null;
  return (
    <>
      <button type="button" className="button button--small" aria-label={label} onClick={() => setOpen(true)}>Suppress…</button>
      {open && <SuppressDialog alarmId={alarm.id} onClose={() => setOpen(false)} />}
    </>
  );
}
