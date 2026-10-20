// Settings › General (approved screen 11) in the shared layout: "On this page"
// and Recent changes on the left, one card per section on the right. A switch
// saves when flipped, a number when it loses focus or Enter is pressed.
import { useState } from "react";

import { ApiError, invalidate, request, useResource } from "../../../api/client";
import type { PersonRow, Role, SettingChangeView, SettingView, SettingsView } from "../../../api/types";
import { useSession } from "../../../app/session";
import { auditActionLabel } from "../../../ui/auditActions";
import { ErrorBox, Loading } from "../../../ui/bits";
import { ago } from "../../../ui/format";
import { Switch } from "../../../ui/Switch";
import { link } from "../groups/groupApi";
import { Card } from "../people/PersonPage";

const SAVED = "Saved · recorded in the audit log";
const APPROVE = "alarms.suppressions.approve";
const slug = (section: string) => `general-${section.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;

export type Saved = { ok: boolean; message: string };

/** Sends one value; the result is the words to show next to the control. `send` is the API call (a stub in tests). */
export async function saveValue(key: string, value: unknown, send: (method: string, path: string, body?: unknown) => Promise<unknown> = request): Promise<Saved> {
  try {
    await send("PATCH", `/api/v1/settings/${encodeURIComponent(key)}`, { value });
    return { ok: true, message: SAVED };
  } catch (e) {
    const field = e instanceof ApiError ? e.fieldErrors?.find((f) => f.field === "value") : undefined;
    return { ok: false, message: field?.message ?? (e instanceof Error ? e.message : "The setting could not be saved.") };
  }
}

/** A recorded value in words. */
const show = (value: unknown) => (value === null || value === undefined ? "default" : value === true ? "on" : value === false ? "off" : String(value));

function Row({ setting }: { setting: SettingView }) {
  const [text, setText] = useState<string>(); // what is typed; undefined shows the saved value
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Saved>();
  const { can } = useSession();
  const off = !can("settings.manage");
  const save = async (value: unknown) => {
    setBusy(true);
    setResult(undefined);
    const saved = await saveValue(setting.key, value);
    setBusy(false);
    setResult(saved);
    if (saved.ok) { setText(undefined); invalidate("/api/v1/settings"); }
  };
  const commit = () => {
    if (text === undefined || busy) return;
    if (text.trim() !== "" && Number(text) === setting.value) { setText(undefined); return; }
    void save(text.trim() === "" ? text : Number(text));
  };
  return (
    <div className="row row--between general-row">
      <div className="stack general-row__text">
        <strong>{setting.label}</strong>
        <span className="subtle">{setting.help}</span>
        {result && (result.ok
          ? <span className="subtle" role="status">{result.message}</span>
          : <span className="general-row__error" role="alert">{result.message}</span>)}
      </div>
      {setting.kind === "bool"
        ? <Switch bare label={setting.label} checked={setting.value === true} busy={busy} disabled={off} onChange={(checked) => void save(checked)} />
        : <input className="input general-row__number" type="number" aria-label={setting.label} min={setting.min ?? undefined} max={setting.max ?? undefined}
            value={text ?? String(setting.value)} disabled={busy || off} aria-invalid={result?.ok === false || undefined}
            onChange={(e) => { setText(e.target.value); setResult(undefined); }} onBlur={commit} onKeyDown={(e) => { if (e.key === "Enter") commit(); }} />}
    </div>
  );
}

function Recent({ lines, settings, names }: { lines: readonly SettingChangeView[]; settings: readonly SettingView[]; names: ReadonlyMap<string, string> }) {
  return (
    <Card title="Recent changes" aside={<a {...link("/audit", { q: "settings.changed" })}>Audit log</a>}>
      {lines.length === 0 ? <p className="subtle person-page__none">Nothing recorded yet.</p> : (
        <ul className="person-page__activity">
          {lines.map((c) => (
            <li key={`${c.at}|${c.key}`}>
              <span>{auditActionLabel("settings.changed")}: {settings.find((s) => s.key === c.key)?.label ?? c.key}, {show(c.old)} → {show(c.new)}</span>
              <span className="subtle">{names.get(c.actor) ?? c.actor} · {ago(c.at)}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** The screen from what the server returned; `roles` (undefined without access to read them) names who can approve. */
export function GeneralBody({ settings, roles, names = new Map() }: { settings: SettingsView; roles?: readonly Role[] | undefined; names?: ReadonlyMap<string, string> }) {
  const sections = [...new Set(settings.items.map((s) => s.section))];
  const approvers = roles?.filter((r) => r.permissions.includes(APPROVE)).map((r) => r.name);
  return (
    <div className="view person-page">
      <header className="person-page__head">
        <div className="stack grow person-page__title"><h1>General</h1><span className="subtle">Settings that apply to the whole console.</span></div>
      </header>
      <div className="person-page__cols">
        <div className="stack person-page__col">
          <Card title="On this page">
            <ul className="person-page__activity">
              {sections.map((s) => (
                <li key={s}>
                  <a href={`#${slug(s)}`} onClick={(e) => { e.preventDefault(); document.getElementById(slug(s))?.scrollIntoView(); }}>{s}</a>
                  <span className="subtle num">{settings.items.filter((i) => i.section === s).length}</span>
                </li>
              ))}
            </ul>
          </Card>
          <Recent lines={settings.recent} settings={settings.items} names={names} />
        </div>
        <div className="stack person-page__col">
          {sections.map((s) => (
            <div key={s} id={slug(s)}>
              <Card title={s}>
                <div className="stack">
                  {settings.items.filter((i) => i.section === s).map((item) => (
                    <div key={item.key} className="stack">
                      <Row setting={item} />
                      {item.key === "suppressions.require_approval" && item.value === true && approvers && (
                        <p className="subtle">Approvers: people whose role holds Approve suppressions on those hosts — {approvers.length ? approvers.join(", ") : "no role holds it yet"}</p>
                      )}
                    </div>
                  ))}
                </div>
              </Card>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function General() {
  const { can } = useSession();
  const settings = useResource<SettingsView>("/api/v1/settings");
  const roles = useResource<Role[]>(can("access.read") ? "/api/v1/roles" : null);
  const people = useResource<PersonRow[]>(can("access.read") ? "/api/v1/users" : null);
  if (settings.error) return <div className="view-pad"><ErrorBox error={settings.error} /></div>;
  if (!settings.data) return <Loading />;
  return <GeneralBody settings={settings.data} roles={roles.data} names={new Map((people.data ?? []).map((p) => [p.user_id, p.display_name]))} />;
}
