// Settings › General (approved screen 11) in the shared layout: "On this page"
// and Recent changes on the left, one card per section on the right. A switch
// saves when flipped, a number when it loses focus or Enter is pressed.
import { useEffect, useState } from "react";

import { ApiError, invalidate, request, useResource } from "../../../api/client";
import type { PersonRow, Role, ServiceProviderView, SettingChangeView, SettingView, SettingsView } from "../../../api/types";
import { useSession } from "../../../app/session";
import { auditActionLabel } from "../../../ui/auditActions";
import { ErrorBox, Loading } from "../../../ui/bits";
import { ago } from "../../../ui/format";
import { Select } from "../../../ui/Select";
import { Switch } from "../../../ui/Switch";
import { link } from "../groups/groupApi";
import { Card } from "../../../ui/detail/DetailPage";
import { createRowEditor } from "./rowEditor";

const SAVED = "Saved · recorded in the audit log";
const APPROVE = "alarms.suppressions.approve";
/** What a section's "default" means, where it is not the built-in value. */
const SECTION_NOTES: Record<string, string> = {
  "Vulnerability feeds": "Default is what vulns.toml says (the built-in value unless it was edited on the server). A change reaches the service within a minute and restarts its running feed downloads.",
  "Single sign-on": "Needs an application set up in your identity provider with the values under “Enter this in your identity provider”. People who are in none of the groups that match a role name cannot sign in. The local admin account always signs in with its password. Signing in with the identity provider arrives in a later release; until then the reply URL below does not answer and this page only prepares the setup.",
  "Assistant": "Default is what the [assistant] part of console.toml says (the built-in value unless it was edited on the server); certificate and key file paths stay in that file. A change applies the next time the console restarts (Maintenance › Service in the admin tool). If the settings are not valid together the assistant stays off and the console logs why.",
  "Agent connections": "Default is what ingest.toml says (the built-in value unless it was edited on the server). A change applies the next time the service restarts (Maintenance › Service in the admin tool). “Keep findings” also sets how long maintenance keeps them.",
  "Rule distribution": "Default is what distribution.toml says (the built-in value unless it was edited on the server). A change applies the next time the service restarts (Maintenance › Service in the admin tool).",
};
const CERTIFICATES = "sso.idp_certificates";
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
const show = (value: unknown) => (value === "set" || value === "not set" ? String(value) : value === null || value === undefined ? "default" : value === true ? "on" : value === false ? "off" : String(value));

function Row({ setting }: { setting: SettingView }) {
  const [, tick] = useState(0);
  const [ed] = useState(() => createRowEditor(setting.key, setting.value, request, () => tick((n) => n + 1), () => invalidate("/api/v1/settings"), setting.kind));
  useEffect(() => { ed.setValue(setting.value); });
  const { can } = useSession();
  const off = !can("settings.manage");
  const { text, busy, result } = ed.state;
  return (
    <div className="row row--between general-row">
      <div className="stack general-row__text">
        <strong>{setting.label}</strong>
        <span className="subtle">{setting.help}</span>
        {setting.applies === "restart" && <span className="subtle">Applies after the service restarts.</span>}
        <span className="subtle" role="status">{result?.ok ? result.message : ""}</span>
        {result?.ok === false && <span className="general-row__error" role="alert">{result.message}</span>}
      </div>
      <div className="stack general-row__control">
        {setting.kind === "bool"
          ? <Switch bare label={setting.label} checked={setting.value === true} busy={busy} disabled={off} onChange={(checked) => void ed.save(checked)} />
          : setting.kind === "choice"
          ? <Select label={setting.label} value={String(setting.value ?? setting.default ?? "")} disabled={off || busy} onChange={(word) => void ed.save(word)}
              options={(setting.options ?? []).map((word) => ({ value: word, label: word }))} />
          : setting.key === CERTIFICATES
          ? <textarea className="textarea mono general-row__wide" rows={6} aria-label={setting.label} spellCheck={false} placeholder={"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"}
              value={text ?? String(setting.value ?? "")} disabled={off} readOnly={busy} aria-invalid={result?.ok === false || undefined}
              onChange={(e) => { if (!busy) ed.type(e.target.value); }} onBlur={() => void ed.commit()} />
          : <input className={`input ${setting.kind === "int" ? "general-row__number" : "general-row__wide"}`}
              type={setting.kind === "int" ? "number" : setting.kind === "secret" ? "password" : "text"} aria-label={setting.label}
              autoComplete={setting.kind === "secret" ? "new-password" : undefined} spellCheck={setting.kind === "int" ? undefined : false}
              placeholder={setting.kind === "secret" ? (setting.is_set ? "Set. Type to replace" : "Not set") : undefined}
              min={setting.min ?? undefined} max={setting.max ?? undefined}
              value={text ?? (setting.kind === "secret" ? "" : String(setting.value ?? ""))} disabled={off} readOnly={busy} aria-disabled={busy || undefined} aria-invalid={result?.ok === false || undefined}
              onChange={(e) => { if (!busy) ed.type(e.target.value); }} onBlur={() => void ed.commit()} onKeyDown={(e) => { if (e.key === "Enter") void ed.commit(); }} />}
        {!off && setting.kind === "secret" && setting.is_set && <button type="button" className="button button--ghost" disabled={busy} onClick={() => void ed.reset()}>Remove</button>}
        {!off && setting.kind !== "secret" && setting.changed_at != null && <button type="button" className="button button--ghost" disabled={busy} onClick={() => void ed.reset()}>Reset to default</button>}
      </div>
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
/** Each pasted certificate in words, so a wrong or expiring one is seen at once. */
function Certificates({ setting }: { setting: SettingView }) {
  const list = setting.certificates ?? [];
  if (list.length === 0) return null;
  return (
    <ul className="stack general-row__certificates">
      {list.map((c) => (
        <li key={c.fingerprint} className="subtle">SHA-256 <span className="mono">{c.fingerprint}</span> · valid until {c.not_after.slice(0, 10)}</li>
      ))}
    </ul>
  );
}

/** Our side of the connection, to copy into the identity provider. */
function ServiceProvider() {
  const { data } = useResource<ServiceProviderView>("/api/v1/sso/service-provider");
  if (!data) return null;
  return (
    <div className="stack">
      <strong>Enter this in your identity provider</strong>
      <span className="subtle">Entity ID (audience)</span><span className="mono">{data.entity_id}</span>
      <span className="subtle">Reply URL (assertion consumer service, HTTP POST)</span><span className="mono">{data.acs_url}</span>
      <span className="subtle">Or import the metadata</span><a href={data.metadata_url} className="mono">{data.metadata_url}</a>
    </div>
  );
}

export function GeneralBody({ settings, roles, names = new Map() }: { settings: SettingsView; roles?: readonly Role[] | undefined; names?: ReadonlyMap<string, string> }) {
  const sections = [...new Set(settings.items.map((s) => s.section))];
  const approvers = roles?.filter((r) => r.permissions.includes(APPROVE)).map((r) => r.name);
  return (
    <div className="view person-page">
      <header className="person-page__head">
        <div className="stack grow person-page__title"><h2>General</h2><span className="subtle">Settings that apply to the whole console.</span></div>
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
                  {SECTION_NOTES[s] && <p className="subtle">{SECTION_NOTES[s]}</p>}
                  {settings.items.filter((i) => i.section === s).map((item) => (
                    <div key={item.key} className="stack">
                      <Row setting={item} />
                      {item.key === CERTIFICATES && <Certificates setting={item} />}
                      {item.key === "suppressions.require_approval" && item.value === true && approvers && (
                        <p className="subtle">Approvers: people whose role holds Approve suppressions on those hosts — {approvers.length ? approvers.join(", ") : "no role holds it yet"}</p>
                      )}
                    </div>
                  ))}
                  {s === "Single sign-on" && <ServiceProvider />}
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
