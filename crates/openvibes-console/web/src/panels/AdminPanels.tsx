// Creation and change forms for administrators, each in a panel beside the
// list: a new service account and its tokens, publishing a signed rule
// bundle, and the audit retention policy.
import { useRef, useState } from "react";

import { ApiError, invalidate, request, useResource } from "../api/client";
import type { AccessInventory, AuditRetention } from "../api/types";
import { nav } from "../app/nav";
import { useSession } from "../app/session";
import { Empty, ErrorBox, Loading } from "../ui/bits";
import { date, when } from "../ui/format";
import { Icon } from "../ui/Icon";
import { PanelHeader, Section } from "../ui/panel";
import { toast } from "../ui/toast";

const message = (error: unknown, fallback: string) => (error instanceof ApiError ? error.message : fallback);
const roles = [["viewer", "Viewer"], ["analyst", "Analyst"], ["operator", "Operator"], ["admin", "Admin"]] as const;

type Secret = { token_id: string; token?: string | null; expires_at: string; secret_available: boolean };

export function SecretOnce({ secret, what }: { secret: Secret; what: string }) {
  if (!secret.token) {
    return <div className="callout callout--warn"><Icon name="alert" size={16} /><span>{what} {secret.token_id} was created by an earlier attempt; its secret cannot be shown again. Revoke it if nobody copied it.</span></div>;
  }
  return (
    <>
      <div className="callout callout--warn"><Icon name="alert" size={16} /> Copy the {what.toLowerCase()} now. It is shown only once.</div>
      <div className="secret"><span className="grow">{secret.token}</span>
        <button type="button" className="icon-button" aria-label="Copy" onClick={() => { void navigator.clipboard?.writeText(secret.token ?? ""); toast("Copied"); }}><Icon name="copy" size={16} /></button>
      </div>
      <p className="subtle">Expires {when(secret.expires_at)}.</p>
    </>
  );
}

/** One Idempotency-Key per distinct request, kept across retries of it. */
function useIdempotency() {
  const attempt = useRef({ signature: "", key: "" });
  return {
    keyFor(body: unknown) {
      const signature = JSON.stringify(body);
      if (attempt.current.signature !== signature) attempt.current = { signature, key: crypto.randomUUID() };
      return attempt.current.key;
    },
    done() { attempt.current = { signature: "", key: "" }; },
  };
}

export function NewServiceAccount() {
  const [name, setName] = useState("");
  const [role, setRole] = useState("viewer");
  const [error, setError] = useState<string>();
  return (
    <>
      <PanelHeader icon="service" kind="Service account" title="New service account" subtitle="An identity for scripts and integrations, with expiring API tokens." />
      <form className="panel-body stack" onSubmit={(event) => {
        event.preventDefault();
        setError(undefined);
        request<{ service_account_id: string }>("POST", "/api/v1/service-accounts", { name: name.trim(), role_id: role })
          .then((account) => { invalidate("/api/v1/service-accounts"); toast(`${name.trim()} created`); nav.open({ kind: "service-account", id: account.service_account_id }, true); },
            (e: unknown) => setError(message(e, "Could not create the account")));
      }}>
        <label className="field">Name<input className="input" required maxLength={128} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. SIEM export" /></label>
        <label className="field">Role<select className="select" value={role} onChange={(e) => setRole(e.target.value)}>{roles.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label>
        {error && <p className="confirm__error" role="alert">{error}</p>}
        <div><button className="button button--primary" type="submit"><Icon name="plus" size={15} /> Create account</button></div>
      </form>
    </>
  );
}

export function IssueServiceToken({ accountId }: { accountId: string }) {
  const [label, setLabel] = useState("");
  const [hours, setHours] = useState(720);
  const [secret, setSecret] = useState<Secret>();
  const [error, setError] = useState<string>();
  const idempotency = useIdempotency();
  if (secret) {
    return (
      <Section title="New token">
        <SecretOnce secret={secret} what="Token" />
        <div><button type="button" className="button button--small" onClick={() => setSecret(undefined)}>Done</button></div>
      </Section>
    );
  }
  return (
    <Section title="Issue a token">
      <form className="row row--wrap" onSubmit={(event) => {
        event.preventDefault();
        setError(undefined);
        const body = { label: label.trim(), expires_in_hours: hours };
        request<Secret>("POST", `/api/v1/service-accounts/${encodeURIComponent(accountId)}/tokens`, body, { "idempotency-key": idempotency.keyFor(body) })
          .then((created) => { idempotency.done(); setSecret(created); setLabel(""); invalidate("/api/v1/service-accounts"); }, (e: unknown) => setError(message(e, "Could not issue the token")));
      }}>
        <input className="input grow" required maxLength={128} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Label, e.g. splunk forwarder" aria-label="Token label" />
        <select className="select" value={hours} onChange={(e) => setHours(Number(e.target.value))} aria-label="Valid for">
          <option value={24}>1 day</option><option value={168}>7 days</option><option value={720}>30 days</option><option value={2160}>90 days</option><option value={8760}>1 year</option>
        </select>
        <button className="button button--small button--primary" type="submit">Issue</button>
      </form>
      {error && <p className="confirm__error" role="alert">{error}</p>}
    </Section>
  );
}

type Preview = { rule_set_id: string; version: number; current_version?: number | null; issuer_key_id: string; envelope_sha256: string; expires_at_ms: number; preview_token: string };

export function PublishBundle() {
  const [envelope, setEnvelope] = useState<Record<string, unknown>>();
  const [file, setFile] = useState<string>();
  const [preview, setPreview] = useState<Preview>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const read = (chosen: File | undefined) => {
    setError(undefined);
    setPreview(undefined);
    setEnvelope(undefined);
    if (!chosen) return;
    if (chosen.size > 1_048_576) { setError("The envelope must be at most 1 MiB."); return; }
    setFile(chosen.name);
    chosen.text().then((text) => {
      const parsed = JSON.parse(text) as unknown;
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("not an object");
      const body = parsed as Record<string, unknown>;
      setEnvelope(body);
      setBusy(true);
      return request<Preview>("POST", "/api/v1/rule-bundles/preview", body).then(setPreview);
    }).catch((e: unknown) => setError(e instanceof SyntaxError || (e instanceof Error && e.message === "not an object") ? "This is not a signed envelope (JSON object)." : message(e, "The envelope could not be verified")))
      .finally(() => setBusy(false));
  };
  return (
    <>
      <PanelHeader icon="rules" kind="Rule sets" title="Publish a signed bundle" subtitle="Bundles are signed offline. The platform checks the signature against the keys it trusts for the set, and agents check it again." />
      <div className="panel-body stack">
        <label className="dropzone">
          <Icon name="download" size={22} />
          <span>{file ?? "Choose a signed envelope (.json, at most 1 MiB)"}</span>
          <input type="file" accept="application/json,.json" onChange={(e) => read(e.currentTarget.files?.[0])} />
        </label>
        {busy && <Loading rows={2} />}
        {error && <p className="confirm__error" role="alert">{error}</p>}
        {preview && envelope && (
          <Section title="Signature verified">
            <dl className="kv">
              <dt>Rule set</dt><dd className="mono">{preview.rule_set_id}</dd>
              <dt>Version</dt><dd>{preview.version} <span className="subtle">(now {preview.current_version ?? "none"})</span></dd>
              <dt>Signed by</dt><dd className="mono">{preview.issuer_key_id}</dd>
              <dt>Expires</dt><dd>{date(preview.expires_at_ms)}</dd>
              <dt>SHA-256</dt><dd className="mono">{preview.envelope_sha256}</dd>
            </dl>
            <div className="row">
              <button type="button" className="button button--primary" disabled={busy} onClick={() => {
                setBusy(true);
                request("POST", "/api/v1/rule-bundles/publish", envelope, { "x-rule-preview-token": preview.preview_token })
                  .then(() => { invalidate("/api/v1/rule-sets"); toast(`${preview.rule_set_id} v${preview.version} published`); nav.open({ kind: "rule-set", id: preview.rule_set_id }, true); },
                    (e: unknown) => setError(message(e, "The bundle could not be published; preview it again")))
                  .finally(() => setBusy(false));
              }}>Publish v{preview.version}</button>
              <button type="button" className="button button--ghost" onClick={() => { setPreview(undefined); setEnvelope(undefined); setFile(undefined); }}>Cancel</button>
            </div>
          </Section>
        )}
      </div>
    </>
  );
}

export function RetentionPanel() {
  const { can } = useSession();
  const policy = useResource<AuditRetention>("/api/v1/audit-retention");
  const [days, setDays] = useState<number>();
  const [error, setError] = useState<string>();
  if (policy.error) return <div className="panel-body"><ErrorBox error={policy.error} /></div>;
  if (!policy.data) return policy.loading ? <Loading /> : <Empty title="No policy" />;
  const current = policy.data;
  const value = days ?? current.retention_days;
  return (
    <>
      <PanelHeader icon="audit" kind="Audit log" title="Retention" subtitle={`Audit events are kept ${current.retention_days} days, then deleted by the maintenance run.`} />
      <div className="panel-body stack">
        <dl className="kv">
          <dt>Changed</dt><dd>{when(current.updated_at)} by {current.updated_by}</dd>
          <dt>Version</dt><dd className="num">{current.version}</dd>
        </dl>
        {can("audit.retention.manage", true) && (
          <form className="row" onSubmit={(event) => {
            event.preventDefault();
            setError(undefined);
            request("PUT", "/api/v1/audit-retention", { retention_days: value }, { "if-match": `"${current.version}"` })
              .then(() => { setDays(undefined); invalidate("/api/v1/audit"); toast(`Audit events are now kept ${value} days`); },
                (e: unknown) => { setError(message(e, "Could not change retention")); if (e instanceof ApiError && e.status === 412) invalidate("/api/v1/audit"); });
          }}>
            <label className="field grow">Keep audit events for (days)
              <input className="input" type="number" min={1} max={36500} required value={value} onChange={(e) => setDays(Number(e.target.value))} />
            </label>
            <button className="button button--primary" type="submit" disabled={value === current.retention_days} style={{ alignSelf: "end" }}>Save</button>
          </form>
        )}
        {error && <p className="confirm__error" role="alert">{error}</p>}
      </div>
    </>
  );
}

export function AssetGroupPanel({ id }: { id: string }) {
  const { can } = useSession();
  const inventory = useResource<AccessInventory>("/api/v1/access-control");
  const group = inventory.data?.asset_groups.find((g) => g.asset_group_id === id);
  const [name, setName] = useState<string>();
  const [selectors, setSelectors] = useState<string>();
  const [error, setError] = useState<string>();
  if (inventory.error) return <div className="panel-body"><ErrorBox error={inventory.error} /></div>;
  if (id !== "new" && !group) return inventory.loading ? <Loading /> : <div className="panel-body"><Empty title="Asset group not found" /></div>;
  const currentName = name ?? group?.name ?? "";
  const currentSelectors = selectors ?? group?.selectors.join("\n") ?? "";
  const bindings = inventory.data?.bindings.filter((b) => b.asset_group_id === id) ?? [];
  const manage = can("asset_groups.manage", true);
  return (
    <>
      <PanelHeader icon="access" kind="Asset group" title={id === "new" ? "New asset group" : group?.name}
        subtitle="Hosts whose tags match every selector belong to the group; roles granted on the group see only those hosts." />
      <form className="panel-body stack" onSubmit={(event) => {
        event.preventDefault();
        setError(undefined);
        const parsed = currentSelectors.split(/[\n,]+/).map((line) => line.trim()).filter(Boolean).map((pair) => {
          const [key = "", ...rest] = pair.split("=");
          return { key: key.trim(), value: rest.join("=").trim() };
        });
        if (parsed.length === 0 || parsed.some((sel) => sel.key === "" || sel.value === "")) { setError("Write one key=value selector per line."); return; }
        const body = { name: currentName.trim(), selectors: parsed };
        const call = id === "new"
          ? request<{ asset_group_id: string }>("POST", "/api/v1/access-control/asset-groups", body)
          : request<{ asset_group_id: string }>("PUT", `/api/v1/access-control/asset-groups/${encodeURIComponent(id)}`, body);
        call.then((saved) => {
          invalidate("/api/v1/access-control");
          toast(id === "new" ? `${body.name} created` : `${body.name} saved`);
          setName(undefined);
          setSelectors(undefined);
          if (id === "new") nav.open({ kind: "asset-group", id: saved.asset_group_id }, true);
        }, (e: unknown) => setError(message(e, "Could not save the group")));
      }}>
        <label className="field">Name<input className="input" required maxLength={128} disabled={!manage} value={currentName} onChange={(e) => setName(e.target.value)} placeholder="e.g. Production" /></label>
        <label className="field">Selectors (one key=value per line)
          <textarea className="textarea mono" rows={4} disabled={!manage} value={currentSelectors} onChange={(e) => setSelectors(e.target.value)} placeholder={"env=prod\nrole=web"} />
        </label>
        {id !== "new" && manage && (selectors !== undefined || name !== undefined) && (
          <div className="callout callout--warn"><Icon name="alert" size={16} /><span>Changing selectors changes which hosts belong to the group, and so what {bindings.length === 1 ? "1 person" : `${bindings.length} people`} with roles on it can see.</span></div>
        )}
        {error && <p className="confirm__error" role="alert">{error}</p>}
        {manage && <div><button className="button button--primary" type="submit">{id === "new" ? "Create group" : "Save"}</button></div>}
      </form>
      {id !== "new" && (
        <Section title={`Roles granted on this group (${bindings.length})`}>
          <ul className="list list--plain" style={{ padding: "0 20px" }}>
            {bindings.length === 0 ? <li className="subtle list__row list__row--static">None yet. Grant one from a person's panel under Access.</li> : bindings.map((b) => (
              <li key={b.binding_id} className="list__row list__row--static"><Icon name="user" size={14} /><span className="grow">{b.display_name}</span><span className="badge badge--accent badge--plain">{b.role_id}</span></li>
            ))}
          </ul>
        </Section>
      )}
    </>
  );
}

type CreatedUser = { user_id: string; username: string; display_name: string; role_id: string; one_time_password: string };

/** A local user with a one-time password, shown once; they set their own at first sign-in (#85). */
export function NewUser() {
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState("viewer");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<CreatedUser>();
  if (created) {
    return (
      <>
        <PanelHeader icon="user" kind="User" title={created.display_name} subtitle={`${created.username} · ${roles.find(([id]) => id === created.role_id)?.[1] ?? created.role_id}`} />
        <div className="panel-body stack">
          <div className="callout callout--warn"><Icon name="alert" size={16} /> Copy the one-time password now. It is shown only once.</div>
          <div className="secret"><span className="grow">{created.one_time_password}</span>
            <button type="button" className="icon-button" aria-label="Copy one-time password" onClick={() => { void navigator.clipboard?.writeText(created.one_time_password); toast("Copied"); }}><Icon name="copy" size={16} /></button>
          </div>
          <p className="subtle">Give it to {created.display_name} by a private channel. At their first sign-in they choose their own password, and nothing else works until they do.</p>
          <div><button type="button" className="button" onClick={() => nav.open({ kind: "user", id: created.user_id }, true)}>Done</button></div>
        </div>
      </>
    );
  }
  return (
    <>
      <PanelHeader icon="user" kind="User" title="New user" subtitle="A local sign-in with a one-time password they replace at first sign-in." />
      <form className="panel-body stack" onSubmit={(event) => {
        event.preventDefault();
        if (busy) return;
        setBusy(true);
        setError(undefined);
        request<CreatedUser>("POST", "/api/v1/access-control/users", { username: username.trim(), display_name: displayName.trim(), role_id: role })
          .then((user) => { invalidate("/api/v1/access-control"); setCreated(user); }, (e: unknown) => setError(message(e, "Could not create the user")))
          .finally(() => setBusy(false));
      }}>
        <label className="field">Username<input className="input mono" required maxLength={64} pattern="[A-Za-z0-9._@+\-]+" autoComplete="off" spellCheck={false} value={username} onChange={(e) => setUsername(e.target.value)} placeholder="e.g. jdoe" /></label>
        <label className="field">Display name<input className="input" required maxLength={160} value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="e.g. Jane Doe" /></label>
        <label className="field">Role<select className="select" value={role} onChange={(e) => setRole(e.target.value)}>{roles.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label>
        {error && <p className="confirm__error" role="alert">{error}</p>}
        <div><button className="button button--primary" type="submit" disabled={busy}><Icon name="plus" size={15} /> {busy ? "Creating…" : "Create user"}</button></div>
      </form>
    </>
  );
}
