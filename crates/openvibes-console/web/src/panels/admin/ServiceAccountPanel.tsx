// A service account, a new one, and issuing its tokens (each secret is shown once).
import { useRef, useState } from "react";

import { apiMessage, invalidate, request, useResource } from "../../api/client";
import type { ServiceAccount, ServiceToken } from "../../api/types";
import { nav } from "../../app/nav";
import { roles } from "../../app/roles";
import { useSession } from "../../app/session";
import { SelectField } from "../../ui/Field";
import { Icon } from "../../ui/Icon";
import { Select } from "../../ui/Select";
import { Ago, Empty, ErrorBox, Loading } from "../../ui/bits";
import { isPast, when } from "../../ui/format";
import { Confirm, PanelHeader, Section } from "../../ui/panel";
import { toast } from "../../ui/toast";

export function ServiceAccountPanel({ id }: { id: string }) {
  if (id === "new") return <NewServiceAccount />;
  return <ExistingServiceAccount id={id} />;
}

function ExistingServiceAccount({ id }: { id: string }) {
  const { can } = useSession();
  const accounts = useResource<{ items: ServiceAccount[] }>("/api/v1/service-accounts");
  const tokens = useResource<{ items: ServiceToken[] }>(`/api/v1/service-accounts/${encodeURIComponent(id)}/tokens`);
  const account = accounts.data?.items.find((item) => item.service_account_id === id);
  if (accounts.error) return <div className="panel-body"><ErrorBox error={accounts.error} /></div>;
  if (!account) return accounts.loading ? <Loading /> : <div className="panel-body"><Empty title="Service account not found" /></div>;
  return (
    <>
      <PanelHeader icon="service" kind="Service account" title={account.name}
        subtitle={<span className="mono subtle">{account.service_account_id}</span>}
        badges={<><span className={`badge badge--${account.enabled ? "ok" : "plain"}`}>{account.enabled ? "Enabled" : "Disabled"}</span>{account.role_ids.map((role) => <span key={role} className="badge badge--accent badge--plain">{role}</span>)}</>}
        actions={can("service_accounts.manage", true) && account.enabled && (
          <Confirm danger label="Disable this account? All of its tokens stop working." onConfirm={async () => {
            await request("POST", `/api/v1/service-accounts/${encodeURIComponent(id)}/disable`);
            invalidate("/api/v1/service-accounts");
            toast(`${account.name} disabled`);
          }}>Disable</Confirm>
        )} />
      {can("service_accounts.tokens", true) && account.enabled && <div className="panel-body"><IssueServiceToken accountId={id} /></div>}
      <Section title="Tokens" flush>
        {!tokens.data ? <Loading rows={2} /> : tokens.data.items.length === 0 ? <Empty title="No tokens" /> : (
          <table className="table table--compact">
            <thead><tr><th>Label</th><th>Expires</th><th>State</th>{can("service_accounts.tokens", true) && <th />}</tr></thead>
            <tbody>
              {tokens.data.items.map((token) => (
                <tr key={token.token_id}>
                  <td>{token.label}</td>
                  <td><Ago value={token.expires_at} /></td>
                  <td><span className={`badge badge--${token.revoked ? "bad" : isPast(token.expires_at) ? "plain" : "ok"}`}>{token.revoked ? "Revoked" : isPast(token.expires_at) ? "Expired" : "Active"}</span></td>
                  {can("service_accounts.tokens", true) && <td>{!token.revoked && !isPast(token.expires_at) && (
                    <Confirm danger label={`Revoke ${token.label}? Whatever uses it stops working at once.`} onConfirm={async () => {
                      await request("POST", `/api/v1/service-accounts/${encodeURIComponent(id)}/tokens/${encodeURIComponent(token.token_id)}/revoke`);
                      invalidate("/api/v1/service-accounts");
                      toast(`${token.label} revoked`);
                    }}>Revoke</Confirm>
                  )}</td>}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </>
  );
}

function NewServiceAccount() {
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
            (e: unknown) => setError(apiMessage(e, "Could not create the account")));
      }}>
        <label className="field">Name<input className="input" required maxLength={128} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. SIEM export" /></label>
        <SelectField label="Role"><Select label="Role" value={role} onChange={setRole} options={roles.map(([id, label]) => ({ value: id, label }))} /></SelectField>
        {error && <p className="confirm__error" role="alert">{error}</p>}
        <div><button className="button button--primary" type="submit"><Icon name="plus" size={15} /> Create account</button></div>
      </form>
    </>
  );
}

type Secret = { token_id: string; token?: string | null; expires_at: string; secret_available: boolean };

function SecretOnce({ secret, what }: { secret: Secret; what: string }) {
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

const TOKEN_LIFETIMES = [{ value: "24", label: "1 day" }, { value: "168", label: "7 days" }, { value: "720", label: "30 days" }, { value: "2160", label: "90 days" }, { value: "8760", label: "1 year" }];

function IssueServiceToken({ accountId }: { accountId: string }) {
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
          .then((created) => { idempotency.done(); setSecret(created); setLabel(""); invalidate("/api/v1/service-accounts"); }, (e: unknown) => setError(apiMessage(e, "Could not issue the token")));
      }}>
        <input className="input grow" required maxLength={128} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Label, e.g. splunk forwarder" aria-label="Token label" />
        <Select label="Valid for" value={String(hours)} onChange={(v) => setHours(Number(v))}
          options={TOKEN_LIFETIMES} />
        <button className="button button--small button--primary" type="submit">Issue</button>
      </form>
      {error && <p className="confirm__error" role="alert">{error}</p>}
    </Section>
  );
}
