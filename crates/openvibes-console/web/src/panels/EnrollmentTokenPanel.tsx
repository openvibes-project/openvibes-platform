// An enrollment token, and creating a new one.
import { useRef, useState } from "react";

import { apiMessage, invalidate, request, useResource } from "../api/client";
import type { CreatedToken, EnrollmentToken } from "../api/types";
import { nav } from "../app/nav";
import { useSession } from "../app/session";
import { SelectField } from "../ui/Field";
import { Icon } from "../ui/Icon";
import { Segmented } from "../ui/Segmented";
import { Ago, Empty, ErrorBox, Loading } from "../ui/bits";
import { when } from "../ui/format";
import { Confirm, PanelHeader, Section } from "../ui/panel";
import { toast } from "../ui/toast";
import { tokenState, tokenUsable } from "./tokens";

export function EnrollmentTokenPanel({ id }: { id: string }) {
  const { can } = useSession();
  const tokens = useResource<{ items: EnrollmentToken[] }>("/api/v1/enrollment-tokens");
  if (id === "new") return <NewEnrollmentToken />;
  const token = tokens.data?.items.find((item) => item.token_id === id);
  if (tokens.error) return <div className="panel-body"><ErrorBox error={tokens.error} /></div>;
  if (!token) return tokens.loading ? <Loading /> : <div className="panel-body"><Empty title="Token not found" /></div>;
  const state = tokenState(token);
  return (
    <>
      <PanelHeader icon="enrollment" kind="Enrollment token" title={token.label ?? token.token_id}
        subtitle={<span className="mono subtle">{token.token_id}</span>}
        badges={<span className={`badge badge--${state.tone}`}>{state.label}</span>}
        actions={can("tokens.revoke", true) && tokenUsable(token) && (
          <Confirm danger label="Revoke this token? Hosts can no longer enroll with it." onConfirm={async () => {
            await request("POST", `/api/v1/enrollment-tokens/${encodeURIComponent(id)}/revoke`);
            invalidate("/api/v1/enrollment-tokens");
            toast("Token revoked");
          }}><Icon name="ban" size={14} /> Revoke</Confirm>
        )} />
      <div className="panel-body stack">
        <div className="usage">
          <div className="row row--between"><span className="subtle">Uses</span><span className="num">{token.standing ? `${token.uses} / no limit` : `${token.uses} / ${token.max_uses}`}</span></div>
          {!token.standing && <div className="meter meter--wide"><span style={{ width: `${Math.min(100, (token.uses / token.max_uses) * 100)}%` }} /></div>}
        </div>
        <dl className="kv">
          <dt>Created</dt><dd>{when(token.created_at)}</dd>
          <dt>Expires</dt><dd>{token.standing ? "Never" : <><Ago value={token.expires_at} /> · {when(token.expires_at)}</>}</dd>
        </dl>
        {token.standing
          ? <p className="subtle">The standing token every agent can enroll with. Show it, or the install line, with <span className="mono">openvibes-admin agent command</span>. Revoking it blocks new enrollments only: agents already enrolled keep working, and the next <span className="mono">agent command</span> creates a new standing token.</p>
          : <p className="subtle">The secret was shown once when the token was created and is not stored in readable form.</p>}
      </div>
    </>
  );
}

function NewEnrollmentToken() {
  const [label, setLabel] = useState("");
  const [uses, setUses] = useState(10);
  const [hours, setHours] = useState(24);
  const [created, setCreated] = useState<CreatedToken>();
  const [error, setError] = useState<string>();
  const attempt = useRef({ signature: "", key: "" });
  return (
    <>
      <PanelHeader icon="enrollment" kind="Enrollment" title="New enrollment token" subtitle="A single secret that lets a bounded number of hosts enroll for a limited time." />
      <div className="panel-body stack">
        {created && !created.token ? (
          <>
            <div className="callout callout--warn"><Icon name="alert" size={16} /><span>The token {created.token_id} was created by an earlier attempt, and its secret cannot be shown again. Revoke it and create a new one if nobody copied it.</span></div>
            <button type="button" className="button" onClick={() => nav.open({ kind: "enrollment-token", id: created.token_id }, true)}>Open the token</button>
          </>
        ) : created ? (
          <>
            <div className="callout callout--warn"><Icon name="alert" size={16} /> Copy the token now. It is shown only once.</div>
            <div className="secret"><span className="grow">{created.token}</span>
              <button type="button" className="icon-button" aria-label="Copy token" onClick={() => { void navigator.clipboard?.writeText(created.token ?? ""); toast("Copied"); }}><Icon name="copy" size={16} /></button>
            </div>
            <Section title="Enroll a host">
              <p className="subtle">On the host, with the <code>openvibes-agent</code> package installed, <code>platform_url</code> set in <code>/etc/openvibes-agent/agent.toml</code>, and this platform's <code>/etc/openvibes/pki/root.crt</code> copied to <code>/etc/openvibes-agent/platform-ca.crt</code>:</p>
              <pre className="code">{`echo '${created.token ?? ""}' | sudo install -o openvibes_agent -g openvibes_agent -m 0600 /dev/stdin /etc/openvibes-agent/token\nsudo systemctl enable openvibes-agent\nsudo systemctl restart openvibes-agent`}</pre>
            </Section>
            <button type="button" className="button" onClick={() => nav.open({ kind: "enrollment-token", id: created.token_id }, true)}>Done</button>
          </>
        ) : (
          <form className="stack" onSubmit={(event) => {
            event.preventDefault();
            setError(undefined);
            // One key per distinct request: a retry after a lost response replays
            // (without the secret) instead of creating a second token.
            const body = { label: label.trim() || null, max_uses: uses, expires_in_hours: hours };
            const signature = JSON.stringify(body);
            if (attempt.current.signature !== signature) attempt.current = { signature, key: crypto.randomUUID() };
            request<CreatedToken>("POST", "/api/v1/enrollment-tokens", body, { "idempotency-key": attempt.current.key })
              .then((token) => { setCreated(token); attempt.current = { signature: "", key: "" }; invalidate("/api/v1/enrollment-tokens"); }, (e: unknown) => setError(apiMessage(e, "Could not create the token")));
          }}>
            <label className="field">Label<input className="input" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Office laptops" /></label>
            <div className="row">
              <label className="field grow">Hosts it may enroll<input className="input" type="number" min={1} max={1000} value={uses} onChange={(e) => setUses(Number(e.target.value))} /></label>
              <SelectField label="Valid for" className="grow">
                <Segmented label="Valid for" value={hours} onChange={setHours} options={[{ value: 1, label: "1 hour" }, { value: 24, label: "1 day" }, { value: 168, label: "7 days" }, { value: 720, label: "30 days" }]} />
              </SelectField>
            </div>
            {error && <p className="confirm__error" role="alert">{error}</p>}
            <div><button className="button button--primary" type="submit"><Icon name="plus" size={15} /> Create token</button></div>
          </form>
        )}
      </div>
    </>
  );
}
