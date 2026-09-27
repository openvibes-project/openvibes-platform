// Panels for the operate and administer areas. Creation happens here too,
// in a panel beside the list, never on a separate page.
import { useState } from "react";

import { ApiError, invalidate, request, useAllPages, useResource } from "../api/client";
import type { AccessInventory, AuditEvent, CreatedToken, EnrollmentToken, RuleBundle, RuleSet, ServiceAccount, ServiceToken } from "../api/types";
import { nav } from "../app/nav";
import { useSession } from "../app/session";
import { Ago, Empty, ErrorBox, Loading, ObjectLink } from "../ui/bits";
import { date, isPast, when } from "../ui/format";
import { Icon } from "../ui/Icon";
import { Confirm, PanelHeader, Section } from "../ui/panel";
import { toast } from "../ui/toast";

export function tokenState(token: EnrollmentToken, now = Date.now()): { label: string; tone: string } {
  if (token.revoked) return { label: "Revoked", tone: "bad" };
  if (Date.parse(token.expires_at) <= now) return { label: "Expired", tone: "plain" };
  if (token.uses >= token.max_uses) return { label: "Used up", tone: "plain" };
  return { label: "Usable", tone: "ok" };
}

export function RuleSetPanel({ id }: { id: string }) {
  const sets = useResource<{ items: RuleSet[] }>("/api/v1/rule-sets");
  const bundles = useResource<{ items: RuleBundle[] }>(`/api/v1/rule-sets/${encodeURIComponent(id)}/bundles`);
  const set = sets.data?.items.find((item) => item.rule_set_id === id);
  if (sets.error) return <div className="panel-body"><ErrorBox error={sets.error} /></div>;
  if (!set) return sets.loading ? <Loading /> : <div className="panel-body"><Empty title="Rule set not found" /></div>;
  return (
    <>
      <PanelHeader icon="rules" kind="Rule set" title={set.rule_set_id}
        badges={<>
          <span className="badge badge--accent badge--plain">version {set.current_version ?? "—"}</span>
          {set.retired && <span className="badge badge--plain">Retired</span>}
          {set.current_signer_removed && <span className="badge badge--bad">Signer key removed</span>}
        </>} />
      <div className="panel-body stack">
        <dl className="kv">
          <dt>Signed by</dt><dd className="mono">{set.current_issuer_key_id ?? "—"}</dd>
          <dt>Expires</dt><dd>{set.current_expires_at_ms ? <><Ago value={set.current_expires_at_ms} /> · {date(set.current_expires_at_ms)}</> : "—"}</dd>
          <dt>Trusted keys</dt><dd className="num">{set.trusted_keys}</dd>
        </dl>
        <p className="subtle">Bundles are signed offline; publish a new version with <code>openvibes-admin rules publish</code> or the API. Agents fetch it on their next contact.</p>
      </div>
      <Section title="Published versions" flush>
        {!bundles.data ? <Loading rows={3} /> : (
          <table className="table table--compact">
            <thead><tr><th>Version</th><th>Published</th><th>By</th><th className="num">Size</th></tr></thead>
            <tbody>
              {bundles.data.items.map((bundle) => (
                <tr key={bundle.version}>
                  <td className="num">{bundle.version}{bundle.version === set.current_version && <span className="badge badge--ok" style={{ marginLeft: 8 }}>Current</span>}</td>
                  <td title={when(bundle.published_at)}><Ago value={bundle.published_at} /></td>
                  <td>{bundle.published_by}</td>
                  <td className="num subtle">{(bundle.bytes / 1024).toFixed(1)} KiB</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </>
  );
}

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
        actions={can("tokens.revoke", true) && state.label === "Usable" && (
          <Confirm danger label="Revoke this token? Hosts can no longer enroll with it." onConfirm={async () => {
            await request("POST", `/api/v1/enrollment-tokens/${encodeURIComponent(id)}/revoke`);
            invalidate("/api/v1/enrollment-tokens");
            toast("Token revoked");
          }}><Icon name="ban" size={14} /> Revoke</Confirm>
        )} />
      <div className="panel-body stack">
        <div className="usage">
          <div className="row row--between"><span className="subtle">Uses</span><span className="num">{token.uses} / {token.max_uses}</span></div>
          <div className="meter meter--wide"><span style={{ width: `${Math.min(100, (token.uses / token.max_uses) * 100)}%` }} /></div>
        </div>
        <dl className="kv">
          <dt>Created</dt><dd>{when(token.created_at)}</dd>
          <dt>Expires</dt><dd><Ago value={token.expires_at} /> · {when(token.expires_at)}</dd>
        </dl>
        <p className="subtle">The secret was shown once when the token was created and is not stored in readable form.</p>
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
  return (
    <>
      <PanelHeader icon="enrollment" kind="Enrollment" title="New enrollment token" subtitle="A single secret that lets a bounded number of hosts enroll for a limited time." />
      <div className="panel-body stack">
        {created ? (
          <>
            <div className="callout callout--warn"><Icon name="alert" size={16} /> Copy the token now. It is shown only once.</div>
            <div className="secret"><span className="grow">{created.token}</span>
              <button type="button" className="icon-button" aria-label="Copy token" onClick={() => { void navigator.clipboard?.writeText(created.token ?? ""); toast("Copied"); }}><Icon name="copy" size={16} /></button>
            </div>
            <Section title="Enroll a host">
              <p className="subtle">On the host, with <code>platform_url</code> and <code>platform_ca_file</code> set in <code>/etc/openvibes/agent.toml</code>:</p>
              <pre className="code">{`echo '${created.token ?? ""}' | sudo install -m 600 /dev/stdin /etc/openvibes/enrollment-token\nsudo systemctl restart openvibes-agent`}</pre>
            </Section>
            <button type="button" className="button" onClick={() => nav.open({ kind: "enrollment-token", id: created.token_id }, true)}>Done</button>
          </>
        ) : (
          <form className="stack" onSubmit={(event) => {
            event.preventDefault();
            setError(undefined);
            request<CreatedToken>("POST", "/api/v1/enrollment-tokens", { label: label.trim() || null, max_uses: uses, expires_in_hours: hours })
              .then((token) => { setCreated(token); invalidate("/api/v1/enrollment-tokens"); }, (e: unknown) => setError(e instanceof ApiError ? e.message : "Could not create the token"));
          }}>
            <label className="field">Label<input className="input" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Office laptops" /></label>
            <div className="row">
              <label className="field grow">Hosts it may enroll<input className="input" type="number" min={1} max={1000} value={uses} onChange={(e) => setUses(Number(e.target.value))} /></label>
              <label className="field grow">Valid for<select className="select" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
                <option value={1}>1 hour</option><option value={24}>1 day</option><option value={168}>7 days</option><option value={720}>30 days</option>
              </select></label>
            </div>
            {error && <p className="confirm__error" role="alert">{error}</p>}
            <div><button className="button button--primary" type="submit"><Icon name="plus" size={15} /> Create token</button></div>
          </form>
        )}
      </div>
    </>
  );
}

export function ServiceAccountPanel({ id }: { id: string }) {
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
      <Section title="Tokens" flush>
        {!tokens.data ? <Loading rows={2} /> : tokens.data.items.length === 0 ? <Empty title="No tokens" /> : (
          <table className="table table--compact">
            <thead><tr><th>Label</th><th>Expires</th><th>State</th></tr></thead>
            <tbody>
              {tokens.data.items.map((token) => (
                <tr key={token.token_id}>
                  <td>{token.label}</td>
                  <td><Ago value={token.expires_at} /></td>
                  <td><span className={`badge badge--${token.revoked ? "bad" : isPast(token.expires_at) ? "plain" : "ok"}`}>{token.revoked ? "Revoked" : isPast(token.expires_at) ? "Expired" : "Active"}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </>
  );
}

export function AuditEventPanel({ id }: { id: string }) {
  const page = useAllPages<AuditEvent>("/api/v1/audit-events", 1000);
  const event = page.data?.find((item) => item.id === id);
  if (page.error) return <div className="panel-body"><ErrorBox error={page.error} /></div>;
  if (!event) return page.loading ? <Loading /> : <div className="panel-body"><Empty title="Event not in the latest 1,000" /></div>;
  const target = event.target_kind === "agent" && event.target_id ? { kind: "agent", id: event.target_id }
    : event.target_kind === "finding" && event.target_id ? { kind: "finding", id: event.target_id }
      : event.target_kind === "enrollment_token" && event.target_id ? { kind: "enrollment-token", id: event.target_id }
        : event.target_kind === "rule_set" && event.target_id ? { kind: "rule-set", id: event.target_id }
          : event.target_kind === "service_account" && event.target_id ? { kind: "service-account", id: event.target_id } : null;
  return (
    <>
      <PanelHeader icon="audit" kind="Audit event" title={<span className="mono">{event.action}</span>}
        badges={<span className={`badge badge--${event.result === "success" ? "ok" : "bad"}`}>{event.result}</span>} />
      <div className="panel-body">
        <dl className="kv">
          <dt>When</dt><dd>{when(event.at)} (<Ago value={event.at} />)</dd>
          <dt>Actor</dt><dd>{event.actor} <span className="subtle">({event.actor_kind ?? "unknown"})</span></dd>
          <dt>Target</dt><dd>{target ? <ObjectLink to={target}>{event.target}</ObjectLink> : event.target ?? "—"}</dd>
          <dt>Method</dt><dd>{event.authentication_method ?? "—"}</dd>
          {event.reason_code && <><dt>Reason</dt><dd className="mono">{event.reason_code}</dd></>}
          <dt>Request</dt><dd className="mono">{event.request_id ?? "—"}</dd>
          <dt>Event ID</dt><dd className="mono">{event.id}</dd>
        </dl>
      </div>
    </>
  );
}

export function UserPanel({ id }: { id: string }) {
  const { can } = useSession();
  const inventory = useResource<AccessInventory>("/api/v1/access-control");
  const [role, setRole] = useState("viewer");
  const [group, setGroup] = useState("");
  if (inventory.error) return <div className="panel-body"><ErrorBox error={inventory.error} /></div>;
  const data = inventory.data;
  const user = data?.users.find((item) => item.user_id === id);
  if (!data || !user) return inventory.loading ? <Loading /> : <div className="panel-body"><Empty title="User not found" /></div>;
  const bindings = data.bindings.filter((binding) => binding.user_id === id);
  const manage = can("rbac.manage", true);
  const effective = [...new Set(bindings.flatMap((binding) => data.roles.find((r) => r.role_id === binding.role_id)?.permissions ?? []))].sort();
  return (
    <>
      <PanelHeader icon="user" kind="User" title={user.display_name} subtitle={<span className="mono subtle">{user.username}</span>} />
      <div className="panel-body stack">
        <Section title="Roles">
          {bindings.length === 0 ? <p className="subtle">No roles: this user can sign in but see nothing.</p> : (
            <ul className="list list--plain">
              {bindings.map((binding) => (
                <li key={binding.binding_id} className="list__row list__row--static">
                  <span className="badge badge--accent badge--plain">{data.roles.find((r) => r.role_id === binding.role_id)?.display_name ?? binding.role_id}</span>
                  <span className="grow subtle">{binding.asset_group_name ? `on ${binding.asset_group_name}` : "everywhere"}</span>
                  {manage && <button type="button" className="icon-button" aria-label="Remove role" onClick={() => {
                    request("DELETE", `/api/v1/access-control/bindings/${encodeURIComponent(binding.binding_id)}`)
                      .then(() => { invalidate("/api/v1/access-control"); toast("Role removed"); }, (e: unknown) => toast(e instanceof ApiError ? e.message : "Failed", true));
                  }}><Icon name="close" size={14} /></button>}
                </li>
              ))}
            </ul>
          )}
          {manage && (
            <form className="row" onSubmit={(event) => {
              event.preventDefault();
              request("POST", "/api/v1/access-control/bindings", { user_id: id, role_id: role, asset_group_id: group || null })
                .then(() => { invalidate("/api/v1/access-control"); toast("Role granted"); }, (e: unknown) => toast(e instanceof ApiError ? e.message : "Failed", true));
            }}>
              <select className="select" value={role} onChange={(e) => setRole(e.target.value)} aria-label="Role">{data.roles.map((r) => <option key={r.role_id} value={r.role_id}>{r.display_name}</option>)}</select>
              <select className="select grow" value={group} onChange={(e) => setGroup(e.target.value)} aria-label="Scope">
                <option value="">Everywhere</option>{data.asset_groups.map((g) => <option key={g.asset_group_id} value={g.asset_group_id}>{g.name}</option>)}
              </select>
              <button className="button button--small" type="submit"><Icon name="plus" size={14} /> Grant</button>
            </form>
          )}
        </Section>
        <Section title={`Effective permissions (${effective.length})`}>
          <div className="row row--wrap">{effective.map((permission) => <span key={permission} className="tag">{permission}</span>)}</div>
        </Section>
      </div>
    </>
  );
}
