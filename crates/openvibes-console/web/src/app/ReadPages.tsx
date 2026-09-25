import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import type { components } from "../api/generated";
import { AgentTags } from "./AgentTags";
import { AssetGroups } from "./AssetGroups";

type AgentDetail = components["schemas"]["AgentDetail"];
type AgentPage = components["schemas"]["AgentPage"];
type AgentSummary = components["schemas"]["AgentSummary"];
type Finding = components["schemas"]["FindingView"];
type FindingPage = components["schemas"]["FindingPage"];
type FindingSummary = components["schemas"]["FindingSummary"];
type AuditEventPage = components["schemas"]["AuditEventPage"];
type AccessInventory = components["schemas"]["AccessInventory"];

type ReadState<T> =
  | { status: "loading" }
  | { status: "error"; code: string; message: string }
  | { status: "ready"; value: T };

function requestHeaders(seeded: boolean): Headers {
  const headers = new Headers({ Accept: "application/json" });
  if (!seeded) return headers;
  try {
    headers.set("X-OpenVIBES-Dev-Persona", localStorage.getItem("openvibes.dev.persona") ?? "analyst");
    headers.set("X-OpenVIBES-Dev-Mode", localStorage.getItem("openvibes.dev.mode") ?? "mixed");
  } catch {
    // Browser storage may be unavailable; the seeded API defaults to Analyst/Mixed.
  }
  return headers;
}

function useRead<T>(url: string, seeded = false): ReadState<T> {
  const [state, setState] = useState<{ url: string; result: ReadState<T> }>({
    url: "",
    result: { status: "loading" },
  });

  useEffect(() => {
    const controller = new AbortController();
    if (url === "") return () => controller.abort();
    void fetch(url, { headers: requestHeaders(seeded), signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) {
          const problem = (await response.json()) as { code?: string; title?: string };
          throw { code: problem.code ?? "request_failed", message: problem.title ?? "The request could not be completed." };
        }
        return (await response.json()) as T;
      })
      .then((value) => setState({ url, result: { status: "ready", value } }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        const detail = typeof error === "object" && error !== null ? error as { code?: string; message?: string } : {};
        setState({
          url,
          result: {
            status: "error",
            code: detail.code ?? "unavailable",
            message: detail.message ?? "The console could not reach the read service.",
          },
        });
      });
    return () => controller.abort();
  }, [url, seeded]);

  return state.url === url ? state.result : { status: "loading" };
}

function ReadStatus<T>({ state, children }: { state: ReadState<T>; children: (value: T) => ReactNode }) {
  if (state.status === "loading") return <p className="read-state" role="status">Loading current data…</p>;
  if (state.status === "error") {
    const forbidden = state.code === "permission_denied";
    const expired = state.code === "session_expired" || state.code === "authentication_required";
    return (
      <section className="read-state read-state--error" role="alert">
        <h2>{forbidden ? "Access unavailable" : expired ? "Session expired" : "Data unavailable"}</h2>
        <p>{forbidden ? "Your current role does not permit this view." : expired ? "Sign in again to continue." : state.message}</p>
      </section>
    );
  }
  return children(state.value);
}

function dateLabel(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function OverviewReadPage({ seeded = false }: { seeded?: boolean }) {
  const agents = useRead<AgentSummary>("/api/v1/agents/summary", seeded);
  const findings = useRead<FindingSummary>("/api/v1/findings/summary", seeded);
  return (
    <div className="read-dashboard">
      <section className="read-card" aria-labelledby="fleet-summary-title">
        <p className="eyebrow">Fleet</p>
        <h2 id="fleet-summary-title">Agent contact</h2>
        <ReadStatus state={agents}>{(summary) => (
          <dl className="summary-list">
            <div><dt>Enrolled</dt><dd>{summary.total.toLocaleString()}</dd></div>
            <div><dt>Active</dt><dd>{summary.active.toLocaleString()}</dd></div>
            <div><dt>Stale</dt><dd>{summary.stale.toLocaleString()}</dd></div>
            <div><dt>Revoked</dt><dd>{summary.revoked.toLocaleString()}</dd></div>
          </dl>
        )}</ReadStatus>
        <a href="/agents">Browse agents</a>
      </section>
      <section className="read-card" aria-labelledby="finding-summary-title">
        <p className="eyebrow">Observations</p>
        <h2 id="finding-summary-title">Latest matches</h2>
        <ReadStatus state={findings}>{(summary) => (
          <dl className="summary-list">
            <div><dt>Open observations</dt><dd>{summary.total.toLocaleString()}</dd></div>
            <div><dt>Agents affected</dt><dd>{summary.impacted_agents.toLocaleString()}</dd></div>
            <div><dt>Critical</dt><dd>{summary.critical.toLocaleString()}</dd></div>
            <div><dt>High</dt><dd>{summary.high.toLocaleString()}</dd></div>
          </dl>
        )}</ReadStatus>
        <a href="/findings">Review findings</a>
      </section>
    </div>
  );
}

function currentSearch(): URLSearchParams {
  return typeof window === "undefined" ? new URLSearchParams() : new URLSearchParams(window.location.search);
}

function pagedUrl(path: string, params: URLSearchParams, cursor: string | null): string {
  const next = new URLSearchParams(params);
  if (cursor === null) next.delete("cursor");
  else next.set("cursor", cursor);
  return `${path}${next.size === 0 ? "" : `?${next.toString()}`}`;
}

export function AgentsReadPage({ seeded = false, csrfToken, canManageTags = false }: { seeded?: boolean; csrfToken?: string | undefined; canManageTags?: boolean }) {
  const params = currentSearch();
  const selectedAgent = params.get("agent");
  const [filterQuery, setFilterQuery] = useState(params.get("q") ?? "");
  const statusParam = seeded ? "status" : "state";
  const [filterStatus, setFilterStatus] = useState(params.get(statusParam) ?? "");
  const detail = useRead<AgentDetail>(selectedAgent ? `/api/v1/agents/${encodeURIComponent(selectedAgent)}` : "", seeded);
  const listParams = new URLSearchParams(params);
  listParams.delete("agent");
  if (!seeded) listParams.delete("q");
  const list = useRead<AgentPage>(selectedAgent ? "" : `/api/v1/agents${listParams.size ? `?${listParams}` : ""}`, seeded);

  if (selectedAgent) {
    return <ReadStatus state={detail}>{(agent) => (
      <section className="read-card read-detail" aria-labelledby="agent-detail-title">
        <a href="/agents">← Back to agents</a>
        <p className="eyebrow">Agent detail</p>
        <h2 id="agent-detail-title">{agent.hostname ?? agent.id}</h2>
        <dl className="detail-list">
          <div><dt>Agent ID</dt><dd>{agent.id}</dd></div>
          {!agent.hostname && <div><dt>Hostname</dt><dd>Hostname not reported</dd></div>}
          <div><dt>Status</dt><dd><StatusPill value={agent.status} /></dd></div>
          <div><dt>Enrolled</dt><dd><time dateTime={agent.enrolled_at}>{dateLabel(agent.enrolled_at)}</time></dd></div>
          <div><dt>Last contact</dt><dd>{agent.last_seen_at ? <time dateTime={agent.last_seen_at}>{dateLabel(agent.last_seen_at)}</time> : "No heartbeat recorded"}</dd></div>
          <div><dt>Scanner</dt><dd>{agent.scanner_version ?? "Not reported"}</dd></div>
          <div><dt>Capabilities</dt><dd>{agent.capabilities.length > 0 ? agent.capabilities.join(", ") : "None reported"}</dd></div>
        </dl>
        <h3>Certificates</h3>
        {agent.certificates.length === 0 ? <p>No certificates recorded.</p> : (
          <ul className="certificate-list">{agent.certificates.map((certificate) => (
            <li key={certificate.serial}>
              <code>{certificate.serial}</code> · Issued {dateLabel(certificate.issued_at)} · Expires {dateLabel(certificate.not_after)}
            </li>
          ))}</ul>
        )}
        <AgentTags agentId={agent.id} csrfToken={csrfToken} canManage={canManageTags && !seeded} />
      </section>
    )}</ReadStatus>;
  }

  return (
    <section aria-labelledby="agents-table-title">
      <ReadStatus state={list}>{(page) => <>
        <div className="read-toolbar">
          <h2 id="agents-table-title">{page.items.length.toLocaleString()} agents on this page</h2>
          <form className="filter-form" action="/agents" method="get">
            {seeded && <label>Search hostname or ID<input name="q" value={filterQuery} onChange={(event) => setFilterQuery(event.currentTarget.value)} maxLength={128} /></label>}
            <label>Status<select name={statusParam} value={filterStatus} onChange={(event) => setFilterStatus(event.currentTarget.value)}>
              <option value="">All statuses</option><option value="active">Active</option><option value="stale">Stale</option><option value="revoked">Revoked</option>
            </select></label>
            <button type="submit">Apply filters</button>
          </form>
        </div>
        {page.items.length === 0 ? <p className="read-state">No agents match these filters.</p> : (
          <div className="table-scroll"><table className="data-table">
            <thead><tr><th scope="col">Hostname</th><th scope="col">Status</th><th scope="col">Last contact</th><th scope="col">Scanner</th></tr></thead>
            <tbody>{page.items.map((agent) => <tr key={agent.id}>
              <th scope="row"><a href={`/agents?agent=${encodeURIComponent(agent.id)}`}>{agent.hostname ?? "Hostname not reported"}</a><span className="table-subtext">{agent.id}</span></th>
              <td><StatusPill value={agent.status} /></td><td>{agent.last_seen_at ? <time dateTime={agent.last_seen_at}>{dateLabel(agent.last_seen_at)}</time> : "Never"}</td><td>{agent.scanner_version ?? "Not reported"}</td>
            </tr>)}</tbody>
          </table></div>
        )}
        <PageFooter page={page} href="/agents" params={listParams} />
      </>}</ReadStatus>
    </section>
  );
}

export function FindingsReadPage({ seeded = false }: { seeded?: boolean }) {
  const params = currentSearch();
  const selected = params.get("finding");
  const severity = params.get("severity") ?? "";
  const query = params.get("q") ?? "";
  const detail = useRead<Finding>(selected ? `/api/v1/findings/latest/${selected.split("/").map(encodeURIComponent).join("/")}` : "", seeded);
  const listParams = new URLSearchParams(params);
  if (!seeded) listParams.delete("q");
  const list = useRead<FindingPage>(selected ? "" : `/api/v1/findings/latest${listParams.size ? `?${listParams}` : ""}`, seeded);

  if (selected) {
    return <ReadStatus state={detail}>{(finding) => (
      <section className="read-card read-detail" aria-labelledby="finding-detail-title">
        <a href="/findings">← Back to findings</a>
        <p className="eyebrow">Observed match</p>
        <h2 id="finding-detail-title">{finding.rule_id} · {finding.rule_set_id === "~unknown" ? "rule set unknown (earlier agent)" : finding.rule_set_id}</h2>
        <dl className="detail-list">
          <div><dt>Agent</dt><dd><a href={`/agents?agent=${encodeURIComponent(finding.agent_id)}`}>{finding.hostname ?? finding.agent_id}</a></dd></div>
          <div><dt>Severity</dt><dd><StatusPill value={finding.severity} /></dd></div>
          <div><dt>Rule version</dt><dd>{finding.rule_version}</dd></div>
          <div><dt>Observation</dt><dd>{finding.message}</dd></div>
          <div><dt>Confidence</dt><dd>{finding.confidence}%</dd></div>
          <div><dt>Origin</dt><dd>{finding.origin === "import" ? "Imported" : "Online"}{finding.authenticated ? " · authenticated" : " · unauthenticated"}</dd></div>
          <div><dt>Scan ID</dt><dd>{finding.scan_id}</dd></div>
          <div><dt>First observed</dt><dd><time dateTime={finding.first_observed_at}>{dateLabel(finding.first_observed_at)}</time></dd></div>
          <div><dt>Last observed</dt><dd><time dateTime={finding.last_observed_at}>{dateLabel(finding.last_observed_at)}</time></dd></div>
          <div><dt>Received</dt><dd><time dateTime={finding.received_at}>{dateLabel(finding.received_at)}</time></dd></div>
          <div><dt>Evidence</dt><dd>{finding.evidence.length > 0 ? <ul>{finding.evidence.map((entry) => <li key={entry}><code>{entry}</code></li>)}</ul> : "No evidence recorded"}</dd></div>
        </dl>
      </section>
    )}</ReadStatus>;
  }

  return (
    <section aria-labelledby="findings-table-title">
      <ReadStatus state={list}>{(page) => <>
        <div className="read-toolbar">
          <h2 id="findings-table-title">{page.items.length.toLocaleString()} observations on this page</h2>
          <form className="filter-form" action="/findings" method="get">
            {seeded && <label>Search host, rule, or text<input name="q" defaultValue={query} maxLength={128} /></label>}
            <label>Severity<select name="severity" defaultValue={severity}>
              <option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
            </select></label>
            <button type="submit">Apply filters</button>
          </form>
        </div>
        {page.items.length === 0 ? <p className="read-state">No findings match these filters.</p> : (
          <div className="table-scroll"><table className="data-table">
            <thead><tr><th scope="col">Rule</th><th scope="col">Severity</th><th scope="col">Agent</th><th scope="col">Last observed</th><th scope="col">Confidence</th><th scope="col">Origin</th></tr></thead>
            <tbody>{page.items.map((finding) => <tr key={finding.id}>
              <th scope="row"><a href={`/findings?finding=${encodeURIComponent(`${finding.agent_id}/${finding.rule_set_id}/${finding.rule_id}`)}`}>{finding.rule_id}</a><span className="table-subtext">{finding.rule_set_id === "~unknown" ? "rule set unknown (earlier agent)" : finding.rule_set_id}</span></th>
              <td><StatusPill value={finding.severity} /></td><td><a href={`/agents?agent=${encodeURIComponent(finding.agent_id)}`}>{finding.hostname ?? finding.agent_id}</a></td>
              <td><time dateTime={finding.last_observed_at}>{dateLabel(finding.last_observed_at)}</time></td>
              <td>{finding.confidence}%</td><td>{finding.origin === "import" ? "Imported · unauthenticated" : "Online"}</td>
            </tr>)}</tbody>
          </table></div>
        )}
        <PageFooter page={page} href="/findings" params={listParams} />
      </>}</ReadStatus>
    </section>
  );
}

export function AuditEventsReadPage({ seeded = false, canExport = false }: { seeded?: boolean; canExport?: boolean }) {
  const [defaultSince] = useState(() => new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString());
  const search = new URLSearchParams(typeof window === "undefined" ? "" : window.location.search);
  const since = search.get("since") ?? defaultSince;
  const actor = search.get("actor") ?? "";
  const action = search.get("action") ?? "";
  const result = search.get("result") ?? "";
  const params = new URLSearchParams({ since, limit: "50" });
  for (const [key, value] of [["actor", actor], ["action", action], ["result", result]] as const) {
    if (value !== "") params.set(key, value);
  }
  const cursor = search.get("cursor");
  if (cursor) params.set("cursor", cursor);
  const page = useRead<AuditEventPage>(`/api/v1/audit-events?${params.toString()}`, seeded);
  const exportParams = new URLSearchParams(params);
  exportParams.delete("cursor");
  exportParams.delete("limit");
  return <section className="read-card" aria-labelledby="audit-events-title">
    <div className="read-card__heading"><div><p className="eyebrow">Audit trail</p><h2 id="audit-events-title">Privileged activity</h2></div></div>
    {canExport && <p><a className="button-link" href={`/api/v1/audit-export.csv?${exportParams.toString()}`}>Download filtered CSV</a></p>}
    <form className="filter-form" action="/audit" method="get">
      <label>Actor<input name="actor" defaultValue={actor} maxLength={128} /></label>
      <label>Action<input name="action" defaultValue={action} maxLength={128} /></label>
      <label>Result<input name="result" defaultValue={result} maxLength={128} /></label>
      <button type="submit">Apply filters</button>
    </form>
    <ReadStatus state={page}>{(events) => <>
      {events.items.length === 0 ? <p className="read-state">No audit events match this time window.</p> : <div className="table-scroll"><table className="data-table">
        <thead><tr><th scope="col">Time</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Result</th></tr></thead>
        <tbody>{events.items.map((event) => <tr key={event.id}>
          <td><time dateTime={event.at}>{dateLabel(event.at)}</time></td><td>{event.actor}</td><td><code>{event.action}</code></td><td>{event.target ?? "—"}</td><td>{event.result}</td>
        </tr>)}</tbody>
      </table></div>}
      {events.next_cursor && <a className="button-link" href={`/audit?${new URLSearchParams({ ...Object.fromEntries(params), cursor: events.next_cursor }).toString()}`}>Next page</a>}
      <p className="read-state">Showing events from <time dateTime={since}>{dateLabel(since)}</time>. Event details and request source data are restricted.</p>
    </>}</ReadStatus>
  </section>;
}

export function AccessControlReadPage({ seeded = false, canManage = false, canManageGroups = false, csrfToken }: { seeded?: boolean; canManage?: boolean; canManageGroups?: boolean; csrfToken?: string | undefined }) {
  const [mutationError, setMutationError] = useState(false);
  const inventory = useRead<AccessInventory>("/api/v1/access-control", seeded);
  async function createBinding(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMutationError(false);
    const values = new FormData(event.currentTarget);
    const headers = requestHeaders(seeded);
    headers.set("Content-Type", "application/json");
    if (csrfToken) headers.set("X-CSRF-Token", csrfToken);
    try {
      const response = await fetch("/api/v1/access-control/bindings", {
        method: "POST", cache: "no-store", credentials: "same-origin", headers,
        body: JSON.stringify({ user_id: values.get("user_id"), role_id: values.get("role_id"), asset_group_id: values.get("asset_group_id") || null }),
      });
      if (response.status !== 201) throw new Error("binding failed");
      window.location.reload();
    } catch {
      setMutationError(true);
    }
  }
  async function revokeBinding(bindingId: string) {
    if (!window.confirm("Revoke this role binding? The user may lose access immediately.")) return;
    const headers = requestHeaders(seeded);
    if (csrfToken) headers.set("X-CSRF-Token", csrfToken);
    try {
      const response = await fetch(`/api/v1/access-control/bindings/${encodeURIComponent(bindingId)}`, {
        method: "DELETE", cache: "no-store", credentials: "same-origin", headers,
      });
      if (response.status !== 204) throw new Error("binding revoke failed");
      window.location.reload();
    } catch {
      setMutationError(true);
    }
  }
  return <section className="read-card" aria-labelledby="access-control-title">
    <div className="read-card__heading"><div><p className="eyebrow">Authorization</p><h2 id="access-control-title">Roles and access bindings</h2></div></div>
    <ReadStatus state={inventory}>{(access) => <>
      {mutationError && <p className="auth-inline-error" role="alert">The access change could not be completed. Reload the page and try again.</p>}
      {canManage && <form className="filter-form" onSubmit={(event) => void createBinding(event)}>
        <label>User<select name="user_id" required>{access.users.map((user) => <option key={user.user_id} value={user.user_id}>{user.display_name} ({user.username})</option>)}</select></label>
        <label>Role<select name="role_id" required>{access.roles.map((role) => <option key={role.role_id} value={role.role_id}>{role.display_name}</option>)}</select></label>
        <label>Scope<select name="asset_group_id"><option value="">Global</option>{access.asset_groups.map((group) => <option key={group.asset_group_id} value={group.asset_group_id}>{group.name}</option>)}</select></label>
        <button type="submit" disabled={access.users.length === 0}>Add role binding</button>
      </form>}
      <h3>Roles</h3>
      <div className="table-scroll"><table className="data-table"><thead><tr><th scope="col">Role</th><th scope="col">Type</th><th scope="col">Permissions</th></tr></thead>
        <tbody>{access.roles.map((role) => <tr key={role.role_id}><th scope="row">{role.display_name}<span className="table-subtext">{role.role_id}</span></th><td>{role.builtin ? "Built in" : "Custom"}</td><td>{role.permissions.join(", ") || "None"}</td></tr>)}</tbody>
      </table></div>
      <h3>Active bindings</h3>
      {access.bindings.length === 0 ? <p className="read-state">No active local-user bindings.</p> : <div className="table-scroll"><table className="data-table"><thead><tr><th scope="col">User</th><th scope="col">Role</th><th scope="col">Scope</th><th scope="col">Added by</th>{canManage && <th scope="col">Actions</th>}</tr></thead>
        <tbody>{access.bindings.map((binding) => <tr key={binding.binding_id}><th scope="row">{binding.display_name}<span className="table-subtext">{binding.username}</span></th><td>{binding.role_id}</td><td>{binding.asset_group_name ?? "Global"}</td><td>{binding.created_by}</td>{canManage && <td><button type="button" onClick={() => void revokeBinding(binding.binding_id)}>Revoke</button></td>}</tr>)}</tbody>
      </table></div>}
      <AssetGroups groups={access.asset_groups} canManage={canManageGroups && !seeded} csrfToken={csrfToken} onError={() => setMutationError(true)} />
    </>}</ReadStatus>
  </section>;
}

function StatusPill({ value }: { value: string }) {
  return <span className={`status-pill status-pill--${value}`}>{value.replaceAll("_", " ")}</span>;
}

function PageFooter({ page, href, params }: { page: { next_cursor?: string | null; generated_at: string }; href: string; params: URLSearchParams }) {
  return <footer className="page-footer">
    <p>Generated <time dateTime={page.generated_at}>{dateLabel(page.generated_at)}</time></p>
    {page.next_cursor && <a className="button-link" href={pagedUrl(href, params, page.next_cursor)}>Next page</a>}
  </footer>;
}
