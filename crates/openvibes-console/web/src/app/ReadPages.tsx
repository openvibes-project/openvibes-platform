import { useEffect, useState, type ReactNode } from "react";

type Page<T> = {
  items: T[];
  next_cursor: string | null;
  generated_at: string;
};

type Agent = {
  id: string;
  hostname: string;
  status: "active" | "stale" | "revoked";
  last_seen_at: string;
  certificate_expires_at: string;
  environment: string;
  platform: string;
};

type AgentSummary = {
  total: number;
  active: number;
  stale: number;
  revoked: number;
};

type AgentDetail = Agent & {
  certificate: { serial: string; not_after: string; revoked: boolean };
};

type Finding = {
  id: string;
  agent_id: string;
  hostname: string;
  rule_set_id: string;
  rule_id: string;
  rule_version: number;
  severity: "critical" | "high" | "medium" | "low";
  message: string;
  first_observed_at: string;
  last_observed_at: string;
  occurrence_count: number;
};

type FindingSummary = {
  total: number;
  impacted_agents: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
};

type ReadState<T> =
  | { status: "loading" }
  | { status: "error"; code: string; message: string }
  | { status: "ready"; value: T };

function requestHeaders(): Headers {
  const headers = new Headers({ Accept: "application/json" });
  try {
    headers.set("X-OpenVIBES-Dev-Persona", localStorage.getItem("openvibes.dev.persona") ?? "analyst");
    headers.set("X-OpenVIBES-Dev-Mode", localStorage.getItem("openvibes.dev.mode") ?? "mixed");
  } catch {
    // Browser storage may be unavailable; the seeded API defaults to Analyst/Mixed.
  }
  return headers;
}

function useRead<T>(url: string): ReadState<T> {
  const [state, setState] = useState<{ url: string; result: ReadState<T> }>({
    url: "",
    result: { status: "loading" },
  });

  useEffect(() => {
    const controller = new AbortController();
    if (url === "") return () => controller.abort();
    void fetch(url, { headers: requestHeaders(), signal: controller.signal })
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
  }, [url]);

  return state.url === url ? state.result : { status: "loading" };
}

function ReadStatus<T>({ state, children }: { state: ReadState<T>; children: (value: T) => ReactNode }) {
  if (state.status === "loading") return <p className="read-state" role="status">Loading current data…</p>;
  if (state.status === "error") {
    const forbidden = state.code === "permission_denied";
    const expired = state.code === "session_expired";
    return (
      <section className="read-state read-state--error" role="alert">
        <h2>{forbidden ? "Access unavailable" : expired ? "Session expired" : "Data unavailable"}</h2>
        <p>{forbidden ? "Your current role does not permit this view." : expired ? "Choose another seeded session to continue." : state.message}</p>
      </section>
    );
  }
  return children(state.value);
}

function dateLabel(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function OverviewReadPage() {
  const agents = useRead<AgentSummary>("/api/v1/agents/summary");
  const findings = useRead<FindingSummary>("/api/v1/findings/summary");
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

export function AgentsReadPage() {
  const params = currentSearch();
  const selectedAgent = params.get("agent");
  const [filterQuery, setFilterQuery] = useState(params.get("q") ?? "");
  const [filterStatus, setFilterStatus] = useState(params.get("status") ?? "");
  const detail = useRead<AgentDetail>(selectedAgent ? `/api/v1/agents/${encodeURIComponent(selectedAgent)}` : "");
  const listParams = new URLSearchParams(params);
  listParams.delete("agent");
  const list = useRead<Page<Agent>>(selectedAgent ? "" : `/api/v1/agents${listParams.size ? `?${listParams}` : ""}`);

  if (selectedAgent) {
    return <ReadStatus state={detail}>{(agent) => (
      <section className="read-card read-detail" aria-labelledby="agent-detail-title">
        <a href="/agents">← Back to agents</a>
        <p className="eyebrow">Agent detail</p>
        <h2 id="agent-detail-title">{agent.hostname}</h2>
        <dl className="detail-list">
          <div><dt>Agent ID</dt><dd>{agent.id}</dd></div>
          <div><dt>Status</dt><dd><StatusPill value={agent.status} /></dd></div>
          <div><dt>Last contact</dt><dd><time dateTime={agent.last_seen_at}>{dateLabel(agent.last_seen_at)}</time></dd></div>
          <div><dt>Environment</dt><dd>{agent.environment}</dd></div>
          <div><dt>Platform</dt><dd>{agent.platform}</dd></div>
          <div><dt>Certificate serial</dt><dd>{agent.certificate.serial}</dd></div>
          <div><dt>Certificate expires</dt><dd><time dateTime={agent.certificate.not_after}>{dateLabel(agent.certificate.not_after)}</time></dd></div>
        </dl>
      </section>
    )}</ReadStatus>;
  }

  return (
    <section aria-labelledby="agents-table-title">
      <ReadStatus state={list}>{(page) => <>
        <div className="read-toolbar">
          <h2 id="agents-table-title">{page.items.length.toLocaleString()} agents on this page</h2>
          <form className="filter-form" action="/agents" method="get">
            <label>Search hostname or ID<input name="q" value={filterQuery} onChange={(event) => setFilterQuery(event.currentTarget.value)} maxLength={128} /></label>
            <label>Status<select name="status" value={filterStatus} onChange={(event) => setFilterStatus(event.currentTarget.value)}>
              <option value="">All statuses</option><option value="active">Active</option><option value="stale">Stale</option><option value="revoked">Revoked</option>
            </select></label>
            <button type="submit">Apply filters</button>
          </form>
        </div>
        {page.items.length === 0 ? <p className="read-state">No agents match these filters.</p> : (
          <div className="table-scroll"><table className="data-table">
            <thead><tr><th scope="col">Hostname</th><th scope="col">Status</th><th scope="col">Last contact</th><th scope="col">Environment</th><th scope="col">Platform</th></tr></thead>
            <tbody>{page.items.map((agent) => <tr key={agent.id}>
              <th scope="row"><a href={`/agents?agent=${encodeURIComponent(agent.id)}`}>{agent.hostname}</a><span className="table-subtext">{agent.id}</span></th>
              <td><StatusPill value={agent.status} /></td><td><time dateTime={agent.last_seen_at}>{dateLabel(agent.last_seen_at)}</time></td><td>{agent.environment}</td><td>{agent.platform}</td>
            </tr>)}</tbody>
          </table></div>
        )}
        <PageFooter page={page} href="/agents" params={listParams} />
      </>}</ReadStatus>
    </section>
  );
}

export function FindingsReadPage() {
  const params = currentSearch();
  const selected = params.get("finding");
  const severity = params.get("severity") ?? "";
  const query = params.get("q") ?? "";
  const detail = useRead<Finding>(selected ? `/api/v1/findings/latest/${selected.split("/").map(encodeURIComponent).join("/")}` : "");
  const list = useRead<Page<Finding>>(selected ? "" : `/api/v1/findings/latest${params.size ? `?${params}` : ""}`);

  if (selected) {
    return <ReadStatus state={detail}>{(finding) => (
      <section className="read-card read-detail" aria-labelledby="finding-detail-title">
        <a href="/findings">← Back to findings</a>
        <p className="eyebrow">Observed match</p>
        <h2 id="finding-detail-title">{finding.rule_id} · {finding.rule_set_id === "~unknown" ? "rule set unknown (earlier agent)" : finding.rule_set_id}</h2>
        <dl className="detail-list">
          <div><dt>Agent</dt><dd><a href={`/agents?agent=${encodeURIComponent(finding.agent_id)}`}>{finding.hostname}</a></dd></div>
          <div><dt>Severity</dt><dd><StatusPill value={finding.severity} /></dd></div>
          <div><dt>Rule version</dt><dd>{finding.rule_version}</dd></div>
          <div><dt>Observation</dt><dd>{finding.message}</dd></div>
          <div><dt>First observed</dt><dd><time dateTime={finding.first_observed_at}>{dateLabel(finding.first_observed_at)}</time></dd></div>
          <div><dt>Last observed</dt><dd><time dateTime={finding.last_observed_at}>{dateLabel(finding.last_observed_at)}</time></dd></div>
          <div><dt>Observations</dt><dd>{finding.occurrence_count.toLocaleString()}</dd></div>
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
            <label>Search host, rule, or text<input name="q" defaultValue={query} maxLength={128} /></label>
            <label>Severity<select name="severity" defaultValue={severity}>
              <option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
            </select></label>
            <button type="submit">Apply filters</button>
          </form>
        </div>
        {page.items.length === 0 ? <p className="read-state">No findings match these filters.</p> : (
          <div className="table-scroll"><table className="data-table">
            <thead><tr><th scope="col">Rule</th><th scope="col">Severity</th><th scope="col">Agent</th><th scope="col">Last observed</th><th scope="col">Count</th></tr></thead>
            <tbody>{page.items.map((finding) => <tr key={finding.id}>
              <th scope="row"><a href={`/findings?finding=${encodeURIComponent(`${finding.agent_id}/${finding.rule_set_id}/${finding.rule_id}`)}`}>{finding.rule_id}</a><span className="table-subtext">{finding.rule_set_id === "~unknown" ? "rule set unknown (earlier agent)" : finding.rule_set_id}</span></th>
              <td><StatusPill value={finding.severity} /></td><td><a href={`/agents?agent=${encodeURIComponent(finding.agent_id)}`}>{finding.hostname}</a></td>
              <td><time dateTime={finding.last_observed_at}>{dateLabel(finding.last_observed_at)}</time></td><td>{finding.occurrence_count.toLocaleString()}</td>
            </tr>)}</tbody>
          </table></div>
        )}
        <PageFooter page={page} href="/findings" params={params} />
      </>}</ReadStatus>
    </section>
  );
}

function StatusPill({ value }: { value: string }) {
  return <span className={`status-pill status-pill--${value}`}>{value.replaceAll("_", " ")}</span>;
}

function PageFooter<T>({ page, href, params }: { page: Page<T>; href: string; params: URLSearchParams }) {
  return <footer className="page-footer">
    <p>Generated <time dateTime={page.generated_at}>{dateLabel(page.generated_at)}</time></p>
    {page.next_cursor && <a className="button-link" href={pagedUrl(href, params, page.next_cursor)}>Next page</a>}
  </footer>;
}
