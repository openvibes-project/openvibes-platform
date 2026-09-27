import { useEffect, useState } from "react";
import type { components } from "../api/generated";

type GroupPage = components["schemas"]["FindingGroupPage"];
type EndpointPage = components["schemas"]["FindingGroupEndpointPage"];

function useData<T>(url: string, seeded: boolean): { data?: T; error?: string; status?: number | undefined } {
  const [state, setState] = useState<{ url: string; data?: T; error?: string; status?: number | undefined }>({ url: "" });
  useEffect(() => {
    const controller = new AbortController();
    if (!url) return () => controller.abort();
    const headers = new Headers({ Accept: "application/json" });
    if (seeded) {
      headers.set("X-OpenVIBES-Dev-Persona", localStorage.getItem("openvibes.dev.persona") ?? "analyst");
      headers.set("X-OpenVIBES-Dev-Mode", localStorage.getItem("openvibes.dev.mode") ?? "mixed");
    }
    void fetch(url, { headers, signal: controller.signal }).then(async (response) => {
      if (!response.ok) {
        const problem = await response.json() as { title?: string; field_errors?: { message: string }[] };
        const detail = problem.field_errors?.map((item) => item.message).join(" ");
        throw Object.assign(new Error([problem.title ?? "Finding data could not be loaded.", detail].filter(Boolean).join(" ")), { status: response.status });
      }
      return await response.json() as T;
    }).then((data) => setState({ url, data })).catch((error: unknown) => {
      if (!controller.signal.aborted) {
        const detail = typeof error === "object" && error !== null ? error as { message?: string; status?: number } : {};
        setState({ url, error: detail.message ?? "Read failed.", status: detail.status });
      }
    });
    return () => controller.abort();
  }, [url, seeded]);
  return state.url === url ? state : {};
}

function when(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function GroupedFindingsPage({ seeded = false, csrfToken, canTriage = false }: { seeded?: boolean; csrfToken?: string | undefined; canTriage?: boolean }) {
  const params = new URLSearchParams(typeof window === "undefined" ? "" : window.location.search);
  const selected = params.get("finding");
  const [ruleSet = "", ruleId = ""] = selected?.split("/", 2) ?? [];
  const [includeOlder, setIncludeOlder] = useState(params.get("include_older") === "true");
  const groupCursor = params.get("cursor");
  const [endpointCursor, setEndpointCursor] = useState(params.get("endpoint_cursor"));
  const since = params.get("since");
  const [endpointWindow, setEndpointWindow] = useState<{ source: string | null; value: string | null }>({ source: since, value: since });
  const endpointSince = endpointWindow.source === since ? endpointWindow.value : since;
  const groupQuery = new URLSearchParams({ limit: "100" });
  if (since) groupQuery.set("since", since);
  if (groupCursor) groupQuery.set("cursor", groupCursor);
  const groupResult = useData<GroupPage>(`/api/v1/findings/groups?${groupQuery}`, seeded);
  const endpointQuery = new URLSearchParams({ include_older: String(includeOlder), limit: "100" });
  if (endpointSince) endpointQuery.set("since", endpointSince);
  if (endpointCursor) endpointQuery.set("cursor", endpointCursor);
  const endpointUrl = selected ? `/api/v1/findings/groups/${[ruleSet, ruleId].map(encodeURIComponent).join("/")}/endpoints?${endpointQuery}` : "";
  const endpointResult = useData<EndpointPage>(endpointUrl, seeded);
  const groups = groupResult.data?.items ?? [];
  const endpoints = endpointResult.data?.items ?? [];
  const [selectedIds, setSelectedIds] = useState<Record<string, number>>({});
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const currentGroup = groups.find((group) => group.rule_set_id === ruleSet && group.rule_id === ruleId);
  function toggle(id: string, version: number, checked: boolean) {
    setSelectedIds((current) => checked ? { ...current, [id]: version } : Object.fromEntries(Object.entries(current).filter(([key]) => key !== id)));
  }
  async function bulkUpdate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!csrfToken || !selected || Object.keys(selectedIds).length === 0) return;
    const form = new FormData(event.currentTarget);
    setBusy(true); setMessage("");
    try {
      const response = await fetch(`/api/v1/findings/groups/${[ruleSet, ruleId].map(encodeURIComponent).join("/")}/triage`, {
        method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", Accept: "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify({ changes: Object.entries(selectedIds).map(([agent_id, version]) => ({ agent_id, version })), state: form.get("state"), assigned_to: form.get("assigned_to") || null, note: form.get("note") || null, accepted_until: form.get("accepted_until") || null }),
      });
      if (!response.ok) {
        const problem = await response.json() as { title?: string; field_errors?: { message: string }[] };
        const detail = problem.field_errors?.map((item) => item.message).join(" ");
        throw new Error([problem.title ?? (response.status === 412 ? "Triage changed elsewhere." : "Bulk triage failed."), detail, "No changes were applied."].filter(Boolean).join(" "));
      }
      setSelectedIds({}); setMessage("Triage updated for every selected endpoint."); window.location.reload();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Bulk triage failed."); }
    finally { setBusy(false); }
  }
  if (selected) return <section aria-labelledby="group-detail-title">
    <a href="/findings">← Back to findings</a>
    <div className="read-card__heading"><div><p className="eyebrow">Grouped observation</p><h2 id="group-detail-title">{ruleId} · {ruleSet === "~unknown" ? "rule set unknown (earlier agent)" : ruleSet}</h2><p>{currentGroup?.latest_message ?? "Current observations reported by endpoints in scope."}</p></div></div>
    <label className="filter-form"><input type="checkbox" checked={includeOlder} onChange={(event) => { setIncludeOlder(event.currentTarget.checked); setEndpointCursor(null); }} /> Include endpoints whose latest match is older than the 24 hour window</label>
    {endpointResult.error && <section className="read-card" role="alert"><h2>{endpointResult.status === 401 ? "Session expired" : "Data unavailable"}</h2><p>{endpointResult.error}</p></section>}
    {endpoints.length === 0 ? <p className="read-state">No endpoints in this group are visible in the selected window.</p> : <div className="table-scroll"><table className="data-table"><thead><tr><th scope="col">Select</th><th scope="col">Endpoint</th><th scope="col">Last observed</th><th scope="col">Rule version</th><th scope="col">Triage</th><th scope="col">Origin</th></tr></thead><tbody>{endpoints.map((endpoint) => <tr key={endpoint.agent_id}>
      <td><input aria-label={`Select ${endpoint.hostname ?? endpoint.agent_id}`} type="checkbox" checked={endpoint.agent_id in selectedIds} onChange={(event) => toggle(endpoint.agent_id, endpoint.triage_version, event.currentTarget.checked)} disabled={!canTriage || seeded || endpoint.outside_window || (Object.keys(selectedIds).length >= 100 && !(endpoint.agent_id in selectedIds))} /></td>
      <th scope="row"><a href={`/agents?agent=${encodeURIComponent(endpoint.agent_id)}`}>{endpoint.hostname ?? endpoint.agent_id}</a><span className="table-subtext">{endpoint.agent_id}{endpoint.origin === "import" ? ` · Imported installation ${endpoint.agent_id.startsWith("import.") ? endpoint.agent_id.slice(7) : endpoint.agent_id}` : ""}</span>{endpoint.outside_window && <span className="table-subtext">Outside the recent window</span>}</th>
      <td><time dateTime={endpoint.last_observed_at}>{when(endpoint.last_observed_at)}</time></td><td>{endpoint.rule_version}</td><td>{endpoint.triage_state} · v{endpoint.triage_version}</td><td>{endpoint.origin === "import" ? "Imported" : endpoint.authenticated ? "Online · authenticated" : "Online · unauthenticated"}</td>
    </tr>)}</tbody></table></div>}
    {endpointResult.data?.next_cursor && <button className="button-link" type="button" onClick={() => { const pageSince = endpointResult.data?.since ?? since; setEndpointWindow({ source: since, value: pageSince }); setEndpointCursor(endpointResult.data?.next_cursor ?? null); }}>Next endpoint page</button>}
    {canTriage && !seeded && <form className="filter-form read-card" onSubmit={(event) => void bulkUpdate(event)}><h3>Update selected endpoints atomically ({Object.keys(selectedIds).length}/100 selected)</h3><label>State<select name="state" defaultValue="investigating"><option value="open">Open</option><option value="investigating">Investigating</option><option value="mitigated">Mitigated</option><option value="accepted_risk">Accepted risk</option><option value="false_positive">False positive</option></select></label><label>Assigned analyst<input name="assigned_to" /></label><label>Note<textarea name="note" maxLength={4000} /></label><label>Accepted until<input type="text" name="accepted_until" placeholder="2026-12-31T23:59:00Z" /></label><button type="submit" disabled={busy || Object.keys(selectedIds).length === 0 || Object.keys(selectedIds).length > 100}>{busy ? "Saving…" : "Apply to all selected"}</button><p role="status">{message || (!canTriage ? "Read only" : "All updates succeed together or none are applied.")}</p></form>}
  </section>;
  return <section aria-labelledby="findings-table-title"><div className="read-toolbar"><div><p className="eyebrow">Recent observations</p><h2 id="findings-table-title">{groups.length.toLocaleString()} rule groups</h2><p>Each rule appears once; open a group to review its visible endpoints.</p></div></div>
    {groupResult.error && <section className="read-card" role="alert"><h2>{groupResult.status === 401 ? "Session expired" : "Data unavailable"}</h2><p>{groupResult.error}</p></section>}
    {!groupResult.data ? <p role="status" className="read-state">Loading finding groups…</p> : groups.length === 0 ? <p className="read-state">No recent findings in this scope.</p> : <div className="table-scroll"><table className="data-table"><thead><tr><th scope="col">Rule group</th><th scope="col">Severity</th><th scope="col">Endpoints</th><th scope="col">Latest observation</th><th scope="col">Triage</th></tr></thead><tbody>{groups.map((group) => <tr key={`${group.rule_set_id}/${group.rule_id}`}>
      <th scope="row"><a href={`/findings?finding=${encodeURIComponent(`${group.rule_set_id}/${group.rule_id}`)}`}>{group.rule_id}</a><span className="table-subtext">{group.rule_set_id === "~unknown" ? "rule set unknown (earlier agent)" : group.rule_set_id}</span><span className="table-subtext">Rule versions {group.rule_versions.join(", ")}</span></th><td>{group.severity}</td><td>{group.endpoint_count.toLocaleString()} recent · {group.older_endpoint_count.toLocaleString()} older</td><td><time dateTime={group.last_observed_at}>{when(group.last_observed_at)}</time><span className="table-subtext">{group.latest_message}</span></td><td>{group.triage_counts.open} open · {group.triage_counts.investigating} investigating · {group.triage_counts.mitigated} mitigated · {group.triage_counts.accepted_risk} accepted · {group.triage_counts.false_positive} false positive</td>
    </tr>)}</tbody></table></div>}
    {groupResult.data?.next_cursor && <a className="button-link" href={`/findings?${new URLSearchParams({ cursor: groupResult.data.next_cursor, since: groupResult.data.since })}`}>Next rule groups</a>}
  </section>;
}
