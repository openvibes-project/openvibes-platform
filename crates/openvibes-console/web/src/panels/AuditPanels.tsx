// An audit event, and the audit retention policy.
import { useState } from "react";

import { ApiError, apiMessage, invalidate, request, useAllPages, useResource } from "../api/client";
import type { AuditEvent, AuditRetention } from "../api/types";
import { useLocation } from "../app/nav";
import { useSession } from "../app/session";
import { Ago, Empty, ErrorBox, Loading, ObjectLink } from "../ui/bits";
import { auditSince, when } from "../ui/format";
import { PanelHeader } from "../ui/panel";
import { toast } from "../ui/toast";

export function AuditEventPanel({ id }: { id: string }) {
  const { params } = useLocation();
  const page = useAllPages<AuditEvent>(`/api/v1/audit-events?since=${encodeURIComponent(auditSince(params))}`, 1000);
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
                (e: unknown) => { setError(apiMessage(e, "Could not change retention")); if (e instanceof ApiError && e.status === 412) invalidate("/api/v1/audit"); });
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
