import { useMemo, useState } from "react";

import { ApiError, invalidate, request, useAllPages, useResource } from "../api/client";
import type { Agent, AlarmSummary, Certificate, Finding, HostPackage, Tag, TagPreview, VulnerabilityPage } from "../api/types";
import { useSession } from "../app/session";
import { useProvideTitle } from "../app/titles";
import { Ago, Empty, ErrorBox, Loading, ObjectLink, SeverityBadge, StatusBadge } from "../ui/bits";
import { date, severityOrder } from "../ui/format";
import { lineage } from "../views/Alarms";
import { packageId } from "../views/Software";
import { Icon } from "../ui/Icon";
import { Confirm, PanelHeader, Section, Tabs } from "../ui/panel";
import { toast } from "../ui/toast";

/** Active alarms the Host page lists; more opens the Alarms view. */
const ALARMS_SHOWN = 100;

type Detail = Agent & { certificates: Certificate[] };

/** The host's installed software (Assets v1), filtered on the server. */
function SoftwareTab({ id }: { id: string }) {
  const [q, setQ] = useState("");
  const [fixable, setFixable] = useState(false);
  const [max, setMax] = useState(200);
  const query = new URLSearchParams();
  if (q.trim()) query.set("q", q.trim());
  if (fixable) query.set("fixable", "true");
  const packages = useAllPages<HostPackage>(`/api/v1/agents/${encodeURIComponent(id)}/packages?${query.toString()}`, max);
  const items = packages.data ?? [];
  return (
    <div className="panel-body stack">
      <div className="row row--wrap">
        <input className="input grow" value={q} onChange={(event) => { setQ(event.target.value); setMax(200); }} placeholder="Filter by package name…" aria-label="Filter installed software" />
        <label className="row"><input type="checkbox" checked={fixable} onChange={(event) => setFixable(event.target.checked)} /> Fix available</label>
      </div>
      {packages.error ? <ErrorBox error={packages.error} /> : packages.loading && !packages.data ? <Loading rows={4} /> : items.length === 0 ? (
        <Empty title={q || fixable ? "Nothing matches" : "No software reported"}>{q || fixable ? null : "The agent reports its packages shortly after it enrolls."}</Empty>
      ) : (
        <ul className="list" aria-label="Installed software">
          {items.map((pkg) => (
            <li key={`${pkg.manager}/${pkg.name}/${pkg.version}/${pkg.release}/${pkg.arch}`}>
              <ObjectLink to={{ kind: "package", id: packageId(pkg) }} className="list__row">
                <span className="mono grow truncate">{pkg.name}</span>
                <span className="mono subtle nowrap">{pkg.version}{pkg.release ? `-${pkg.release}` : ""}</span>
                {pkg.fixable_vulnerable && <span className="badge badge--warn badge--plain">fix available</span>}
              </ObjectLink>
            </li>
          ))}
        </ul>
      )}
      {items.length >= max && <button type="button" className="button" onClick={() => setMax((m) => m + 200)}>Show more</button>}
    </div>
  );
}

export function AgentPanel({ id }: { id: string }) {
  const { can } = useSession();
  const agent = useResource<Detail>(`/api/v1/agents/${encodeURIComponent(id)}`);
  const findings = useAllPages<Finding>(can("findings.read") ? "/api/v1/findings/latest" : null);
  const vulns = useResource<VulnerabilityPage>(can("vulnerabilities.read") ? `/api/v1/vulnerabilities?host=${encodeURIComponent(id)}` : null);
  const alarms = useAllPages<AlarmSummary>(can("alarms.read") ? `/api/v1/alarms?agent_id=${encodeURIComponent(id)}&state=active` : null, ALARMS_SHOWN);
  const alarmItems = alarms.data ?? [];
  // A full page may hide more: say so rather than a round number.
  const alarmCount = alarmItems.length >= ALARMS_SHOWN ? `${ALARMS_SHOWN}+` : String(alarmItems.length);
  useProvideTitle({ kind: "agent", id }, agent.data?.hostname ?? undefined);
  const mine = useMemo(() => (findings.data ?? []).filter((finding) => finding.agent_id === id)
    .sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9)), [findings.data, id]);

  if (agent.error) return <div className="panel-body"><ErrorBox error={agent.error} /></div>;
  if (!agent.data) return <Loading />;
  const data = agent.data;
  const name = data.hostname ?? data.id;
  const vulnItems = vulns.data?.items ?? [];

  return (
    <>
      <PanelHeader
        icon="agents" kind="Host" title={name}
        subtitle={<span className="mono subtle">{data.id}</span>}
        badges={<><StatusBadge status={data.status} />{data.scanner_version && <span className="badge badge--plain">agent {data.scanner_version}</span>}</>}
        askAbout={{ ref: { kind: "agent", id }, label: name }}
        actions={can("agents.revoke") && data.status !== "revoked" && data.status !== "imported" && (
          <Confirm danger label={`Revoke ${name}? Its certificate stops working at once; the host must enroll again.`} reason="Reason (kept in the audit log)"
            onConfirm={async (reason) => {
              await request("POST", `/api/v1/agents/${encodeURIComponent(id)}/revoke`, { reason });
              invalidate("/api/v1/agents");
              toast(`${name} revoked`);
            }}>
            <Icon name="ban" size={14} /> Revoke
          </Confirm>
        )}
      />
      <div className="panel-glance">
        <div><span className="subtle">Last contact</span><strong><Ago value={data.last_seen_at} /></strong></div>
        <div><span className="subtle">Findings</span><strong className="num">{findings.loading ? "…" : mine.length}</strong></div>
        <div><span className="subtle">Vulnerabilities</span><strong className="num">{vulns.loading ? "…" : vulnItems.length}</strong></div>
        {can("alarms.read") && <div><span className="subtle">Active alarms</span><strong className="num">{alarms.loading ? "…" : alarmCount}</strong></div>}
        <div><span className="subtle">Enrolled</span><strong>{date(data.enrolled_at)}</strong></div>
      </div>
      <Tabs tabs={[
        { id: "findings", label: "Findings", count: mine.length },
        { id: "vulns", label: "Vulnerabilities", count: vulnItems.length },
        ...(can("alarms.read") ? [{ id: "alarms", label: "Alarms", count: alarmItems.length }] as const : []),
        { id: "software", label: "Software" },
        { id: "details", label: "Details" },
      ]}>
        {(tab) => tab === "findings" ? (
          mine.length === 0 ? <Empty title={findings.loading ? "Loading…" : "No findings"}>{findings.loading ? null : "This host matches no rule right now."}</Empty> : (
            <ul className="list">
              {mine.map((finding) => (
                <li key={finding.id}>
                  <ObjectLink to={{ kind: "finding", id: `${finding.rule_set_id}/${finding.rule_id}` }} className="list__row">
                    <SeverityBadge severity={finding.severity} />
                    <span className="grow truncate">{finding.message}</span>
                    <span className="mono subtle nowrap">{finding.rule_id}</span>
                  </ObjectLink>
                </li>
              ))}
            </ul>
          )
        ) : tab === "vulns" ? (
          vulnItems.length === 0 ? <Empty title={vulns.loading ? "Loading…" : "No open vulnerabilities"} /> : (
            <ul className="list">
              {vulnItems.map((item) => (
                <li key={item.advisory_id}>
                  <ObjectLink to={{ kind: "advisory", id: item.advisory_id }} className="list__row">
                    <SeverityBadge severity={item.severity} />
                    <span className="grow truncate">{item.title}</span>
                    {item.exploited && <span className="badge badge--critical badge--plain" title="Known to be exploited"><Icon name="flame" size={12} /> KEV</span>}
                    {item.reboot_needed && <span className="badge badge--warn badge--plain">Reboot</span>}
                  </ObjectLink>
                </li>
              ))}
            </ul>
          )
        ) : tab === "alarms" ? (
          alarmItems.length === 0 ? <Empty title={alarms.loading ? "Loading…" : "No active alarms"} /> : (
            <ul className="list">
              {alarmItems.map((alarm) => (
                <li key={alarm.id}>
                  <ObjectLink to={{ kind: "alarm", id: alarm.id }} className="list__row">
                    <SeverityBadge severity={alarm.severity} />
                    <span className="grow truncate">{alarm.message}</span>
                    <span className="mono subtle nowrap">{lineage(alarm)}</span>
                  </ObjectLink>
                </li>
              ))}
            </ul>
          )
        ) : tab === "software" ? (
          <SoftwareTab id={id} />
        ) : (
          <div className="panel-body stack">
            <Section title="Identity">
              <dl className="kv">
                <dt>Host name</dt><dd>{data.hostname ?? "—"}</dd>
                <dt>Agent ID</dt><dd className="mono">{data.id}</dd>
                {data.os_id && <><dt>System</dt><dd>{data.os_id} {data.os_version ?? ""}</dd></>}
                {data.running_kernel && <><dt>Running kernel</dt><dd className="mono">{data.running_kernel}</dd></>}
                {data.inventory_at && <><dt>Software as of</dt><dd><Ago value={data.inventory_at} /></dd></>}
                <dt>Status</dt><dd><StatusBadge status={data.status} /></dd>
                <dt>Enrolled</dt><dd>{date(data.enrolled_at)}</dd>
                {data.revoked_at && <><dt>Revoked</dt><dd>{date(data.revoked_at)}</dd></>}
                <dt>Capabilities</dt><dd className="row row--wrap">{data.capabilities.length ? data.capabilities.map((c) => <span key={c} className="tag">{c}</span>) : "—"}</dd>
              </dl>
            </Section>
            {can("asset_groups.manage", true) && <TagEditor id={id} />}
            <Section title="Certificates">
              <ul className="list list--plain">
                {data.certificates.map((certificate, index) => (
                  <li key={certificate.serial} className="list__row list__row--static">
                    <span className="mono">{certificate.serial}</span>
                    <span className="grow" />
                    <span className="subtle nowrap">until {date(certificate.not_after)}</span>
                    {index === 0 && <span className="badge badge--ok">Current</span>}
                  </li>
                ))}
              </ul>
            </Section>
          </div>
        )}
      </Tabs>
    </>
  );
}

function TagEditor({ id }: { id: string }) {
  const [draft, setDraft] = useState("");
  const [preview, setPreview] = useState<TagPreview>();
  const [error, setError] = useState<string>();
  const parse = (text: string): Tag[] => text.split(/[\s,]+/).filter(Boolean).map((pair) => {
    const [key = "", ...rest] = pair.split("=");
    return { key, value: rest.join("=") };
  });
  return (
    <Section title="Tags">
      <form className="stack" onSubmit={(event) => {
        event.preventDefault();
        setError(undefined);
        request<TagPreview>("POST", `/api/v1/agents/${encodeURIComponent(id)}/tags/preview`, { tags: parse(draft) })
          .then(setPreview, (e: unknown) => setError(e instanceof ApiError ? e.message : "Preview failed"));
      }}>
        <div className="row">
          <input className="input grow" value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="env=prod role=web" aria-label="Tags as key=value pairs" />
          <button className="button button--small" type="submit">Preview</button>
        </div>
        {error && <p className="confirm__error" role="alert">{error}</p>}
        {preview && (
          <div className="card card__body stack">
            <div className="row row--wrap"><span className="subtle">Now</span>{preview.current.map((t) => <span key={`${t.key}=${t.value}`} className="tag">{t.key}={t.value}</span>)}</div>
            <div className="row row--wrap"><span className="subtle">After</span>{preview.proposed.map((t) => <span key={`${t.key}=${t.value}`} className="tag">{t.key}={t.value}</span>)}</div>
            {(preview.gained_groups.length > 0 || preview.lost_groups.length > 0) && (
              <p className="subtle">Joins {preview.gained_groups.map((g) => g.name).join(", ") || "no group"}; leaves {preview.lost_groups.map((g) => g.name).join(", ") || "no group"}.</p>
            )}
            <div className="row">
              <button type="button" className="button button--small button--primary" onClick={() => {
                request("PUT", `/api/v1/agents/${encodeURIComponent(id)}/tags`, { tags: preview.proposed, preview_token: preview.preview_token })
                  .then(() => { setPreview(undefined); setDraft(""); invalidate("/api/v1/agents"); toast("Tags updated"); },
                    (e: unknown) => setError(e instanceof ApiError ? e.message : "Update failed"));
              }}>Apply</button>
              <button type="button" className="button button--small button--ghost" onClick={() => setPreview(undefined)}>Discard</button>
            </div>
          </div>
        )}
      </form>
    </Section>
  );
}
