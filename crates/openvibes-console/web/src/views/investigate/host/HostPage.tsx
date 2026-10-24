// A host's page (approved screen 17; roles spec §10.2), replacing the host
// panel and its tabs: header facts and actions, four tiles leading to the
// full lists, and the cards. The summary route decides what this person may
// see and do on this host; the agent's own record feeds Rule sets, the
// hardening row and Export.
import { type FormEvent, useState } from "react";

import { ApiError, invalidate, request, useResource } from "../../../api/client";
import type { AgentDetail, HostSummary } from "../../../api/types";
import { assistant } from "../../../app/assistant";
import { hostPath } from "../../../app/location";
import { nav, viewLink } from "../../../app/nav";
import { useProvideTitle } from "../../../app/titles";
import { AddToCase } from "../../../panels/cases/AddToCase";
import { Ago, Empty, ErrorBox, Loading, SAVED_HEARTBEAT_HINT, StatusBadge } from "../../../ui/bits";
import { DetailPage } from "../../../ui/detail/DetailPage";
import { Tile } from "../../../ui/detail/Tile";
import { Icon } from "../../../ui/Icon";
import { MenuButton } from "../../../ui/Menu";
import { toast } from "../../../ui/toast";
import { DialogHead, Modal } from "../../admin/people/NewPersonDialog";
import { CertificatesCard, DetailsCard, InventoryCard, ProtectionCard, RuleSetsCard, TopCards, systemName } from "./HostCards";
import { HostExport } from "./HostExport";
import { HostLabels } from "./HostLabels";

export const summaryPath = (id: string) => `/api/v1/hosts/${encodeURIComponent(id)}/summary`;
const agentPath = (id: string) => `/api/v1/agents/${encodeURIComponent(id)}`;

const short = new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short" });
const shortYear = new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short", year: "numeric" });
/** "3 Oct" this year, "3 Oct 2025" before. */
export function shortDate(value: string, now = new Date()): string {
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? "—" : (at.getFullYear() === now.getFullYear() ? short : shortYear).format(at);
}

export function NoSuchHost() {
  return <div className="view"><Empty icon="agents" title="No such host">This host does not exist, or it is outside the hosts you can see.</Empty></div>;
}

export function HostPage({ id }: { id: string }) {
  const summary = useResource<HostSummary>(summaryPath(id));
  const agent = useResource<AgentDetail>(agentPath(id));
  useProvideTitle({ kind: "agent", id }, summary.data?.host.hostname ?? undefined);
  if (summary.error?.status === 404) return <NoSuchHost />;
  if (summary.error) return <div className="view"><div className="view-pad"><ErrorBox error={summary.error} /></div></div>;
  if (!summary.data) return <div className="view"><Loading /></div>;
  return <HostView summary={summary.data} agent={agent.data} agentError={agent.error} />;
}

export function HostView({ summary, agent, agentError }: { summary: HostSummary; agent: AgentDetail | undefined; agentError?: ApiError | undefined }) {
  const { host, tiles, can } = summary;
  const name = host.hostname ?? host.id;
  const [error, setError] = useState<string>();
  const q = { host: host.id };
  const tile = (label: string, value: number | null | undefined, view: string, params?: Record<string, string>) =>
    value != null && <Tile key={label} label={label} value={value} to={params ? { view, params } : { view }} />;
  return (
    <DetailPage
      crumb={<a {...viewLink("/hosts")}>Hosts</a>}
      icon={<span className="detail-page__os">{host.os.family === "windows" ? "WIN" : host.os.family === "linux" ? "LX" : <Icon name="agents" size={20} />}</span>}
      title={<span className="mono">{name}</span>}
      status={<StatusBadge status={host.status} />}
      facts={[
        host.id, systemName(host), host.address,
        host.scanner_version && <>{host.scanner_version}{host.agent_older && <span className="warn-text"> (older)</span>}</>,
        host.last_seen_at && <Ago value={host.last_seen_at} hint={SAVED_HEARTBEAT_HINT} />,
        `enrolled ${shortDate(host.enrolled_at)}`,
      ]}
      actions={<HostActions summary={summary} agent={agent} name={name} onError={setError} />}
      error={error}
      tiles={[
        tile("Open alarms", tiles.open_alarms, "/alarms", q),
        // The Compliance list's failing (seen within a day): a host silent for a day has no count to show.
        tiles.compliance_stale && tiles.compliance_failing != null
          ? <Tile key="Compliance failing" label="Compliance failing" value={null} to={{ view: "/compliance", params: q }} note="No report in the last day" />
          : tile("Compliance failing", tiles.compliance_failing, "/compliance", q),
        tile("Vulnerabilities", tiles.vulnerabilities, "/vulnerabilities", q),
        tile("Software", tiles.software, `${hostPath(host.id)}/software`),
      ]}
      left={<>
        <DetailsCard host={host} />
        <ProtectionCard summary={summary} agent={agent} />
        {host.status !== "imported" && <RuleSetsCard agent={agent} error={agentError} />}
        <HostLabels id={host.id} labels={summary.labels} groups={summary.groups} editable={can.label} />
        <CertificatesCard summary={summary} agent={agent} />
      </>}
      right={<>
        <TopCards summary={summary} />
        <InventoryCard summary={summary} />
      </>}
    />
  );
}

/** Compare, Export, Add to case, Ask about this, and ⋯ with Revoke. */
function HostActions({ summary, agent, name, onError }: { summary: HostSummary; agent: AgentDetail | undefined; name: string; onError: (message: string | undefined) => void }) {
  const { host, can } = summary;
  const [revoking, setRevoking] = useState(false);
  return (
    <>
      <button type="button" className="button" onClick={() => nav.open({ kind: "compare", id: host.id })}><Icon name="layers" size={14} /> Compare</button>
      {can.export && agent && <HostExport agent={agent} />}
      {can.add_to_case && <AddToCase kind="host" id={host.id} label={name} />}
      {can.ask && <button type="button" className="button" onClick={() => assistant.askAbout({ kind: "agent", id: host.id }, name)}><Icon name="sparkles" size={14} /> Ask about this</button>}
      {can.revoke && <MenuButton label="More actions" icon="more" compact items={[{ value: "revoke", label: "Revoke…", description: "Its certificate stops working at once" }]} onPick={() => { onError(undefined); setRevoking(true); }} />}
      {revoking && <RevokeDialog id={host.id} name={name} onClose={() => setRevoking(false)} onError={onError} />}
    </>
  );
}

function RevokeDialog({ id, name, onClose, onError }: { id: string; name: string; onClose: () => void; onError: (message: string | undefined) => void }) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!reason.trim()) return;
    setBusy(true);
    try {
      await request("POST", `${agentPath(id)}/revoke`, { reason: reason.trim() });
      invalidate("/api/v1/hosts");
      invalidate("/api/v1/agents");
      toast(`${name} revoked`);
      onClose();
    } catch (e) {
      onError(e instanceof ApiError ? e.message : "The host could not be revoked.");
      onClose();
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal label={`Revoke ${name}`} onClose={onClose}>
      <form className="bulk-dialog stack" onSubmit={(event) => void submit(event)}>
        <DialogHead title={`Revoke ${name}`} onClose={onClose} />
        <p>Its certificate stops working at once; the host must enroll again.</p>
        <input className="input" autoFocus required aria-label="Reason (kept in the audit log)" placeholder="Reason (kept in the audit log)" value={reason} onChange={(e) => setReason(e.target.value)} />
        <div className="row row--end">
          <button type="button" className="button button--ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="button button--danger" disabled={busy || !reason.trim()}>{busy ? "Revoking…" : "Revoke"}</button>
        </div>
      </form>
    </Modal>
  );
}
