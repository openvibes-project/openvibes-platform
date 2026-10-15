// A rule set: its versions and where it runs, and publishing a signed bundle.
import { useState } from "react";

import { apiMessage, invalidate, request, useResource } from "../api/client";
import type { AttackCoverage, RuleBundle, RuleSet, RuleSetAssignments } from "../api/types";
import { nav } from "../app/nav";
import { useSession } from "../app/session";
import { Icon } from "../ui/Icon";
import { Ago, Empty, ErrorBox, Loading } from "../ui/bits";
import { date, when } from "../ui/format";
import { PanelHeader, Section } from "../ui/panel";
import { toast } from "../ui/toast";
import { WhereItRuns } from "./WhereItRuns";
import { readsRules, sourceDetail } from "./ruleAssignment";

export function RuleSetPanel({ id }: { id: string }) {
  const { can } = useSession();
  const reads = readsRules(can);
  const sets = useResource<{ items: RuleSet[] }>(reads ? "/api/v1/rule-sets" : null);
  const set = sets.data?.items.find((item) => item.rule_set_id === id);
  const bundles = useResource<{ items: RuleBundle[] }>(set ? `/api/v1/rule-sets/${encodeURIComponent(id)}/bundles` : null);
  const assignments = useResource<RuleSetAssignments>(reads ? "/api/v1/rule-set-assignments" : null);
  const assignment = assignments.data?.items.find((item) => item.rule_set_id === id);
  const coverage = useResource<AttackCoverage>(reads && assignment?.published ? "/api/v1/rules/coverage" : null);
  const checks = coverage.data ? coverage.data.rules.filter((r) => r.rule_set_id === id && !r.draft).length : null;
  const error = sets.error ?? assignments.error;
  if (error) return <div className="panel-body"><ErrorBox error={error} /></div>;
  if (!set && !assignment) return sets.loading || assignments.loading ? <Loading /> : <div className="panel-body"><Empty title="Rule set not found" /></div>;
  return (
    <>
      <PanelHeader icon="rules" kind="Rule set" title={id}
        badges={<>
          {assignment && !assignment.published ? <span className="badge badge--plain">Not published</span>
            : set && <span className="badge badge--accent badge--plain">version {set.current_version ?? "—"}</span>}
          {set?.retired && <span className="badge badge--plain">Retired</span>}
          {set?.current_signer_removed && <span className="badge badge--bad">Signer key removed</span>}
        </>} />
      <div className="panel-body stack">
        <dl className="kv">
          {set && <>
            <dt>Signed by</dt><dd className="mono">{set.current_issuer_key_id ?? "—"}</dd>
            <dt>Expires</dt><dd>{set.current_expires_at_ms ? <><Ago value={set.current_expires_at_ms} /> · {date(set.current_expires_at_ms)}</> : "—"}</dd>
          </>}
          {assignment
            ? <><dt>Source</dt><dd>OpenVIBES rules package <span className="subtle">{sourceDetail(id, checks)}</span></dd></>
            : set && <><dt>Trusted keys</dt><dd className="num">{set.trusted_keys}</dd></>}
        </dl>
        {!assignment && <p className="subtle">Bundles are signed offline; publish a new version with <code>openvibes-admin rules publish</code> or the API. Agents fetch it on their next contact.</p>}
        {assignment && <WhereItRuns assignment={assignment} groups={assignments.data?.asset_groups ?? []} canChange={can("rules.upload", true)} />}
      </div>
      {set && (
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
      )}
    </>
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
    }).catch((e: unknown) => setError(e instanceof SyntaxError || (e instanceof Error && e.message === "not an object") ? "This is not a signed envelope (JSON object)." : apiMessage(e, "The envelope could not be verified")))
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
                    (e: unknown) => setError(apiMessage(e, "The bundle could not be published; preview it again")))
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
