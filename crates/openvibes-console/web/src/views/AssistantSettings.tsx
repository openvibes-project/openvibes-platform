// Admin → Assistant: the two opt-in internet-lookup levels (spec 2026-10-10 §2).
// Turning a level on asks first, repeating its risk text; turning it off does not.
import { type ReactNode, useEffect, useRef, useState } from "react";

import { ApiError, invalidate, request, useResource } from "../api/client";
import type { AssistantInternet, AssistantInternetTest, AssistantStatus } from "../api/types";
import { ErrorBox, Loading } from "../ui/bits";
import { Icon } from "../ui/Icon";
import { Switch } from "../ui/Switch";
import { toast } from "../ui/toast";
import { ViewHeader } from "../ui/ViewHeader";
import { toDomains, validSearxngUrl } from "./assistantRules";

const message = (error: unknown, fallback: string) => (error instanceof ApiError ? error.message : fallback);
const PATH = "/api/v1/assistant-internet";
const LEVEL1_RISK = "Sends public IDs only (like CVE-2026-1234) to api.osv.dev and bodhi.fedoraproject.org. No host data leaves your network.";
const LEVEL2_RISK = "The query goes to your SearXNG and the engines behind it; code refuses any query naming a host, agent ID, IP address, user name or internal domain; website snippets reach the assistant as data and may be wrong or hostile; every answer shows what was searched.";

type Change = { level: number; searxng_url: string | null; internal_domains: string[] };

/** A native modal dialog: focus trapped, Escape closes it. */
function TurnOnDialog({ title, risk, canConfirm, busy, error, onConfirm, onClose, children }: Readonly<{
  title: string; risk: string; canConfirm: boolean; busy: boolean; error: string | undefined;
  onConfirm: () => void; onClose: () => void; children?: ReactNode;
}>) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => { if (!dialog.current?.open) dialog.current?.showModal(); }, []);
  return (
    <dialog ref={dialog} className="palette bulk-modal" aria-label={title} onClose={onClose}>
      <form className="bulk-dialog stack" onSubmit={(event) => { event.preventDefault(); onConfirm(); }}>
        <div className="row row--between"><h2>{title}</h2>
          <button type="button" className="icon-button" aria-label="Close" onClick={onClose}><Icon name="close" size={16} /></button></div>
        <p>{risk}</p>
        {children}
        {error && <p className="confirm__error" role="alert">{error}</p>}
        <div className="row row--end">
          <button type="button" className="button button--ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="button button--primary" disabled={!canConfirm || busy}>Turn on</button>
        </div>
      </form>
    </dialog>
  );
}

export function AssistantSettings() {
  const setting = useResource<AssistantInternet>(PATH);
  const status = useResource<AssistantStatus>("/api/v1/assistant/status");
  const [asking, setAsking] = useState<1 | 2>();
  const [url, setUrl] = useState("");
  const [domains, setDomains] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [testing, setTesting] = useState(false);
  const [tested, setTested] = useState<AssistantInternetTest>();
  if (setting.error) return <div className="view"><ViewHeader title="Assistant" /><div className="view-pad"><ErrorBox error={setting.error} /></div></div>;
  const current = setting.data;
  if (!current) return <div className="view"><ViewHeader title="Assistant" /><Loading rows={4} /></div>;
  const off = status.data?.available === false;
  // The draft stays until the next reload, so the box never flickers back before the refetch; a concurrent change elsewhere shows as a 412 on save.
  const domainText = domains ?? current.internal_domains.join("\n");


  const save = (change: Change, done: string) => {
    setBusy(true);
    setError(undefined);
    return request("PUT", PATH, change, { "if-match": `"${current.version}"` })
      .then(() => { setAsking(undefined); setDomains(change.internal_domains.join("\n")); invalidate(PATH); toast(done); },
        (e: unknown) => { setError(message(e, "Could not change the setting")); if (e instanceof ApiError && e.status === 412) invalidate(PATH); })
      .finally(() => setBusy(false));
  };
  const base = { searxng_url: current.searxng_url ?? null, internal_domains: toDomains(domainText) };
  const test = () => {
    setTesting(true);
    setTested(undefined);
    request<AssistantInternetTest>("POST", `${PATH}/test`)
      .then(setTested, (e: unknown) => setTested({ ok: false, detail: message(e, "Could not run the test") }))
      .finally(() => setTesting(false));
  };
  const close = () => { setAsking(undefined); setError(undefined); };

  return (
    <div className="view">
      <ViewHeader title="Assistant" />
      <div className="view-pad stack">
        {off && <div className="callout callout--warn"><Icon name="alert" size={16} /><span>The assistant is off; turn it on in Setup.</span></div>}
        <p className="subtle">Both levels are off until you switch them on. Changed {current.updated_at.slice(0, 10)} by {current.updated_by}.</p>
        <section className="stack">
          <Switch label="Look up security references" checked={current.level >= 1} disabled={off || busy}
            onChange={(on) => { if (on) setAsking(1); else void save({ ...base, level: 0 }, "Internet lookups are off"); }} />
          <p className="subtle">{LEVEL1_RISK}</p>
        </section>
        <section className="stack">
          <Switch label="Search the web" checked={current.level >= 2} disabled={off || busy || current.level < 1}
            onChange={(on) => { if (on) { setUrl(current.searxng_url ?? ""); setAsking(2); } else void save({ ...base, level: 1 }, "Web search is off"); }} />
          <p className="subtle">{LEVEL2_RISK}</p>
          {current.level >= 2 && current.searxng_url && (
            <div className="row">
              <p className="subtle">SearXNG: <span className="mono">{current.searxng_url}</span></p>
              <button type="button" className="button button--ghost" disabled={off || busy || testing} onClick={test}>Test connection</button>
              {tested && <p className={tested.ok ? "subtle" : "confirm__error"} role="status">{tested.ok ? "Works: " : "Failed: "}{tested.detail}</p>}
            </div>
          )}
        </section>
        <form className="stack" onSubmit={(event) => { event.preventDefault(); void save({ ...base, level: current.level }, "Internal domains saved"); }}>
          <label className="field">Internal domains (one per line)
            <textarea className="textarea mono" rows={4} disabled={off} value={domainText} onChange={(event) => setDomains(event.target.value)} placeholder={"corp.example\nlan.example"} />
          </label>
          <p className="subtle">Always included: <span className="mono">{current.platform_domain}</span>. A search naming any of these is refused, never trimmed.</p>
          {!asking && error && <p className="confirm__error" role="alert">{error}</p>}
          <div><button type="submit" className="button button--primary" disabled={off || busy || toDomains(domainText).join("\n") === current.internal_domains.join("\n")}>Save domains</button></div>
        </form>
      </div>
      {asking === 1 && <TurnOnDialog title="Look up security references" risk={LEVEL1_RISK} canConfirm busy={busy} error={error} onClose={close}
        onConfirm={() => void save({ ...base, level: 1 }, "Security reference lookups are on")} />}
      {asking === 2 && <TurnOnDialog title="Search the web" risk={LEVEL2_RISK} canConfirm={validSearxngUrl(url.trim())} busy={busy} error={error} onClose={close}
        onConfirm={() => void save({ ...base, level: 2, searxng_url: url.trim() }, "Web search is on")}>
        <label className="field">SearXNG URL
          <input className="input mono" type="url" autoFocus value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://searx.corp.example" />
        </label>
      </TurnOnDialog>}
    </div>
  );
}
