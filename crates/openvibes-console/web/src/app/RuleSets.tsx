import { useEffect, useState, type FormEvent } from "react";
import type { components } from "../api/generated";

type Sets=components["schemas"]["RuleSetPage"];
type Bundles=components["schemas"]["RuleBundlePage"];
type Preview=components["schemas"]["RuleBundlePreview"];

export function RuleSetsPage({csrfToken,canRead,canUpload}:{csrfToken?:string|undefined;canRead:boolean;canUpload:boolean}){
  const [sets,setSets]=useState<Sets>();
  const [history,setHistory]=useState<Record<string,Bundles>>({});
  const [preview,setPreview]=useState<Preview>();
  const [envelope,setEnvelope]=useState("");
  const [error,setError]=useState("");
  const [busy,setBusy]=useState(false);
  const [refresh,setRefresh]=useState(0);
  const [now,setNow]=useState(0);
  useEffect(()=>{
    if(!canRead)return;
    const controller=new AbortController();
    void fetch("/api/v1/rule-sets",{cache:"no-store",credentials:"same-origin",signal:controller.signal})
      .then(async response=>{if(!response.ok)throw new Error("Rule sets could not be loaded.");return await response.json() as Sets;})
      .then(value=>{setSets(value);setNow(Date.now());setError("");})
      .catch(value=>{if(!controller.signal.aborted)setError(value instanceof Error?value.message:"The request failed.");});
    return ()=>controller.abort();
  },[canRead,refresh]);
  if(!canRead)return <section className="read-card"><h2>Rule sets</h2><p role="alert">Your role cannot read rule sets.</p></section>;
  async function loadHistory(id:string){
    setError("");
    try{const response=await fetch(`/api/v1/rule-sets/${encodeURIComponent(id)}/bundles`,{cache:"no-store",credentials:"same-origin"});if(!response.ok)throw new Error("Bundle history could not be loaded.");const bundles=await response.json() as Bundles;setHistory(value=>({...value,[id]:bundles}));}
    catch(value){setError(value instanceof Error?value.message:"The request failed.");}
  }
  async function previewFile(event:FormEvent<HTMLFormElement>){
    event.preventDefault();if(!csrfToken||!envelope)return;setBusy(true);setError("");setPreview(undefined);
    try{const response=await fetch("/api/v1/rule-bundles/preview",{method:"POST",cache:"no-store",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:envelope});if(!response.ok)throw new Error("The envelope failed signature or trust validation.");setPreview(await response.json() as Preview);}
    catch(value){setError(value instanceof Error?value.message:"The request failed.");}finally{setBusy(false);}
  }
  async function publish(){
    if(!csrfToken||!preview||!envelope||!window.confirm(`Publish ${preview.rule_set_id} v${preview.version}?`))return;setBusy(true);setError("");
    try{const response=await fetch("/api/v1/rule-bundles/publish",{method:"POST",cache:"no-store",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken,"X-Rule-Preview-Token":preview.preview_token},body:envelope});if(response.status!==201&&response.status!==204)throw new Error("The bundle could not be published; preview it again and check its signer and version.");setPreview(undefined);setEnvelope("");setRefresh(value=>value+1);}
    catch(value){setError(value instanceof Error?value.message:"The request failed.");}finally{setBusy(false);}
  }
  return <section className="read-card" aria-labelledby="rules-title">
    <p className="eyebrow">Operate</p><h2 id="rules-title">Rule sets</h2>
    <p>Review signed bundle versions and publish only envelopes verified against locally trusted public keys.</p>
    {error&&<p role="alert">{error}</p>}
    {canUpload&&<form className="filter-form" onSubmit={event=>void previewFile(event)}><label>Signed envelope JSON<input type="file" accept="application/json,.json" required onChange={event=>{const file=event.currentTarget.files?.[0];if(!file)return;if(file.size>1_048_576){setError("Envelope must be at most 1 MiB.");return;}void file.text().then(setEnvelope).catch(()=>setError("The selected file could not be read."));}}/></label><button type="submit" disabled={busy||!csrfToken||!envelope}>{busy?"Verifying…":"Preview signed bundle"}</button></form>}
    {preview&&<section className="one-time-secret" aria-label="Verified bundle preview"><h3>Signature verified</h3><dl><dt>Rule set</dt><dd>{preview.rule_set_id}</dd><dt>Version</dt><dd>{preview.version}{preview.current_version!==null?` · current ${preview.current_version}`:" · no current version"}</dd><dt>Issuer</dt><dd>{preview.issuer_key_id}</dd><dt>SHA-256</dt><dd><code>{preview.envelope_sha256}</code></dd><dt>Expires</dt><dd>{new Date(preview.expires_at_ms).toLocaleString()}</dd></dl><button type="button" disabled={busy} onClick={()=>void publish()}>Confirm publish</button><button type="button" disabled={busy} onClick={()=>setPreview(undefined)}>Cancel</button></section>}
    {!sets?<p role="status">Loading rule sets…</p>:sets.items.length===0?<p>No rule sets are configured. Add public trust keys locally before publishing a signed bundle.</p>:<div className="table-scroll"><table className="data-table"><thead><tr><th scope="col">Rule set</th><th scope="col">Current</th><th scope="col">Trusted keys</th><th scope="col">State</th><th scope="col">History</th></tr></thead><tbody>{sets.items.map(set=><tr key={set.rule_set_id}><th scope="row">{set.rule_set_id}</th><td>{set.current_version==null?"None":`v${set.current_version}`}{set.current_signer_removed?" · signer removed":""}</td><td>{set.trusted_keys}</td><td>{set.retired?"Retired":set.current_expires_at_ms!=null&&set.current_expires_at_ms<=now?"Expired":"Active"}</td><td><button type="button" onClick={()=>void loadHistory(set.rule_set_id)}>View bundles</button>{history[set.rule_set_id]?.items.map(bundle=><p key={bundle.version}>v{bundle.version} · {bundle.issuer_key_id} · {bundle.bytes} bytes · expires {new Date(bundle.expires_at_ms).toLocaleDateString()}<br/><code>{bundle.envelope_sha256}</code></p>)}</td></tr>)}</tbody></table></div>}
  </section>;
}
