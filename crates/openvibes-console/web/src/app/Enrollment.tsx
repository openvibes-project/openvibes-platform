import { useEffect, useState, type FormEvent } from "react";
import type { components } from "../api/generated";

type TokenPage=components["schemas"]["EnrollmentTokenPage"];
type Created=components["schemas"]["CreatedEnrollmentToken"];

function tokenState(token:TokenPage["items"][number]):string{
  if(token.revoked)return "Revoked";
  if(Date.parse(token.expires_at)<=Date.now())return "Expired";
  if(token.uses>=token.max_uses)return "Used up";
  return "Usable";
}

export function EnrollmentPage({csrfToken,canRead,canCreate,canRevoke}:{csrfToken?:string|undefined;canRead:boolean;canCreate:boolean;canRevoke:boolean}){
  const [page,setPage]=useState<TokenPage>();
  const [error,setError]=useState("");
  const [secret,setSecret]=useState<Created>();
  const [copied,setCopied]=useState(false);
  const [busy,setBusy]=useState(false);
  const [refresh,setRefresh]=useState(0);
  const [pendingKey,setPendingKey]=useState("");
  const [pendingBody,setPendingBody]=useState("");
  useEffect(()=>{
    if(!canRead)return;
    const controller=new AbortController();
    void fetch("/api/v1/enrollment-tokens",{cache:"no-store",credentials:"same-origin",signal:controller.signal})
      .then(async response=>{if(!response.ok)throw new Error("Enrollment tokens could not be loaded.");return await response.json() as TokenPage;})
      .then(value=>{setPage(value);setError("");})
      .catch(value=>{if(!controller.signal.aborted)setError(value instanceof Error?value.message:"Enrollment tokens could not be loaded.");});
    return ()=>controller.abort();
  },[canRead,refresh]);
  if(!canRead)return <section className="read-card"><h2>Enrollment tokens</h2><p role="alert">Your role cannot read enrollment tokens.</p></section>;
  async function create(event:FormEvent<HTMLFormElement>){
    event.preventDefault();if(!csrfToken)return;const formElement=event.currentTarget;setBusy(true);setError("");setSecret(undefined);
    const form=new FormData(event.currentTarget);
    const body=JSON.stringify({label:String(form.get("label")??"").trim()||null,expires_in_hours:Number(form.get("expires_in_hours")),max_uses:Number(form.get("max_uses"))});
    const key=pendingBody===body&&pendingKey?pendingKey:crypto.randomUUID();setPendingKey(key);setPendingBody(body);
    try{
      const response=await fetch("/api/v1/enrollment-tokens",{method:"POST",cache:"no-store",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken,"Idempotency-Key":key},body});
      if(!response.ok)throw new Error("The enrollment token could not be created.");
      setSecret(await response.json() as Created);setRefresh(value=>value+1);formElement.reset();setPendingKey("");setPendingBody("");
    }catch(value){setError(value instanceof Error?value.message:"The request failed.");}finally{setBusy(false);}
  }
  async function revoke(id:string){
    if(!csrfToken||!window.confirm("Revoke this enrollment token? Agents that have not used it yet will be unable to enroll."))return;
    setBusy(true);setError("");
    try{const response=await fetch(`/api/v1/enrollment-tokens/${encodeURIComponent(id)}/revoke`,{method:"POST",cache:"no-store",credentials:"same-origin",headers:{"X-CSRF-Token":csrfToken}});if(response.status!==204)throw new Error("The token could not be revoked.");setRefresh(value=>value+1);}
    catch(value){setError(value instanceof Error?value.message:"The request failed.");}finally{setBusy(false);}
  }
  return <section className="read-card" aria-labelledby="enrollment-title">
    <p className="eyebrow">Enrollment</p><h2 id="enrollment-title">Enrollment tokens</h2>
    <p>Token secrets appear once at creation. Copy and store the secret before leaving this page.</p>
    {error&&<p role="alert">{error}</p>}
    {secret&&<section className="one-time-secret" aria-label="New token secret"><h3>{secret.secret_available?"Copy this token now":"Token already created"}</h3>{secret.token?<><code>{secret.token}</code><button type="button" onClick={()=>{const value=secret.token;if(!value)return;void navigator.clipboard.writeText(value).then(()=>setCopied(true)).catch(()=>setError("Clipboard access is unavailable. Select and copy the token manually."));}}>{copied?"Copied":"Copy token"}</button></>:<p>The original response was already used. For safety, the secret cannot be recovered; revoke this token and create another if you did not save it.</p>}<p>Token ID: <code>{secret.token_id}</code>{secret.replayed?" · Replay":""}</p><button type="button" onClick={()=>setSecret(undefined)}>Dismiss</button></section>}
    {canCreate&&<form className="filter-form" onSubmit={(event)=>void create(event)}><label>Label<input name="label" maxLength={128}/></label><label>Expires in hours<input name="expires_in_hours" type="number" min={1} max={8760} defaultValue={168} required/></label><label>Maximum enrollments<input name="max_uses" type="number" min={1} max={100000} defaultValue={1} required/></label><button type="submit" disabled={busy||!csrfToken}>{busy?"Working…":"Create token"}</button></form>}
    {!page?<p role="status">Loading tokens…</p>:page.items.length===0?<p>No enrollment tokens have been created.</p>:<div className="table-scroll"><table className="data-table"><thead><tr><th scope="col">Label / ID</th><th scope="col">State</th><th scope="col">Uses</th><th scope="col">Expires</th>{canRevoke&&<th scope="col">Action</th>}</tr></thead><tbody>{page.items.map(token=><tr key={token.token_id}><th scope="row">{token.label||"Unlabelled"}<span className="table-subtext">{token.token_id}</span></th><td>{tokenState(token)}</td><td>{token.uses} / {token.max_uses}</td><td><time dateTime={token.expires_at}>{new Date(token.expires_at).toLocaleString()}</time></td>{canRevoke&&<td>{token.revoked||tokenState(token)!=="Usable"?"—":<button type="button" disabled={busy} onClick={()=>void revoke(token.token_id)}>Revoke</button>}</td>}</tr>)}</tbody></table></div>}
  </section>;
}
