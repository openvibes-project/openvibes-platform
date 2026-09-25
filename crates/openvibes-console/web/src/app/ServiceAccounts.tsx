import { useEffect, useState, type FormEvent } from "react";
import type { components } from "../api/generated";

type Accounts=components["schemas"]["ServiceAccountPage"];
type Tokens=components["schemas"]["ServiceTokenPage"];
type Secret=components["schemas"]["CreatedServiceToken"];

export function ServiceAccountsPage({csrfToken,canRead,canManage}:{csrfToken?:string|undefined;canRead:boolean;canManage:boolean}){
  const [accounts,setAccounts]=useState<Accounts>();
  const [tokens,setTokens]=useState<Record<string,Tokens>>({});
  const [error,setError]=useState("");
  const [secret,setSecret]=useState<Secret>();
  const [busy,setBusy]=useState(false);
  const [refresh,setRefresh]=useState(0);
  const [pendingKey,setPendingKey]=useState("");
  const [pendingBody,setPendingBody]=useState("");
  useEffect(()=>{
    if(!canRead)return;
    const controller=new AbortController();
    void fetch("/api/v1/service-accounts",{cache:"no-store",credentials:"same-origin",signal:controller.signal})
      .then(async response=>{if(!response.ok)throw new Error("Service accounts could not be loaded.");return await response.json() as Accounts;})
      .then(value=>{setAccounts(value);setError("");})
      .catch(value=>{if(!controller.signal.aborted)setError(value instanceof Error?value.message:"The request failed.");});
    return ()=>controller.abort();
  },[canRead,refresh]);
  if(!canRead)return <section className="read-card"><h2>Service accounts</h2><p role="alert">Your role cannot read service accounts.</p></section>;
  async function createAccount(event:FormEvent<HTMLFormElement>){
    event.preventDefault();if(!csrfToken)return;const formElement=event.currentTarget;setBusy(true);setError("");
    const form=new FormData(event.currentTarget);
    try{const response=await fetch("/api/v1/service-accounts",{method:"POST",cache:"no-store",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify({name:String(form.get("name")??"").trim(),role_id:String(form.get("role_id")??"viewer")})});if(!response.ok)throw new Error("The service account could not be created.");formElement.reset();setRefresh(value=>value+1);}
    catch(value){setError(value instanceof Error?value.message:"The request failed.");}finally{setBusy(false);}
  }
  async function loadTokens(id:string){
    setError("");
    try{const response=await fetch(`/api/v1/service-accounts/${encodeURIComponent(id)}/tokens`,{cache:"no-store",credentials:"same-origin"});if(!response.ok)throw new Error("Tokens could not be loaded.");const tokenPage=await response.json() as Tokens;setTokens(value=>({...value,[id]:tokenPage}));}
    catch(value){setError(value instanceof Error?value.message:"The request failed.");}
  }
  async function issueToken(id:string){
    if(!csrfToken)return;const label=window.prompt("Token label");if(!label?.trim())return;
    const body=JSON.stringify({label:label.trim(),expires_in_hours:720});
    const key=pendingBody===body&&pendingKey?pendingKey:crypto.randomUUID();setPendingKey(key);setPendingBody(body);
    setBusy(true);setError("");
    try{const response=await fetch(`/api/v1/service-accounts/${encodeURIComponent(id)}/tokens`,{method:"POST",cache:"no-store",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken,"Idempotency-Key":key},body});if(!response.ok)throw new Error("The token could not be issued.");setSecret(await response.json() as Secret);setPendingKey("");setPendingBody("");await loadTokens(id);setRefresh(value=>value+1);}
    catch(value){setError(value instanceof Error?value.message:"The request failed.");}finally{setBusy(false);}
  }
  async function postAction(url:string,question:string){
    if(!csrfToken||!window.confirm(question))return;setBusy(true);setError("");
    try{const response=await fetch(url,{method:"POST",cache:"no-store",credentials:"same-origin",headers:{"X-CSRF-Token":csrfToken}});if(response.status!==204)throw new Error("The change could not be completed.");setRefresh(value=>value+1);}
    catch(value){setError(value instanceof Error?value.message:"The request failed.");}finally{setBusy(false);}
  }
  return <section className="read-card" aria-labelledby="service-accounts-title">
    <p className="eyebrow">Administration</p><h2 id="service-accounts-title">Service accounts</h2>
    <p>Use service accounts for integrations. Each token is shown once and expires automatically.</p>
    {error&&<p role="alert">{error}</p>}
    {secret&&<section className="one-time-secret" aria-label="New service token"><h3>{secret.secret_available?"Copy this token now":"Token already issued"}</h3>{secret.token?<><code>{secret.token}</code><button type="button" onClick={()=>void navigator.clipboard.writeText(secret.token as string).catch(()=>setError("Clipboard access is unavailable. Select and copy the token manually."))}>Copy token</button></>:<p>The original secret cannot be recovered. Revoke the token and issue another if you did not save it.</p>}<p>Token ID: <code>{secret.token_id}</code>; expires {new Date(secret.expires_at).toLocaleString()}{secret.replayed?" · Replay":""}.</p><button type="button" onClick={()=>setSecret(undefined)}>Dismiss</button></section>}
    {canManage&&<form className="filter-form" onSubmit={event=>void createAccount(event)}><label>Name<input name="name" minLength={1} maxLength={128} required/></label><label>Initial role<select name="role_id" defaultValue="viewer"><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="operator">Operator</option></select></label><button type="submit" disabled={busy||!csrfToken}>{busy?"Working…":"Create service account"}</button></form>}
    {!accounts?<p role="status">Loading service accounts…</p>:accounts.items.length===0?<p>No service accounts have been created.</p>:<div className="table-scroll"><table className="data-table"><thead><tr><th scope="col">Name / ID</th><th scope="col">Roles</th><th scope="col">Tokens</th><th scope="col">State</th><th scope="col">Actions</th></tr></thead><tbody>{accounts.items.map(account=><tr key={account.service_account_id}><th scope="row">{account.name}<span className="table-subtext">{account.service_account_id}</span></th><td>{account.role_ids.join(", ")}</td><td>{account.active_tokens}</td><td>{account.enabled?"Enabled":"Disabled"}</td><td>{canManage&&account.enabled?<><button type="button" disabled={busy} onClick={()=>void loadTokens(account.service_account_id)}>Tokens</button><button type="button" disabled={busy} onClick={()=>void issueToken(account.service_account_id)}>Issue token</button><button type="button" disabled={busy} onClick={()=>void postAction(`/api/v1/service-accounts/${encodeURIComponent(account.service_account_id)}/disable`,"Disable this account and revoke every token?")}>Disable</button>{tokens[account.service_account_id]?.items.map(token=><div key={token.token_id}>{token.label} · {token.revoked?"Revoked":new Date(token.expires_at).toLocaleDateString()} {!token.revoked&&<button type="button" disabled={busy} onClick={()=>void postAction(`/api/v1/service-accounts/${encodeURIComponent(account.service_account_id)}/tokens/${encodeURIComponent(token.token_id)}/revoke`,"Revoke this service token?")}>Revoke</button>}</div>)}</>:"—"}</td></tr>)}</tbody></table></div>}
  </section>;
}
