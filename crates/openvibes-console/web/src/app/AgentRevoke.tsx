import { useState, type FormEvent } from "react";

export function AgentRevoke({ agentId, csrfToken, canRevoke }: { agentId: string; csrfToken?: string | undefined; canRevoke: boolean }) {
  const [reason,setReason]=useState("");
  const [error,setError]=useState("");
  const [busy,setBusy]=useState(false);
  if(!canRevoke||!csrfToken)return null;
  const csrf=csrfToken;
  async function submit(event:FormEvent<HTMLFormElement>){
    event.preventDefault();setError("");
    if(!window.confirm("Revoke this agent? Its next platform request will be refused."))return;
    setBusy(true);
    try{
      const response=await fetch(`/api/v1/agents/${encodeURIComponent(agentId)}/revoke`,{method:"POST",cache:"no-store",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify({reason})});
      if(response.status!==204)throw new Error(response.status===404?"The agent is unavailable in your current scope.":"The revocation could not be completed.");
      window.location.reload();
    }catch(value){setError(value instanceof Error?value.message:"The request failed.");}finally{setBusy(false);}
  }
  return <section className="agent-revoke" aria-labelledby="agent-revoke-title"><h3 id="agent-revoke-title">Revoke agent</h3>
    <form onSubmit={(event)=>void submit(event)}><label>Reason<textarea required value={reason} onChange={(event)=>setReason(event.currentTarget.value)} maxLength={500} rows={2}/></label><button type="submit" disabled={busy||reason.trim().length===0}>{busy?"Revoking…":"Revoke agent"}</button></form>
    {error&&<p role="alert">{error}</p>}
  </section>;
}
