import { useState, type FormEvent } from "react";

type Group = { asset_group_id: string; name: string; selectors: string[] };

function selectorInputs(text: string): { key: string; value: string }[] | undefined {
  const lines = text.split("\n").map((line) => line.trim()).filter(Boolean);
  const selectors = lines.map((line) => { const split=line.indexOf("="); return split<1?undefined:{key:line.slice(0,split).trim(),value:line.slice(split+1).trim()}; });
  if (selectors.length===0 || selectors.length>32 || selectors.some((selector)=>!selector || !selector.key || !selector.value)) return undefined;
  const complete=selectors.filter((selector):selector is {key:string;value:string}=>selector!==undefined);
  return new Set(complete.map((selector)=>selector.key)).size===complete.length?complete:undefined;
}

function AssetGroupForm({ group, csrfToken, onError }: { group?: Group; csrfToken?: string | undefined; onError: () => void }) {
  const [name,setName]=useState(group?.name??"");
  const [selectors,setSelectors]=useState(group?.selectors.join("\n")??"");
  const [busy,setBusy]=useState(false);
  async function save(event:FormEvent<HTMLFormElement>) {
    event.preventDefault(); const parsed=selectorInputs(selectors);
    if (!parsed) { onError(); return; }
    if (group && !window.confirm("Changing selectors can change which agents match this asset group and which scoped users can see them. Continue?")) return;
    setBusy(true);
    try {
      const headers=new Headers({"Content-Type":"application/json","X-CSRF-Token":csrfToken??""});
      const response=await fetch(group?`/api/v1/access-control/asset-groups/${encodeURIComponent(group.asset_group_id)}`:"/api/v1/access-control/asset-groups",{method:group?"PUT":"POST",cache:"no-store",credentials:"same-origin",headers,body:JSON.stringify({name,selectors:parsed})});
      if (response.status!==(group?200:201)) throw new Error("asset group save failed");
      window.location.reload();
    } catch { onError(); } finally { setBusy(false); }
  }
  return <form className="asset-group-form" onSubmit={(event)=>void save(event)}>
    <label>Name<input required value={name} onChange={(event)=>setName(event.currentTarget.value)} maxLength={128}/></label>
    <label>Exact selectors (one key=value per line)<textarea required rows={3} value={selectors} onChange={(event)=>setSelectors(event.currentTarget.value)} maxLength={10240}/></label>
    <button type="submit" disabled={busy}>{busy?"Saving…":group?"Update group":"Create group"}</button>
  </form>;
}

export function AssetGroups({ groups, canManage, csrfToken, onError }: { groups: Group[]; canManage: boolean; csrfToken?: string | undefined; onError: () => void }) {
  return <>
    <h3>Asset groups</h3>
    <p>Each group matches agents that have every listed exact tag. Changing selectors can change access granted by scoped role bindings.</p>
    {canManage && <AssetGroupForm csrfToken={csrfToken} onError={onError}/>}
    {groups.length===0 ? <p className="read-state">No manual asset groups are configured.</p> : groups.map((group)=><details className="asset-group-item" key={group.asset_group_id}>
      <summary><strong>{group.name}</strong>: {group.selectors.join(" AND ")}</summary>
      {canManage && <AssetGroupForm group={group} csrfToken={csrfToken} onError={onError}/>}
    </details>)}
  </>;
}
