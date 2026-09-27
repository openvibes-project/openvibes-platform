import { useState, type FormEvent } from "react";

type Tag = { key: string; value: string };
type Impact = { asset_group_id: string; name: string };
type BindingImpact = { binding_id: string; username: string; role_id: string; asset_group_name: string };
type Preview = { current: Tag[]; proposed: Tag[]; gained_groups: Impact[]; lost_groups: Impact[]; gained_bindings: BindingImpact[]; lost_bindings: BindingImpact[]; preview_token: string };

export function AgentTags({ agentId, csrfToken, canManage }: { agentId: string; csrfToken?: string | undefined; canManage: boolean }) {
  const [text, setText] = useState("");
  const [preview, setPreview] = useState<Preview>();
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  if (!canManage || !csrfToken) return null;
  const parse = (): Tag[] | undefined => {
    const lines = text.split("\n").map((line) => line.trim()).filter(Boolean);
    const tags = lines.map((line) => { const split = line.indexOf("="); return split < 1 ? undefined : { key: line.slice(0, split).trim(), value: line.slice(split + 1).trim() }; });
    if (tags.some((tag) => tag === undefined) || tags.length > 64) return undefined;
    const complete = tags.filter((tag): tag is Tag => tag !== undefined);
    if (new Set(complete.map((tag) => tag.key)).size !== complete.length) return undefined;
    return complete;
  };
  const submitPreview = async (event: FormEvent) => {
    event.preventDefault(); setMessage("");
    const tags = parse(); if (!tags) { setMessage("Enter one unique key=value tag per line (up to 64). "); return; }
    setBusy(true);
    try {
      const response = await fetch(`/api/v1/agents/${encodeURIComponent(agentId)}/tags/preview`, { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": csrfToken }, body: JSON.stringify({ tags }) });
      if (!response.ok) throw new Error(response.status === 403 ? "Access is unavailable for your role." : "The impact preview could not be loaded.");
      setPreview(await response.json() as Preview);
    } catch (error) { setMessage(error instanceof Error ? error.message : "The request failed."); setPreview(undefined); }
    finally { setBusy(false); }
  };
  const apply = async () => {
    if (!preview) return; setBusy(true); setMessage("");
    try {
      const response = await fetch(`/api/v1/agents/${encodeURIComponent(agentId)}/tags`, { method: "PUT", headers: { "content-type": "application/json", "x-csrf-token": csrfToken }, body: JSON.stringify({ tags: preview.proposed, preview_token: preview.preview_token }) });
      if (response.status === 409) { setPreview(await response.json() as Preview); setMessage("The membership changed since this preview. Review the refreshed impact before applying."); return; }
      if (!response.ok) throw new Error("Tags could not be applied.");
      setText(preview.proposed.map((tag) => `${tag.key}=${tag.value}`).join("\n")); setPreview(undefined); setMessage("Tags updated and the membership change was audited.");
    } catch (error) { setMessage(error instanceof Error ? error.message : "The request failed."); }
    finally { setBusy(false); }
  };
  return <section className="agent-tags" aria-labelledby="agent-tags-title">
    <h3 id="agent-tags-title">Access tags</h3>
    <p>Enter the complete tag set, one <code>key=value</code> pair per line. Group membership uses exact matches.</p>
    <form onSubmit={(event) => void submitPreview(event)}>
      <label>Tags<textarea value={text} onChange={(event) => { setText(event.currentTarget.value); setPreview(undefined); }} rows={5} maxLength={20480} placeholder="environment=production" /></label>
      <button type="submit" disabled={busy}>{busy ? "Working…" : "Preview impact"}</button>
    </form>
    {message && <p role="status">{message}</p>}
    {preview && <div className="agent-tags__preview"><h4>Membership impact</h4>
      <p>Groups gained: {preview.gained_groups.map((group) => group.name).join(", ") || "None"}</p>
      <p>Groups lost: {preview.lost_groups.map((group) => group.name).join(", ") || "None"}</p>
      <p>Bindings gained: {preview.gained_bindings.map((binding) => `${binding.username} (${binding.role_id}, ${binding.asset_group_name})`).join(", ") || "None"}</p>
      <p>Bindings lost: {preview.lost_bindings.map((binding) => `${binding.username} (${binding.role_id}, ${binding.asset_group_name})`).join(", ") || "None"}</p>
      <p>Current: {preview.current.map((tag) => `${tag.key}=${tag.value}`).join(", ") || "No tags"}</p>
      <button type="button" disabled={busy} onClick={() => void apply()}>Confirm tag change</button>
    </div>}
  </section>;
}
