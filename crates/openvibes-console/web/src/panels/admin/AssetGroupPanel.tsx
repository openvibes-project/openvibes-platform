// An asset group: the hosts it selects, and how many roles reach it.
import { useState } from "react";

import { apiMessage, invalidate, request, useResource } from "../../api/client";
import type { HostGroup } from "../../api/types";
import { nav } from "../../app/nav";
import { useSession } from "../../app/session";
import { Icon } from "../../ui/Icon";
import { Empty, ErrorBox, Loading } from "../../ui/bits";
import { PanelHeader, Section } from "../../ui/panel";
import { toast } from "../../ui/toast";

export function AssetGroupPanel({ id }: { id: string }) {
  const { can } = useSession();
  const inventory = useResource<HostGroup[]>("/api/v1/host-groups");
  const group = inventory.data?.find((g) => g.asset_group_id === id);
  const [name, setName] = useState<string>();
  const [selectors, setSelectors] = useState<string>();
  const [error, setError] = useState<string>();
  if (inventory.error) return <div className="panel-body"><ErrorBox error={inventory.error} /></div>;
  if (id !== "new" && !group) return inventory.loading ? <Loading /> : <div className="panel-body"><Empty title="Asset group not found" /></div>;
  const currentName = name ?? group?.name ?? "";
  const currentSelectors = selectors ?? group?.selectors.join("\n") ?? "";
  const roles = group?.roles ?? 0;
  const manage = can("host_groups.manage", true);
  return (
    <>
      <PanelHeader icon="access" kind="Asset group" title={id === "new" ? "New asset group" : group?.name}
        subtitle="Hosts whose tags match every selector belong to the group; roles granted on the group see only those hosts." />
      <form className="panel-body stack" onSubmit={(event) => {
        event.preventDefault();
        setError(undefined);
        const parsed = currentSelectors.split(/[\n,]+/).map((line) => line.trim()).filter(Boolean).map((pair) => {
          const [key = "", ...rest] = pair.split("=");
          return { key: key.trim(), value: rest.join("=").trim() };
        });
        if (parsed.length === 0 || parsed.some((sel) => sel.key === "" || sel.value === "")) { setError("Write one key=value selector per line."); return; }
        const body = { name: currentName.trim(), selectors: parsed };
        const call = id === "new"
          ? request<{ asset_group_id: string }>("POST", "/api/v1/access-control/asset-groups", body)
          : request<{ asset_group_id: string }>("PUT", `/api/v1/access-control/asset-groups/${encodeURIComponent(id)}`, body);
        call.then((saved) => {
          invalidate("/api/v1/host-groups");
          toast(id === "new" ? `${body.name} created` : `${body.name} saved`);
          setName(undefined);
          setSelectors(undefined);
          if (id === "new") nav.open({ kind: "asset-group", id: saved.asset_group_id }, true);
        }, (e: unknown) => setError(apiMessage(e, "Could not save the group")));
      }}>
        <label className="field">Name<input className="input" required maxLength={128} disabled={!manage} value={currentName} onChange={(e) => setName(e.target.value)} placeholder="e.g. Production" /></label>
        <label className="field">Selectors (one key=value per line)
          <textarea className="textarea mono" rows={4} disabled={!manage} value={currentSelectors} onChange={(e) => setSelectors(e.target.value)} placeholder={"env=prod\nrole=web"} />
        </label>
        {id !== "new" && manage && (selectors !== undefined || name !== undefined) && (
          <div className="callout callout--warn"><Icon name="alert" size={16} /><span>Changing selectors changes which hosts belong to the group, and so what {roles === 1 ? "the 1 role" : `the ${roles} roles`} reaching it can see.</span></div>
        )}
        {error && <p className="confirm__error" role="alert">{error}</p>}
        {manage && <div><button className="button button--primary" type="submit">{id === "new" ? "Create group" : "Save"}</button></div>}
      </form>
      {id !== "new" && <Section title="Roles"><p className="subtle" style={{ padding: "0 20px" }}>{roles === 0 ? "No role reaches this group yet." : `${roles} ${roles === 1 ? "role reaches" : "roles reach"} this group.`}</p></Section>}
    </>
  );
}
