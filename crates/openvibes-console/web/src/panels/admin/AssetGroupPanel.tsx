// A host group: its membership and the roles reaching it. Read-only until
// the host group page replaces this panel.
import { useResource } from "../../api/client";
import type { HostGroup } from "../../api/types";
import { Empty, ErrorBox, Loading } from "../../ui/bits";
import { PanelHeader, Section } from "../../ui/panel";

export function AssetGroupPanel({ id }: { id: string }) {
  const inventory = useResource<HostGroup[]>("/api/v1/host-groups");
  const group = inventory.data?.find((g) => g.asset_group_id === id);
  if (inventory.error) return <div className="panel-body"><ErrorBox error={inventory.error} /></div>;
  if (!group) return inventory.loading ? <Loading /> : <div className="panel-body"><Empty title="Host group not found" /></div>;
  const roles = group.roles.map((r) => r.name).join(", ");
  return (
    <>
      <PanelHeader icon="access" kind="Host group" title={group.name} subtitle={group.membership} />
      <Section title="Roles"><p className="subtle" style={{ padding: "0 20px" }}>{roles || "No role reaches this group yet."}</p></Section>
    </>
  );
}
