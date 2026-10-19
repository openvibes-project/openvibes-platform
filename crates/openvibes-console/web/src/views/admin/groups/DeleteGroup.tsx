// "Delete group…": what deleting would change (the save preview with `{}`),
// the rule-set switches it removes, then DELETE with the version read.
import { useState } from "react";

import { ApiError, invalidate, request } from "../../../api/client";
import type { HostGroupDetail } from "../../../api/types";
import { toast } from "../../../ui/toast";
import { DialogHead, Modal } from "../people/NewPersonDialog";
import { PreviewNote } from "./badges";
import { groupPath, refreshGroups, toList, usePreview } from "./groupApi";
import { refusal } from "./groupState";

export function DeleteGroup({ group, onClose }: { group: HostGroupDetail; onClose: () => void }) {
  const path = groupPath(group.asset_group_id);
  const preview = usePreview(`${path}/preview`, {});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const remove = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await request("DELETE", `${path}?version=${group.version}`);
      refreshGroups();
      toast("Group deleted");
      toList();
    } catch (e) {
      if (e instanceof ApiError && e.code === "group_in_use") {
        setError(`Roles still use this group: ${group.roles.map((r) => r.name).join(", ") || "reload to see which"}.`);
      } else {
        const { message, reload } = refusal(e, "The group could not be deleted.");
        setError(message);
        if (reload) invalidate(path);
      }
    } finally {
      setBusy(false);
    }
  };
  const switches = preview && preview !== "failed" ? preview.overrides_removed : 0;
  return (
    <Modal label="Delete group" onClose={onClose}>
      <div className="bulk-dialog stack">
        <DialogHead title={`Delete group: ${group.name}`} onClose={onClose} />
        <p>{group.kind === "automatic" ? "Deleting it is remembered; it won't come back." : "This cannot be undone."}</p>
        <PreviewNote preview={preview} verb="delete" />
        {switches > 0 && <p>Removes {switches} rule-set {switches === 1 ? "switch" : "switches"}.</p>}
        {error && <p className="confirm__error" role="alert">{error}</p>}
        <div className="row row--end">
          <button type="button" className="button button--ghost" onClick={onClose}>Cancel</button>
          <button type="button" className="button button--danger" disabled={busy} onClick={() => void remove()}>{busy ? "Deleting…" : "Delete group"}</button>
        </div>
      </div>
    </Modal>
  );
}
