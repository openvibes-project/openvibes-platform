// The sticky bar under the role page: what the role is, the server's refusal
// (if any) above it, and Cancel / Delete role / Create role or Save role.
import { Icon } from "../../../ui/Icon";

export function RoleBar({ name, summary, error, isNew, readOnly, busy, onCancel, onSave, onDelete }: {
  name: string; summary: string; error: string | undefined; isNew: boolean; readOnly: boolean; busy: boolean;
  onCancel: () => void; onSave: () => void; onDelete: (() => void) | undefined;
}) {
  const unnamed = name.trim() === "";
  return (
    <div className="role-bar">
      {error && <div className="callout callout--bad role-bar__error" role="alert"><Icon name="alert" size={16} /><span>{error}</span></div>}
      <div className="role-bar__row">
        <span className="row grow role-bar__summary"><strong>{unnamed ? "Unnamed role" : name}</strong><span className="subtle">{`· ${summary}`}</span></span>
        {onDelete && !readOnly && <button type="button" className="button button--ghost" disabled={busy} onClick={onDelete}>Delete role</button>}
        <button type="button" className="button" onClick={onCancel}>{readOnly ? "Back" : "Cancel"}</button>
        {!readOnly && (isNew
          ? <button type="button" className="button button--primary" disabled={unnamed || busy} title={unnamed ? "Give it a name first" : undefined} onClick={onSave}>Create role</button>
          : <button type="button" className="button button--primary" disabled={unnamed || busy} onClick={onSave}>Save role</button>)}
      </div>
    </div>
  );
}
