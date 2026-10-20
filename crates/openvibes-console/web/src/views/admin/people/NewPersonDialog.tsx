// "+ New person": a local sign-in with a one-time password, shown once; they
// set their own at first sign-in (#85). Also the modal and the one-time
// password box the person page's Reset password uses.
import { type ReactNode, useEffect, useRef, useState } from "react";

import { apiMessage, request, useResource } from "../../../api/client";
import type { Role } from "../../../api/types";
import { useSession } from "../../../app/session";
import { SelectField } from "../../../ui/Field";
import { Icon } from "../../../ui/Icon";
import { Select } from "../../../ui/Select";
import { toast } from "../../../ui/toast";
import { fitsShare, refreshPeople } from "./people";
import { hostsSummary } from "../roles/roleState";

/** A native modal dialog: focus trapped, Escape closes it (onClose); once
 * unmounted it gives focus back to what opened it. It never calls close()
 * itself: that would fire onClose again, and close it under StrictMode's
 * dev remount. */
export function Modal({ label, onClose, children }: { label: string; onClose: () => void; children: ReactNode }) {
  const dialog = useRef<HTMLDialogElement>(null);
  // Read while rendering, before showModal moves focus (a StrictMode remount would see the dialog's own focus).
  const [opener] = useState(() => (typeof document !== "undefined" && document.activeElement instanceof HTMLElement ? document.activeElement : null));
  useEffect(() => {
    const d = dialog.current;
    if (d && !d.open) d.showModal();
    // After the commit: a remount keeps the dialog in the page, and focus with it.
    return () => queueMicrotask(() => { if (!d?.isConnected) opener?.focus(); });
  }, [opener]);
  return <dialog ref={dialog} className="palette bulk-modal" aria-label={label} onClose={onClose}>{children}</dialog>;
}

export const DialogHead = ({ title, onClose }: { title: string; onClose: () => void }) => (
  <div className="row row--between"><h2>{title}</h2>
    <button type="button" className="icon-button" aria-label="Close" onClick={onClose}><Icon name="close" size={16} /></button></div>
);

/** The one-time password, shown once, with the hand-over note. */
export function OneTimePassword({ password, name, onDone }: { password: string; name: string; onDone: () => void }) {
  return (
    <>
      <div className="callout callout--warn"><Icon name="alert" size={16} /> Copy the one-time password now. It is shown only once.</div>
      <div className="secret"><span className="grow">{password}</span>
        <button type="button" className="icon-button" aria-label="Copy one-time password" onClick={() => { void navigator.clipboard?.writeText(password); toast("Copied"); }}><Icon name="copy" size={16} /></button>
      </div>
      <p className="subtle">Give it to {name} by a private channel. At their first sign-in they choose their own password, and nothing else works until they do.</p>
      <div className="row row--end"><button type="button" className="button button--primary" onClick={onDone}>Done</button></div>
    </>
  );
}

type CreatedUser = { user_id: string; username: string; display_name: string; role_ids: string[]; one_time_password: string };

export function NewPersonDialog({ onClose }: { onClose: () => void }) {
  const { session } = useSession();
  // Only roles inside the viewer's share; the server refuses the others.
  const roles = (useResource<Role[]>("/api/v1/roles").data ?? []).filter((r) => fitsShare(session?.capabilities ?? [], r));
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  // No default role: least privilege is a deliberate choice.
  const [role, setRole] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<CreatedUser>();
  return (
    <Modal label="New person" onClose={onClose}>
      {created ? (
        <div className="bulk-dialog stack">
          <DialogHead title={created.display_name} onClose={onClose} />
          <OneTimePassword password={created.one_time_password} name={created.display_name} onDone={onClose} />
        </div>
      ) : (
        <form className="bulk-dialog stack" onSubmit={(event) => {
          event.preventDefault();
          if (busy) return;
          setBusy(true);
          setError(undefined);
          const body = { username: username.trim(), display_name: displayName.trim(), role_ids: [role], ...(email.trim() ? { email: email.trim() } : {}) };
          request<CreatedUser>("POST", "/api/v1/users", body)
            .then((user) => { refreshPeople(); setCreated(user); }, (e: unknown) => setError(apiMessage(e, "Could not create the person")))
            .finally(() => setBusy(false));
        }}>
          <DialogHead title="New person" onClose={onClose} />
          <p className="subtle">A local sign-in with a one-time password they replace at first sign-in.</p>
          <label className="field">Username<input className="input mono" required maxLength={64} pattern="[A-Za-z0-9._@+\-]+" autoComplete="off" spellCheck={false} value={username} onChange={(e) => setUsername(e.target.value)} placeholder="e.g. jdoe" /></label>
          <label className="field">Display name<input className="input" required maxLength={160} value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="e.g. Jane Doe" /></label>
          <label className="field">Email (optional)<input className="input" type="email" maxLength={254} value={email} onChange={(e) => setEmail(e.target.value)} placeholder="e.g. jane@example.com" /></label>
          <SelectField label="Role"><Select label="Role" value={role} placeholder="Choose a role…" onChange={setRole}
            options={roles.map((r) => ({ value: r.role_id, label: r.name, hint: `· ${hostsSummary(r.reach)}` }))} /></SelectField>
          {error && <p className="confirm__error" role="alert">{error}</p>}
          <div className="row row--end">
            <button type="button" className="button button--ghost" onClick={onClose}>Cancel</button>
            <button className="button button--primary" type="submit" disabled={busy || !role}>{busy ? "Creating…" : "Create person"}</button>
          </div>
        </form>
      )}
    </Modal>
  );
}
