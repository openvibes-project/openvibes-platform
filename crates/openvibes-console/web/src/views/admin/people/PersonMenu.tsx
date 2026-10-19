// The person page's ⋯ menu: Reset password (shows the new one-time password
// once), Disable (asks first) and Enable. Hidden on your own page.
import { useState } from "react";

import { ApiError, request } from "../../../api/client";
import type { PersonView } from "../../../api/types";
import { MenuButton } from "../../../ui/Menu";
import { toast } from "../../../ui/toast";
import { DialogHead, Modal, OneTimePassword } from "./NewPersonDialog";
import { type PersonAction, refreshPeople, refusal, userPath } from "./people";

const ASK = {
  reset: { title: "Reset password", text: "Their password stops working now. You get a one-time password to give them; they choose their own at the next sign-in.", confirm: "Reset password" },
  disable: { title: "Disable user", text: "They are signed out everywhere and cannot sign in until someone enables them again. Their roles stay.", confirm: "Disable user" },
};

export function PersonMenu({ person, actions, onError }: { person: PersonView; actions: PersonAction[]; onError: (message: string | undefined) => void }) {
  const [asking, setAsking] = useState<"reset" | "disable">();
  const [password, setPassword] = useState<string>();
  const [busy, setBusy] = useState(false);
  const close = () => { setAsking(undefined); setPassword(undefined); };
  const run = async (action: PersonAction["value"]) => {
    setBusy(true);
    onError(undefined);
    try {
      const reply = await request<{ one_time_password?: string } | undefined>("POST", `${userPath(person.user_id)}/${action === "reset" ? "reset-password" : action}`);
      refreshPeople();
      if (action === "reset") {
        if (!reply?.one_time_password) throw new Error("The server sent no one-time password. Reset the password again.");
        setPassword(reply.one_time_password);
      }
      else { toast(action === "disable" ? "User disabled" : "User enabled"); close(); }
    } catch (e) {
      onError(refusal(e, e instanceof Error && !(e instanceof ApiError) ? e.message : "The change failed."));
      close();
    } finally {
      setBusy(false);
    }
  };
  if (actions.length === 0) return null;
  const ask = asking ? { ...ASK[asking], action: asking } : undefined;
  return (
    <>
      <MenuButton label="More actions" icon="more" compact items={actions}
        onPick={(value) => { if (value === "enable") void run("enable"); else setAsking(value as "reset" | "disable"); }} />
      {ask && (
        <Modal label={ask.title} onClose={close}>
          <div className="bulk-dialog stack">
            <DialogHead title={`${ask.title}: ${person.display_name}`} onClose={close} />
            {password !== undefined ? <OneTimePassword password={password} name={person.display_name} onDone={close} /> : (
              <>
                <p>{ask.text}</p>
                <div className="row row--end">
                  <button type="button" className="button button--ghost" onClick={close}>Cancel</button>
                  <button type="button" className={ask.action === "disable" ? "button button--danger" : "button button--primary"} disabled={busy}
                    onClick={() => void run(ask.action)}>{busy ? "Working…" : ask.confirm}</button>
                </div>
              </>
            )}
          </div>
        </Modal>
      )}
    </>
  );
}
