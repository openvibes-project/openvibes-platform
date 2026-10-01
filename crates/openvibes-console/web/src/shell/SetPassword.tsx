// Setting your own password (#85): forced after a one-time password (the
// console refuses everything else until then), and self-service from the
// account menu, where it can be cancelled.
import { type FormEvent, useState } from "react";

import { ApiError, request } from "../api/client";

const reasons: Record<string, string> = {
  invalid_current_password: "The current password is not right.",
  weak_password: "Use at least 15 characters for the new password.",
  password_unchanged: "Choose a password different from the current one.",
};

export function SetPassword({ required, onDone, onCancel, onSignOut }: {
  required: boolean;
  onDone: () => void;
  onCancel?: () => void;
  onSignOut?: () => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    if (next !== again) { setError("The two new passwords differ."); return; }
    setBusy(true);
    setError(undefined);
    try {
      await request("POST", "/api/v1/session/password", { current_password: current, new_password: next });
      onDone();
    } catch (failure: unknown) {
      setError(failure instanceof ApiError ? reasons[failure.code] ?? failure.message : "The password was not changed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="signin">
      <form className="signin__card" onSubmit={(event) => void submit(event)}>
        <picture>
          <source srcSet={`${import.meta.env.BASE_URL}brand/openvibes-wordmark-dark.svg`} media="(prefers-color-scheme: dark)" />
          <img className="signin__logo" src={`${import.meta.env.BASE_URL}brand/openvibes-wordmark-light.svg`} alt="OpenVIBES" />
        </picture>
        <h1>{required ? "Set your password" : "Change your password"}</h1>
        {required && <p className="subtle">You signed in with a one-time password. Choose your own to continue.</p>}
        <label className="field">{required ? "One-time password" : "Current password"}
          <input className="input" type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} />
        </label>
        <label className="field">New password (at least 15 characters)
          <input className="input" type="password" autoComplete="new-password" required minLength={15} value={next} onChange={(e) => setNext(e.target.value)} />
        </label>
        <label className="field">New password again
          <input className="input" type="password" autoComplete="new-password" required minLength={15} value={again} onChange={(e) => setAgain(e.target.value)} />
        </label>
        {error && <p className="confirm__error" role="alert">{error}</p>}
        <button className="button button--primary" type="submit" disabled={busy}>{busy ? "Saving…" : "Set password"}</button>
        {onCancel && <button className="link-button" type="button" onClick={onCancel}>Cancel</button>}
        {onSignOut && <button className="link-button" type="button" onClick={onSignOut}>Sign out</button>}
      </form>
    </main>
  );
}
