import { type FormEvent, useEffect, useState } from "react";

export function SignIn({ onDemo }: { onDemo: () => void }) {
  const [csrf, setCsrf] = useState<string>();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    fetch("/auth/v1/preauth", { cache: "no-store", credentials: "same-origin", signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error("preauth");
        setCsrf(((await response.json()) as { csrf_token: string }).csrf_token);
      })
      .catch(() => { if (!controller.signal.aborted) setError("Sign in is unavailable. Is the console service running?"); });
    return () => controller.abort();
  }, []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!csrf || busy) return;
    setBusy(true);
    setError(undefined);
    try {
      const response = await fetch("/auth/v1/login", {
        method: "POST", cache: "no-store", credentials: "same-origin",
        headers: { "content-type": "application/json", "x-csrf-token": csrf },
        body: JSON.stringify({ username, password }),
      });
      if (response.ok) { window.location.reload(); return; }
      setError(response.status === 401 ? "Username or password is incorrect." : response.status === 429 ? "Too many attempts. Wait a minute and try again." : "Sign in failed. Reload and try again.");
    } catch {
      setError("The console could not be reached.");
    } finally {
      setPassword("");
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
        <h1>Sign in</h1>
        <label className="field">Username<input className="input" autoComplete="username" required value={username} onChange={(e) => setUsername(e.target.value)} /></label>
        <label className="field">Password<input className="input" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        {error && <p className="confirm__error" role="alert">{error}</p>}
        <button className="button button--primary" type="submit" disabled={!csrf || busy}>{busy ? "Signing in…" : "Sign in"}</button>
        <button className="link-button" type="button" onClick={onDemo}>Explore the demo instead</button>
      </form>
    </main>
  );
}
