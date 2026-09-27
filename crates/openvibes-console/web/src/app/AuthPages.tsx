import { useEffect, useState, type FormEvent } from "react";

import type { components } from "../api/generated";
import { Brand } from "../components/Brand";
import { ThemeControl } from "../components/ThemeControl";

type PreauthResponse = components["schemas"]["PreauthResponse"];
type LoginRequest = components["schemas"]["LoginRequest"];

export type BrowserSession = components["schemas"]["SessionResponse"];

type GateState = "checking" | "unauthenticated" | "unavailable";

export function SessionGate({ state }: { state: GateState }) {
  const message = state === "checking"
    ? "Checking your session…"
    : state === "unauthenticated"
      ? "Sign in to use the OpenVIBES console."
      : "The authentication service is unavailable. Try again shortly.";

  return (
    <div className="auth-page">
      <header className="auth-page__topbar">
        <Brand compact={false} />
        {state !== "checking" && <ThemeControl />}
      </header>
      <main className="auth-card" id="main-content" aria-labelledby="auth-title">
        <p className="eyebrow">OpenVIBES Console</p>
        <h1 id="auth-title">Your session</h1>
        <p role="status" aria-live="polite">{message}</p>
        {state === "unauthenticated" && <a className="button-link" href="/login">Sign in</a>}
        {state === "unavailable" && <button className="button-link" type="button" onClick={() => window.location.reload()}>Try again</button>}
      </main>
    </div>
  );
}

export function LoginPage() {
  const [csrfToken, setCsrfToken] = useState<string>();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/auth/v1/preauth", {
      cache: "no-store",
      credentials: "same-origin",
      signal: controller.signal,
    }).then(async (response) => {
      if (!response.ok) throw new Error("preauth unavailable");
      const body = await response.json() as PreauthResponse;
      setCsrfToken(body.csrf_token);
    }).catch(() => {
      if (!controller.signal.aborted) setError("Sign in is unavailable right now. Try reloading this page.");
    });
    return () => controller.abort();
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (csrfToken === undefined || busy) return;
    setBusy(true);
    setError(undefined);
    const request: LoginRequest = { username, password };
    setPassword("");
    try {
      const response = await fetch("/auth/v1/login", {
        method: "POST",
        cache: "no-store",
        credentials: "same-origin",
        headers: {
          "content-type": "application/json",
          "x-csrf-token": csrfToken,
        },
        body: JSON.stringify(request),
      });
      if (response.ok) {
        window.location.assign("/");
        return;
      }
      if (response.status === 401) {
        setError("Username or password is incorrect.");
      } else if (response.status === 429 || response.status === 503) {
        setError("Sign in is temporarily unavailable. Try again shortly.");
      } else {
        setError("Sign in could not be completed. Reload this page and try again.");
      }
    } catch {
      setError("Sign in could not reach the service. Check your connection and try again.");
    } finally {
      setBusy(false);
      setPassword("");
    }
  }

  return (
    <div className="auth-page">
      <a className="skip-link" href="#auth-title">Skip to sign in</a>
      <header className="auth-page__topbar">
        <Brand compact={false} />
        <ThemeControl />
      </header>
      <main className="auth-card" id="main-content" aria-labelledby="auth-title">
        <p className="eyebrow">OpenVIBES Console</p>
        <h1 id="auth-title">Sign in</h1>
        <p className="auth-card__intro">Use your local console account to continue.</p>
        <form className="auth-form" onSubmit={submit}>
          <label htmlFor="login-username">Username</label>
          <input
            id="login-username"
            name="username"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            maxLength={64}
            required
            value={username}
            onChange={(event) => setUsername(event.currentTarget.value)}
            disabled={busy}
          />
          <label htmlFor="login-password">Password</label>
          <input
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.currentTarget.value)}
            disabled={busy}
          />
          {error && <p className="auth-form__error" role="alert">{error}</p>}
          <button className="auth-form__submit" type="submit" disabled={busy || csrfToken === undefined}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </main>
    </div>
  );
}
