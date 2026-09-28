// Where data comes from. An installed console is always live; the in-browser
// demo exists only in development and in the demo build (the GitHub Pages
// preview), where `?live=1` / `?demo=1` switch for the browser tab.
export type Env = { DEV: boolean; VITE_DEMO: string | undefined };

export function chooseSource(search: string, stored: string | null, env: Env): { demo: boolean; demoAllowed: boolean; remember: "demo" | "live" | null } {
  const demoAllowed = env.DEV || env.VITE_DEMO === "true";
  if (!demoAllowed) return { demo: false, demoAllowed, remember: null };
  const query = new URLSearchParams(search);
  const asked = query.get("live") === "1" ? "live" : query.get("demo") === "1" ? "demo" : null;
  const choice = asked ?? (stored === "live" || stored === "demo" ? stored : null) ?? "demo";
  return { demo: choice === "demo", demoAllowed, remember: asked };
}
