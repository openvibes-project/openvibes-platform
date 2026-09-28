import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./shell/App";
import { applyStoredDensity } from "./shell/theme";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/components.css";
import "./styles/shell.css";
import "./styles/panels.css";

// Data source: the Pages preview is built with VITE_V2_SOURCE=demo; a local
// `npm run dev:v2` defaults to demo; `?live=1` / `?demo=1` switch for the
// browser session.
const query = new URLSearchParams(window.location.search);
let choice: string | null = query.get("live") === "1" ? "live" : query.get("demo") === "1" ? "demo" : null;
try {
  if (choice) sessionStorage.setItem("openvibes.v2.source", choice);
  else choice = sessionStorage.getItem("openvibes.v2.source");
} catch {
  // Without session storage the build default applies.
}
const fallback = import.meta.env.VITE_V2_SOURCE ?? (import.meta.env.DEV ? "demo" : "live");
const demo = (choice ?? fallback) === "demo";

applyStoredDensity();
const root = document.getElementById("root");
if (root === null) throw new Error("OpenVIBES root element is missing");
createRoot(root).render(<StrictMode><App demo={demo} /></StrictMode>);
