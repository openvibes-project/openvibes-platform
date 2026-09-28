import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { registerDemo } from "./api/client";
import { chooseSource } from "./app/source";
import { App } from "./shell/App";
import { applyStoredDensity } from "./shell/theme";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/components.css";
import "./styles/shell.css";
import "./styles/panels.css";

const sourceKey = "openvibes.v2.source";
let stored: string | null = null;
try { stored = sessionStorage.getItem(sourceKey); } catch { /* the build default applies */ }
const source = chooseSource(window.location.search, stored, { DEV: import.meta.env.DEV, VITE_DEMO: import.meta.env.VITE_DEMO as string | undefined });
if (source.remember) {
  try { sessionStorage.setItem(sourceKey, source.remember); } catch { /* per tab only */ }
}

async function start() {
  // A constant per build: an installed console's bundle does not contain the demo at all.
  if (import.meta.env.DEV || import.meta.env.VITE_DEMO === "true") {
    const { createDemoServer } = await import("./demo/server");
    registerDemo((persona) => createDemoServer({ persona }));
  }
  applyStoredDensity();
  const root = document.getElementById("root");
  if (root === null) throw new Error("OpenVIBES root element is missing");
  createRoot(root).render(<StrictMode><App demo={source.demo} demoAllowed={source.demoAllowed} /></StrictMode>);
}

void start();
