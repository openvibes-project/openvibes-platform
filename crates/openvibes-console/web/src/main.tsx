import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./app/App";
import "./styles/tokens.css";
import "./styles/global.css";
import "./styles/shell.css";
import "./styles/pages.css";

const rootElement = document.getElementById("root");

const demoRequested = new URLSearchParams(window.location.search).get("seeded") === "1";
if (demoRequested) {
  try {
    sessionStorage.setItem("openvibes.demo", "true");
  } catch {
    // This only controls whether the loopback demo banner is shown.
  }
}
let persistedDemo = false;
try {
  persistedDemo = sessionStorage.getItem("openvibes.demo") === "true";
} catch {
  // Without browser storage the demo banner can still be enabled by the build.
}
const seeded = import.meta.env.DEV || import.meta.env.VITE_OPENVIBES_SEEDED === "true" || persistedDemo;

if (rootElement === null) {
  throw new Error("OpenVIBES Console root element is missing");
}

createRoot(rootElement).render(
  <StrictMode>
    <App seeded={seeded} />
  </StrictMode>,
);
