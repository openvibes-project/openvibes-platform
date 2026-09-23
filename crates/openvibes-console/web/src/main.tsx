import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./app/App";
import "./styles/tokens.css";
import "./styles/global.css";
import "./styles/shell.css";

const rootElement = document.getElementById("root");

if (rootElement === null) {
  throw new Error("OpenVIBES Console root element is missing");
}

createRoot(rootElement).render(
  <StrictMode>
    <App seeded={import.meta.env.DEV || import.meta.env.VITE_OPENVIBES_SEEDED === "true"} />
  </StrictMode>,
);
