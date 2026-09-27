import { useState } from "react";

function selectedValue(key: string, fallback: string): string {
  try {
    return localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}

export function SeededBanner() {
  const [persona, setPersona] = useState(() => selectedValue("openvibes.dev.persona", "analyst"));
  const [mode, setMode] = useState(() => selectedValue("openvibes.dev.mode", "mixed"));

  function change(key: string, value: string) {
    try {
      localStorage.setItem(key, value);
    } catch {
      // The loopback demo defaults to Analyst/Mixed if browser storage is disabled.
    }
    window.location.reload();
  }

  return (
    <aside className="seeded-banner" aria-label="Seeded development data">
      <div className="seeded-banner__notice">
        <span className="seeded-banner__label">Seeded environment</span>
        <span>Data shown here is deterministic demonstration data, not a production system.</span>
      </div>
      <div className="seeded-banner__controls">
        <label>Persona<select value={persona} onChange={(event) => {
          setPersona(event.currentTarget.value);
          change("openvibes.dev.persona", event.currentTarget.value);
        }}>
          <option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="operator">Operator</option><option value="scoped_operator">Scoped Operator</option><option value="admin">Admin</option>
        </select></label>
        <label>Data scenario<select value={mode} onChange={(event) => {
          setMode(event.currentTarget.value);
          change("openvibes.dev.mode", event.currentTarget.value);
        }}>
          <option value="mixed">Mixed fleet</option><option value="empty">Empty</option><option value="large">50,000 agents</option><option value="stale">Stale fleet</option><option value="partial_failure">Partial failure</option><option value="expired_session">Expired session</option><option value="permission_removed">Permission removed</option>
        </select></label>
      </div>
    </aside>
  );
}
