# web/src

The whole console web app (React, Vite, TypeScript). One folder per kind of code; the user-facing screens are in `views/` and the detail panels they open are in `panels/`.

| File | What it does |
|---|---|
| `main.tsx` | Entry point: picks live or demo data, loads the stylesheets and mounts the app. |
| `test-setup.ts` | Unit-test setup: points the tests at the in-browser demo API. |
| `test-session.tsx` | Unit-test helper: wraps markup in a signed-in session (`withSession`). |
| `shell/` | The page frame: sign-in, rail, top bar, command palette, assistant dock. |
| `app/` | App-wide state and wiring: navigation in the URL, session, windows, the view and panel registry. |
| `api/` | The client for /api/v1 and the types generated from the console's OpenAPI document. |
| `ui/` | Shared building blocks (table, dropdown, charts, formatting) that carry no screen logic. |
| `views/` | The screens, one per menu item, grouped by menu section. |
| `panels/` | The detail panels that open in the inspector beside a list. |
| `dashboards/` | The home dashboard: tile grid, widgets and the dashboard editor. |
| `demo/` | The in-browser fake API used for the demo build, development and tests. |
| `styles/` | The CSS: design tokens, base rules, components, shell and panels. |

Adding things: a new screen or panel is a file under `views/` or `panels/` plus one entry in `app/registry.tsx`; shared widgets go in `ui/`; each API route a screen uses also needs a route in `demo/`. Update the README row in the same change (`scripts/check-folder-readmes.sh` checks them). Steps: "Where code lives" and "Adding things" in the page below.

More: [docs/components/console-web.md](../../../../docs/components/console-web.md)
