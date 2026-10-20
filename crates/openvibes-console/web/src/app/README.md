# app

App-wide state and wiring that is neither a screen nor a shared widget: where the user is, who they are, what is open.

| File | What it does |
|---|---|
| `registry.tsx` | The one place views and panel kinds are declared; a new screen or panel is an entry here. |
| `location.ts` | Reads and writes the navigation state kept in the URL (view, open panels, filters). |
| `nav.ts` | Navigation over the History API, so back and forward close panels and change views. |
| `permissions.ts` | The permission catalogue and role templates, and the needs closure (`turnOn`, `turnOff`). |
| `session.tsx` | The signed-in session and what it may do (`can`). |
| `source.ts` | Chooses live or demo data for this browser tab. |
| `windows.ts` | Floating windows popped out of the inspector, with their positions. |
| `titles.ts` | Readable names panels learn once their data loads, for breadcrumbs and the palette. |
| `assistant.ts` | Assistant conversation and dock state shared by every "Ask about this". |
| `liveAlarms.ts` | Polls for the newest alarm so alarm views, toasts and the menu count update without a reload. |
| `livePresence.ts` | Listens for agent online/offline changes so agent views refetch. |
| `menuCount.ts` | Formats the count beside a menu item (nothing at 0, 99+ beyond 99), and counts the suppression requests the viewer can decide. |

More: [docs/components/console-web.md](../../../../../docs/components/console-web.md)
