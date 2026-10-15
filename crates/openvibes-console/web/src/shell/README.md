# shell

The page frame around every view, and what you see before signing in.

| File | What it does |
|---|---|
| `App.tsx` | The root component: session gate, rail, top bar, view, inspector and windows. |
| `Chrome.tsx` | The navigation rail and the top bar. |
| `Frames.tsx` | The inspector (panel stack with breadcrumb) and floating windows. |
| `CommandPalette.tsx` | Ctrl+K: jump to views, actions, recent objects and search. |
| `AssistantDock.tsx` | The assistant column kept open beside your work. |
| `SignIn.tsx` | The sign-in screen. |
| `SetPassword.tsx` | Setting your own password: forced after a one-time password, or from the account menu. |
| `theme.ts` | Light/dark theme and density, stored per viewer. |

More: [docs/components/console-web.md](../../../../../docs/components/console-web.md)
