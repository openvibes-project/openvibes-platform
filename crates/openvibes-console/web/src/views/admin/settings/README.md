# views/admin/settings

The Settings page, one tab per area. A tab opens to its own permission; a new tab is one line in `Settings.tsx`.

| File | What it does |
|---|---|
| `Settings.tsx` | The Settings page and its tab list. |
| `Access.tsx` | Users, their roles and asset groups. |
| `Enrollment.tsx` | Adding hosts and managing enrollment tokens. |
| `RuleSets.tsx` | Published rule sets, where each runs and its state. |
| `ServiceAccounts.tsx` | API identities and their tokens. |
| `AssistantSettings.tsx` | The assistant's opt-in internet lookups. |
| `assistantRules.ts` | Input rules for the assistant internet setting, mirroring the server's. |

More: [docs/components/console-web.md](../../../../../../../docs/components/console-web.md)
