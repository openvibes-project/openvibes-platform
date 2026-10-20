# views/admin/settings

The Settings page, one tab per area. A tab opens to its own permission; a new tab is one line in `Settings.tsx`.

| File | What it does |
|---|---|
| `Settings.tsx` | The Settings page, its tab list and the `subPage` hook for full pages under `/settings/…` (roles, people, host groups). |
| `People.tsx` | The People tab: each person's roles with where they apply, how they sign in, status and last sign-in. |
| `Roles.tsx` | The Roles tab: every role, where it applies, its permissions and people. |
| `HostGroups.tsx` | The Host groups tab: each group's kind, membership, hosts, open problems and who reaches it. |
| `Enrollment.tsx` | Adding hosts and managing enrollment tokens. |
| `RuleSets.tsx` | Published rule sets, where each runs (with `rules.assignment.read`) and its state. |
| `ServiceAccounts.tsx` | API identities and their tokens. |
| `AssistantSettings.tsx` | The assistant's opt-in internet lookups. |
| `assistantRules.ts` | Input rules for the assistant internet setting, mirroring the server's. |

More: [docs/components/console-web.md](../../../../../../../docs/components/console-web.md)
