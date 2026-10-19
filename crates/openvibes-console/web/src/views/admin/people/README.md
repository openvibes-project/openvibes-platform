# views/admin/people

A person's page, a full page under Settings (`/settings/people/{id}`; approved screens 7 and 8), and the New person dialog of Settings › People.

| File | What it does |
|---|---|
| `PersonPage.tsx` | Loads the person; the header, Details (editable), Recent activity, Roles and Access grouped by where it applies. |
| `PersonMenu.tsx` | The ⋯ menu: Reset password, Disable and Enable, each asked in a dialog; hidden on your own page. |
| `AddRoleDialog.tsx` | "+ Add role": a search over the roles the person does not hold and the viewer may hand out. |
| `NewPersonDialog.tsx` | "+ New person" with its one-time password, shown once; also the modal and the one-time password box. |
| `people.ts` | Access grouping, the share check, role changes, refusals and the ⋯ actions, without React. |

More: [docs/components/console-web.md](../../../../../../../docs/components/console-web.md)
