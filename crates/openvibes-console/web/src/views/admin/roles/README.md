# views/admin/roles

The role page, a full page under Settings (`/settings/roles/new`, `/settings/roles/{id}`; approved screens 2–5).

| File | What it does |
|---|---|
| `RolePage.tsx` | Loads the role and host groups, lays out the steps, and creates, saves or deletes the role. |
| `roleState.ts` | The editor's state as a pure reducer: Start from, chip clicks with their needs, hosts, and the save body. |
| `PermissionMatrix.tsx` | The matrix: areas × View / Change / Export / Approve and publish, "All" per row and per column. |
| `HostsPicker.tsx` | Hosts: search over host groups with "All hosts" first, chosen ones as chips with ×. |
| `RoleBar.tsx` | The sticky bar: the summary, the server's refusal, Cancel, Delete role, Create or Save. |

More: [docs/components/console-web.md](../../../../../../../docs/components/console-web.md)
