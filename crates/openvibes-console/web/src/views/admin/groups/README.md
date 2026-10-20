# views/admin/groups

A host group's page, a full page under Settings (`/settings/host-groups/new`, `/settings/host-groups/{id}`; approved screens 10, 10b and 10c). The list is `settings/HostGroups.tsx` (screen 9).

| File | What it does |
|---|---|
| `GroupPage.tsx` | Loads the group, its hosts and (with `access.read`) people and roles; the header, left column and editing (a reload mid-edit keeps the user's own changes). |
| `groupApi.ts` | Shared by the pages and the delete dialog: paths, saving, who may write, the debounced preview. |
| `NewGroup.tsx` | A new group or a duplicate (`?from={id}`): name, description, Rule or Manual, the editor and Create group. |
| `DeleteGroup.tsx` | Delete group…: the delete preview, rule-set switches removed, and the refusals. |
| `RuleEditor.tsx` | The Rule card: "Where"/"and" rows, read-only or with field, operator and a chip input for values. |
| `PickedHosts.tsx` | Hosts picked by hand: chips, and in edit mode × and "Search hosts to add". |
| `GroupHosts.tsx` | Hosts in this group: the filterable table. |
| `badges.tsx` | The kind badge, open problems (shared with the list) and the preview callout. |
| `groupState.ts` | The draft as a pure reducer, the PATCH/POST/preview bodies, the preview sentence and the list's wording. |

More: [docs/components/console-web.md](../../../../../../../docs/components/console-web.md)
