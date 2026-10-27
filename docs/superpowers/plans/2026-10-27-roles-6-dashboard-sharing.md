# Dashboard sharing: implementation plan (step 6)

**Goal:** screen 18 of the roles spec (board issue #364, epic #320; spec §11, §16 step 6). A dashboard is `private`, shared with some of the owner's roles, or shared with everyone. Sharing respects the roles and reach model that steps 1 to 5 built.

**Approach:** one migration (0068) adds `console_dashboards.visibility`; the role links already live in `console_dashboard_roles` (schema 52). The store, the sharing route and the header menu change; nothing else does.

## Plan rulings, 2026-10-27 (step 6)

The spec fixes the storage, permissions and rules (§11). These fill the gaps, and no approved mockup of screen 18 is in the repository, so the layout follows the existing dashboard menu.

1. **Visibility.** `private` | `roles` | `everyone`, stored in `visibility` (default `private`). `roles` has one or more rows in `console_dashboard_roles`; `everyone` and `private` have none. Upgrade: a dashboard with a row there becomes `roles`, the rest `private`, so nobody gains or loses a dashboard.
2. **API.** `PUT /api/v1/dashboards/{id}/sharing` takes `{visibility, role_ids}` and replaces `{role_id}` (the only client is the console). An unknown visibility is 400. `roles` needs `dashboards.share` and at least one role (422 `no_roles`), each must exist (422 `unknown_role`) and be held by the owner through a live binding (422 `role_not_held`). `everyone` needs `dashboards.publish` (403). Going back to `private` needs no permission: an owner can always stop sharing. Each change bumps the version and is audited with before and after.
3. **Who sees what.** Everyone signed in sees an `everyone` dashboard; holders of a listed role see a `roles` one. Only the owner edits or deletes. Widgets are computed with the viewer's own access, as before.
4. **Role names.** The owner sees every role a dashboard is shared with. Anyone else sees only the roles they hold themselves, so a shared dashboard does not list other roles' names to someone who cannot see them.
5. **Role deleted.** Deleting a role takes it off every dashboard (cascade). A dashboard left shared with roles but with none becomes private, in the same transaction, with a version bump and a `dashboard.share` audit row (reason `role deleted`, actor the person who deleted the role) so the owner can see why. Only a role nobody holds can be deleted, so nobody loses sight of a dashboard by it.
6. **Owner loses a role.** Nothing happens to the dashboard. It stays shared with the role, which stays in the menu, ticked, so it can be unticked; the owner just cannot add it again. Only roles being added must be held.
7. **Make a copy.** Anyone who sees a dashboard they do not own gets a "Make a copy" button in the header and the menu item. The copy is private and the viewer's own. The owner's menu item stays "Duplicate".
8. **Header.** A badge under the title: "Only you", "Shared with Ops, Night" or "Everyone"; for a viewer "Shared by Name · …". The menu's "Who can see this" section lists Only you, the roles the owner holds (ticks, several at once, the menu stays open) when they hold `dashboards.share`, and Everyone when they hold `dashboards.publish`. The section also shows to an owner without the permissions when the dashboard is already shared, so they can stop sharing.
9. **Demo.** The demo server mirrors all of the above, including a deleted role.

## Verification

- `cargo test -p platform-store --test console_dashboards --test custom_roles`: sharing rules, the audit rows, role deletion, the upgrade from 67.
- `cargo test -p openvibes-console --test dashboards_http --test role_names_http`: the routes and permissions.
- Web: vitest (demo server), `tsc`, lint, the demo and live e2e specs.
