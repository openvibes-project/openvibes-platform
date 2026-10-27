# Roles, permissions, host groups and the Hosts pages

Date: 2026-10-16. Design decisions by the user, the same day, in a design
session with full-screen mockups (`rbac-ui/approved.md`, 34 screens). It
replaces the four built-in roles of `2026-09-23-console-product-design.md`
and the tag-selected asset groups of the console identity schema
(migration 0017). Single sign-on (SAML/OIDC, and "download the claims
needed") is the **next** spec; this one prepares for it (§4.6) but does not
build it.

## 1. Goal

Almost everything in the console can be controlled, per role.

- An admin creates roles that start empty, and picks exactly what each
  role may do and on which hosts.
- Hosts fall into groups that mostly maintain themselves.
- Suppressing an alarm can require a second person.
- The Hosts list and a host's page are reworked so that everything about
  a host is easy to find (added to this spec by the user).
- The other list pages get the same treatment (also added by the user):
  filters with counts, richer one-line rows, and full detail pages
  instead of side panels (§10.3).

**Success:**

- A homelab user never notices: they are Administrator, as today.
- A small business can give a Windows team its own role on its own
  servers without that team seeing or changing anything else.
- Upgrading changes nobody's access.

## 2. Decisions (user, 2026-10-16)

1. **Roles are created by an admin and start empty:** no permissions and
   no hosts.
2. **Templates are guidance only:** Viewer, Analyst, Operator, Team lead,
   Auditor and Rule author.
   - They have no members and are not listed as roles.
   - They are offered in a role's "Start from" field. Picking one fills
     the permissions live and outlines what changed, so they can be
     compared.
   - A template never picks hosts.
3. **One permission per action** (48, §3), shown as a matrix.
4. **Hosts are chosen inside the role:** none (the default), all hosts, or
   chosen host groups.
5. **Permissions and hosts are independent.** Any permission may go in any
   role.
   - Host permissions apply on the hosts the role reaches.
   - Platform permissions apply platform-wide, and carry an ⓘ mark in the
     console.
   - (This supersedes an earlier idea of "all hosts only" permissions.)
6. **Prerequisites:** turning a permission on turns on what it needs, and
   turning one off turns off what depends on it. The console says what
   else changed.
7. **Nobody grants more than they hold.** A team admin acts only within
   their share (§4.4).
8. **One protected built-in role, Administrator.**
   - It has every permission, including future ones, on all hosts.
   - It cannot be edited or deleted.
   - Its last enabled member cannot be removed or disabled.
9. **New permissions from an update go only to Administrator.** Custom
   roles never gain rights silently; the release note lists the new
   permissions.
10. **A person or a service account may hold several roles.** Each
    permission applies on the hosts of the role that gives it.
11. **Host groups come in three kinds, never mixed:**
    - **Automatic:** made by OpenVIBES from what agents report.
    - **Rule:** the user's own, kept up to date by its rule.
    - **Manual:** hosts picked by hand.

    No hosts are added to or taken out of a rule group by hand.
12. **Access tags are dropped.** Free **labels** remain. They are for
    filtering and finding hosts and never affect access.
13. **"Suppressions need approval"** is a General setting, off by default.
    - When on, a suppression does nothing until someone allowed to approve
      it on those hosts says yes. Until then, matching alarms keep
      arriving.
    - Nobody approves their own request.
    - There is no separate Approvals page; approvals happen on Alarm
      suppressions.
14. **Dashboards are shared** with only me, with the roles you hold, or
    with everyone. Viewers always see counts from their own access.
15. **Settings is always in the menu.** Its tabs are General, People,
    Roles, Host groups, Service accounts, Enrollment, Rule sets and
    Assistant. Each tab is shown when one of your permissions needs it.
16. **Profile pictures** are cropped in the browser and inspected and
    re-encoded on the server (§9).
17. **The Hosts list gets filters and more columns.** The host side panel
    becomes a full **host page** (§10).
    - Ports, Services, Software, Vulnerabilities, Compliance, Alarms and
      Cases follow the same pattern (§10.3).
18. **Single sign-on users** are locked where the identity provider owns
    the data, and are removed after N days without signing in (setting in
    General, 90 by default).
    - Each role's single sign-on group is simply the role's name.
    - The setting is stored now and acted on by the SSO spec.

## 3. Permissions

`Scope` says where a permission applies: **host** means on the hosts the
granting role reaches; **platform** means everywhere (the ⓘ mark).
`Needs` lists prerequisites; they are transitive. The ID is the wire and
database name.

| Area | Permission (console text) | ID | Column | Scope | Needs |
|---|---|---|---|---|---|
| Alarms | View alarms | `alarms.read` | View | host | |
| | View suppressions | `alarms.suppressions.read` | View | host | alarms.read |
| | Triage alarms | `alarms.triage` | Change | host | alarms.read |
| | Suppress alarms (with a reason) | `alarms.suppress` | Change | host | alarms.read, alarms.suppressions.read |
| | Export alarms | `alarms.export` | Export | host | alarms.read |
| | Approve suppressions | `alarms.suppressions.approve` | Approve | host | alarms.suppressions.read |
| Compliance | View findings | `compliance.read` | View | host | |
| | Triage findings | `compliance.triage` | Change | host | compliance.read |
| | Export findings | `compliance.export` | Export | host | compliance.read |
| Vulnerabilities | View vulnerabilities | `vulnerabilities.read` | View | host | |
| | Triage vulnerabilities | `vulnerabilities.triage` | Change | host | vulnerabilities.read |
| | Export vulnerabilities | `vulnerabilities.export` | Export | host | vulnerabilities.read |
| Hosts | View hosts | `hosts.read` | View | host | |
| | Label hosts | `hosts.label` | Change | host | hosts.read |
| | Revoke a host | `hosts.revoke` | Change | host | hosts.read |
| | Export host data | `hosts.export` | Export | host | hosts.read |
| Cases | View cases | `cases.read` | View | host | |
| | Create and edit cases | `cases.write` | Change | host | cases.read |
| | Assign cases | `cases.assign` | Change | host | cases.write |
| Rule sets | View rule sets and versions | `rules.read` | View | platform | |
| | View where sets run | `rules.assignment.read` | View | platform | rules.read |
| | View ATT&CK coverage | `rules.coverage.read` | View | platform | |
| | View rule contents | `rules.contents.read` | View | platform | rules.read |
| | Change where sets run | `rules.assignment.write` | Change | platform | rules.assignment.read |
| | Publish a rule bundle | `rules.publish` | Approve | platform | rules.read |
| Site rules | View site rule drafts | `site_rules.read` | View | platform | |
| | Edit site rule drafts | `site_rules.write` | Change | platform | site_rules.read |
| | Test a draft on a host | `site_rules.test` | Change | platform | site_rules.write, hosts.read |
| | Publish site rules | `site_rules.publish` | Approve | platform | site_rules.write |
| Dashboards | Share dashboards with your roles | `dashboards.share` | Change | platform | |
| | Publish dashboards to everyone | `dashboards.publish` | Approve | platform | dashboards.share |
| Assistant | Use the assistant | `assistant.use` | View | host | |
| | Configure the assistant and internet lookups | `assistant.admin` | Change | platform | |
| Access | View people and roles | `access.read` | View | platform | |
| | Create, edit and disable users | `access.users` | Change | platform | access.read |
| | Create and edit roles | `access.roles` | Change | platform | access.read |
| | Give people roles | `access.grant` | Change | platform | access.read |
| | Manage host groups | `host_groups.manage` | Change | platform | access.read, hosts.read |
| Service accounts | View service accounts | `service_accounts.read` | View | platform | |
| | Create and disable service accounts | `service_accounts.manage` | Change | platform | service_accounts.read |
| | Issue and revoke their tokens | `service_accounts.tokens` | Change | platform | service_accounts.read |
| Enrollment | View enrollment tokens | `tokens.read` | View | platform | |
| | Create and revoke tokens | `tokens.manage` | Change | platform | tokens.read |
| | Download the agent installer | `tokens.installer` | Export | platform | tokens.read |
| Audit log | View the audit log | `audit.read` | View | platform | |
| | Change retention | `audit.retention.manage` | Change | platform | audit.read |
| | Export the audit log | `audit.export` | Export | platform | audit.read |
| General | Change general settings | `settings.manage` | Change | platform | |

Notes:

- **The audit log** records platform-wide actions too, so it stays
  platform scope. A team needing its own trail reads the host's Recent
  activity.
- **`assistant.use` is host scope:** the assistant answers only with data
  the person can see (today's behaviour, now per role).
- **The ATT&CK coverage view** shows what the rules detect, not host data,
  so it needs no other permission.
- **The catalogue is declared once, in Rust,** with its area, column,
  scope, needs and text, and exported to `web/src/api/roles.json` as
  today. A test checks that the needs are acyclic and that every ID used
  by a route guard is in the catalogue.

## 4. Roles

### 4.1 What a role is

A role has:

- a **name**, unique regardless of case, 1–64 characters (it doubles as
  the SSO group name);
- an optional description;
- a set of permissions, closed under needs;
- a **reach**: none, all hosts, or a list of host groups.

The server enforces closure: a save with a permission missing what it
needs is refused with a 422 that names the missing permission. The
console never sends one, because it adds needs as you click.

A role whose reach is none still grants its platform permissions. Its
host permissions do nothing, and the role page says so ("These apply on
no hosts until you choose some").

### 4.2 Templates

Templates are fixed in code. The permission sets are those in the
approved mockup (`gen.py` `TEMPLATE_PERMS`), with the IDs of §3:

- **Viewer:** view alarms, suppressions, findings, vulnerabilities, hosts,
  cases, rule sets and coverage.
- **Analyst:** Viewer, plus triage everywhere, suppress, create and edit
  cases, and the assistant.
- **Operator:**
  - view alarms, findings, vulnerabilities and hosts;
  - label and revoke hosts;
  - all of Enrollment;
  - all rule-set views;
  - publish bundles, and change where sets run.
- **Team lead:** Analyst, plus approve suppressions, label hosts, share
  dashboards, view people and roles, and give people roles.
- **Auditor:**
  - every view permission except the assistant;
  - every export permission except the agent installer (`tokens.installer`);
  - the audit log and its export;
  - nothing that changes anything.
- **Rule author:** view hosts, all rule-set views, and all of Site rules.

`GET /v1/role-templates` returns them. Picking one in the console only
fills the form.

### 4.3 Administrator

Administrator is the role `admin` (its ID is unchanged, so setup and the
admin CLI keep `--role admin`), shown as "Administrator" and marked
`builtin`.

- The access check treats it as "every permission in the catalogue, all
  hosts", whatever is stored.
- Its permission rows are still stored, all of them, so that SQL joining
  role permissions (case assignees, the signer's upload check) sees it.
  Every migration that adds a permission also gives it to `admin`.
- It cannot be edited or deleted.
- First-run setup (`openvibes-admin user create --role admin`) puts the
  first person on it, and the same command recovers access.
- The guards that keep its last enabled member live in the store, inside
  the same transaction as the change, so two concurrent removals cannot
  both succeed.

(Plan ruling, 2026-10-16: the ID stays `admin` instead of becoming
`administrator`.)

### 4.4 Granting within your share

A person's **share** is the union, over their roles, of (permission, reach)
pairs. Any request that creates or changes a role, or gives or removes a
role, is checked against it. The check is server-side, and the console
only hides what would fail.

- **Creating or editing a role** needs `access.roles`. Every permission
  the role will have must be held by the editor. For a host permission,
  the editor must hold it on every group the role reaches, and on all
  hosts if the role reaches all hosts.
- **Giving or removing a role** needs `access.grant`, and the whole role
  (permissions × reach) must fit inside the editor's share.
- **People and service accounts:**
  - An editor without Administrator sees, in People and Service accounts,
    only those whose roles all fit inside the editor's share.
  - They can only disable, or reset the password of, such a person.
  - That needs `access.users` for people and `service_accounts.manage`
    for service accounts.
- **Nobody** can change their own roles, or the roles of a role they hold,
  in a way that widens their own share.
- **A role's reach** may be changed only to groups inside the editor's
  share.

A refused request returns 403 with the reason, for example "You can only
give roles that fit inside your own access (Revoke a host is outside it)".

### 4.5 Who holds roles

- Role bindings keep their current shape: one binding per (person or
  service account, role).
- **The binding's own `asset_group_id` scope is retired.** The reach now
  lives in the role.
- Service accounts are bound exactly like people.

### 4.6 Ready for single sign-on

- The SSO spec maps an identity-provider group whose name equals a
  role's name to that role.
- This spec adds `console_users.auth_source` (`password` | `sso`,
  default `password`) and `console_users.last_sign_in_at`.
- People shows "Signs in with". The locked fields (7b) appear only for
  `sso` users, of whom there are none until the SSO spec.
- The General setting "Remove inactive single sign-on users after N days"
  (1–3650, default 90) is stored and shown now. The purge job belongs to
  the SSO spec.

## 5. Host groups and labels

### 5.1 The three kinds

| Kind | Made by | Membership | Editing |
|---|---|---|---|
| Automatic | OpenVIBES | one agent fact: OS family, or distribution and release | editing turns it into a rule group (the user's own) |
| Rule | a person with `host_groups.manage` | its rule, evaluated live | rule edited on the group page |
| Manual | a person with `host_groups.manage` | hosts picked by hand | add/remove hosts on the group page |

- **Automatic groups:**
  - When the first host with a new OS family (`Linux`, and later
    `Windows`) or a new distribution and release (`Debian 12`,
    `Fedora 44`, from `os_id` and `os_release`) reports, a group is
    created. It is recorded in the audit log as made by OpenVIBES.
  - Deleting or editing one records its key in
    `console_host_group_dismissed`, so it is not made again (an edited one
    becomes the person's rule group).
  - An automatic group whose last host leaves stays, with 0 hosts.
- **Rules:**
  - A rule is a list of **conditions, all of which must match**.
  - Each condition is a field plus one or more values, any of which may
    match.
  - The fields are only those an agent reports:
    - `os_family`;
    - `distribution` (for example `debian 12`);
    - `hostname` (a pattern; `*` matches any run of characters,
      case-insensitive);
    - `ip` (CIDR ranges).
  - A condition may be negated ("is not", "does not match", "is not
    in"), as on the approved screen 10 (plan ruling, 2026-10-19).
  - A host whose fact is unknown (no hostname, no address, no OS
    reported yet) never satisfies a condition on that field, negated or
    not (plan ruling, 2026-10-19).
  - Labels are never a field.
  - At most 16 conditions, and 64 values per condition.
- **The IP address** is the source address of the agent's last mTLS
  connection, recorded by ingest as `agents.last_address inet`. The group
  page says so ("the address OpenVIBES sees; behind NAT this is the
  router").
- **Membership is computed in SQL when queried,** never stored, so it is
  never stale. Every condition maps to an indexed predicate on `agents`.
  Manual groups use `console_host_group_members (group_id, agent_id)`.
- **Revoked hosts** are members of no group.
- **Before saving** a rule change, a manual change, or a delete,
  `POST /v1/host-groups/{id}/preview` returns the hosts that would join
  and leave, and the people and roles that would gain or lose access to
  each. The console shows "If you save: +n / −n hosts…".

Group names are unique regardless of case, 1–128 characters, and have an
optional description.

**Who may change groups** (plan ruling, 2026-10-19): changing a group's
membership changes access for everyone whose role reaches it, so creating,
editing or deleting a group needs `host_groups.manage` **and** `hosts.read`
on all hosts (Administrators qualify). Everyone else may view groups.
Host lists and counts on group pages show only hosts the viewer reaches
with `hosts.read`.

Rule-set assignment (`rule_set_group_assignment`, spec 2026-10-14)
already refers to groups by ID; it works unchanged with every kind.

### 5.2 Labels

- **Storage:** labels are free strings on a host, 1–64 characters, in
  `console_host_labels (agent_id, label, added_at, added_by)`, at most
  32 per host.
- **Changing them** needs `hosts.label` on that host.
- **Use:** they filter and search the Hosts list. They never affect
  access, groups or rule assignment.

### 5.3 Upgrade from tags

- Each existing asset group becomes a **manual** group holding exactly the
  hosts its tag selectors match at upgrade time. Nobody's access changes.
- The group page then shows a one-time note: "This group was made from
  tags. You can turn it into a rule group."
- Each `key=value` tag becomes the label `key:value`.
- `console_agent_tags` and `console_asset_group_selectors` are dropped
  after the copy, in the same migration.

## 6. The access check

One function decides every request:
`allowed(principal, permission, target) -> bool`.

- **A platform permission** is allowed when any of the principal's roles
  has it.
- **A host permission on host H** is allowed when any role that has it
  reaches H: all hosts, or H is in one of the role's groups.
- **Lists** are filtered by the same rule: a person sees an alarm, finding,
  vulnerability or host only on hosts where they hold the matching view
  permission. Today's scoped queries (`AssetGroups { ids }`) become
  "hosts reached for permission P", computed once per request as a set of
  group IDs or "all".
- **Aggregates** — dashboard widgets, counts, menu badges, the assistant's
  context — use the viewer's own reach. Sharing a dashboard never shows
  more (§11).
- **A case** is visible when the person can see at least one of its items'
  hosts, or when they created it or are assigned to it. A case with no
  items is visible to those holding `cases.read` on all hosts, and to
  its creator and assignee.

The resolved set is loaded from the database on every request, with one
indexed query, as permissions are today. A revoked right stops at the
next request. (Plan ruling, 2026-10-16: no cache; it is added only if
measurements call for it.)

## 7. Settings › General

- **Storage:** settings live in `console_settings (key text PRIMARY KEY,
  value jsonb, changed_at, changed_by)`. Each key has a typed definition
  in code (type, range, default).
- **API:** `GET /v1/settings` and `PATCH /v1/settings/{key}` (needs
  `settings.manage`). A value out of range is refused with 422.
- **Audit:** every change is audited with the old and new values.
- **Keys now:**
  - `suppressions.require_approval` (bool, default false);
  - `sso.remove_inactive_days` (int, 1–3650, default 90).
- **Layout:** the shared layout of `approved.md`. Each row saves on
  change. The left column lists sections and the last five changes.

## 8. Alarm suppressions with approval

### 8.1 What a suppression covers

- **What:** this program, or this exact command. The existing `host`
  scope (everything from one rule on one host) stays valid for existing
  rows; the form no longer offers it.
- **Where** (new):
  - **This host:** `agent_id`.
  - **A group:** `host_group_id`.
  - **All hosts:** neither. It is offered only to a person whose
    `alarms.suppress` reaches all hosts.

  The form offers only the hosts and groups the person's `alarms.suppress`
  reaches. Program and command suppressions made before this spec were
  fleet-wide and become **All hosts**.
- **For:** 7 days, 30 days, or until removed (`expires_at`, counted from
  activation).
- **Reason:** required, 1–4000 characters, as today.

### 8.2 States

`waiting` → `active` | `rejected` | `withdrawn`; `active` → `removed` |
`expired`.

- **Request:** with `suppressions.require_approval` off, a new suppression
  is `active` at once. With it on, it is `waiting`, and matching alarms
  keep arriving.
- **Approve or reject:**
  - Needs `alarms.suppressions.approve` on the suppression's where:
    - for a host, a role reaching that host;
    - for a group, a role reaching that group (the group is in the role,
      or the role reaches all hosts);
    - for all hosts, a role reaching all hosts.
  - The approver is never the requester (checked server-side).
  - Rejecting needs a reason (1–4000 characters), which the requester
    sees.
  - Approving starts the "For" period.
- **Withdraw:** the requester can withdraw their own waiting request.
- **Turning the setting off** leaves waiting requests waiting. They can
  still be decided or withdrawn, and new ones are active at once.
- **Matching:** only `active`, unexpired suppressions are applied by alarm
  matching. Expiry is checked when matching runs, so it needs no job.
  Expired rows show as Expired.
- **"Would have closed N alarms in the last 7 days"** is counted when the
  list is read, from `alarms`, with the same matcher.

### 8.3 Where it shows

- **Alarm suppressions** (screen 14): waiting first, with Approve /
  Reject… for those allowed. The menu badge counts waiting requests the
  viewer could decide.
- **The alarm panel** shows a waiting request's state with Withdraw.
- **Audit:** every transition is audited, with who and why.

### Plan rulings, 2026-10-20

These fill gaps in §7 and §8.

1. **`GET /v1/settings` needs `settings.manage`.** The suppress form learns whether approval is on from `GET /v1/alarm-suppressions/options` (Task 5), so no one else needs the settings list.
2. **A suppression remembers its source alarm** (`alarm_id`, the platform row id). The alarm panel finds a waiting request through it, screen 14's "Open alarm" uses it, and "Ask again…" sends it again. Rows made before this step have none, so they show no "Open alarm" and no "Ask again…".
3. **Activation closes the source alarm.** This happens at create-when-active and at approval: if the source alarm is still open or investigating, it becomes `false_positive` with `suppressed_by` set. This is the close the web used to do itself before quieting. A waiting request closes nothing, so "these alarms keep arriving".
4. **Deleting a host group ends its suppressions.** Its waiting requests become `withdrawn` and its active ones `removed`. The delete preview counts them ("Ends N alarm suppressions"). There is no foreign key: a suppression whose group is gone matches nothing, because `console_host_in_group` needs the group row.
5. **Who sees which suppression** (with `alarms.suppressions.read`):
   - a host row, if the host is in reach;
   - a group row, if the group is in the viewer's role, or the viewer reaches all hosts;
   - an all-hosts row, for every reader, because it closes alarms on their hosts too.

   Before this step, program and command rows were global-only.
6. **Remove needs `alarms.suppress` on the row's where**, with the same rule as creating it.
7. **The list returns** waiting, active (including expired, shown with an Expired badge) and rejected rows. Withdrawn and removed rows live in the audit log.
8. **Bulk "suppress"** (compliance bulk, program and all hosts, global callers only) goes through the same store function, so it waits when approval is on. Its result says "requested" for waiting ones.
9. **Device and signature suppressions** (made by `openvibes-admin`) are always active, and netlog's matcher is unchanged. `removed_at` stays in step with `state = 'removed'`.

## 9. People and profile pictures

### 9.1 People and a person's page

- **New columns:** `console_users.email` (optional, at most 254
  characters, validated as an address), `last_sign_in_at`, and
  `auth_source` (§4.6).
- **Edit details** changes the display name and email. It needs
  `access.users` on someone else; anyone may change their own.
- **Reset password and Disable** keep today's behaviour and guards.
- **Roles and Access:** the page's Access card is computed from the
  person's roles: each permission, where it applies, and the role that
  gives it.

### 9.2 Pictures

Anyone may set their own picture (from the account menu or their page).
Setting someone else's needs `access.users` within the share.

1. **The browser:** it crops to a square around the circle and uploads
   the original file plus the crop rectangle. The browser is never
   trusted.
2. **The server's limits before decoding:**
   - at most 10 MB;
   - the type taken only from magic bytes (the name and Content-Type are
     ignored): JPEG, PNG, GIF (animated too), WebP, AVIF, BMP or TIFF;
   - SVG always refused;
   - HEIC refused with "Convert it to JPEG or PNG first";
   - at most 4096 × 4096 pixels and 300 frames, read from the header
     before any pixel is decoded.
3. **Decoding** runs in a separate helper process:
   - no network;
   - no writable files;
   - memory capped at 256 MiB;
   - 10 s of CPU;
   - killed when over either limit.

   It crops and re-encodes to **WebP at 256 and 64 px**, keeping the
   animation for a GIF (at most 300 frames).
4. **Storage:**
   - The original is never kept, so no metadata survives by construction.
   - The two WebP images are stored in `console_user_pictures` in the
     database (never on disk).
5. **Serving:** `GET /v1/users/{id}/picture?size=64|256`, behind sign-in,
   with:
   - `Content-Type: image/webp`;
   - `X-Content-Type-Options: nosniff`;
   - `Content-Security-Policy: sandbox; default-src 'none'`;
   - `Content-Disposition: inline`;
   - a strong ETag.

   It is never served as HTML.
6. **Audit:** uploads and removals are audited.
7. **Without a picture,** the initials are shown, as today.

## 10. Hosts list and host page

### 10.1 The list (screen 16)

- **Search** covers the host name and IP address.
- **Filters** (all combine; each value shows how many hosts it matches):
  - Status (online/offline);
  - OS family;
  - Group;
  - Label;
  - Problems: has critical, has open alarms, none open;
  - Agent: older than the latest release / latest, from the version check
    of #285; unknown matches neither.
- **Filters live in the URL,** so a view can be bookmarked.
- **Save view** stores a named filter set for the person
  (`console_saved_views`, per user).
- **Columns:**
  - Host and IP;
  - OS (distribution and family);
  - Groups;
  - Labels;
  - Open problems;
  - Last heartbeat;
  - Agent version.

  Columns can be hidden, and the choice is remembered per user.
- **Paging is server-side,** as today, so the list stays fast at large
  fleets. Counts come from the same filtered query.

### 10.2 The host page (screen 17)

`/hosts/{agent_id}` replaces the side panel and its tabs. Everything the
panel showed is kept.

- **Header:** the name, status, and a key-facts line, plus Compare,
  Export, Add to case, Ask about this, and ⋯ (Revoke).
- **Tiles,** one number each: open alarms, compliance failing,
  vulnerabilities, software. Each links to the full list filtered to the
  host.
- **Left column:**
  - Details;
  - Protection: threat alarms, hardening, last test;
  - Rule sets;
  - Groups and labels: groups with their kind, plus labels you can edit
    with `hosts.label`;
  - Certificates.
- **Right column:**
  - the top three open alarms, vulnerabilities and failing checks, each
    with "Show all n";
  - a software, ports and services summary.
- **Permissions:** each card and action appears only with its permission
  on this host.
- **Lists:** the full lists (all alarms, packages, ports, services and so
  on) are the existing tables, reached from the cards with the host
  filter applied.

### 10.3 The other list pages (screens 19–32)

Ports, Services, Software, Vulnerabilities, Compliance, Alarms and Cases
follow the Hosts pattern. The approved screens in `rbac-ui/approved.md`
are the reference for each page's filters, columns and cards.

**One pattern, built once.** The web gets the shared pieces, and each page
supplies only its data, filters and cards:

- A `FilterBar`: search, and filter chips that show per-value counts. The
  filters live in the URL. It has Clear all, Save view (per-user saved
  views, `console_saved_views`, keyed by page) and Columns (remembered per
  user and page).
- A list `SummaryLine`.
- The bulk bar: Set state ▾, Assign ▾, Add to case, plus Suppress… on
  Alarms.
- A `DetailPage` in the shared layout:
  - a header with a facts line and actions;
  - four tiles;
  - a left column and a right column of cards;
  - a hosts table with segment chips;
  - a Related card.

**Routes.** Every row opens a page instead of a side panel:

- `/ports/{port}`;
- `/services/{unit}`;
- `/software/{package}`;
- `/vulnerabilities/{advisory}`;
- `/compliance/{rule_id}`;
- `/alarms/{id}`;
- `/cases/{id}`.

The side panels and their tabs are removed once their page exists. Today's
deep links to a panel redirect to the page.

**Server.**

- **List counts:** each list route accepts its page's filters and returns
  the rows, the total, and the count for every value of every filter (with
  the other filters applied). These come from the same query, so the
  numbers always agree.
- **Detail summaries:** each detail page has one summary route returning
  everything above the fold (`GET /v1/<kind>/{id}/summary`). The tables
  stay paged and use the existing list routes, filtered.
- **Scoping:** all of it is scoped by §6. Counts never include hosts the
  viewer cannot see.

**New data the pages need:**

- **Distinct command lines per alarm** (screen 30). Today an alarm keeps
  one sample and a count.
  - From now on it also keeps each distinct command line (by the
    agent's `args_sha256` and the masked sample) with its own count and
    last-seen time: `alarm_commands (alarm_id, args_sha256,
    sample, count, first_at, last_at)`.
  - It keeps at most 50 per alarm. After that only the counts of known
    lines grow, and the page says "50 or more different commands".
  - Masking of secrets stays as today.
- **"This week" and "Needs a look":**
  - "This week" on Ports, Services and Software is read from the change
    log (migration 0065, step 5e): what appeared and went away on each
    host, written at ingest. The inventory history this section first
    named does not exist. No agent change is needed.
  - "Needs a look" is a fixed list of plain rules in code, for example: a
    database or remote-admin port exposed; a port or service new this
    week; a service running as root that is not from a package. Each rule
    has its own line of text.
- **Short names for compliance checks:**
  - Rules get an optional `title` (at most 80 characters), for example
    "SSH allows root login". This is a rule-format change, made in
    openvibes-protocol first, and the rules repository adds titles to
    its sets.
  - The platform reads titles from the rule bundles it already stores, so
    agents and the findings protocol do not change.
  - The list shows the title, and the rule's message moves to the check
    page ("Why it matters"). A rule without a title shows its ID.
- **Outcomes on case items:**
  - Today's three outcomes stay, renamed in the console:
    - `resolved` → Fixed;
    - `false_positive` → False positive;
    - `accepted_risk` → Risk accepted.
  - Two are added: `confirmed_malicious` (Confirmed malicious) and
    `expected` (Expected activity).
  - Every outcome except Fixed still needs a note, as today.
  - "Close case…" requires every item to have an outcome.
  - The mockup's list of four is shortened. Risk accepted belongs in it
    too.
- **Due dates on advisories** come from the CISA known-exploited list
  already imported (`cve_enrichment.kev_due`). "Due within 30 days" is a filter on that date.

**Unchanged:** the triage states and their rules, the evidence the agents
send, and what each permission allows. A page shows a card or action only
when the viewer holds its permission on those hosts (§6).

### Plan rulings, 2026-10-20

These fill gaps in §10.

1. **Paths:** the list moves from `/agents` to `/hosts`, and the page is `/hosts/{agent_id}`.
   - Old URLs redirect:
     - `/agents?…` → `/hosts?…`, with `status=active` → `online` and `stale` → `offline`;
     - `?open=agent:ID` and `/agents?agent=ID` → `/hosts/ID`.
   - Every `nav.open({kind:"agent"})` goes to the page.
   - The assistant's citation links point at `/hosts/{id}`.
2. **Status values:** online, offline, revoked and imported. Today's list shows all four, and the spec's online/offline are the two a person filters by most.
3. **Each filter takes one value,** a single URL parameter. Filters AND together.
4. **Problems:**
   - "has critical" means at least one critical vulnerability;
   - "has open alarms" means at least one open agent alarm;
   - "none open" means no open alarm, no critical vulnerability and no failing compliance check.

   Each problem count is shown only for hosts in the viewer's reach for that kind: `alarms.read`, `vulnerabilities.read` and `compliance.read` respectively. Elsewhere it is "—" and is not counted in that filter.
5. **The group filter** lists groups with at least one host the viewer can see, plus the group currently chosen. It never names a group only on hosts out of reach. The label filter lists the 50 most-used labels on visible hosts, plus the label currently chosen.
6. **Paging is by offset:** `offset` 0..=100000, `limit` 1..=100, default 50. Order is the chosen sort (host name, heartbeat, agent version or problems, ascending or descending), ties broken by agent ID.
7. **Agent version:**
   - "Older" uses the same rules as today's web check (`olderThan` in `views/lists/rows.ts`): numeric segments compared, a pre-release is older than its release, build metadata is ignored.
   - It is computed in SQL by `console_version_older(v, latest)`, which returns null for unknown. Its Rust twin is tested against the same table.
   - The latest version is the update checker's `latest_agent_version`. When that is unknown, both values count 0 and the column has no amber.
8. **Saved views and columns:**
   - A saved view stores the URL query (at most 1000 characters) under a name (1–60 characters, unique per person and page regardless of case), at most 50 per person and page.
   - Hidden columns are stored per person and page, and the Host column cannot be hidden.
   - The routes are `GET/POST/DELETE /v1/saved-views` and `GET/PUT /v1/list-columns/{page}`. They need a signed-in browser session; writes check CSRF.
   - Pages are a fixed list in code; `hosts` is the first.
   - Views saved in the browser under `openvibes.v2.views./agents` are imported once into the server and then removed from the browser.
9. **Full lists from the host page:**
   - Open alarms, Compliance failing and Vulnerabilities link to `/alarms?host=ID`, `/compliance?host=ID` and `/vulnerabilities?host=ID`. Those views gain a `host` filter shown as a removable chip with the host name, and their APIs already accept it.
   - Software, ports and services link to `/hosts/{id}/software`, `/hosts/{id}/ports` and `/hosts/{id}/services`. These sub-pages show today's per-host tables at full width.
10. **The summary route** covers:
    - the header facts;
    - the tiles;
    - Details;
    - Protection's threat alarms and last test;
    - groups and labels;
    - certificates;
    - the top-three lists;
    - the software, ports and services counts.

    The Rule sets card and the hardening row keep their existing components and routes (`/agents/{id}/rule-set-assignments`, `/rule-sets`), which are already permission-aware.
11. **`DetailPage` builds only what screen 17 uses:** the header, four tiles and the two columns. The hosts table with segment chips and the Related card come with step 5's first page that needs them.

### Plan rulings, 2026-10-20 (step 5a)

These fill gaps in the Alarms list and an alarm's page.

**User decisions (2026-10-20):**

1. **Commands seen = siblings.** The page lists every alarm on the same host with the same rule set, rule, program (`exe`) and parent (`ancestors[0].exe`). Each sibling is one distinct command line, with its count, first and last seen, state, case and suppression. The spec's `alarm_commands` table is dropped. Agents already split alarms by command line (contracts-v1, alarm collapse), so the siblings are those lines. Old data works as is.
2. **The last 24 hours = per-hour starts.** Ingest records the growth of each alarm's count, bucketed by the hour the report arrived. Rows are kept 7 days. The page draws 24 hourly bars for the alarm and its siblings together.
3. **"What happened" and "what to check" come from rules.**
   - Rules gain optional `explain` and `check` text, at most 600 characters each. This is changed in `openvibes-protocol` first.
   - Old agents ignore the fields: the agent's `Rule` has no `deny_unknown_fields`, and the rule-set schema allows extra properties.
   - The platform reads the fields from the verified bundle JSON, so no agent release is needed.
   - Until a rule has the text, the card shows the rule's title and its message.

**Rulings:**

1. **A new list route, `GET /v1/alarm-list`.** The keyset-paged `GET /v1/alarms` stays for its current users: live alarms, dashboards and the host page. `/alarms/{id}` is the page.
2. **Filter values** (one per filter, all combining):
   - **State:** open, mitigated, accepted_risk, false_positive. The default view is "open"; a `state=all` value shows every state.
   - **Severity:** the five levels.
   - **Suppressed:** hidden (default), shown. Shown means suppressed alarms are included.
   - **Host:** the host chip from step 4.
   - **Group:** groups with at least one host the viewer can see, plus the chosen one.
   - **Technique:** techniques of alarms in reach, from the rule-metadata index. An alarm whose rule has no technique matches none.
   - **Case:** in a case, not in a case.
   - **Assignee:** me, unassigned, and people with at least one alarm in reach.
3. **Search** covers the message, rule ID, host name, program and parent program.
4. **Paging is by offset,** as on Hosts: `offset` 0..=100000, `limit` 1..=100, default 50.
   - **Sorts:** last seen (default, newest first), first seen, count, severity.
   - Ties are broken by id.
5. **The summary line:** "N open · N critical or high · N on hosts with alarms off". The last part shows only with `hosts.read`.
6. **Ask about this** on the page uses the host page's pattern (`assistant.askAbout`), shown with `assistant.use` on that host.
7. **⋯** holds Export (a CSV of this alarm and its siblings, with `alarms.export`) and Copy link.
8. **The rule-metadata index:**
   - `console_rule_meta` (rule_set_id, rule_set_version, rule_id, rule_version, title, message, explain, check, attack jsonb) is filled from verified bundles when a rule set is stored or uploaded.
   - On console start, a one-time background backfill indexes every stored bundle not yet indexed.
   - An alarm whose rule is not indexed falls back to `GET /alarms/{id}/rule`, which resolves it as today.
9. **"Same rule elsewhere"** shows the count of other hosts in reach with an open alarm from this rule, and links to the list filtered by the rule (`?q=<rule_id>`). Rule ID is not a separate filter.
10. **Hourly starts:**
    - a new alarm adds its whole count to the hour it was received;
    - a growing count adds the difference to the hour of the report;
    - a shrinking count is ignored.

    The table is `alarm_hourly_starts (alarm_row_id bigint, hour timestamptz, starts int, PK (alarm_row_id, hour))`. It is not partitioned, and maintenance deletes hours older than 7 days.

### Plan rulings, 2026-10-22 (step 5b)

These fill gaps in the Vulnerabilities list and a vulnerability's page.

**User decisions (2026-10-22):**

1. **One row and one page per CVE,** as in the mockups.
   - An advisory without a CVE appears under its own ID.
   - Triage is still saved per host and advisory. Setting a CVE's state on a host changes that host's covering advisory. When that advisory also covers other CVEs, the page and the confirmation say which ones.
2. **Set state and Assign on a list row, and the page header's Set state, change the open hosts in reach.**
   - "In reach" means hosts where the viewer holds `vulnerabilities.triage`.
   - A confirmation says how many hosts will change.
   - Mitigated, accepted, false-positive and fixed pairs are left as they are.
   - To change only some hosts, tick them in the page's Hosts table.

**Rulings:**

1. **A new list route, `GET /v1/vulnerability-list`.** `GET /v1/vulnerabilities` stays as it is.
2. **What a row is.**
   - **The key** is the CVE ID, or the advisory ID for an advisory without CVEs.
   - **Pairs under a row:** every host and advisory pair in reach whose advisory names that CVE. This includes fixable pairs (`vulnerabilities`), pairs with no fix (`version_vulnerabilities` through `host_packages`), and, with the Lower confidence signal only, CPE matches (`cpe_findings`) for that CVE.
   - **Severity** is the worst severity among the covering advisories in reach.
   - **Title** is the title of the covering advisory with the most hosts in reach (ties by advisory ID).
   - **Exploited** means KEV or EUVD. **Due** is the earliest `kev_due`. **CVSS** and **EPSS** come from `cve_enrichment` for that CVE.
   - **Package** shows the first affected package name, plus "+n" for more. Under it:
     - "fixed in V" when every pair with a fix names the same fixed version;
     - "fixed in n versions" when the fixed versions differ;
     - "no fix yet" when no pair has a fix.
   - **Hosts** shows "n open of m". n is the open pairs (triage state open, and not fixed); m is every pair, whatever its state.
   - **Assignee** shows One when exactly one person is assigned among the open pairs (others may be unassigned); Several(n) for n people; None ("—") when no open pair is assigned. (Amended 2026-10-23; it first said "when every open pair has the same assignee".)
3. **Filter values** (one value per filter; all filters combine):
   - **State:**
     - `open` (the default), `mitigated`, `accepted_risk`, `false_positive`, `resolved` (fixed by an update) and `all`;
     - a row matches when at least one of its pairs is in that state.
   - **Severity:** critical, important, moderate, low and unrated, shown as today's labels.
   - **Signals:**
     - `exploited`;
     - `due30`: `kev_due` within 30 days of today, overdue included;
     - `nofix`;
     - `reboot`;
     - `lowconf`: only rows with a lower-confidence match (below today's `MIN_CONFIDENCE`), showing those matches. Without it, lower-confidence matches are left out, as today.
   - **Package:** the 50 package names with the most rows in reach, plus the chosen one.
   - **Group, Assignee and Host:** as on Alarms (5a rulings 2 and 3).
   - **Advisory** (`advisory=ID`): a removable chip, used by redirects (ruling 7). It keeps the CVEs that advisory names.
4. **Search** covers the CVE ID, advisory IDs, title and package names.
5. **Paging is by offset:** `offset` 0..=100000, `limit` 1..=100, default 50.
   - **Sorts:** priority (the default, today's rank: exploited, EPSS percentile, severity, CVSS), severity, CVSS, EPSS, hosts open and due.
   - Ties are broken by key.
6. **The summary line:** "N open on N hosts · N known exploited · N with a due date · N without a fix · N unassigned". The counts are rows, except hosts.
7. **Old links.** The `advisory` panel kind and `AdvisoryPanel.tsx` are removed. `nav.open({kind:"advisory", id})` and `?open=advisory:ID` go to `/vulnerabilities/ID`, and the summary route resolves the key:
   - **a CVE ID:** that page;
   - **an advisory with one CVE:** that CVE's page, with `key` set to the CVE, and the web replaces the URL;
   - **an advisory with no CVE:** its own page;
   - **an advisory with several CVEs:** 409 `advisory_has_several_cves`, and the web replaces the URL with `/vulnerabilities?advisory=ID&state=all`.

   Old list URLs map onto the new filters: `state=all`, `exploited=true` → `signal=exploited`, `reboot=true` → `signal=reboot`, `nofix=true` → `signal=nofix` and `lowconf=true` → `signal=lowconf`. When an old URL sets several flags, the first in that order wins.

   Views saved in the browser under `openvibes.v2.views./vulnerabilities` are imported once, as on Alarms.
8. **Bulk on rows** (user decision 2):
   - Each ticked row sends `{advisory_id}` items, one per covering advisory in reach, plus `agent_id` when the Host chip is set.
   - `set_state` and `assign` with advisory-wide items change only open pairs. Closed pairs are left alone and not reported one by one; an item with no open pair left is skipped with the reason "not open".
   - Refined in the final review: closed pairs are left out before the 10,000-item cap (with an advisory-wide or `open_only` item, not a reopen), so they do not count toward it.
   - Reopen is not offered on list rows. It stays on the page's Hosts table, which sends `{agent_id, advisory_id}` pairs.
   - The confirmation shows the sum of the rows' open-in-reach counts, and names the other CVEs that the changed advisories also cover.
9. **Hosts card segments:**
   - **Open:** triage open and not fixed;
   - **Mitigated:** triage mitigated;
   - **Resolved:** fixed by an update, accepted risk or false positive;
   - **All:** every pair.

   The route is `GET /v1/vulnerabilities/{key}/hosts?segment=&offset=&limit=`. It returns rows (host, OS and address, installed version, state, assignee, covering advisory, triage version) and the four segment counts.

   Refined in the final review: a pair fixed by an update has a null triage version (no tick; bulk never expands it), and each row also carries `reboot_needed` and `first_seen`, shown with the pair's open cases as the old panel did.
10. **Ask about this** sends the assistant the covering advisory with the most hosts in reach (`{kind:"advisory"}` as today), so the assistant does not change. It is shown with `assistant.use`.
11. **⋯** holds Export (a CSV of the CVE's hosts in reach, with `vulnerabilities.export`) and Copy link.
12. **Related:**
    - **Alarms:** open alarms on the affected hosts in reach, the top 3 and the total, shown only with `alarms.read`.
    - **Cases:** cases holding any pair of this CVE, shown only with `cases.read`.
    - **Same package:** other CVEs in reach on the same package names, as a count with their severities, linking to `/vulnerabilities?package=NAME`.
13. **Performance:**
    - The list must answer within 2 s at full reach on the `docs/sizing.md` fleet: 10,000 Debian hosts, 3.2 M fixable pairs, plus the pairs with no fix. Record the scoped time as well.
    - Met: 1.90 s at full reach and 1.53 s scoped (`console-read.md`). Migration 0061 holds the stored group membership (ruling 15), and the index the timing test needed, `vulnerabilities (advisory_id)`, is migration 0062 (this ruling first said 0061).
14. **List rows name the other CVEs.** Each list row also carries `also_covers`: the other CVEs named by its covering advisories in reach, at most 10, so the bulk confirmation can name them.
15. **Stored group membership** (user decision, 2026-10-22). Computing membership per request kept the list at 12.7 s, so migration 0061 stores it in `console_host_group_membership`, kept by triggers on hosts, groups, their members and conditions. Its lock is taken before the auto-group lock, so the two never deadlock.
16. **`open_only` bulk items.** A vulnerability bulk item may carry `open_only: true`. List rows always send it, so a close or assign stays open-only even with the Host chip set (`{agent_id, advisory_id}`). A reopen ignores it, and the page's Hosts table sends pairs without it. Without this flag, ruling 8 would break user decision 2 whenever the Host chip is set.
17. **Pairs with no fix stay untriageable,** as before: triage needs a `vulnerabilities` row. Their rows and hosts say they can't be triaged until a fix is known. Hosts-table rows for them have no checkbox, and the bulk confirmation counts only triageable open hosts. Making them triageable is a separate redesign.
18. **Add to case without triage.** The bulk route needs `vulnerabilities.triage` for every action, Add to case included. A person with `cases.write` but no triage gets an Add to case button on each triageable Hosts row of the page, as the old panel had, and no header or bulk case action.
19. **Lower-confidence pairs on the page** count only when the CVE has no other pairs, to match the list, which shows them only under their signal.
20. **History** shows state changes and notes only. `vulnerability_triage_history` does not store assignee changes, and adding them is a schema change outside this step.
21. **What to do counts every pair that is not fixed** per distribution, mitigated, accepted and false-positive ones included: they still need the fixed build.

### Plan rulings, 2026-10-24 (step 5c)

These fill gaps in the Compliance list and a check's page. Rule titles are already required by the protocol (`rule-set.schema.json` `required`), so the optional `title` change planned in "Short names for compliance checks" is already done.

**User decisions (2026-10-24):**

1. **Passing is inferred from rule-set health.** A host passes a check when all of these hold:
   - it is active and in reach;
   - its last heartbeat (`agents.health`, within 24 hours) lists the check's rule set as assigned (`state` not `not_assigned`) and not refused;
   - the collector the check needs ran ok in its last scan;
   - it has no failing finding for the check.

   The agent reports only a count of rules it could not evaluate, so a host whose facts for this one rule were missing can be counted as passing.
2. **The last 14 days come from current findings.** For each day, the count is the hosts whose current finding was open that day, from first seen to fixed. An earlier episode (a check that failed, was fixed, then failed again) is not counted.
3. **Evidence is the fact and its value, plus the file.**
   - The fact and value come from the finding's detection inputs, for example `sshd.permitrootlogin = yes`.
   - The file comes from a small fact-to-file map, for example `sshd.*` → `/etc/ssh/sshd_config`.
   - There is no line number. Passing hosts have no evidence to show.
4. **The rule text comes from the existing optional fields.** `explain` is shown as "Why it matters", and `check` as "How to fix" (the exact setting and command). The rules repository adds both to the 85 baseline and hardening rules; the user reviews the wording and re-signs the sets. Until then the page shows the rule's message.

**Rulings:**

1. **A new list route, `GET /v1/compliance-list`.** The existing `/v1/compliance/*` routes stay for their current users: dashboards, the host page, the assistant and cases.
2. **What a row is.**
   - **The key** is (`rule_set_id`, `rule_id`).
   - **Pairs under a row:** every host in reach with a current finding for the check (`current_findings`), plus the hosts that pass it (user decision 1).
   - **Failing** means a current finding with `ended_at IS NULL`, seen within the window the current Compliance list uses by default. Ended findings are no longer failing.
   - **Title, message, explain and check** come from `console_rule_meta`, using the newest indexed version of the rule. A check without metadata shows its rule ID.
   - **Severity** is the severity of the newest finding, else the rule's indexed severity (`console_rule_meta.severity`, schema 63), so a check only passing hosts run still has one.
   - **Since** is the earliest first-seen time among the failing pairs.
   - **"n of m":** n is failing hosts; m is failing plus passing hosts.
   - **The hosts bar** shows open, mitigated, accepted and false-positive counts among the failing pairs (by triage state, with an expired acceptance counting as open), then pass.
   - **Assignee** follows the 5b rule: One when exactly one person is assigned among the open failing pairs; Several(n) for n people; None when no open failing pair is assigned.
3. **Area** is derived from the rule ID, using a fixed map in code (`check_area(rule_id) -> &'static str`):
   - `port.*` → Network exposure;
   - `package.*` → Packages;
   - `harden.ssh.*` → SSH;
   - `harden.net.*` → Network;
   - `harden.kernel.*` and `harden.modules.*` → Kernel;
   - `harden.files.*` and `harden.fs.*` → Files;
   - `harden.accounts.*` and `harden.login.*` → Accounts;
   - `harden.lsm.*` → Security modules;
   - `harden.services.*` → Services;
   - `test.*` → Tests;
   - anything else → Other.
4. **Filter values** (one value per filter; all filters combine):
   - **State:**
     - `open` (the default), `mitigated`, `accepted_risk`, `false_positive`, `passing` and `all`;
     - a row matches when at least one of its pairs is in that state. A failing pair's state is its triage state, with no triage row counting as open.
   - **Severity:** the five levels.
   - **Rule set:** the sets of rows in reach, plus the chosen one.
   - **Area:** the areas of rows in reach.
   - **Group, Assignee and Host:** as on Alarms and Vulnerabilities.
5. **Search** covers the title, rule ID and rule set.
6. **Paging is by offset:** `offset` 0..=100000, `limit` 1..=100, default 50.
   - **Sorts:** severity (the default, worst first, then most failing), failing, since and title.
   - Ties are broken by key.
7. **The summary line:** "N checks failing on N hosts · N critical · N unassigned", followed by a count per rule set ("baseline N, hardening-linux-l1 N").
8. **Routes for the page:** `/compliance/{rule_set_id}/{rule_id}`, with `GET /v1/compliance/checks/{rule_set_id}/{rule_id}/summary` and `/hosts`. The spec's `/compliance/{rule_id}` is extended with the set, because rule IDs can repeat across sets.
9. **Old links.**
   - The `finding` panel kind and `FindingPanel.tsx` are removed.
   - `nav.open({kind:"finding", id:"set/rule"})` and `?open=finding:set/rule` go to the page, through `settle()` with replace.
   - Case items and the audit panel keep their refs and link through `nav`.
   - Old list URLs map: `state=all` stays; `severity` stays; the old `window`/`since` parameter is dropped.
   - Views saved in the browser under `openvibes.v2.views./compliance` are imported once.
10. **Bulk on rows** follows step 5b (user decision 2 of 5b, ruling 8 and the `open_only` refinement):
    - rows send compliance items `{rule_set_id, rule_id, open_only: true}`, plus `agent_id` when the Host chip is set;
    - Set state and Assign change only open, failing pairs in reach;
    - Reopen is offered only on the page's Hosts table;
    - passing hosts are never touched.

    `open_only` is extended to compliance items. Add to case from a row adds only its failing (not ended) pairs: a fixed host is not something to investigate from the list. A named pair keeps today's behaviour.
11. **Hosts card segments:**
    - **All:** failing and passing;
    - **Failing:** a failing pair in any triage state;
    - **Passing:** inferred passing hosts.

    Rows show the host, OS and address, state, evidence, assignee and checked (the last observation for failing hosts; `health_at` for passing hosts). Failing rows have checkboxes. Passing rows have none, because there is nothing to triage.
12. **The 14 days** are 14 numbers, oldest first. Each is the failing hosts in reach on that UTC day: `first_observed_at` ≤ end of day, and `ended_at` null or after the start of day. They are shown with the existing `HourlyBars` pattern (generalised to N bars) or a new `DayBars`.
13. **Details:**
    - **Rule:** the rule ID and version.
    - **Rule set:** a link to it, with the version.
    - **Applies to:** from the rule set (`hardening-linux-*` → "Linux hosts"; baseline → "All hosts"; site sets → "Hosts with this rule set").
    - **Reference:** the rule's ATT&CK techniques from `attack` (there is no other reference field).
14. **History:** the triage history of pairs in reach, the episode starts and ends (first seen and `ended_at`, labelled "passes again"), and rule-set version publishes. Newest first, at most 50.
15. **Related:**
    - **Port:** for `port.*` checks, the port parsed from the rule expression (`'N' in facts['port.tcp.exposed']`) joined to `host_listeners` in reach (exposed on n hosts), linking to `/ports/{port}`.
    - **Service:** for `harden.services.*`, the unit parsed from the expression, joined to `host_services`, linking to `/services/{unit}`.
    - **Same area:** other failing checks in reach with the same area, as a count with their worst severity.
16. **Ask about this** sends `{kind:"finding", id:"set/rule"}`, as the panel does today. It is shown with `assistant.use`.
17. **⋯** holds Export (a CSV of the check's hosts in reach, with `compliance.export` or the existing findings export permission) and Copy link.
18. **Performance:** the list must answer within 2 s at full reach on a fleet of 10,000 hosts with 500,000 current findings (50 per host, `docs/sizing.md` "Finding changes"), with heartbeat health for every host. Record the scoped time too. Migration 0063 adds an index on `current_findings (rule_set_id, rule_id) WHERE ended_at IS NULL`, plus any other index the timing test needs.

**Amendments during implementation (2026-10-24):**

- **Ended findings are not failing anywhere.** The host page, the Hosts list and the older `/v1/compliance/*` summary, groups and latest-finding reads (dashboards, the assistant) all leave findings with `ended_at` set out; only the per-rule endpoint list keeps them, for its "fixed" badge. Existing compliance counts can drop after the upgrade.
- **One failing definition.** The host page's tile and top failing, and the Hosts list's failing count, use the list's: a failing finding whose triage state is open (an expired acceptance counts as open), `check_list_sql::open_failing`.
- **A host with no report in the last day is unknown, not 0.** When its last contact is older than the 24-hour window, the host page shows "—" with "No report in the last day" and no failing count, and the Hosts list shows "—" in its Problems column's compliance part and leaves the host out of "none open".
- **The check page is timed too:** a widespread check's summary (Same area reads every failing finding in reach in the area) must answer within 2 s on the ruling 18 fleet, full and scoped.
- **Bulk from a check row reaches what the row counts** (final review): a rule-wide or `open_only` item reaches only pairs failing by the list's definition (not ended and seen within the 24-hour window), in every mode (state, assign, add to case and the "not open" test); a stale, never-ended pair is neither changed, added to a case nor counted toward the cap.
- **A row under a Group filter sends its group** (final review): compliance and vulnerability bulk items take an optional `group` (UUID); the item then reaches only that group's members, still inside reach, so the confirmation's count is the row's. Both lists send it when the Group filter is set.
- **The compliance summary uses the one failing definition** (final review): `/v1/compliance/summary` (the menu count, the dashboard's Breakdown tile) and the count history (`compliance.open.*` metrics, top hosts) count open failing findings (host and check pairs, `check_list_sql::open_failing`), by the same definition as the list they open; they count findings while the list counts checks (controller ruling), and the menu count and tile are labelled "N failing findings"; the older groups read counts an expired acceptance as open.
- **Passing needs a recent scan** (final review): the host's last scan (`last_scan.finished_at_unix_ms`, read as 1–18 digits before any cast) must have finished within the 24-hour window, on the list and a check's page alike.

### Plan rulings, 2026-10-25 (step 5d)

These fill gaps in the Cases list and a case's page.

**User decision (2026-10-25):**

1. **"Close case…" asks for a closing note only.**
   - Items carry the outcomes, and closing needs a short required summary note.
   - The case-level `resolution` stays on old closed cases and is shown on them, but new closes no longer set it.
   - Risk accepted keeps a re-open date, now per item.

**Rulings:**

1. **Outcome values.** The wire values are `resolved`, `false_positive`, `accepted_risk`, `confirmed_malicious` and `expected`. The labels are Fixed, False positive, Risk accepted, Confirmed malicious and Expected activity.
   - A note is required for every outcome except `resolved`.
   - `resolved` still needs the evidence to be gone (today's rule).
   - `accepted_risk` needs `outcome_until`, a future date at most 365 days ahead (the same bound as today's case date).
2. **Which items take an outcome.** Alarms, compliance findings and vulnerabilities take one, as today. Host and software items are context and take none.
   - "n/m with an outcome" and "need an outcome" count only the items that take one.
   - Close needs every one of them in the case, hidden ones included: today's `HiddenItemsUnresolved` stays.
3. **Close and reopen.**
   - Closing needs `closing_note` (1–4000 characters), stored in `resolution_note`. `resolution` stays null for new closes, and old rows keep theirs.
   - When an item's `outcome_until` passes, the case reopens (lazily, as today) and that item's outcome clears. Today's case-level `accepted_until` reopen still works for old rows.
   - Reopen stays on ⋯.
4. **Visibility (spec §6).** A case is visible to its creator, its assignee, and anyone who can see one of its items' hosts. A case with no items is also visible to holders of `cases.read` on all hosts (step 5d added this; the SQL before it left that part out).
5. **A new list route, `GET /v1/case-list`.** `GET /v1/cases` stays for its current users: Add to case, the palette and the badges.
6. **Filter values** (one value per filter; all filters combine):
   - **Status:** active (the default: not closed), open, investigating, closed, all.
   - **Severity:** critical, high, medium, low.
   - **Assignee:** me, unassigned, and people with at least one case visible to the viewer.
   - **Contains:** alarms, vulnerabilities, findings. A case matches when it holds at least one visible item of that kind.
   - **Host:** the Host chip; a case matches when it has a visible item on that host.
   - **Group:** groups with at least one host the viewer can see, plus the chosen one; a case matches when it has a visible item on a host in the group.
   - **Updated:** today, this week (the last 7 days), quiet (not updated for 7 days or more).
7. **Search** covers the title, `C-<number>`, the number alone, and the opener's name.
8. **Paging is by offset:** `offset` 0..=100000, `limit` 1..=100, default 50.
   - **Sorts:** updated (the default, newest first), severity, number and opened.
   - Ties are broken by case id.
9. **Row fields:**
   - number, title, opened by (name), the latest note (its first 120 characters and the time), severity, status, assignee;
   - hosts: distinct visible item hosts;
   - kinds: counts per kind among visible items;
   - `with_outcome` / `takes_outcome` counts, among visible items;
   - updated at.
10. **The summary line:** "N open · N investigating · N unassigned · N ready to close". A case is ready to close when it is not closed and every visible item that takes an outcome has one.
11. **Routes for the page:** `/cases/{id}`, with `GET /v1/cases/{id}/summary`. The existing `GET /v1/cases/{id}` stays as the full detail.
    - Old links: `nav.open({kind:"case", id})` and `?open=case:ID` go to the page, with replace.
    - `{kind:"case", id:"new"}` goes to `/cases/new`, which shows today's new-case form.
12. **The summary view:**
    - header facts: number, status, severity, opener, created, assignee;
    - tiles:
      - items, the count of visible items;
      - need an outcome, the visible items still without one, or "Ready to close";
      - hosts;
      - open for: created → now, or created → closed_at.
    - Details: title, severity, status, opener, created, updated, and the old resolution with its note if present;
    - hosts: each visible host with its open problems — open alarms, critical vulnerabilities and failing checks — using the step-4 problem rules and `open_failing` from 5c, counted only where the viewer holds that kind's read permission;
    - who can see it (ruling 13);
    - `can`: `{ edit, assign, close, reopen, note, outcome, ask, export }`.
13. **Who can see it:**
    - the opener and the assignee;
    - enabled people whose live role binding holds `cases.read` on all hosts, or on a group containing one of the case's item hosts.
    - At most 20 names are listed, plus "and N more". The names are shown only to viewers holding `access.read`; everyone else sees the count only.
14. **Ask about this** is shown when the assistant supports a `case` reference (check `assistant/`). If it doesn't, the page omits the button and the report says so.
15. **⋯** holds Export (a CSV of the items and timeline, with `cases.read`), Copy link, and Reopen (on a closed case, with `cases.write`).
16. **Performance:** the list must answer within 2 s at full reach on 10,000 hosts, 20,000 cases and 200,000 items. Record the scoped time too. Add indexes in migration 0064 if needed.

### Plan rulings, 2026-10-25 (step 5e)

These fill gaps in the Ports list (screen 19), a port's page (screen 20) and the shared change log.

**User decision (2026-10-25):**

1. Three PRs in dependency order: 5e Ports (this plan), 5f Services, 5g Software.
2. A new change log written at ingest for packages, listeners and services (appeared / went away), no agent change, first report is the baseline (no "appeared" flood on first report or on upgrade), 90-day retention. 5e builds it for all three kinds (Services and Software reuse it later) but only Ports reads it in this step.
3. (For 5g; note only) A Software row is the package name across managers.
4. Add to case on the port and service pages adds fleet-wide items of new kinds `port` (and later `service`), like `software`: no outcome, and they do not make a case visible on their own ("hosts decide"). 5e adds `port`.

**Rulings:**

1. **Order and size.** §16's "Software, Services and Ports" becomes Ports, Services, Software (user decision 1). The change log lands here because Ports is first. *Why:* services link ports, software links services. *Cost if wrong:* none in code; only the spec's order line.
2. **The change log table** (migration 0065): `change_log (at timestamptz, agent_id text REFERENCES agents ON DELETE CASCADE, kind text CHECK IN ('package','listener','service'), key text, change text CHECK IN ('appeared','went_away','exposed','local'), detail jsonb)`. Keys: listener `tcp/22` (the API's spelling); service the unit; package the name, with `detail = {manager, version, arch}` where `version` is `epoch:version-release`. Indexes `(kind, key, at DESC)` (a page) and `(kind, at)` (lists, pruning). A one-row `change_log_start (at)` set by the migration. *Why:* one table serves all three kinds and the three pages; package key = name matches decision 3. *Cost if wrong:* a rename or a key migration in 5g.
3. **What counts as a change.**
   - **Listener:** per host, the set of `(protocol, port)`; exposed = any bound address is non-loopback. A port that appears or goes away writes `appeared` / `went_away`. A port that stays but flips exposure writes `exposed` or `local`. Addresses alone changing (0.0.0.0 → ::) write nothing. *Why:* screen 20's Recent changes shows "db-02 now listens only locally"; decision 2's appeared/went-away cannot say that. *Cost if wrong:* one CHECK value and one branch to drop.
   - **Service:** the set of units; process-count, program or user changes write nothing (5f may add more).
   - **Package:** the set of package versions; an upgrade is `went_away` of the old version plus `appeared` of the new, at the same `at` (5g reads the pair as "updated"). *Cost if wrong:* 5g recomputes "updated" differently; no data lost.
4. **Baseline and upgrade.** A host's first report (stored digest null: `services_sha256` / `inventory_sha256`) writes nothing. After the upgrade, existing hosts already have stored rows, so their next report diffs against them: no flood. A P11 resync (full inventory) diffs against the stored rows. *Cost if wrong:* a missed "appeared" on a host's very first report, which decision 2 asks for.
5. **No change, no write.** An unchanged digest returns before any change-log work (today's early return). A changed digest with the same keys (for example a process count) computes the diff and inserts zero rows, with no INSERT statement issued. *Cost if wrong:* ingest load on a 10,000-host fleet.
6. **Retention.** `change_log::prune(client, now)` deletes rows older than 90 days, per kind, from `openvibes-admin maintenance` next to `prune_alarm_hourly`. Partitioning is not needed at the sized volume (`ponytail:` comment naming daily partitions as the upgrade path). *Cost if wrong:* a slower daily delete.
7. **"First seen"** = the earliest of: the earliest `appeared` in reach, and, for each host in reach listening now that has no `appeared` event for the port (amended 2026-10-27 on review, lime approved: an event is the truth for its host), `greatest(enrolled_at, floor)`, where `floor = greatest(change_log_start.at, now − 90 days)`. When the result equals `floor`, it shows "Before {floor date}". *Why:* a port seen in a host's baseline report or before the log has no event, and 90-day pruning removes old ones; this never claims a date later than the truth. *Cost if wrong:* a "first seen" that is earlier than needed.
8. **This week** = the last 7 days: hosts in reach with an `appeared` (`added`) and with a `went_away` (`removed`) for this port; exposure flips count in the page's Recent changes, not here. The list cell shows "+n hosts" and "−n hosts"; "No change" when both are 0. The page tile shows the same, or "no host started or stopped".
9. **The port map** (`crates/platform-store/src/port_names.rs`): `pub fn port_info(protocol: &str, port: u16) -> Option<PortInfo>`, `PortInfo { name, usual_use, class: PortClass (Database | RemoteAdmin | Other), area: Option<&'static str>, packages: &'static [&'static str] }`. About 40 well-known ports: at least 21, 22 (SSH, area "SSH", packages `openssh-server`, `openssh`), 23, 25, 53 (tcp, udp), 80, 110, 111, 123/udp, 137–139, 143, 161/udp, 389, 443, 445, 465, 587, 631, 636, 993, 995, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5984, 5985, 5986, 6379, 8080, 8443, 9042, 9200, 11211, 27017. Database class: 1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 11211, 27017. Remote-admin class: 23, 2375, 3389, 5900, 5985, 5986. *Cost if wrong:* a wrong label; the map is one file.
10. **Needs a look** (fixed rules, first match first, codes on the wire, text in the web):
    - `database_exposed` "Database reachable from the network": Database class, exposed on a host in reach;
    - `remote_admin_exposed` "Remote admin reachable from the network": RemoteAdmin class, exposed;
    - `new_unusual` "New this week, not a usual port": not in the map, an `appeared` in reach this week.
    A row carries every matching code; the cell shows the first and "+n". SSH (22) is not flagged. *Cost if wrong:* noise or a missed flag; one list to edit.
11. **A new list route, `GET /v1/port-list`.** `GET /v1/ports`, `/v1/ports/{protocol}/{port}` stay for their current users (API, assistant). *Why:* the 5c/5d rule.
12. **What a row is.** Key `(protocol, port)`. One host counts once whatever its bound addresses. "n of m": n = hosts in reach listening; m = active hosts in reach that have sent a services report (`services_at IS NOT NULL`), the same m as the summary's "from n hosts' last reports".
13. **Filter values** (one value per filter; all combine):
    - **Exposure:** `exposed` (exposed on at least one host in reach), `local` (on none);
    - **Protocol:** `tcp`, `udp`;
    - **Group:** groups with a listening host in reach, plus the chosen one; matches when a host in that group listens;
    - **Service:** owner units seen on rows in reach, plus `~none` "Owner not collected" (a listening host with a null service); matches when a host listens with that owner;
    - **Changes:** `new` (an `appeared` this week), `look` (any Needs a look code);
    - **Host:** the Host chip.
14. **Search** covers the port number, `22/tcp`, the usual name (resolved in Rust from the map to a bound list of keys) and owner units.
15. **Paging is by offset:** `offset` 0..=100000, `limit` 1..=100, default 50. **Sorts:** port (the default, ascending, then protocol), hosts, exposed, week (most added first). Ties by key.
16. **Groups column** shows automatic and rule groups with a listening host in reach, most hosts first, as `portsList`'s `groupsFor` does (manual groups left out). *Cost if wrong:* manual groups invisible in the cell; the Group filter still offers them.
17. **Columns:** `hideable("ports")` = `hosts, exposed, services, groups, week, look`. Port is never hidden.
18. **Routes for the page:** `/ports/{port}/{protocol}` (reads like "22/tcp"; the spec's `/ports/{port}` lacks the protocol), with `GET /v1/ports/{protocol}/{port}/summary` and `GET /v1/ports/{protocol}/{port}/hosts?segment=all|exposed|local&offset&limit`. Invalid protocol or port → 400 `invalid_port`. A port with no listening host in reach and no change in reach in 90 days → 404 `port_not_found`; one that went away from every host stays viewable for 90 days with zero tiles.
19. **Old links.** `parsePortId(id)` in `app/location.ts` accepts `tcp/443`, `tcp:443`, `443/tcp` and `443` (TCP). `nav.open({kind:"port"})` and `?open=port:…` go to the page through `PAGES`, with replace. The `port` panel kind and `PortPanel` go; `UnitPanel` stays until 5f, moved to `UnitPanel.tsx`. Old list URL `?exposed=true` maps to `exposure=exposed`. Views saved in the browser under `openvibes.v2.views./ports` are imported once. *Fixes the 5c bug:* `CheckCards.tsx:237` passes `tcp:22` while `splitPortId` splits on `/`; the shared parser handles both, and CheckCards passes `tcp/22`.
20. **The summary view:** header `{protocol, port, name?, usual_use?, listening, of, exposed, services, first_seen {at, before}}`; tiles `{listening, exposed, local, week {added, removed}}`; details `{programs, owners {collected, of}}`; `by_group: [{group_id, name, listening, of}]` (of = group members in reach); `changes`: the 20 newest events in reach `{at, agent_id, hostname, change}`; `related` (ruling 22); `can {export, add_to_case, ask}`.
21. **Hosts rows:** one per host: `{agent_id, hostname, os, ip, bound: [addresses], exposed, service?, program?, owners_partial, reported_at}` with `reported_at = services_at`, shown in warning colour after 24 hours (step-4 rule). Segments: all / exposed (any address non-loopback) / local. Sort by hostname, agent id. "Lab-ws-04 stopped reporting" (mockup) is not a log event; it shows here as a stale last report.
22. **Related** (each only with its read permission, counted on listening hosts in reach):
    - **Compliance:** failing checks (5c's meaning) whose rule names this port (`rule_port` over `console_rule_meta` rows with `port.%` ids) or, when the map gives an area, whose `check_area` is that area. At most 5, worst first, each linking to its check page, then "n more" linking to `/compliance?area=…`.
    - **Vulnerabilities:** for each package in the map's `packages`, open vulnerabilities on listening hosts: "openssh: n open on m hosts", linking to `/vulnerabilities?package=NAME`. Omitted for unmapped ports (no port→package link exists yet).
    - **Alarms:** open alarms on listening hosts whose `process->>'exe'` basename equals that host's listener program for this port; "None open" when 0; "Program not collected" when no listening host names a program.
23. **Export** (header button, with `hosts.export`): a CSV of the port's hosts in reach (the hosts route, all pages), as 5c's `exportRows` does.
24. **Add to case** (with `cases.write`): item kind `port`, ref `tcp/22` (migration 0066). Like `software`: `agent_id` null, no outcome, visible inside a case only to a viewer with a listening host in reach, and it never makes a case visible by itself. Adding it is refused as `item_not_found` when no host in reach listens. The case list counts it in a new `ports` kind count.
25. **Ask about this** sends `{kind:"port", id:"tcp/22"}` with `assistant.use`, if the assistant resolves it (`assistant/lookups.rs` has `host_services`); if it does not, the button is omitted and the report says so (as 5d ruling 14).
26. **Performance:** the list answers within 2 s at full reach on 10,000 hosts with 20 listeners each (200,000 rows, about 300 distinct ports, 10 % exposed) and 500,000 change-log rows; record the scoped time too. The change log's ingest cost is measured on the same fleet (Task 2): median extra time per changed services report ≤ 5 ms, per 150-package upgrade report ≤ 50 ms, and zero rows and zero extra statements for an unchanged report.

### Plan rulings, 2026-10-27 (step 5f)

These fill gaps in the Services list (screen 21) and a service's page (screen 22); the change log, the case-item decision and the order come from step 5e. The full plan is `docs/superpowers/plans/2026-10-27-roles-5f-services-pages.md`.

1. **What a row is.** Key: the unit as reported (`sshd.service`). A host counts once per unit. "n of m": n = hosts in reach running it; m = active hosts in reach that have sent a services report (same m as Ports).
2. **Routes.** `GET /v1/service-list`; `GET /v1/services/{unit}/summary`; `GET /v1/services/{unit}/hosts?segment=all|exposed|root&offset&limit`. `GET /v1/services` and `/services/{unit}` stay for the API and the assistant. The page is `/services/{unit}`. An empty or over-long (200) unit, or one with a control character → 400 `invalid_unit`. No host in reach runs it and no change in reach in 90 days → 404 `service_not_found`; one that went away everywhere stays viewable for 90 days with zero tiles.
3. **The service map** (`platform-store/src/service_names.rs`): about 40 well-known units with `name`, `usual_use`, `class` (Database | RemoteAdmin | Other), `area` (compliance area) and `packages`. Unit names are matched by *base* (`.service` and any `@instance` removed, lower case). *Cost if wrong:* a wrong label; one file.
4. **From a package, by name.** The agent does not report which package owns a unit's program, so a host "has the unit from a package" when it has an installed package named like the unit's base or one of the map's `packages`. This is a name match, not file ownership, and the page says "matched by name". *Cost if wrong:* an unusual package name shows "not from a package" (amber) for a packaged service; the fix is one map entry.
5. **Runs as.** Privileged = `root`, `0`, `SYSTEM`, `LocalSystem` or `NT AUTHORITY\SYSTEM` (any case). A host with no `run_as` is not privileged. A row is *root on n hosts*.
6. **Filters** (one value each, all AND): `runs_as` = `root` (privileged on at least one host in reach) | `other` (on none); `listens` = `exposed` (owns an exposed listener on at least one host) | `local` (owns listeners, none exposed) | `none` (owns no listener); `packaged` = `yes` (from a package on every host) | `no` (not on at least one); `group`; `changes` = `new` (an `appeared` this week) | `look`; `host`. Search covers the unit, the map's name and use, programs, matched package and owned ports. "Listens" counts only listeners whose owner the agent collected; a host with partial owners can under-report ports.
7. **Needs a look** (fixed, first match first, codes on the wire): `root_unpackaged` "Runs as root and not from a package" (some host runs it privileged and unmatched); `database_exposed` "Database reachable from the network" (a Database-class unit with an exposed listener); `remote_admin_exposed` "Remote admin reachable from the network" (RemoteAdmin class, exposed); `new_unusual` "New this week, not a usual service" (not in the map, an `appeared` this week). A row carries every matching code.
8. **This week** = the last 7 days: hosts in reach with `appeared` (`added`) and `went_away` (`removed`) for the unit. Same text as Ports.
9. **Columns:** Service (and what it is), Hosts ("5 of 11"), Runs as (amber for root), Ports (amber when exposed, linking to the port page; at most 4 and "+n"), Programs and package, This week, Needs a look. `hideable("services")` = `hosts, runs_as, ports, package, week, look`. Service is never hidden. Sorts: service (default, ascending), hosts, week. Ties by unit.
10. **Summary line:** "n run as root · n listen on an exposed port · n not from a package · n new this week · n need a look · from n hosts' last reports", over the rows matching every filter.
11. **First seen** = as Ports ruling 7, over `change_log` kind `service`.
12. **The page (screen 22).** Tiles: *Running on* (hosts, of m), *Open alarms*, *Vulnerabilities in its package*, *Versions in use*. Alarms and Vulnerabilities need `alarms.read` / `vulnerabilities.read` (their tile is left out without it). Versions in use = distinct versions of the matched package(s) on hosts running the unit, "—" when no package matched.
    - **Left:** Details (what it is, runs as with host counts, programs, package matched by name, total processes, first seen); Ports (owned ports, exposed ones amber, each linking to its port page, with host counts); By group; Recent changes (20 newest `appeared`/`went_away` in reach).
    - **Right:** Hosts (segments All / Exposed (an owned listener is exposed) / Runs as root; per host: version, processes, ports, runs as, problems (open alarms and open vulnerabilities of the matched package, each with its permission) and last report; shown in warning colour after 24 hours); Related.
13. **Related** (each only with its read permission, counted on hosts running the unit): failing checks whose rule names the unit (`rule_unit` over `harden.services.*`) or, where the map has an area, whose `check_area` is it; open vulnerabilities per matched package; open alarms whose process program is one of the unit's programs on that host.
14. **Add to case** (`cases.write` and `cases.read`): item kind `service`, ref = the unit, no outcome, fleet-wide like `software` and `port`; refused as `item_not_found` when no host in reach runs it. The case list counts them in a `services` count (migration 0067 widens both checks).
15. **Ask about this** is left out: the assistant has no lookup by unit (as 5d ruling 14). **Export** (`hosts.export`): CSV of the unit's hosts in reach.
16. **Old links.** `nav.open({kind:"unit"})` and `?open=unit:…` open the page; the `unit` panel kind and `UnitPanel.tsx` go. Old list URLs have no filters to map. Views saved in the browser under `openvibes.v2.views./services` import once. `/services/{unit}` is added to `frontend-contract.json`.
17. **Performance:** the list answers within 2 s at full reach on 10,000 hosts with 20 listeners and 30 services each (300,000 service rows, about 150 distinct units), 2,000 packages per host for the name match; record the scoped time too.

### Plan rulings, 2026-10-27 (step 5g)

These fill gaps in the Software list (screen 23) and a package's page (screen 24); the change log, the page shape and the order come from steps 5e and 5f. The full plan is `docs/superpowers/plans/2026-10-27-roles-5g-software-pages.md`.

1. **What a row is.** Key: the package name, rpm and dpkg together (`openssl` is one row whichever package database reports it). A host counts once per name even when it holds two versions (a kernel). A version is `(epoch, version, release)`; the architecture and the manager do not make a version of their own. "n of m": n = hosts in reach that have it; m = active hosts in reach that have sent a package report. Revoked hosts are left out. There is no package description.
2. **Routes.** `GET /v1/software-list`; `GET /v1/software-pages/{name}/summary`; `GET /v1/software-pages/{name}/hosts?segment=all|update|current&offset&limit`. `GET /v1/software` and `/software/{manager}/{name}` stay for the API. The page is `/software/{name}`. An empty or over-long (200) name, or one with a control character, is 400 `invalid_package`. No host in reach has it and no change in reach in 90 days is 404 `package_not_found`; one that went away everywhere stays viewable for 90 days with zero tiles.
3. **Versions column.** Oldest "to" newest of the versions in use, in the order where a digit run is a number (`10.1` is after `9.9`), the epoch first; then the count ("3 versions" in amber, "1 version"). It is not a distribution's own comparison: it names a range, nothing decides on it. *Cost if wrong:* a range that reads oddly for an exotic version string; the count is exact.
4. **Open vulnerabilities** are counted as the Vulnerabilities list's defaults count them: an advisory is open on a host when its triage is open or an accepted risk that has expired, it is not a lower-confidence match, and either the host has a fixable pair for the package, or a version in use has the advisory with no fix. Worst severity is critical, important, moderate, low, unrated; Exploited is a CISA KEV or EUVD flag on a CVE of an open advisory.
5. **Filters** (one value each, all AND): `vulns` = `exploited` | `critical_high` (worst is critical or important) | `any` | `none`; `fix` = `available` (an update fixes an open advisory on at least one host) | `none` (an open advisory has no fix yet); `versions` = `one` | `several`; `type` = `dpkg` | `rpm` (reported by that package database on at least one host); `group`; `changes` = `new` | `updated` | `removed`; `host`. Search covers the name and the services that run from it. The value counts are taken over the rows that match every other filter. A group's chip shows the **hosts** it has in reach ("8 hosts"), not packages, so the chip reads the same on every Software list.
6. **Fix column.** "Update on n hosts" counts hosts with an open fixable advisory that is not waiting for a reboot; "No fix yet" when an open advisory has no fix; a dash otherwise. *Cost if wrong:* a host waiting for a reboot is not counted for an update it cannot take yet.
7. **Used by.** The services that run from the package, by name, as for Services (ruling 4 there): the unit's base or one of the service map's packages equals the package name. Most hosts first, three shown and "+n". It is a name match and the page says so.
8. **This week** = the last 7 days, in hosts: *new* (installed), *updated* (the old version went away and a new one appeared on the same host) and *removed*. A host that installed and removed it counts in neither.
9. **Columns:** Package (with the managers), Hosts, Versions, Vulnerabilities (worst severity, count, Exploited), Fix, Used by, This week. `hideable("software")` = `hosts, versions, vulnerabilities, fix, used_by, week`; Package is never hidden. Sorts: package (default, ascending), hosts, vulnerabilities (Exploited, then worst severity, then count), versions, week. Ties by name.
10. **Summary line:** "n have an exploited vulnerability · n have an update available · n have several versions in use · n new this week · from n hosts' last reports", over the rows matching every filter.
11. **Performance:** the list answers within 2 s at full reach on the sizing fleet (10,000 hosts, 400 packages each out of 600 names, 2,000 advisories, 500,000 change rows); record the scoped time and the extreme fleet (2,000 packages per host) too. If it misses, add a stored host count (the board's wording), not before.
12. **The page (screen 24).** Tiles: *Hosts that have it* (of m), *Open vulnerabilities*, *Hosts that need an update*, *Versions in use*. **Left:** Details (managers, the version most hosts run, versions, open vulnerabilities and how many have no fix), Versions (most hosts first, a bar of the share of hosts; a version with an open vulnerability is red and names some of its CVEs), Used by (linked services), By group, Recent changes (20 newest installs and removals in reach, with the version). **Right:** Vulnerabilities (what they affect, the version that fixes each, hosts; at most 50) and Hosts.
13. **Hosts card.** Segments All / Need an update / Up to date; per host its versions, "Update to x" (the newest fixed version among its open fixable advisories) or "Up to date", the services using it, and its last report (amber after 24 hours). Advisory facts here need `hosts.read` only, as the host page's package list shows them; the Vulnerabilities list stays behind `vulnerabilities.read`.
14. **Add to case** (`cases.write` and `cases.read`): item kind `software`, ref = the **bare name**, no outcome, fleet-wide, refused as `item_not_found` when no host in reach has it. Older items (`rpm/openssl`) keep working: a ref without a `/` is the package under every manager, one with `manager/name` only that manager's. The ref hint reads "Package name, e.g. openssh".
15. **Export** (`hosts.export`): CSV of the package's hosts in reach, one row per host and version. **Ask about this** is left out, as for services.
16. **Old links.** `nav.open({kind:"package"})` and `?open=package:rpm/openssl` open the page; the `package` panel and `PackagePanel.tsx` go, and a `manager/` prefix on the id is dropped. Views saved in the browser under `openvibes.v2.views./software` import once. `/software/{package}` is added to `frontend-contract.json`. The old Fix available and Multiple versions chips are today's Fix and Versions filters.
17. **Order of panels.** An old link with several panels opens the first of: host, alarm, advisory, finding, case, port, service, package.

## 11. Dashboards

- **Storage:** `console_dashboards.shared_role_id` becomes a visibility:
  - `visibility` is `private` | `roles` | `everyone`;
  - the roles are in `console_dashboard_roles (dashboard_id, role_id)`.
- **Sharing with roles** needs `dashboards.share`, and only roles you hold.
- **Sharing with everyone** needs `dashboards.publish`.
- **Upgrade:** a dashboard with a `shared_role_id` becomes `roles` with
  that role. Other dashboards become `private`.
- **Who sees what:**
  - A shared dashboard is seen by people holding one of its roles (or
    everyone).
  - Only the owner edits it; others can **Make a copy**.
  - Widgets are always computed with the viewer's own access.
- **When a role is deleted,** it is removed from every dashboard's roles,
  and a dashboard left with no roles becomes private.
- **The header badge** shows Only you / Shared with … / Everyone.

## 12. Upgrade

Migrations applied together in one transaction; nobody's access
changes. The order:

1. **Permissions:** the new catalogue replaces `console_permissions`. Old
   IDs map to new ones:
   - `agents.read` → `hosts.read`
   - `agents.revoke` → `hosts.revoke`
   - `cases.manage` → `cases.write` and `cases.assign`
   - `tokens.create` and `tokens.revoke` → `tokens.manage` and
     `tokens.installer`
   - `rules.upload` → `rules.publish`
   - `rules.write` → `rules.assignment.write`, `site_rules.write`,
     `site_rules.test`, `site_rules.publish`
   - `rbac.read` → `access.read`
   - `rbac.manage` → `access.users`, `access.roles`, `access.grant`
   - `asset_groups.manage` → `host_groups.manage`
   - `service_accounts.manage` → `service_accounts.manage` and
     `service_accounts.tokens`
   - every other ID is unchanged.

   Every role then gets the **needs** of what it holds, and every
   `X.export` whose `X.read` it holds. Export was part of viewing before.
   It also gets the new view permissions that cover what it could see
   before:
   - `alarms.suppressions.read` with `alarms.read`;
   - `rules.assignment.read`, `rules.coverage.read` and
     `rules.contents.read` with `rules.read`;
   - `site_rules.read` with `rules.write`;
   - `rules.read`, `rules.assignment.read` and `rules.coverage.read`
     with `rules.upload`, whose holders can see Rule sets and Coverage
     today (plan ruling, 2026-10-16).
2. **Roles:**
   - The built-in `admin` stays `admin`, shown as Administrator and
     protected (§4.3).
   - Every other built-in role in use (viewer, analyst, operator) becomes
     an ordinary role with the same name, its mapped permissions, reach
     **all hosts**, and its members.
   - A built-in role nobody holds is deleted (the templates cover it).
3. **Scoped bindings** (`asset_group_id` set): a holder's scoped
   bindings of one role are taken together as one set of groups. For each
   distinct (role, set of groups), a role named "<Role> (<groups>)" — for example
   "Operator (Lab)" — is created with that reach. The bindings move to it.
   - As before, only the old agent-bound permissions applied there. The
     new role gets those permissions only, so that nobody gains anything.
   - Its name is shortened, with a number added, if it would exceed 64
     characters or clash.
4. **Groups and tags:** as in §5.3.
5. **Suppressions:**
   - Every existing row becomes `active`.
   - Program and command rows get where = all hosts.
   - Host rows keep their host.
   - `expires_at` stays empty.
6. **Dashboards:** as in §11.

The migration's tests start from a database holding every old shape, and
assert each person's effective (permission, host) set before and after.
The sets must be equal, apart from the added export, needs and view
permissions listed above.

## 13. API (summary)

All routes are under `/v1`, behind sign-in, and guarded by §6. Every
change is audited and idempotent where today's routes are
(`Idempotency-Key`).

- **Roles:**
  - `GET/POST /roles`;
  - `GET/PATCH/DELETE /roles/{id}`, which refuses Administrator;
  - `GET /role-templates`;
  - `GET /permissions`, the catalogue with area, column, scope and needs.
- **Role holders:** `POST/DELETE /users/{id}/roles/{role}` and
  `POST/DELETE /service-accounts/{id}/roles/{role}`.
- **Host groups:**
  - `GET/POST /host-groups`;
  - `GET/PATCH/DELETE /host-groups/{id}`;
  - `POST /host-groups/{id}/preview`;
  - `GET /host-groups/{id}/hosts`.
- **Labels and hosts:**
  - `PUT/DELETE /hosts/{agent_id}/labels/{label}`;
  - `GET /hosts`, with the filters of §10.1;
  - `GET /hosts/{agent_id}/summary`, the host page in one call.
- **Settings:** `GET /settings`, `PATCH /settings/{key}`.
- **Suppressions:** `POST /alarm-suppressions/{id}/approve | reject |
  withdraw`.
- **Pictures:** `PUT/DELETE /users/{id}/picture`,
  `GET /users/{id}/picture`.
- **Dashboards:** `PATCH /dashboards/{id}/sharing`.
- **Saved views:** `GET/POST/DELETE /saved-views`.

The OpenAPI document, the demo server and `roles.json` follow, as today.

## 14. Failure behaviour

- **Concurrent edits:** a role, group or setting changed by someone else
  since it was read returns 409. The console reloads it and shows what
  changed.
- **A role in use:** deleting a role that people or service accounts
  hold is refused with 409 `role_in_use`, naming how many hold it (plan
  ruling, 2026-10-16).
- **A group in use:** deleting a group that a role reaches is refused,
  naming the roles, until they no longer use it. A group used by a
  rule-set override can be deleted; the override goes with it, and the
  preview says so.
- **A failed picture helper** (crash, timeout, over a limit) returns 422
  "This picture couldn't be read", logs the reason, and stores nothing.
- **Membership queries** are bounded by the same limits as the Hosts list.
  A rule that matches nothing is allowed (it may match later).

## 15. Testing

- **Unit tests:**
  - catalogue invariants (needs acyclic, closure, every guarded route
    named);
  - the access check over a table of (roles, reach, host) cases;
  - the share check (§4.4) with a refusal for each rule;
  - the rule matcher for each field, including patterns, CIDR and case;
  - suppression state transitions, including self-approval refused and
    expiry.
- **Store tests** against the test database:
  - the upgrade migration's before/after equality (§12);
  - the last-Administrator guard under two concurrent removals;
  - automatic group creation and dismissal.
- **Picture tests:**
  - each accepted format;
  - SVG, HEIC, a renamed file, a 4097-pixel header, a 301-frame GIF, and
    a decompression bomb;
  - a truncated file;
  - the helper's limits, which kill it rather than the server;
  - the served headers.
- **Console tests:**
  - the shared `FilterBar` (counts, URL round trip, saved views) and
    `DetailPage`, once;
  - per list page: each filter, and opening a detail page;
  - distinct-command capping at 50;
  - the role page (needs added and removed, templates compared, sticky
    bar);
  - group preview;
  - suppress, approve and reject;
  - Hosts filters and the URL;
  - the host page;
  - dashboard sharing.
- **The demo server** covers every new route, so the demo build exercises
  the screens.
- **The live end-to-end suite** adds:
  - a two-team setup in which each team sees and changes only its hosts;
  - a suppression approved by the other team lead.

## 16. Delivery

This is too much for one plan, so it ships in this order. Each step is its
own plan (step 5 is one plan with a pull request per page), and each
step leaves the console working:

1. **Permissions and roles:** the catalogue, custom roles, Administrator,
   reach, the share check, the upgrade, and the Roles and People screens
   with person pages (screens 1–8, without pictures).
2. **Host groups and labels:** the three kinds, the preview, the tag
   upgrade, and screens 9–10c.
3. **Settings › General and suppressions with approval:** screens 11, 12
   and 14.
4. **Hosts list and host page:** screens 16 and 17, which also build the
   shared `FilterBar`, `DetailPage`, saved views and list-count support.
5. **The other list pages** (§10.3), one pull request per page, each with
   its detail page: Alarms (with distinct commands), Vulnerabilities,
   Compliance, Cases, then Ports, Services and Software (user decision, 2026-10-25).
6. **Dashboard sharing:** screen 18.
7. **Profile pictures:** screen 7c and the helper.

Single sign-on follows as its own spec, using §4.6.

## 17. Out of scope

- SSO itself, and the purge job.
- Approval for anything other than suppressions.
- Per-host exceptions inside rule groups. Use a manual group, or a rule
  condition.
- Labels in group rules.
- Field-level permissions inside a page. A card is shown or hidden as a
  whole.
