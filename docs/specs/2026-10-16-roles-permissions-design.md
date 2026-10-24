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
  - "This week" on Ports, Services and Software is computed from the host
    inventory history that already exists (`host_daily_counts`, and the
    inventory change tracking of `2026-09-27-inventory-changes-design.md`).
    No new collection is needed.
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
   Compliance, Cases, then Software, Services and Ports.
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
