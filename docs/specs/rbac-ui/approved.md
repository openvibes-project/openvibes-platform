# Roles, permissions and hosts: approved console screens

Spec: `../2026-10-16-roles-permissions-design.md`. All the screens below
were approved by the user one by one on 2026-10-16.

The mockups are real console pages, captured from the demo build, with the
new parts drawn in, and most of them can be clicked. To regenerate them:

```sh
python3 gen.py base OUT_DIR
```

`base/` holds the captured page HTML, the demo build's stylesheet, icons
and brand files. Each page's caption bar says what to try. Screen numbers
13 (a separate Approvals page) and 15 (labels in the old side panel) were
dropped during review, so their numbers are unused.

## Shared layout (screens 7, 10, 11, 14, 17)

Detail and settings pages share one layout, decided on screen 11:

- A header: title (or icon/picture and name), one summary line, actions
  on the right.
- A narrow left column of cards (details, "On this page", recent changes
  from the audit log with a link to it).
- A wide right column of cards. Settings are rows inside a card: name and
  explanation on the left, the control on the right.
- Each setting saves as soon as it is changed, and its row says
  "Saved · recorded in the audit log". There is no Save bar.
- Everything is full width; nothing sits in a side panel.

## Screens

1. **Settings › Roles.** Settings is always in the menu; its tabs are
   General, People, Roles, Host groups, Service accounts, Enrollment,
   Rule sets and Assistant, each shown when one of your permissions needs
   it. One search field per tab (no outer Settings filter). The list
   shows the roles (templates are not listed), their members, where they
   apply, and the protected Administrator.
2. **New role** (full page, full width). The steps, in order:
   1. **Name**, with **Start from** beside it (Blank by default).
   2. The **permission matrix**: areas as rows; View / Change / Export /
      Approve and publish as columns; chips, plus "All" per row and
      toggles per column heading.
      - Platform-wide permissions carry an ⓘ mark.
      - Turning on a permission turns on what it needs. Turning one off
        turns off what depends on it. A notice says what else changed.
   3. **Hosts:** a search field over host groups with "All hosts" on top.
      Chosen groups show as chips with ×.

   A sticky bottom bar sums up the role and holds Cancel and Create role.
3. **Start from.** Blank and the six templates, each with one line on what
   it is for.
4. **Comparing templates.** Switching template refills the matrix live.
   Permissions it adds are outlined green, and ones it removes red. A
   template never picks hosts.
5. **Editing a role limited to groups** (Windows lead on WindowsServers).
   Any permission may be added; host permissions apply on its groups only.
6. **Settings › People.** One search field. Columns:
   - Person.
   - Roles, as badges with where each applies ("Windows lead ·
     WindowsServers").
   - Signs in with (Password / single sign-on · provider).
   - Status.
   - Last sign-in.

   A team admin sees only the people inside their share.
7. **A person's page** (one page, no tabs).
   - **Header:**
     - picture or initials, with a camera button;
     - name, status, and a line with roles · permissions · last sign-in;
     - Edit details, and ⋯ (Reset password, Disable).
   - **Left column:**
     - Details, read-only until Edit;
     - Recent activity.
   - **Right column:**
     - Roles, as compact cards with + Add role and Remove;
     - Access, grouped by where it applies (all hosts / only on <groups> /
       platform-wide), each "From <role>".

   7c. **Uploading a picture.** A crop dialog:
   - drag and zoom inside a circle;
   - previews at 64, 32 and 24 px;
   - a file line with type, frames, size and dimensions;
   - "Stays animated" for a GIF;
   - Save picture.

   7b. **A single sign-on user.** Details and the roles that come from
   identity-provider groups are locked ("Managed by single sign-on").
   Extra roles can be added by hand. The page says the account is removed
   after the configured number of days without signing in.
8. **Adding a role to a person.** Search by name. Each role shows where it
   applies and how many permissions it has. A team admin is offered only
   roles inside their share.
9. **Settings › Host groups.** The three kinds are listed apart: automatic
   (made by OpenVIBES), rule and manual. Each row shows:
   - the description, and the rule or "picked by hand";
   - hosts, and how many are online;
   - open problems;
   - who reaches it (roles, people);
   - the last change.
10. **A rule group** (WindowsServers), in the shared layout.
    - **Left column:** Details, who reaches it, recent changes.
    - **Right column:**
      - Membership, read-only until Edit. The rule is built only from what
        agents report: OS family, distribution, host-name pattern, IP
        range.
      - The hosts table, with why each host is in.

    Before saving an edit, the page shows "If you save: +n / −n hosts"
    and who gains or loses access.

    10b. **A manual group** (Pilot hosts): hosts picked by hand; it never
    changes by itself.

    10c. **An automatic group** (Debian 12), made when the first Debian 12
    host reported. Editing it makes it yours.
11. **Settings › General.** In the shared layout.
    - **Left column:**
      - "On this page", listing the sections with how many settings each
        has;
      - Recent changes.
    - **Right column:**
      - *Alarm suppressions › Suppressions need approval*: off by default.
        When on, it says who can approve.
      - *Single sign-on › Remove inactive single sign-on users*, after
        90 days by default, with the note "Takes effect once single
        sign-on is set up."
12. **Suppressing an alarm** (the alarm panel's "Quiet…" becomes a form):
    - **What:** this program, or this exact command (shown).
    - **Where:** this host, or a group your role reaches.
    - **For:** 7 days, 30 days, or until removed.
    - **Reason:** required.

    With approvals on, a note says it will wait. After Request, the panel
    reads "Suppression requested, waiting for approval… these alarms keep
    arriving", with **Withdraw request**.
14. **Alarm suppressions** (approvals live here, no separate page). In the
    shared layout.
    - **Left column:** By status (Waiting / Active / Rejected, with counts)
      and Recent changes.
    - **Right column:** one card per status, with a row per suppression:
      - the command, What/Where/For chips, the quoted reason, and who
        asked and when;
      - for a waiting request, "would have closed N alarms in the last
        7 days";
      - the status badge, Open alarm, and the actions.

    The actions:
    - **Approve** and **Reject…**, the reject reason being required and
      inline, for anyone allowed to approve on those hosts;
    - **Withdraw** on your own waiting request;
    - **Remove…** on an active one;
    - **Ask again…** on a rejected one.

    The menu count of waiting requests sits on Alarm suppressions.
16. **Hosts.**
    - **Search plus filter chips:** Status, OS, Group, Label, Problems, and
      Agent (older than the latest / latest). Each lists its values with
      counts, and a chosen value becomes a chip with ×.
    - **On the right:** Clear all, Save view, Columns.
    - **Columns:**
      - Host and IP;
      - OS (distribution, family);
      - Groups (two, then "+n");
      - Labels;
      - Open problems;
      - Last heartbeat and online/offline;
      - Agent version (amber when older than the latest release).

    The summary line reads "9 online · 4 with an older agent · 4 with
    critical vulnerabilities". Clicking a host opens its page.
17. **A host's page** (replaces the side panel and its tabs).
    - **Header:**
      - an OS badge, the name and status;
      - a line with agent ID · OS · IP · agent version · heartbeat ·
        enrolled;
      - Compare, Export, Add to case, Ask about this, and ⋯ (Revoke).
    - **Four tiles, one number each,** each leading to its full list:
      open alarms, compliance failing, vulnerabilities, software.
    - **Left column:**
      - Details;
      - Protection (threat alarms, hardening, last test);
      - Rule sets;
      - Groups and labels: groups with their kind, plus labels with × and
        "Add a label";
      - Certificates.
    - **Right column:**
      - the top three open alarms, vulnerabilities and failing checks,
        each with "Show all n";
      - a software, ports and services summary.
18. **Sharing a dashboard.** A **Share** button on the dashboard header
    opens the dialog:
    - **The three choices:**
      - **Only me.**
      - **People with these roles:** chips of the roles you hold, and how
        many people that is.
      - **Everyone:** disabled, with the reason, unless you hold "Publish
        dashboards to everyone".
    - **A note:** each person sees counts from their own access, only the
      owner edits, and others can make a copy.

    The header then shows a badge: Only you / Shared with … / Everyone.
