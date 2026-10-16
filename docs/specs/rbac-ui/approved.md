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

## The other list pages (screens 19–32)

Added at the user's request ("some of the other pages to have the same
design changes"), and approved one page at a time on 2026-10-16. Every
list page follows the Hosts list (16), and every detail page follows the
host page (17) and the shared layout.

19. **Ports.**
    - **Filters:** Exposure, Protocol, Group, Service, Changes (new this
      week / needs a look).
    - **Columns:**
      - Port, with its usual name;
      - Hosts ("5 of 11");
      - Exposed on;
      - Services;
      - Groups;
      - This week;
      - Needs a look (for example "Database reachable from the network",
        or "New this week, not a usual port").
20. **A port's page** (22/tcp).
    - **Tiles:** hosts listening, exposed, local only, this week.
    - **Left column:**
      - Details (usual use, services, programs, first seen);
      - By group, with bars;
      - Recent changes.
    - **Right column:**
      - Hosts, with All / Exposed / Local only. Each row shows where it is
        bound, the service and program, its exposure and last report.
      - Related: compliance checks, vulnerabilities and alarms.
21. **Services.**
    - **Filters:** Runs as (root or SYSTEM / another user), Listens (on an
      exposed port / local only / no ports), Group, Package (from a
      package or not), Changes.
    - **Columns:**
      - Service and what it is;
      - Hosts;
      - Runs as (amber for root/SYSTEM);
      - Ports (amber when exposed, linking to the port page);
      - Programs and package ("not from a package" in amber);
      - This week;
      - Needs a look.
22. **A service's page** (nginx.service).
    - **Tiles:** hosts, open alarms, vulnerabilities in its package,
      versions in use.
    - **Left column:**
      - Details;
      - Ports (linked);
      - By group;
      - Recent changes.
    - **Right column:**
      - Hosts, with version, processes, ports, problems and last report;
      - Related alarms, vulnerabilities and checks.
23. **Software.** One line per package.
    - **Filters:** Vulnerabilities (exploited / critical or high / any /
      none), Fix (available / no fix yet), Versions (one / several), Group,
      Type (deb, rpm, Windows), Changes.
    - **Columns:**
      - Package, with what it is and its type;
      - Hosts;
      - Versions, as a range with a count;
      - Vulnerabilities: the worst severity, the number of advisories and
        Exploited, side by side;
      - Fix ("Update on n hosts" / "No fix yet");
      - Used by;
      - This week.
24. **A package's page** (openssl).
    - **Tiles:** hosts, vulnerabilities, hosts needing an update, versions.
    - **Left column:**
      - Details;
      - Versions, with bars, the vulnerable ones in red with their CVEs;
      - Used by (linked services);
      - Recent changes.
    - **Right column:**
      - Vulnerabilities: what each affects, what fixes it, and its hosts;
      - Hosts, with All / Need an update / Up to date. Each row shows the
        version, "Update to x" or "Up to date", and what uses it.
25. **Vulnerabilities.** The nine toggle chips become filters: Severity,
    State (replaces "Include resolved"), Signals (Known exploited, Due
    within 30 days, No fix yet, Reboot needed, Lower confidence), Package,
    Group, Assignee.
    - **Columns:**
      - Severity;
      - Advisory, with Exploited;
      - Package, with "fixed in x" or "no fix yet";
      - CVSS;
      - EPSS;
      - Hosts ("n open of m", with a progress bar);
      - Due (the CISA date, amber when close);
      - Assignee.
    - **Bulk:** ticking rows shows a bar with Set state ▾, Assign ▾, Add to
      case and Clear.
26. **An advisory's page** (CVE-2026-10042).
    - **Header:** triage actions (Set state ▾, Assign ▾, Add to case, ⋯),
      with the CISA due date as a banner below it.
    - **Tiles:** open on, fix available, EPSS, CVSS.
    - **Left column:**
      - What to do (the fixed build per distribution, and whether a reboot
        is needed);
      - Details (the distribution advisories, confidence, vector);
      - History.
    - **Right column:**
      - Hosts, with All / Open / Mitigated / Resolved. Each row shows the
        installed version, state, assignee and the covering advisory, with
        checkboxes for bulk triage.
      - Related alarms, cases and same-package advisories.
27. **Compliance.** Each check gets a short name, with its rule ID and rule
    set under it. The long explanation moves to the check's page.
    - **Filters:** Severity, State, Rule set, Area (Network exposure, SSH,
      Accounts, Packages, Kernel…), Group, Assignee.
    - **Columns:**
      - Severity;
      - Check;
      - Area;
      - Failing ("2 of 5");
      - Hosts: a colour bar with words under it ("3 open · 2 mitigated ·
        6 pass");
      - Since;
      - Assignee.
    - **Bulk:** the bulk bar stays.
28. **A check's page** (SSH allows root login).
    - **Tiles:** failing on, passing, first seen, and the last 14 days as
      bars.
    - **Left column:**
      - Why it matters;
      - How to fix (the exact setting and command);
      - Details (rule, rule set, applies to, reference);
      - History.
    - **Right column:**
      - Hosts, with All / Failing / Passing. Each row shows its evidence
        (the exact line and file).
      - Related port, service and checks in the same area.
29. **Alarms.**
    - **Filters:** Severity, State, Suppressed (hidden by default), Host,
      Group, Technique (ATT&CK), Case, Assignee.
    - **Columns:**
      - Severity;
      - Alarm, with its process chain and technique;
      - Host, with its OS;
      - Count;
      - Last and first seen;
      - State;
      - Assignee;
      - Case.
    - **Suppress:** the per-row "Quiet…" menu is removed. Suppress… is in
      the bulk bar and on the alarm's page.
30. **An alarm's page** ("A web server started a shell" on web-01).
    - **Header:** Set state ▾, Assign ▾, Suppress…, Ask about this, ⋯.
    - **Tiles:** starts matched, different commands, first seen,
      confidence.
    - **Left column:**
      - What happened, in plain words, plus what to check;
      - Details;
      - History.
    - **Right column:**
      - Commands seen: every distinct command line with its count. The
        usual one has "Suppress this command…" (the screen-12 form); a
        command seen once is highlighted, with Add to case.
      - Process chain;
      - Last 24 hours, as a timeline;
      - Related alarms on the host, vulnerabilities, and the same rule
        elsewhere.
31. **Cases.**
    - **Filters:** Status (closed hidden by default), Severity, Assignee,
      Contains (alarms / vulnerabilities / findings), Host, Group, Updated
      (today / this week / quiet for 7 days or more).
    - **Columns:**
      - Case;
      - Title, with who opened it and the latest note;
      - Severity;
      - Status;
      - Assignee;
      - Hosts;
      - Items (the kinds, and "n/m with an outcome" with a bar);
      - Updated.
32. **A case's page** (C-104).
    - **Header:** Edit, Assign ▾, Ask about this, Close case…, ⋯.
    - **Tiles:** items, need an outcome (it counts down to "ready to
      close"), hosts, open for.
    - **Left column:**
      - Details;
      - Hosts in this case, with their open problems;
      - Who can see it.
    - **Right column:**
      - Items, with an Outcome per item (Confirmed malicious, Expected
        activity, False positive, Fixed; the spec adds Risk accepted, which
        exists today);
      - Notes and timeline: write a note at the top, newest first.
