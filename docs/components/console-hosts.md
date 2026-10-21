# console-hosts (the Hosts list and the host page)

The console's Hosts list (`/hosts`, approved screen 16) and host page
(`/hosts/{id}`, screen 17), from roles step 4 (spec §10.1–10.3, plan
`docs/superpowers/plans/2026-10-20-roles-4-hosts-pages.md`). They replace
the old Agents view and host panel. The shared pieces they are built from
(FilterBar, Columns, saved views, SummaryLine, DetailPage) are in
[console-web.md](console-web.md#shared-list-and-detail-pieces).

## Interfaces

- `GET /api/v1/hosts`: filtered, counted, sorted and paged list
  (`crates/openvibes-console/src/hosts/list.rs`, store `host_list.rs`;
  [platform-store.md](platform-store.md)).
- `GET /api/v1/hosts/{id}/summary`: everything above the fold of the host
  page, with what this person may see and do on the host (`can`).
- `GET /api/v1/agents/{id}`: rule sets, hardening and all certificates (up
  to 100) for the page.
- `GET|POST|DELETE /api/v1/saved-views`, `GET|PUT /api/v1/list-columns/hosts`
  ([saved-views.md](saved-views.md)).

## Behaviour

- **Hosts** (`/hosts`, `g a`; approved screen 16): `views/investigate/Hosts.tsx`
  over `GET /api/v1/hosts`, filtered, counted, sorted and paged on the
  server. The search matches a host name (contains), an agent id or an
  address (prefix), or a CIDR range. The host name is a link to the host's
  page (a new tab works too); an empty cell shows "—" with its meaning for
  screen readers. The FilterBar's chips are Status (online, offline, revoked,
  imported), OS, Group, Label, Problems (has critical, has open alarms,
  none open) and Agent (older than the latest, the latest), each value with
  the server's count under the other filters; saved views and columns are
  the page `hosts`. Columns: Host and IP; OS (distribution, family); Groups
  (two, then "+n"); Labels; Open problems (alarms, critical, failing, "—"
  where the viewer may not read that kind on the host); Last heartbeat with
  the status, and an "Alarms off" warning beside it when the host is online
  with threat alarms off by a fault (`alarms_off`; off by choice stays
  quiet); Agent version (amber, with a title, when older than the
  latest agent release; never amber while that release is unknown). The
  summary line reads "9 online · 4 with an older agent · 4 with critical
  vulnerabilities" (the older part left out while the latest release is
  unknown). Sorting (Host, Open problems, Last heartbeat, Agent) is the
  server's (`DataTable serverSort`; the URL keeps the column key, `agent`
  sent as `version`); 50 rows a page, Previous and Next, `offset` in the URL
  (not a filter, not saved in a view; a filter, search or sort change starts
  again at the first page). The last page stays on screen while the next
  loads. On first visit, views kept in the browser under
  `openvibes.v2.views./agents` are imported (`hostsQuery` maps their
  status values). A view is never discarded: after each run the key holds
  exactly the views not yet on the server (refused, or a 503/network
  failure) and is removed only when none are left; saved and exact-duplicate
  views leave the key. Refusals (view limit, name clash after the
  " (imported)" retry, invalid view) are tried again on the next visit and
  told once per browser session: "N views saved in this browser couldn't be
  moved to your account (reason). They stay in this browser and will be
  tried again."
- **Old addresses** (`app/location.ts` `redirect`, plan ruling 1):
  `/agents?…` reads as `/hosts?…` with `status=active` → `online` and
  `stale` → `offline`; `/agents?open=agent:ID` and the assistant's
  `/agents?agent=ID` read as `/hosts/ID`. `app/nav.ts` replaces the URL in
  place (no dead history entry) on load, Back/Forward, and any in-app
  navigation to `/agents` (the dashboard List widget's "Open list").
- **Host page** (`/hosts/{id}`, approved screen 17, `views/investigate/host/`):
  it replaces the old host panel and its tabs; everything the panel showed
  is kept (spec §10.2). A row of the Hosts list, any host link
  (`ObjectLink`, whose href is the page), the palette, an assistant
  citation and `nav.open({kind: "agent"})` (in `app/nav.ts`, so every call
  site follows) open it and close any open panels (a host is a whole page); the `agent` panel kind is gone, and old
  `?open=agent:ID` addresses on any view read as the page, with no panels. A host window popped out before is dropped. A malformed or
  unreachable address says "No such host". It reads
  `GET /api/v1/hosts/{id}/summary` (what this person may see and do on
  this host) and `GET /api/v1/agents/{id}` (rule sets, hardening, Export,
  all certificates); if that fails, Rule sets says why and Export is not offered.
  - **Header:** an OS badge (LX, WIN), the name and status; the facts line
    "agent ID · system · IP · agent version (older, in amber) · last
    heartbeat · enrolled 3 Oct"; Compare (opens the compare panel), Export
    (`can.export`), Add to case (`can.add_to_case`), Ask about this
    (`can.ask`), and ⋯ with **Revoke…** (`can.revoke`; a dialog that needs
    a reason, kept in the audit log).
  - **Tiles:** Open alarms, Compliance failing, Vulnerabilities (each only
    with its read permission on this host) and Software, linking to
    `/alarms?host=ID`, `/compliance?host=ID`, `/vulnerabilities?host=ID`
    and `/hosts/ID/software`.
  - **Left column:** Details (host name, agent ID, system, running kernel,
    IP, agent version, software as of, status, enrolled, revoked,
    capabilities); Protection (threat alarms, the hardening row, last
    test); Rule sets; Groups and labels (labels with × and "Add a label"
    with `can.label`, never on a revoked or imported host); Certificates
    (the five newest, the first marked Current; "Show all n" lists every
    one from the agent's record, which holds the 100 newest, so past 100
    the toggle reads "Show the 100 newest of n").
  - **Right column**, in the left menu's order (#118): the top three open
    alarms, failing checks and vulnerabilities (Exploited for KEV or EUVD,
    the title on hover, Add to case each),
    each with "Show all n" to the filtered list; then "Software, ports and
    services" with counts and links to the host's lists.
  - **The host's lists** (`/hosts/{id}/software|ports|services`,
    `HostSubPage.tsx`): the panel's Software, Ports and Services tabs at
    full width (software filtered on the server by name and "Fix
    available", 200 at a time), with links between the three.
  - **The host filter:** Alarms, Compliance and Vulnerabilities take
    `host=ID` (`views/lists/HostChip.tsx`), shown as a removable chip
    "Host: web-01 ×" and sent as `agent_id` (alarms) or `host`
    (vulnerabilities); Compliance reads `/compliance/groups?agent_id=`,
    that host's findings by rule with its own triage (Include resolved,
    Reopen and bulk close work as usual). Bulk actions then name the host
    (`agent_id`), so they touch it alone. The Compliance tile and "Show all
    n" add `window=all`, so the view asks for every current finding of the
    host (`since` 1970, allowed with `agent_id` only) and a host silent for
    days lists what the tile counts; removing the chip drops both. The page counts what these lists
    show by default: open-triaged alarms, checks and advisories, and
    vulnerabilities mapped at confidence 80 or more; the Hosts list's
    failing count is open-triaged checks too, and its critical count the
    critical advisories as the page counts them.
  **Last test** shows when the host last raised the harmless test alarm
  and test finding (`openvibes-test alarm|finding`, from `last_test` in
  the summary), with both commands; test alarms and findings carry a
  Test badge in the lists (`views/lists/testRules.ts`).
  **Threat alarms** reads "On (eBPF)" or "On (audit)", or "Off: why", "To
  fix: …", and, when there is one, the command in a wrapped code block with
  a copy button. The list, page and
  host export call `last_seen_at` **Last heartbeat**. Its hover text
  says agents send one about every minute and a host is online within three
  minutes of the last. Online and offline changes show up without a reload:
  `app/livePresence.ts` keeps `GET /api/v1/agents/events` open (a fetch marked
  background, so it does not extend the session) and refetches the agent
  views, the Hosts list and the host summaries (`PRESENCE_PREFIXES`:
  `/api/v1/agents`, `/api/v1/hosts`), at most every two seconds, when the
  server reports a change.

## Demo

- **Demo Hosts list** (`demo/routes/hostList.ts`): `GET /api/v1/hosts`
  with the same filters, per-value counts, summary, sort and paging, rows
  inside the persona's `hosts.read` reach and each problem count only where
  its permission `reaches`; groups from `demo/hostGroups.ts`, labels from
  the demo data, versions by `demo/versionOrder.ts` (the twin of
  `version_order.rs`, tested on the same table; its sort compares as SQL's
  int[] with unknown versions last either way) against the about/update
  route's `LATEST_AGENT_VERSION`. The same 400s for a bad value, a `q` over
  200 or a `label` over 64 characters; a `group` must have the demo's id
  shape (`grp-…`), standing in for the server's UUID check.

The demo's group pages count critical with the same `listedCritical`
(`demo/routes/groups.ts`), as the server's group pages read
`host_listed_critical`.

## Failure behaviour

- Rows, counts and the summary come only from hosts the viewer may read;
  each problem count is "—" where its read permission does not reach.
- A malformed or unreachable host address shows "No such host".
- If the agent's record fails, Rule sets says why and Export is not offered.
- A refused saved-view or column change is shown (an alert or a toast) and
  the server's copy stays.

## Upgrading

Saved views that searched by agent version (`q=0.4.2`) now match nothing:
the search covers host name, IP and agent ID. Re-save the view with the
Agent filter instead.

## How to test

- Unit: `views/investigate/Hosts.test.tsx`,
  `views/investigate/host/*.test.tsx`, `demo/routes/hostList.test.ts`,
  `demo/routes/hostSummary.test.ts`, `app/location.test.ts` (redirects).
- Demo e2e (`npm run test:e2e:demo`): `e2e/demo/hosts.spec.ts` (filters
  and the URL, saved views, columns, paging, keyboard) and
  `e2e/demo/host-page.spec.ts`.
- Live e2e (`scripts/test-console-e2e.sh`): `e2e/live/hosts.spec.ts`, a
  Linux team lead sees only the team's hosts and the counts agree with the
  rows, saves a view that is there after a reload, opens a host page with
  no Revoke (no `hosts.revoke`), and an Administrator's counts include both
  teams.
- Store: `crates/platform-store/tests/host_list.rs`, `host_summary.rs`.
