# console-services (the Services list and a service's page)

The console's Services list (`/services`, approved screen 21) and a
service's page (`/services/{unit}`, for example `/services/sshd.service`,
screen 22), from roles step 5f (spec §10.3 and its "Plan rulings,
2026-10-27 (step 5f)", plan
`docs/superpowers/plans/2026-10-27-roles-5f-services-pages.md`). One row and
one page per systemd unit, however many hosts run it. They are built from
the shared list and detail pieces in
[console-web.md](console-web.md#shared-list-and-detail-pieces), like the
[Ports pages](console-ports.md), and read the [change log](change-log.md).
The page replaces the old unit side panel.

## Interfaces

| Route | What | Code |
|---|---|---|
| `GET /api/v1/service-list` | the list: filters with counts, sorts, offset paging (`hosts.read`) | `src/services/list_page.rs`; store `service_list*.rs` |
| `GET /api/v1/services/{unit}/summary` | the page above the Hosts card | `src/services/page.rs`; store `service_summary.rs`, `service_related.rs` |
| `GET /api/v1/services/{unit}/hosts?segment=&offset=&limit=` | the Hosts card (All, Exposed, Runs as root) | `src/services/page.rs` |
| `GET /api/v1/services`, `/services/{unit}` | unchanged, for the assistant and the host page | `src/hosts/ports.rs` |

Errors: `invalid_unit` (400) for an empty or over-long (200) unit or one with
a control character; `service_not_found` (404) when no host in reach runs it
and nothing in reach changed it in 90 days. A unit that went away from every
host stays viewable for 90 days with zero tiles. The server serves the
page's address on a direct load (`web/frontend-contract.json`).

Web: `views/investigate/Services.tsx` (the list) and
`views/investigate/service/` (the page). The demo mirrors the routes in
`src/demo/routes/serviceList.ts` and `servicePage.ts`, over
`serviceData.ts` and `serviceNames.ts`.

## What a row and a page count

- A host counts once per unit. **n of m:** n hosts in reach run it; m is
  the active hosts in reach that have sent a services report.
- **Runs as:** root means `root`, `0`, `SYSTEM`, `LocalSystem` or `NT
  AUTHORITY\SYSTEM` (any case) on at least one host. A host that reports no
  user is not counted as root.
- **From a package, by name.** The agent does not say which package owns a
  unit's program, so a host has the unit from a package when it has an
  installed package named like the unit's base (lower case, `.service` and
  any `@instance` removed) or one of the map's packages for it. The page
  says "matched by name". An unusual package name shows "not from a package"
  for a packaged service; the fix is one entry in the map. Every `systemd-*` unit
  also counts as packaged when `systemd`, `systemd-udev` or `udev` is installed,
  and the map names the other stock root units (`getty@`, `smartd`,
  `accounts-daemon`, `mdmonitor`) so a stock host has no false flag.
- **Owns a port:** the listeners whose owner unit is this one. A host whose
  report leaves owners out can under-report ports ("not collected").
- **Needs a look** (first match first; a row carries every code): runs as
  root and not from a package; a database exposed to the network; remote
  admin exposed to the network; a unit outside the map that started this
  week. The map (`platform-store/src/service_names.rs`, about 45 units)
  also supplies the usual name and use, the class and the compliance area.
- **This week:** hosts in reach that started (`appeared`) and stopped
  (`went_away`) running it in the last 7 days.
- **Related** is gated by permission: failing compliance checks naming the
  unit or its area, open vulnerabilities in the matched packages, and open
  alarms from the unit's programs.
- **Actions:** Export (`hosts.export`) saves the hosts as CSV; Add to case
  (`cases.write` and `cases.read`). There is no Ask about this: the
  assistant has no lookup by unit.

Everything is counted inside the caller's reach: a unit run only out of
reach answers 404, and a unit in and out of reach counts, names and links
only the hosts in reach.

## Cases

A service can be a case item (kind `service`, ref the unit, migration 0067).
Like software and ports it is fleet-wide: no host of its own, no outcome,
visible inside a case only to someone with a host in reach running it, and
it never makes a case visible by itself. The Cases list counts them in a
`services` count. See [console-cases.md](console-cases.md).

## Old links

`nav.open({kind: "unit"})` and `?open=unit:…` open the page, with no panel
left; the `unit` panel and `UnitPanel.tsx` are gone. Views saved in this
browser under `openvibes.v2.views./services` are imported once. This week
and Recent changes start empty after the upgrade, as for ports.

## Failure behaviour

The Hosts card shows its own error without hiding the rest of the page.

## How to test

- Store: `cargo test -p platform-store --test service_list --test
  service_summary --test console_cases --test case_list_scope`.
- Console: `cargo test -p openvibes-console --test service_list_http --test
  service_page_http --test case_list_http`.
- Web: `npm test` (`Services.test.tsx`, `service/ServicePage.test.tsx`, the
  demo route tests) and, in `web/`, `npx playwright test -c
  playwright.demo.config.ts e2e/demo/service-list.spec.ts
  e2e/demo/service-page.spec.ts`.
- Real console: `scripts/test-console-e2e.sh e2e/live/services.spec.ts` (a
  team lead sees only their hosts' units, the counts match the rows, This
  week and Recent changes, no Export, add to case, old links).
- Timing: `cargo test --release -p platform-store --test
  service_list_timing -- --ignored --nocapture`. At 10,000 hosts running 30 units each (300,000 service rows, 150 units, 20 owned
  listeners per host, 2,000 packages per host for the name match, 500,000
  change-log rows) the unfiltered list answers in 3.3 s at full reach and
  1.8 s for one group's reach (about 500 hosts; searches and filters 2.3 to
  3.1 s at full reach). The plan's limit of 2 s holds for the scoped reach,
  not for the extreme full-reach fleet, which is far beyond a real one (the
  test fails above 5 s there). Three things made the difference: the package
  name match reaches `host_packages` through an index per matched package
  (a scan of 20 million rows took 15 s), the statement runs with JIT off (`SET LOCAL` in a
  transaction, so a dropped request cannot leak it; compiling cost more than
  running it), and the programs
  and users are read for the page's 50 rows only. A rollup table kept at
  ingest would be the next step if a real fleet needs it.
