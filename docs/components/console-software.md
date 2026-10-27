# console-software (the Software list and a package's page)

The console's Software list (`/software`, approved screen 23) and a
package's page (`/software/{name}`, for example `/software/openssl`,
screen 24), from roles step 5g (spec §10.3 and its "Plan rulings,
2026-10-27 (step 5g)", plan
`docs/superpowers/plans/2026-10-27-roles-5g-software-pages.md`). One row
and one page per package name, rpm and dpkg together, however many hosts
have it. They are built from the shared list and detail pieces in
[console-web.md](console-web.md#shared-list-and-detail-pieces), like the
[Ports](console-ports.md) and [Services](console-services.md) pages, and
read the [change log](change-log.md). The page replaces the old package
side panel.

## Interfaces

| Route | What | Code |
|---|---|---|
| `GET /api/v1/software-list` | the list: filters with counts, sorts, offset paging (`hosts.read`) | `src/software_pages/list_page.rs`; store `software_list.rs`, `software_list_sql.rs` |
| `GET /api/v1/software-pages/{name}/summary` | the page above the Hosts card | `src/software_pages/page.rs`; store `software_summary.rs` |
| `GET /api/v1/software-pages/{name}/hosts?segment=&offset=&limit=` | the Hosts card (All, Need an update, Up to date) | `src/software_pages/page.rs` |
| `GET /api/v1/software`, `/software/{manager}/{name}` | unchanged, for the API | `src/hosts/software.rs` |

Errors: `invalid_package` (400) for an empty or over-long (200) name or one
with a control character; `package_not_found` (404) when no host in reach
has it and nothing in reach changed it in 90 days. A package that went away
from every host stays viewable for 90 days with zero tiles. The server
serves the page's address on a direct load (`web/frontend-contract.json`).

Web: `views/investigate/Software.tsx` (the list) and
`views/investigate/software/` (the page). The demo mirrors the routes in
`src/demo/routes/softwareList.ts` and `softwarePage.ts`, over
`softwareData.ts`.

## What a row and a page count

- A host counts once per name, even when it holds two versions. **n of m:**
  n hosts in reach have it; m is the active hosts in reach that have sent a
  package report. A version is `(epoch, version, release)`.
- **Versions:** the oldest to the newest in use, with digit runs compared as
  numbers (`10.1` after `9.9`), the epoch first. A range for reading, not a
  distribution's own comparison.
- **Vulnerabilities:** the open advisories of the package, counted as the
  Vulnerabilities list's defaults count them (open or expired accepted
  risk, not a lower-confidence match), from the hosts' fixable pairs and
  from the no-fix advisories of the versions in use that are written for
  the OS release of a host holding that version. Worst severity,
  count, and Exploited (a KEV or EUVD flag on a CVE).
- **Fix:** "Update on n hosts" counts hosts with an open fixable advisory
  not waiting for a reboot; "No fix yet" when an open advisory has none.
- **Used by:** the services that run from the package, by name (the unit's
  base or the service map's packages), most hosts first.
- **This week:** hosts in reach with the package new, updated (a
  `went_away` and an `appeared` at the same instant) or removed in the last
  7 days; a host that installed and removed it counts in none.
- **Group chips** show the hosts the group has in reach, not packages.
- **The Hosts card** gives each host its versions, "Update to x" (the newest
  fixed version of its open fixable advisories) or "Up to date", and the
  services using it. Advisory facts need `hosts.read` only, as the host
  page's package list shows them.
- **Actions:** Export (`hosts.export`) saves the hosts as CSV, one row per
  host and version; Add to case (`cases.write` and `cases.read`). There is
  no Ask about this.

Everything is counted inside the caller's reach: a package only out of
reach answers 404, and one in and out of reach counts, names and links only
the hosts in reach.

## Cases

A package can be a case item (kind `software`, ref the bare name; no
migration, the kind has existed since 5d). Older items (`rpm/openssl`) keep
working: a ref without `/` is the package under every manager, one with
`manager/name` only that manager's. See [console-cases.md](console-cases.md).

## Old links

`nav.open({kind: "package"})` and `?open=package:rpm/openssl` open the page,
with no panel left; the `package` panel and `PackagePanel.tsx` are gone. Views
saved in this browser under `openvibes.v2.views./software` are imported once.
The old Fix available and Multiple versions chips are the Fix and Versions
filters.

## Failure behaviour

The Hosts card shows its own error without hiding the rest of the page.

## How to test

- Store: `cargo test -p platform-store --test software_list --test
  software_summary --test console_cases`.
- Console: `cargo test -p openvibes-console --test software_list_http --test
  software_page_http`.
- Web: `npm test` (`Software.test.tsx`, the demo route tests) and, in
  `web/`, `npx playwright test -c playwright.demo.config.ts
  e2e/demo/software-list.spec.ts e2e/demo/software-page.spec.ts`.
- Real console: `scripts/test-console-e2e.sh e2e/live/software.spec.ts` (a
  team lead sees only their hosts' packages, the counts match the rows, This
  week and Recent changes, no Export, add to case, old links).
- Timing: `cargo test --release -p platform-store --test
  software_list_timing -- --ignored --nocapture` (set
  `SOFTWARE_TIMING_PACKAGES=2000` for the extreme fleet). On the sizing fleet
  (10,000 hosts, 400 packages each out of 600 names, 2,000 advisories,
  500,000 change rows) the unfiltered list answers in 1.7 s at full reach,
  an exploited filter 1.6 s, a search 1.5 s, a group filter 1.8 s,
  fix available with several versions 2.2 s, one group's reach (about 500
  hosts) 1.2 s, and a sort by hosts 3.1 s. With a quarter of the hosts on
  another OS release (the no-fix advisories are matched to each host's
  release, so the links of the versions with a no-fix advisory are read) the
  unfiltered list takes 2.0 s and one group's reach 2.1 s. The target of 2 s holds
  for the default view and the scoped reach; a sort by hosts and the
  heaviest filters run past it. On the extreme fleet (2,000 packages on each
  host, 3,000 names, 20 million links) the unfiltered list takes 2.5 s and a
  sort by hosts 10.8 s (the test fails above 5 s on the sizing fleet).
  What made the difference: the host counts come from one grouped pass over
  `host_packages` that, for a reach of half the hosts or more, counts every
  host and takes away those outside the reach (a text-key join of 4 million
  links cost 2 s); the exact count of hosts for names with several versions
  (a host with two kernels counts once) is made for the 50 rows on the page,
  and for every name only when the sort is by hosts; the statement runs with
  JIT off. A stored host count kept at ingest is the next step (the board's
  wording) if a real fleet needs a fast sort by hosts.
