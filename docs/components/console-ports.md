# console-ports (the Ports list and a port's page)

The console's Ports list (`/ports`, approved screen 19) and a port's page
(`/ports/{port}/{protocol}`, for example `/ports/22/tcp`, screen 20), from
roles step 5e (spec §10.3 and its "Plan rulings, 2026-10-25 (step 5e)", plan
`docs/superpowers/plans/2026-10-25-roles-5e-ports-pages.md`). One row and one
page per `(protocol, port)`, however many hosts listen on it. They are built
from the shared list and detail pieces in
[console-web.md](console-web.md#shared-list-and-detail-pieces), like the
Alarms, Vulnerabilities and Compliance pages, and read the
[change log](change-log.md).

## Interfaces

| Route | What | Code |
|---|---|---|
| `GET /api/v1/port-list` | the list: filters with counts, sorts, offset paging (`hosts.read`) | `src/ports/list_page.rs`; store `port_list*.rs` |
| `GET /api/v1/ports/{protocol}/{port}/summary` | the page above the Hosts card | `src/ports/page.rs`; store `port_summary.rs` |
| `GET /api/v1/ports/{protocol}/{port}/hosts?segment=&offset=&limit=` | the Hosts card (All, Exposed, Local only) | `src/ports/page.rs` |
| `GET /api/v1/ports`, `/ports/{protocol}/{port}` | unchanged, for the assistant and the host page | `src/hosts/ports.rs` |

Errors: `invalid_port` (400) for a bad protocol or port number;
`port_not_found` (404) when no host in reach listens and nothing in reach
changed it in 90 days. A port that went away from every host stays viewable
for 90 days with zero tiles. The server serves the page's address on a
direct load (`web/frontend-contract.json`).

Web: `views/investigate/Ports.tsx` (the list) and
`views/investigate/port/` (the page). The demo mirrors the routes in
`src/demo/routes/portList.ts` and `portPage.ts`.

## What a row and a page count

- A host counts once per port however many addresses it binds, and is
  exposed if any address is not loopback.
- **n of m:** n hosts in reach listen; m is the active hosts in reach that
  have sent a services report.
- **Needs a look** (first match first; a row carries every code): a
  database port exposed, a remote-admin port exposed, or a port outside the
  built-in map that appeared this week. SSH is not flagged. The map
  (`platform-store/src/port_names.rs`, about 40 ports) also supplies the
  usual name, use, the compliance area and the packages shown under Related.
- **This week:** hosts in reach that started (`appeared`) and stopped
  (`went_away`) listening in the last 7 days. Exposure flips show in Recent
  changes, not here.
- **Owner not collected:** hosts that do not send owner units (the agent's
  default) show "not collected" in the Service · program cells, the
  Services column and the Details card.
- **Related** is gated by permission: failing compliance checks for the
  port's area, open vulnerabilities in the port's packages, and open alarms
  from the listening program.
- **Actions:** Export (`hosts.export`) saves the hosts as CSV; Add to case
  (`cases.write` and `cases.read`); Ask about this (`assistant.use`, when
  the assistant is on).

Everything is counted inside the caller's reach: a port listened on only
out of reach answers 404, and a port in and out of reach counts, names and
links only the hosts in reach.

## Cases

A port can be a case item (kind `port`, ref `tcp/22`, migration 0066). Like
software it is fleet-wide: no host of its own, no outcome, visible inside a
case only to someone with a listening host in reach, and it never makes a
case visible by itself. The Cases list counts them in a `ports` count. See
[console-cases.md](console-cases.md).

## Failure behaviour

The Hosts card shows its own error without hiding the rest of the page.

## How to test

- Store: `cargo test -p platform-store --test port_list --test
  port_summary --test console_cases --test case_list_scope`.
- Console: `cargo test -p openvibes-console --test port_list_http --test
  port_page_http`.
- Web: `npm test` (`Ports.test.tsx`, `port/PortPage.test.tsx`, the demo
  route tests) and, in `web/`, `npx playwright test -c
  playwright.demo.config.ts e2e/demo/port-list.spec.ts
  e2e/demo/port-page.spec.ts`.
- Real console: `scripts/test-console-e2e.sh e2e/live/ports.spec.ts` (a
  team lead sees only their hosts' ports, the counts match the rows, This
  week and Recent changes, no Export, add to case, old links).
- Timing: `cargo test --release -p platform-store --test port_list_timing --
  --ignored --nocapture`. At 10,000 hosts with 20 listeners each (about
  300 ports) the unfiltered list answers in 0.9 s at full reach, 0.4 s for
  one group's reach (about 500 hosts); the limit is 2 s.
