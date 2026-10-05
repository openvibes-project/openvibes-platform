# console-about

The About page (`/about`) and its two read endpoints in `openvibes-console`.

## Interface

- `GET /api/v1/about`: platform version, the database schema version the
  build requires and the one applied, the PostgreSQL server version, and
  whether the web UI is embedded in this build. No migration; every value is
  already known to the process.
- `GET /api/v1/about/update`: whether a newer release is published.
  `state` is `disabled`, `unavailable`, `up_to_date` or `available`, with
  `latest_version` and `release_url` when known. Network problems are never an
  error response; they are `unavailable`.

Both need a signed-in browser session and no particular permission. Bearer
tokens are refused, as for dashboards.

## Update check

The console server, not the browser (the CSP allows only same-origin
requests), reads the latest non-draft, non-prerelease GitHub release of
`openvibes-project/openvibes-platform`. One request at a time, 4 second
timeout, response capped at 1 MiB, no redirects. A found release is cached
for 6 hours, a failure for 15 minutes. A tag must be plain `major.minor.patch`
(optionally with a leading `v`) and the release link must point into the
project's own repository, otherwise the result is `unavailable`.

Proxy settings come from the environment (`HTTPS_PROXY`). Set
`update_check = false` in the console configuration on hosts that must make
no outbound connections; the page then says the check is off.

## How to check

`cargo test -p openvibes-console about` (unit tests, including a loopback
server for the fetch and cache), `tests/about_http.rs` (needs the test
database), and `npx playwright test --config playwright.demo.config.ts
e2e/demo/about.spec.ts` in `crates/openvibes-console/web`.
