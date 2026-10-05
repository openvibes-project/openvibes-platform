# Developer setup

Work on the console's web interface and see each change in the browser as
you save it, next to a normal OpenVIBES install (or none).

The console frontend is a React app in `crates/openvibes-console/web`. In
development it runs on a Vite dev server with hot module replacement. It
does not touch an installed release: the dev server uses port 5174 and
never reads `/etc/openvibes`.

| | Installed release | Dev server |
|---|---|---|
| Console | 443 (or the port Setup chose) | 5174 |
| Agents | 18423, 18424 | not used |
| Config | `/etc/openvibes` | none (demo) or your own scratch files |

## Prerequisites

- Node.js 22.12 or newer and npm 10 or newer. (`scripts/build-console.sh`
  pins Node 22.23.1 exactly, but only the release build needs that.)
- For the live backend (below) also: the Rust toolchain from
  `rust-toolchain.toml` (rustup installs it on first `cargo` run) and the
  PostgreSQL server binaries (`initdb`, `pg_ctl`, `psql`).

## 1. Edit the interface with demo data

```sh
cd crates/openvibes-console/web
npm ci --ignore-scripts      # first time, and after package-lock.json changes
npm run dev                  # http://127.0.0.1:5174
```

Dev mode uses an in-browser demo backend (`src/demo/`) with synthetic data
and a persona switcher (viewer, analyst, operator, scoped operator, admin).
No database, console or login is needed. Saving a file updates the page,
usually without a reload; a refresh always shows the latest code.

Where things live:

| To change | Edit |
|---|---|
| The left rail | `src/shell/Chrome.tsx` (`Rail`) and its CSS in `src/styles/` |
| Which views and panels exist | `src/app/registry.tsx`: one entry per view, one per object kind |
| An inspector panel | `src/panels/` |
| A view | `src/views/` |
| Dashboards and widgets | `src/dashboards/` |
| Demo data | `src/demo/data.ts`, `src/demo/server.ts` |

A quick first change: add an entry to `registry.tsx` next to "Software" and
it appears in the rail on save. [`components/console-web.md`](components/console-web.md)
describes the structure and conventions.

Before committing, run what CI runs for the frontend:

```sh
npm run lint && npm run typecheck && npm test
npm run test:e2e:demo        # optional: browser tests against the demo build
```

Rules that bite:

- A new top-level browser route must also be listed in
  `web/frontend-contract.json`; the Rust router reads it, and
  `src/app/frontendContract.test.ts` fails until it matches.
- A new file in `web/public/` must be declared in the same contract's
  `publicAssets`.
- Lint runs with `--max-warnings 0`.

## 2. Edit the interface against a real backend

Use this when your change needs real API behaviour (permissions, data that
only a database holds). The dev server proxies `/api` and `/auth` to
`http://127.0.0.1:18490` (set `CONSOLE_URL` to change it). Add `?live=1`
to the dev URL to switch that browser tab from demo to live data
(`?demo=1` switches back).

> **Not yet walked through.** The steps follow the code and
> `scripts/console-e2e-server.sh`, but this path has not been run end to
> end. If sign-in fails, check `public_origin` and the session cookie first
> (see the notes below).

1. A scratch PostgreSQL, under `target/pg`, no root and no system service:

   ```sh
   eval "$(scripts/test-db.sh)"      # exports OPENVIBES_TEST_DATABASE_URL
   psql "$OPENVIBES_TEST_DATABASE_URL" -c "CREATE DATABASE ov_dev"
   ```

2. Files for the console, in a directory you own (for example
   `target/dev/`; `target/` is ignored by git). Use your own database URL:
   the same URL as step 1 with the database name changed to `ov_dev`.

   `admin.toml`:

   ```toml
   database_url = "postgresql:///ov_dev?host=/ABS/PATH/target/pg/run&user=openvibes_test"
   ```

   `console.toml`:

   ```toml
   development_listen = "127.0.0.1:18490"
   health_listen = "127.0.0.1:18491"
   transport_mode = "development"
   database_url = "postgresql:///ov_dev?host=/ABS/PATH/target/pg/run&user=openvibes_test"
   public_origin = "http://127.0.0.1:5174"
   ```

3. Create the schema and a user:

   ```sh
   cargo run -p openvibes-admin -- --config target/dev/admin.toml migrate
   cargo run -p openvibes-admin -- --config target/dev/admin.toml \
     user create --username dev --display-name "Dev" --role admin --password-stdin
   ```

   `scripts/console-e2e-server.sh` also imports sample findings for six
   hosts (`admin import`); copy that part if you want data to look at.

4. Run the console and the dev server in two terminals:

   ```sh
   cargo run -p openvibes-console -- --config target/dev/console.toml
   cd crates/openvibes-console/web && npm run dev
   ```

   Open `http://127.0.0.1:5174/?live=1` and sign in as `dev`.

Notes:

- In `development` mode `public_origin` must be an `http://` loopback
  address. It is set to the dev server's origin because that is the origin
  the browser sends; this is the likeliest cause of a refused sign-in.
- The session cookie is `__Host-` prefixed. Chrome and Firefox accept it on
  a loopback `http://` address; Safari may not, so use Chrome or Firefox.
- Without `--features embedded-ui`, the console serves the API only. The
  interface comes from the dev server, which is what you want here, and no
  Node build is needed for the Rust side.

## 3. Changing the Rust side

The Rust crates have no hot reload. Rebuild and restart on save with
[`cargo-watch`](https://crates.io/crates/cargo-watch):

```sh
cargo install cargo-watch
cargo watch -x 'run -p openvibes-console -- --config target/dev/console.toml'
```

If you change an API response or request, regenerate the TypeScript client
and its snapshot (`npm run generate:api`, in `web/`) and commit both.
Migrations are append-only (see [`AGENTS.md`](../AGENTS.md)).

## 4. Building the embedded interface

Only needed for `--all-features` builds (workspace clippy, docs, tests),
the `embedded-ui` feature, or an RPM. Node must be exactly 22.23.1:

```sh
scripts/build-console.sh
```

It runs the API check, lint, typecheck, unit tests and `vite build`, writes
the build stamp, and builds the release binary. `build.rs` stops with a
message if `web/dist` is missing or stale. The full browser suite against
the real console is `scripts/test-console-e2e.sh`.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Blank page or "not reachable" in live mode | the console is not running on `CONSOLE_URL`, or you are still in demo mode (add `?live=1`) |
| Sign-in rejected | `public_origin` does not match the dev server's origin, or the browser refused the `__Host-` cookie |
| `frontend contract validation failed` from cargo | a route or public file was added without updating `web/frontend-contract.json` |
| `embedded-ui frontend validation failed` | run `scripts/build-console.sh` |
| Port 5174 or 18490 already in use | another dev server or console is running; stop it or change the port |
