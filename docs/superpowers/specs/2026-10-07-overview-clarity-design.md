# Overview clarity: three named kinds, trends over time

Status: approved in conversation 2026-10-07, waiting for written-spec review.
Mockups (local): `.superpowers/brainstorm/` in the workspace
(`overview-b-v2.html`, `graphs-v3.html`).

## 1. Problem

On a host with 4 critical/high vulnerabilities, the built-in Overview showed
"Open critical findings 0", "Open high findings 0" and "Needs attention: All
clear", while "Most exposed hosts" listed the host with "4 serious". Every
API call succeeded; the page mixes two data sets without naming them:

- the top tiles and the severity bar count rule results ("findings"), which
  the sidebar already calls **Compliance**;
- "Most exposed hosts" counts package vulnerabilities;
- "Needs attention" lists exploited vulnerabilities only, not serious ones.

There is also no way to see any count over time; the only graph (Trend)
follows a single compliance rule.

## 2. Goals

1. The console names exactly three kinds of problem, everywhere:
   **Alarms** (threat detection), **Vulnerabilities** (package CVEs),
   **Compliance findings** (a host failing a rule check). The bare word
   "finding(s)" disappears from the UI, the console API and permission IDs.
2. The Overview never says "0 critical" or "All clear" while a host has an
   open critical or high problem of any kind; every number says what it counts.
3. Counts can be seen over time: a small trend inside a Number tile, and a
   Graph widget. The built-in Overview shows 30-day trends for Active alarms,
   Critical, High and Exploited vulnerabilities.
4. Users build everything themselves: any count in the catalogue can be a
   number, a trend or a graph line.

Non-goals: renaming the agent-platform wire protocol, ingest, or the
`findings` / `current_findings` tables; rebuilding history from before the
upgrade.

## 3. Names, API and permissions (PR 1)

### 3.1 User-visible text

| Old | New |
|---|---|
| finding / findings (rule result) | compliance finding(s); "Compliance" where short (sidebar, chips, kind column) |
| Open critical findings / Open high findings | removed from the Overview (see §4); in the catalogue: "Open critical compliance findings" etc. |
| Open findings by severity | Compliance findings by severity |
| Exploited | Exploited vulnerabilities |
| Case item kind "Finding" | Compliance finding |
| Assistant dock intro, command palette placeholder, Cases texts, Compliance rules page, rule editor "Finding message", host panel "No findings" | same sentences with "compliance findings" |

### 3.2 Console API (clean rename, no aliases)

- Every `/api/v1/findings/...` route moves to `/api/v1/compliance/...` with the
  same request and response shapes: `summary`, `groups`,
  `groups/{rule_set_id}/{rule_id}/endpoints`, `.../triage`, `latest`,
  `latest/{agent_id}/{rule_set_id}/{rule_id}[...]` and its triage, `history`,
  `history/{observed_day}/{finding_id}`. Old paths return 404.
- Problem codes and OpenAPI tags that say `finding` move to `compliance`
  (e.g. `finding_not_found` → `compliance_finding_not_found`).
- OpenAPI snapshot (`docs/api/console-v1.openapi.json`), generated TS client,
  demo server (`web/src/demo`) and `docs/components/*.md` change in the same PR.
- Release notes state that scripts calling the old paths must be updated.

### 3.3 Permissions and stored data (one migration)

- `findings.read` → `compliance.read`, `findings.triage` → `compliance.triage`:
  insert the new IDs into `console_permissions`, rewrite
  `console_role_permissions` and every other column that stores permission IDs
  (service-account and API-token grants; the plan lists each one), delete the
  old IDs. Seeded role lists (`seeded.rs`, web `navigation`/`registry`) change.
- Saved dashboards: in `console_dashboards.layout`, metric IDs
  `findings.open.<sev>` → `compliance.open.<sev>`, breakdown source
  `findings` → `compliance`, attention kind `findings` → `compliance`.
- Case items: kind `finding` → `compliance_finding` (CHECK constraint updated).
- The audit log is not rewritten: old entries keep their old action names.

## 4. The Overview (PR 3)

Same widgets and look as today; what changes is what they count and say.
Layout (12-column grid, top to bottom):

1. Four Number tiles, each with a 30-day smooth trend (§6.2):
   - **Active alarms**.
   - **Critical** = active critical alarms + open critical vulnerabilities +
     open critical compliance findings. Fine print under the number:
     "0 alarms · 1 vulnerability · 0 compliance"; each part opens its list with
     `severity=critical`.
   - **High**: the same for high.
   - **Exploited vulnerabilities**.
   Units are each page's own row: one alarm, one host-advisory pair, one
   host-rule pair, so a tile always equals the sum of what its links open.
2. **Needs attention** (7 columns): adds open critical and high
   vulnerabilities. Each row starts with its kind (Alarm / Vulnerability /
   Compliance). Order: critical alarms, exploited vulnerabilities, other
   critical, high, stale hosts.
3. Right column: **Vulnerabilities by severity**, **Compliance findings by
   severity** (two breakdowns), then **Most exposed hosts** counting all
   kinds per host ("4 serious · 7 open"), with fine print "all kinds".
4. Fleet row unchanged: online, stale, need a reboot.

After the upgrade, trends show "Collecting since <date>" until two days exist.

## 5. History (PR 2)

### 5.1 Storage

New table `host_daily_counts`, one row per host per day:

```
day date, agent_id text, status text (active|stale|revoked),
alarms_critical, alarms_high, alarms_medium, alarms_low, alarms_info int,
vulns_critical, vulns_high, vulns_medium, vulns_low int,
vulns_exploited, vulns_no_fix int, needs_reboot boolean,
compliance_critical, compliance_high, compliance_medium, compliance_low int,
PRIMARY KEY (day, agent_id)
```

"Active alarm", "open vulnerability" and "open compliance finding" use the
same definitions as the current summaries; `alarms.active` sums all five
alarm columns, matching the alarm list (info alarms included). Per-host rows are what make
history respect asset-group scope: a scoped user's series sums only hosts
they can see, as the lists do.

### 5.2 Writing

`openvibes-admin maintenance` (the existing daily timer) records each host's
counts as they are when it runs, under that run's date; re-running the same
day replaces that day's rows. A missed day stays a gap (past states cannot be
recomputed). It
deletes rows older than `--history-days` (default 400, range 30–3650).
Size: about 80–100 MB per 1,000 hosts per year (measured), so about 1 GB
at 10,000 hosts and the 400-day default.

### 5.3 Reading

`GET /api/v1/metrics/history?metric=<id>&days=<7|30|90|365>` returns
`{ metric, points: [{ day, value }] }` for days that have rows; today's point
is computed live from current counts, so a trend ends at the tile's number.
Permission: the metric's own read permission; scope: the caller's asset
groups. Days before the first snapshot are absent, never zero.

## 6. Widgets and customisation (PR 3)

### 6.1 Count catalogue

One list (server and web) used by Number, Graph and the history API:

| Group | IDs |
|---|---|
| Cross-kind | `all.open.critical`, `all.open.high` |
| Alarms | `alarms.active`, `alarms.active.<sev>` |
| Vulnerabilities | `vulns.open.<sev>`, `vulns.exploited`, `vulns.no_fix`, `vulns.reboot_hosts` |
| Compliance | `compliance.open.<sev>` |
| Hosts | `agents.active`, `agents.stale`, `agents.revoked` |

`<sev>` is critical, high, medium or low. Each entry has a label, a
permission (cross-kind entries need all three read permissions; a role
missing one sees "Not available with your role") and the list it opens.

### 6.2 Number widget

New settings: trend off / 7 / 30 / 90 days (default off; on, 30 days, on
the built-in Overview), line style smooth (default) / stepped. With a trend:
the change since the start of the period beside the number. Cross-kind
counts show the per-kind fine print.

### 6.3 Graph widget (new type `graph`)

Settings: 1–4 counts, period 7 / 30 / 90 / 365 days, line style, optional
title. One y-axis (all counts), whole-number ticks, recessive grid, dates on
the x-axis, a dot on today's value, hover crosshair with every line's value,
a table view for screen readers. One line: accent colour, no legend. Two or
more: legend plus end-of-line labels, colours from a fixed categorical
order (validated with the dataviz palette script, light and dark).
Severity colours are not used for lines.

Smooth = monotone cubic interpolation (Fritsch-Carlson): never above the
largest or below the smallest neighbouring value, so never below 0.
Stepped = step-after.

### 6.4 Other widgets

- Breakdown sources: alarms, vulnerabilities, compliance, hosts.
- Needs attention kinds: alarms, exploited vulnerabilities, serious
  vulnerabilities (new), compliance, stale hosts.
- Most exposed hosts: count all kinds (default) or vulnerabilities only.
- The server allow-list (`dashboards.rs`) validates the new type and settings.

## 7. Failure behaviour

- History endpoint with an unknown metric or period: 422 with field errors.
- No snapshot rows yet: empty `points`; the tile shows "Collecting since …".
- Maintenance failing to write snapshots: logged, exit non-zero, Health
  shows the maintenance unit failed (existing behaviour); graphs show a gap.
- A widget referring to a count the user cannot read: "Not available with
  your role", as today.

## 8. Testing

- Store: snapshot values against seeded alarms/vulnerabilities/compliance
  rows; re-run idempotent; retention delete; scope sums.
- Console API: history permission and asset-group scope; renamed routes;
  old routes 404; migration rewrites permissions, dashboards, case items.
- Web unit: monotone curve bounds; catalogue labels; settings validation.
- Playwright (demo and live): Overview tiles and fine-print links, Needs
  attention kinds, graph editor, hover values, table view.
- Local gate (`testing.md` §2) for each PR; Fedora job (§3) for PR 2, which
  changes maintenance.

## 9. Delivery

1. PR 1: rename (UI, API, permissions, migration, docs).
2. PR 2: history table, maintenance snapshot, history API.
3. PR 3: catalogue, Number trend, Graph widget, Overview, other widgets.

PR 3 depends on 1 and 2; 1 and 2 are independent.
