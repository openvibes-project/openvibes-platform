# Console read models

`platform_store::console_read` supplies bounded, typed read queries for
the OpenVIBES web console. It contains all SQL for agent summaries and pages,
certificate metadata, latest and grouped findings, finding summaries, and retained finding
history. The console crate converts these records to its HTTP DTOs and applies
authentication and scope rules before calling them. The unscoped functions
are global read primitives. `agents_in_scope` and `agent_in_scope` enforce
agent visibility in SQL for the supplied global or host-group scope.

## Interfaces

- `agent_summary` and `finding_summary` each use one deliberate aggregate
  query; collection endpoints do not compute exact totals.
- `agents` uses a stable cursor over last-seen time descending, nulls last, and
  agent ID ascending. The state filter is allow-listed and stale state is
  computed against the supplied time.
- `AgentScope::AssetGroups` matches an agent that is a member of any
  authorized host group, read from the stored membership table
  `console_host_group_membership` (schema 61, kept by triggers to the rule
  of schema 53; see platform-store.md "Host groups"). Revoked and imported
  hosts are in no group. Empty group sets match no agents.
  `agent_summary_in_scope`, `agents_in_scope`, and `agent_in_scope` apply that
  predicate before aggregation, status filtering, cursor traversal, ordering,
  and limiting. Imported installations are excluded from host-group scopes
  until an association contract exists; global readers can see them.
  `agent_in_scope` hides out-of-scope IDs as absent.
- `certificates_in_scope` verifies the owning agent's scope in the same SQL
  query before paging certificate metadata. Out-of-scope agents return an
  empty page.
- `finding_summary_in_scope`, `latest_findings_in_scope`,
  `latest_finding_in_scope`, `finding_history_in_scope`, and
  `finding_event_in_scope` enforce the same membership predicate directly in
  SQL before aggregate, filter, cursor, and detail operations. Hidden detail
  rows are returned as absent. `finding_summary_in_scope` and
  `latest_findings_in_scope` leave ended findings (fixed) out, as the
  Compliance list does; the single-finding reads keep them. The authenticated console does not expose
  production data routes until these store functions are wired to permission
  checks.
- `finding_groups_in_scope` groups current snapshots by rule set and rule
  only after applying asset scope, leaves ended findings out of every
  count, and returns in-window endpoint counts,
  severity, version and triage rollups plus older endpoint counts.
  `finding_group_endpoints_in_scope` pages the visible endpoints (with each
  one's triage state, version, assignee username and accepted-until, and
  for a P13 agent `ended_at`/`end_approximate` once the match ended, ended
  rows included for the "fixed" badge) and
  hides a group with no recent in-scope endpoint. The authenticated console exposes
  opaque cursors bound to the time window and caller scope, and provides
  atomic endpoint triage through the companion `console_triage` store module.
  Imported installations remain global only until association is implemented.
- `agent` reads one agent. `certificates` pages certificate serial and
  validity metadata and never selects the stored PEM chain.
- `latest_findings` and `latest_finding` read the complete snapshot in
  `current_findings`, including host label and display fields. They do not
  join an event partition to render current state.
- `finding_history` requires a lower time bound for partition pruning and
  supports bounded exact agent, rule-set, and rule filters. `finding_event`
  uses the event table's `(observed_day, finding_id)` primary key.
- Finding detail returns its stored P17 detection explanation. Alarm and
  finding rule links resolve the historical signed bundle identified by the
  explanation's preimage hash; legacy rows without a hash are shown only when
  retained history identifies one unambiguous rule. The HTTP layer checks the
  same finding/alarm read permission and asset scope as the source record.
- Every list requires `PageLimit`, which accepts 1–100 rows, and fetches at
  most one extra row to decide whether to return a continuation cursor. The
  console serializes cursors and binds them to filters and authorization.
- The Hosts list (`host_list::hosts`, see platform-store.md) applies the
  same visibility predicate to its rows, total, per-value counts and
  summary, and gates each problem count by its own kind's scope, so no
  number or group or label value comes from a host out of reach.
- The Alarms list (`alarm_list::alarm_list`, see platform-store.md) reads
  its rows, total, per-value counts and summary only from agent alarms on
  hosts the `alarms.read` scope reaches, so no number or group, technique
  or person value comes from a host out of reach.
- `schema_is_current` is false for an empty, older, or newer schema; callers
  must keep readiness false and must not serve data unless it returns true.

## Configuration and failure behaviour

The functions use a `platform_store::Client` from the bounded pool. PostgreSQL
or query failures return the fixed `StoreError` categories. Invalid page sizes
cannot be represented as `PageLimit`. The module does not log query values,
apply user permissions, or expose raw SQL errors.

## How to test

```sh
eval "$(scripts/test-db.sh)"
cargo test --locked -p platform-store --test console_read -- --nocapture
```

The PostgreSQL acceptance test loads 50,000 agents, records the plans and
latency for the paged list and summary queries, and checks cursor traversal,
latest snapshots, and history partition keys.

## Acceptance measurement

The local PostgreSQL 18.6 throwaway-cluster run with 50,000 agents selected
`agents_console_last_seen_idx` for the ordered first page: 51 rows took
0.051 ms execution time with 54 shared buffers. Thirty client round trips for
the 50-row page measured p50 496 µs and p95 568 µs. The deliberate summary
aggregate used a sequential scan of 50,000 rows (758 shared buffers, 9.158 ms
execution); its thirty client round trips measured p50 6.910 ms and p95 7.527
ms. These are local warm-cache observations, not a deployment latency target.

Hosts list (2026-10-20, same cluster, run under `nice -n 19`): 20,000 agents,
20 groups (5 distribution and 5 host-name rule groups, 10 manual groups of
about 1,000 hosts), labels, alarms, vulnerability counts and failing checks
on a share of hosts. The default list (no filters, host order, 50 rows,
every count and the summary) measured a median of 744 ms over 7 runs
(735–776 ms); with failing checks counted by open triage and critical read
from `host_listed_critical` (Task 7 fix round 2), 872 ms (810–911 ms). Run it with
`cargo test -p platform-store --test host_list_timing -- --ignored --nocapture`;
it fails above 1 s. Through `console_host_in_group` per host and group the
same query took 9.0 s; group membership is therefore evaluated in one pass
with the inlinable `console_condition_holds_prepared`, and the version
functions are single expressions so they inline (a call per host cost
750 ms). Since schema 61 membership is stored (`console_host_group_membership`,
kept by triggers), so the list joins it instead of evaluating conditions.

Alarms list (2026-10-20, same cluster, run under `nice -n 19`): the same
20,000 agents and 20 groups with 200,000 agent alarms (ten per host over
six days, a third mitigated, rule metadata for some rules, 1,000 in a case,
a tenth of hosts reporting alarms off). The default list (open, not
suppressed, newest first, 50 rows, every count and the summary) measured a
median of 609 ms over 7 runs (597–625 ms) at full reach (120,000 matching),
and 219 ms (217–227 ms) scoped to two manual groups of about 1,000 hosts
each (10,956 matching). Run it with
`cargo test -p platform-store --test alarm_list_timing -- --ignored --nocapture`;
it fails above 1 s at full reach. The cost is the one materialised pass
over the alarms in reach (it spills past `work_mem` at this size) and the
group membership pass; the counts read a small cube, not the alarms.

Vulnerabilities list (2026-10-22, same cluster, `nice -n 19`, default
PostgreSQL settings, 2 parallel workers): the `docs/sizing.md` fleet
generated in SQL (10,000 Debian 12 hosts with 389 packages, 3.2 M fixable
pairs, 27.5 M pairs without a fix, 100 advisories with both a fixed and an
unfixed package, 1 % of open pairs triaged, ten manual and five rule
groups). The default list (open, by priority, 50 rows, every count and
the summary) measured a median of 1.90 s over 5 runs (1.86–1.95 s) at full
reach (4,382 rows, 10,000 hosts) and 1.53 s (1.47–1.55 s) scoped to two
manual groups. Run it with
`cargo test -p platform-store --test vuln_list_timing -- --ignored --nocapture`;
it fails above 2 s. The cost is two parallel passes, the fixable pairs
joined to the hosts in reach (about 0.85 s) and the per-host package
fingerprints (about 0.45 s), plus about 0.3 s taking the 180,000 unfixed
fixable pairs of the 100 mixed advisories out of the no-fix counts (0.45 s
before their advisory ids were sorted bytewise). The margin is small: a
fleet with more mixed advisories, or a busier host, can pass 2 s. Before
the stored group membership the same list took 12.7 s.

A vulnerability's page (2026-10-23, same fleet and settings, plus a
kernel: `linux` on every host, CVE-2026-90000 fixable on all 10,000 and
1,999 more `linux` advisories without a fix, so Related's same-package
count walks 2,000 candidates): the summary (header, tiles, what to do,
details, history, related with alarms and cases) measured a median of
175 ms over 5 runs (173–199 ms) at full reach and 40 ms (40–42 ms) scoped
to two manual groups. Run it with
`cargo test -p platform-store --test vuln_list_timing records_cve_page_summary_latency_for_a_kernel_cve -- --ignored --nocapture`;
it fails above 2 s. The same-package candidates need no narrowing to the
releases in reach at this size.

Compliance list (2026-10-24, same cluster and settings; see
[console-compliance.md](console-compliance.md)): the step 5c
ruling 18 fleet generated in SQL (10,000 hosts with heartbeat health
running baseline and hardening-linux-l1, 85 indexed rules, 500,000 current
findings, 50 per host, 1 % triaged, 1 % of hosts with stale health and 1 %
with baseline not assigned, ten manual groups). The default list (open, by
severity, 50 rows, every count and the summary) measured a median of
753 ms over 5 runs (741–842 ms) at full reach (85 rows, 10,000 hosts) and
266 ms (257–267 ms) scoped to two manual groups. Run it with
`cargo test -p platform-store --test check_list_timing -- --ignored --nocapture --test-threads=1`
(each test seeds its own fleet); it fails above 2 s. The cost is one serial pass over the findings joined
to the hosts in reach and hashed per check, severity and host class
(about 0.4 s), working out each host's rule sets, versions and collectors
(about 0.1 s), and the summary's per-host probe for an open failing pair
(about 0.15 s). Without the extended statistics on (rule set, rule,
severity) the planner expected 170,000 groups, sorted the 500,000 rows on
disk and took 1.5 s; grouping by the varbit mask did the same (0.9 s
before the blocking rule), and listing passing hosts pair by pair
instead of counting them per class took 4.7 s.

A check's page (2026-10-24, same fleet): the summary of `baseline/port.r20`
(failing on 5,870 hosts; its area, Network exposure, holds 41 other checks
and about 250,000 failing findings, which Same area reads through
`console_check_area`) measured a median of 1.08 s over 5 runs
(1.08–1.11 s) at full reach and 453 ms scoped to two manual groups (578
failing hosts); the same file's `records_check_page_latency_on_the_ruling_18_fleet`
fails above 2 s.
