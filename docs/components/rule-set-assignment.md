# Rule-set assignment

Which of the project's assignable rule sets run on which hosts, switched per
asset group in the console with no host-side step. Spec:
[`../specs/2026-10-14-rule-set-assignment-design.md`](../specs/2026-10-14-rule-set-assignment-design.md).

## Purpose

Agents know the project's sets and ask for every one of their OS family
(protocol P20). The platform answers per host: a set that is off for the host
gets `410 Gone`, the agent stops running it and reports `not_assigned`, and
ingest ends its open matches there (triage untouched, one history entry
saying why).

## Interfaces

**Tables (schema 49).** `rule_set_assignment` has one row per assignable set
with its default: `hardening-linux-l1` on, `hardening-linux-l2` off (the row
exists before the rules are published). `rule_set_group_assignment` holds
on/off overrides per asset group; deleting a group deletes its rows.

**A host's state for a set:** on if any group the host matches says on (on
wins); else off if any of its groups says off; else the default. A host
is in a group when `console_host_in_group` says so, as for access
(platform-store.md "Host groups").

**Distribution.** `POST /v1/rule-bundle` answers `410 Gone` with no body for an
assignable set that is off on the asking host, checked after the 404 cases
(even when the agent is current); every other answer is unchanged.

**Ingest.** The note is written on the transition: a heartbeat whose
health lists an assignable set with `state: not_assigned` (P20) when the
agent's stored report did not (`platform_store::finding_changes::end_unassigned`,
called before ingest stores the report, under the agent's row lock, one
transaction). It ends this host's still-open matches of that set, as when the
host stops matching, and writes one triage-history entry by `system` with
the note "rule set no longer assigned to this host", state unchanged, for
every match of (host, set) whose end the platform recorded since the stored
report (`current_findings.end_recorded_at >= agents.health_at`, both on the
platform's clock, so a skewed agent clock changes nothing) or here, whoever
ended it. In the real flow the agent ends them itself through P13 in the
scan that got the 410, just before the report (lab check 2026-10-14), so its
end times are kept. A match that ended earlier (the host was fixed) gets no
note, and no match gets it twice (a retried heartbeat whose report was not
stored). If this fails, ingest still records the host as seen
(`agent_presence`), answers 503 and does not store the report, so the
agent's next heartbeat finds the transition again. A set that is not assignable, an entry
without `state`, or a report that repeats `not_assigned` writes nothing. No
audit row, as for any match end. Triage (state, note, assignee, version)
never changes here (user decision 2026-10-14). The stored `match_sha256` is
unchanged when the platform ends matches, so if the heartbeat arrives before
the agent's own P13 end, the agent's next delta gets one `findings_resync`:
expected and harmless. `end_unassigned` also ends `source='scan'` rows
(scan-path agents; P20 agents use P13). Switching the set back on:
the agent's next scan starts the match again through the usual rules, as
for any finding that comes back. Schema 49 adds `current_findings.end_recorded_at`: set to the platform's
time wherever a match ends (P13 `ended`, replace and transient ends, and
here), cleared when it starts again; `NULL` for matches that ended before
schema 49. Grants: `openvibes-ingest` may read
`rule_set_assignment` and the key, `note` and `changed_at` columns of
`console_finding_triage_history` (it already updates `current_findings` and
writes triage history).

**Store (`platform_store::rule_assignment`).** `overview` (sets, overrides,
whether a live bundle is published, Linux hosts on and off per set, every
group with its Linux host count (`selectors` is empty since schema 53, until
the console shows a membership summary); a Linux host is an
active agent, stale included, revoked and imported not, whose inventory
reported os-release), `for_agent` (per set: state, the group that decided it,
the first by name when several agree, and whether the set is published),
`set_default` and `set_group` (`None` removes an override). A change writes one audit row
`rules.assignment.change` (actor: the console user's id, shown by display
name; `rule_set_id`, `asset_group_id`,
`asset_group_name`, `old`, `new`; `null` for "default" or "no override");
setting the current value writes nothing. `overview` counts with one CTE
(`FLEET`). `HOST_STATE` returns the host's on and off group ids, so
distribution never reads group names. `hardening_facts(agent)` reads the
outcome from `agents.health` and `agents.hardening_facts_ok_at` (schema 50).

`assigned(agent, set)` (distribution) and `for_agent(scope, agent)` (the
console's host view, `None` outside the caller's scope) share one SQL
resolution (`HOST_STATE`). A set that is not assignable is always
assigned. Grants: `openvibes-distribution` may read the two tables, the
group conditions and members, `console_asset_groups (asset_group_id, kind)`
and the agent facts membership uses; not labels or group names.

## Console API

All answers carry `Cache-Control: no-store`; errors are
`application/problem+json`.

| Method and path | Permission | Body | 200 response |
|---|---|---|---|
| `GET /api/v1/rule-set-assignments` | `rules.assignment.read` (global) | none | `RuleSetAssignmentsView` |
| `PUT /api/v1/rule-set-assignments/{rule_set_id}` | `rules.assignment.write` (global), CSRF | `{"default_enabled": bool}` | `RuleSetAssignmentView` |
| `PUT /api/v1/rule-set-assignments/{rule_set_id}/groups/{asset_group_id}` | `rules.assignment.write` (global), CSRF | `{"enabled": bool}` | `RuleSetAssignmentView` |
| `DELETE /api/v1/rule-set-assignments/{rule_set_id}/groups/{asset_group_id}` | `rules.assignment.write` (global), CSRF | none | `RuleSetAssignmentView` (idempotent) |
| `GET /api/v1/agents/{agent_id}/rule-set-assignments` | `hosts.read` (scoped) | none | `HostRuleSetAssignmentsView` |

Shapes: `RuleSetAssignmentsView { items: [RuleSetAssignmentView],
asset_groups: [{asset_group_id, name, selectors: [], hosts}] }` (`selectors`
empty since schema 53);
`RuleSetAssignmentView { rule_set_id, default_enabled, published, hosts_on,
hosts_off, groups: [{asset_group_id, name, enabled}] }`;
`HostRuleSetAssignmentsView { items: [{rule_set_id, enabled, source:
"default"|"group", group, published}], hardening_facts,
hardening_facts_ok_at }`. Host counts are
**Linux hosts**: active agents (stale included; revoked and imported not)
whose inventory reported os-release (`os_id`); `hosts` is how many a group
matches, `hosts_on`/`hosts_off` how many run the set or not. `group` names
the group that decided the host's state (the first by name when several
agree; `null` for the default). `hardening_facts` is the hardening
collector's outcome in the host's latest health report (`ok`, `not_found`
when the root-facts helper's file is stale or malformed, `invalid_data`),
`null` without one; the agent reports nothing when the helper's file is
missing. `hardening_facts_ok_at` is when a stored report last had it `ok`
(schema 50, set by ingest), `null` when none did since enrollment. `group`
is returned to every caller who may see the host, also when the group is
outside their scope (user, 2026-10-15). Errors: 400 `invalid_request` (bad body),
403 `permission_denied`, 404 `rule_set_not_assignable`,
`asset_group_not_found`, `agent_not_found`, 503.

Reading needs `rules.assignment.read` (operator, admin), changing
`rules.assignment.write`, all global; an analyst or viewer holds neither and
gets 403. The same check (`rules_reader`) guards `GET /api/v1/rule-sets` and
its bundle history with `rules.read`, and `GET /api/v1/rules/coverage` and
`GET /api/v1/attack` with `rules.coverage.read` (schema 51). The list carries every asset group, so an operator (without
`access.read`) can add an override; operators therefore see
every group's name. Writes are absolute values (no `If-Match`):
a repeated write changes nothing and is not audited. The audit row's actor
is the signed-in user's id. The host detail's `rule_sets[].state` (on `GET
/api/v1/agents/{agent_id}`) is the agent's own report (`not_assigned`, else
`null`); the host view above is the platform's decision. A test: `cargo test
-p openvibes-console --test rule_assignment_http`.

## Configuration

None: defaults come from the migration and are changed in the console.

## Failure behaviour

A database error is a 503 for the console caller; nothing is half written
(each change is one transaction). A change whose actor has no console user
writes no audit row, so it fails and rolls back (503): nothing changes
unaudited.

## How to test

`eval "$(scripts/test-db.sh)"; cargo test -p platform-store --test rule_assignment`.
`cargo test -p openvibes-console --test rule_assignment_http` covers the
console API (needs the same database).
`cargo test -p platform-store --test end_unassigned` covers the match end
(and pins the assignable sets to the protocol vector
`vectors/project-rule-sets.json`); `cargo test -p openvibes-ingest --test
assignment` covers the heartbeat path.

## Console screens

Approved 2026-10-15 (`../specs/rule-set-assignment-ui/approved.md`).
Settings › Rule sets shows the tab to holders of `rules.read`
(global). The list merges published sets with the assignable
ones, so L2 is listed before it is published ("—", **Not published**), and
its **Runs on** column reads the default (Linux, or Off) and how many groups
differ (`panels/rules/ruleAssignment.ts`). Operators see
the same list and panels as admins, and the Coverage menu entry (user,
2026-10-15). A set's panel adds **Where it runs** (`panels/rules/WhereItRuns.tsx`):
the default switch, "Runs on N Linux hosts · off on M" once published, the
group overrides (Group, Matches, Hosts, Runs: a switch and ×), "+ Add
group" (an inline row: a group not listed yet, On | Off with the opposite of
the default preselected, Add or Cancel; Esc cancels), and the explanation.
Switches show the server's state: a change waits for the answer, a failure
shows its error in a toast and leaves the switch as it was (a failed Add
keeps the row and its choice), and the list and host views are refetched
either way. Until that refetch lands the controls are `aria-disabled`, not
disabled, so focus stays on the control used, and presses are not sent
again; after Add or ×, focus moves to "+ Add group". Without `rules.assignment.write` the switches
are disabled and Add and × are hidden. The Source row's check count comes
from `GET /api/v1/rules/coverage`.
Toasts: "<set> is now on/off by default", "<set> is now on/off for
<group>", "<group> follows the default again"; errors show the API's title
("Asset group not found" when the group was deleted meanwhile). "+ Add
group" is disabled with "No asset groups yet: create one under Settings ›
Access." or "Every asset group is listed.".
`npm test -- src/panels/WhereItRuns.test.tsx src/app/registry.test.tsx`
covers the markup and the menu access; `e2e/demo/where-it-runs-focus.spec.ts`
the focus, single-send and failed-Add behaviour; clicks and toasts are in the e2e.

The host panel's Details (`panels/hosts/HostHardening.tsx`, Linux hosts only) add
a **Hardening** row after Threat alarms: per assignable set "L1 on" or
"off", the deciding group in brackets, "waits until published" for an on
set not published yet, and "pending" while the agent's latest report
disagrees with the platform's decision. No switch time is stored, so an
agent too old to know the project sets shows "pending" for L1 until it is
updated (controller ruling, 2026-10-15). A hardening collector outcome other
than `ok` adds the warning **Hardening facts unavailable** with its cause:
"has not reported for N days" (N from `hardening_facts_ok_at`, at least 1),
"has not reported since enrollment" when no report was ever `ok`, or "sent
invalid hardening facts" for `invalid_data`. In the Rule sets section, a set
the agent reports `not_assigned` shows **Not assigned** and "off for
<group>", or "off by default" when the default switched it off. Operators
with `rules.read` see the "behind" badge there.
