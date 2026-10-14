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
matches a group when it carries every selector tag; a group without
selectors matches no host (as for access).

**Distribution.** `POST /v1/rule-bundle` answers `410 Gone` with no body for an
assignable set that is off on the asking host, checked after the 404 cases
(even when the agent is current); every other answer is unchanged.

**Store (`platform_store::rule_assignment`).** `overview` (sets, overrides,
whether a live bundle is published, every group), `set_default` and
`set_group` (`None` removes an override). A change writes one audit row
`rules.assignment.change` (actor, `rule_set_id`, `asset_group_id`,
`asset_group_name`, `old`, `new`; `null` for "default" or "no override");
setting the current value writes nothing.

`assigned(agent, set)` (distribution) and `for_agent(scope, agent)` (the
console's host view, `None` outside the caller's scope) share one SQL
resolution (`HOST_STATE`). A set that is not assignable is always
assigned. Grants: `openvibes-distribution` may read the two tables and only
`console_agent_tags (agent_id, tag_key, tag_value)` and
`console_asset_group_selectors (asset_group_id, tag_key, tag_value)`.

## Configuration

None: defaults come from the migration and are changed in the console.

## Failure behaviour

A database error is a 503 for the console caller; nothing is half written
(each change is one transaction).

## How to test

`eval "$(scripts/test-db.sh)"; cargo test -p platform-store --test rule_assignment`.
