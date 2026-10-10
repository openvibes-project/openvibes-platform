# Plan: bulk triage and one detail view (#237, #239, #240)

Spec: `docs/specs/2026-10-10-bulk-triage-design.md` (#243). **The user
approved the spec on 2026-10-10 and asked for it to be built for 0.2.7
before going to bed** (relayed by the release coordinator); this plan was
not reviewed by the user, by that request. Built in one branch,
`claude/bulk-triage`, by one Claude Code session: each task is implemented,
then reviewed against the spec and the task's checks before the next (no
subagents: the user has not asked for them), then the whole branch is
reviewed before the PR. One heavy build at a time on the host (shared with
openvibes-02).

## Tasks

**T1. Migration 0045 (`triage_v2`).**
- Alarms and finding triage: every `investigating` row becomes `open`
  (assignee, note and case links kept) with a history row ("investigating
  retired; cases replace it"); the state CHECKs drop `investigating`.
- `vulnerability_triage` (agent_id, advisory_id, state, assigned_to, note,
  accepted_until, version, updated_at/by, mitigated_at) and
  `vulnerability_triage_history`; permission `vulnerabilities.triage`
  (agent-scoped) to the roles that have `compliance.triage`; grants.
- Check: migration test (old states become open with history; the CHECK
  refuses `investigating`).

**T2. Store: one state model.** `transition_allowed` lets any state move to
any other; `investigating` refused everywhere (`fields_valid`, alarms,
filters such as `active` = `open` only); history and audit as today.
- Check: store tests for open→mitigated in one step, reopen, and the note
  rule (every close needs a note).

**T3. Store: vulnerability triage.** get/update for one host × advisory
(version-checked, as findings), the list and Overview counts treating
mitigated/accepted/false-positive as not open, a downgrade keeping only an
unexpired accepted risk or false positive.
- Check: store tests.

**T4. Store: bulk writes.** One function per kind taking up to 10,000
items: a state change (note required for closes, expiry for accepted
risk), or an assignee; scope enforced in SQL; items out of scope or gone
are skipped and returned with a reason; one history row per item and one
audit row per bulk action. Compliance and vulnerability items without a
host expand to every host in scope.
- Check: store tests (scope skip, expand, note refused, 10,001 refused).

**T5. Console API.** `POST /api/v1/{alarms,compliance,vulnerabilities}/bulk`
(`state:<s>`, `assign`, `case` with `case_id` or `new_case`, alarms
`suppress` per distinct rule and program); single vulnerability triage
endpoints; permissions (`cases.manage` for case actions); OpenAPI snapshot
and TS client.
- Check: HTTP tests (CSRF, permission, scope, skips, case exclusivity).

**T6. Selection in `DataTable`.** Checkbox column, shift-click range, `x`
on the cursor row, header box for the page, the "Select all N matching"
bar (up to 10,000), selection cleared when the filter changes.
- Check: unit tests (`table.test.ts`), #227 control rules (no native
  checkbox: the console's own control).

**T7. Bulk bar and dialogs.** One `BulkBar` (count, actions, Clear) and
`BulkDialog` (note required for closes, expiry for accept, assignee
`Select`, case `Select` with "New case…"); result toast with skips.
- Check: unit tests for the request body and the note rule.

**T8. The three lists.** Alarms, Compliance, Vulnerabilities use selection
and the bulk bar; `investigating` removed from chips, triage panels and
`triage.ts`; case badges on rows.

**T9. One detail template.** `TriageDetail`: summary (title, severity,
hosts, ATT&CK chips, what it checks, what to do), action buttons on every
open host, tabs Hosts | Evidence | History (`Segmented` on a phone).
FindingPanel and AdvisoryPanel (with vulnerability triage) use it with a
paged, selectable Hosts table that scrolls inside the panel; AlarmPanel
uses it with a Process tab.

**T10. Demo and e2e.** Demo server: bulk endpoints, vulnerability triage,
no `investigating`. Demo e2e: select several alarms and mitigate (note
required, refused without), select all matching, bulk add to a new case,
a finding's Hosts tab paged and not cut off, phone width. Live e2e: one
bulk mitigate against the real console.

**T11. Docs and gate.** Component docs (console, console-web,
platform-store), the testing.md gate, a whole-branch review, PR.
