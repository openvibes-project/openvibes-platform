# Finding and alarm explanations

Status: proposed for user approval. Implementation has not started.

## User request

Open a finding or alarm, see exactly what was detected and why, and click
its rule to read the rule that caused it.

## Experience

1. Clicking a finding opens its existing grouped detail panel. Add a
   **What was found** section with a host selector and the selected host's
   saved observation: message, observation time, rule version, and evidence.
   A single affected host is selected automatically; multiple hosts require
   an explicit selection. Each host row also offers **View evidence**.
   Keep existing host navigation and triage actions.
2. Clicking an alarm opens its existing detail panel. Show **What was
   found** with its recorded process, command arguments, user/effective user,
   working directory, and ancestor tree. Mark masked or truncated data.
   Repeated alarms must identify the stored sample; a count does not imply
   that every contributing process start has been retained.
3. Both panels have a clickable rule name under **Why it triggered**.
   It opens a read-only nested rule panel and preserves the selected host,
   observation and navigation back to the result.
4. The rule panel shows rule ID, set ID, rule and set versions when known,
   description/message, severity, confidence, rule kind, applicable program
   restrictions, and the complete CEL condition in a selectable code block.
   Show the saved detection inputs alongside the condition, with raw
   structured evidence available in an expandable section.
5. Explain condition results from recorded evaluation data when available.
   Clearly distinguish true, false, unevaluated, and unavailable conditions.
   A referenced field alone is not proof that a branch caused the match.

Illustrative presentation (example data, not an existing observation):

```text
What was found
Host: lab-server       Observed: 5 October, 14:32
Matched value: TCP port 2375 is in the recorded listening-port list

Why it triggered
Rule: Docker API exposed [View rule]     Rule version: 2
Condition: 2375 in facts['net.tcp.listen_ports']
Result at detection: true
```

## Existing data and gaps

The current FindingPanel groups hosts and versions without displaying the
per-host evidence. The latest-finding API already exposes evidence strings,
message, rule version, scan ID, observation times and origin. These strings
are evidence identifiers, not retained fact values. The inspected agent
evaluator collects references during expression checking, including branches
which may be short-circuited during execution. Do not label those references
as matched values or a condition trace.

Alarm detail already stores the process and ancestors, rule version and
rule-set version. Masking means some original values cannot be recovered.
Inspect the current agent alarm aggregation semantics before labeling a
sample as the first or latest occurrence.

Published signed bundles are retained in platform storage. The console's
bundle API currently exposes metadata; a scoped rule-content read is needed.
Findings currently lack the rule-set version needed to select an exact bundle.

## Historical rule identity

For new detections, retain set ID, set version, rule ID, rule version, and
the signed bundle identity/hash carried by the agent. Resolve content from
that stored bundle, including retired or expired bundles. Show historical
status without treating today's expiry or trust status as a new detection.

Never silently substitute the current rule. For old findings, identify
candidates using the recorded set, rule and rule version. Only show content
as an unambiguous historical definition if all candidates agree; otherwise
say **Exact rule version unavailable**. Missing locally provisioned bundles
and imported findings also get an explicit unavailable state. The evidence
remains readable independently of rule availability.

## Recording evidence

Specify the additive wire contract in openvibes-protocol first, covering
snapshot findings, finding changes/resync, alarms, and offline exports.
Old senders remain accepted and old receivers retain existing behavior.

Capture bounded evidence during the original evaluation, before source
facts change. Include fact/event keys, relevant typed values or matching
list members, and enough condition results to explain the evaluated path.
For absence checks record the tested value, absence result and completeness
of the collection. Truncation must never turn a partial list into proof of
absence. Do not send an entire package/process inventory for each match.

Use explicit unavailable, masked and truncated markers. Preserve masking on
the agent and never transmit a secret merely to explain a match. A rule
using an unmasked value may consequently have an incomplete explanation.
Do not reconstruct historical evidence from today's host inventory or
re-evaluate masked arguments and present that as the original outcome.

Protocol design must set concrete per-record/field limits and explain how
evidence fits the existing batch/queue ceilings. Evidence collection shares
the existing evaluation budget; it must not change the detection result.
Compare memory, CPU and wire size against the existing agent budgets.

## API, storage and access

Add observation-bound rule/evidence reads to the console API. Authorize the
observation and host scope before resolving its rule. A reader authorized
to inspect a result can inspect that result's rule; this grants neither
editing rights nor access to unrelated rules or other hosts. Keep the
general rule catalog's existing permission boundary.

Persist evidence with the immutable observation and the latest finding
snapshot so retention of history does not strip the current result's
explanation. Preserve exact bundle identity. Alarms retain evidence for the
same sample as their displayed process tree. Errors, denied access, missing
records, and missing historical rule content have distinct UI states.

Read rule content on demand with bounded decoding and response sizes.
Render rule text and evidence as escaped text. Update OpenAPI, generated
TypeScript and demo fixtures together. Shared storage changes are separate
commits, following repository ownership and migration rules.

## Delivery and acceptance

1. Protocol/schema fixtures and bounded evidence design; confirm current
   pinned agent behavior before implementation.
2. Shared storage and historical rule lookup, then console detail panels.
   Existing records expose their available evidence with honest limitations.
3. Agent capture, transport and offline handling; integrate recorded inputs
   and condition explanations in the console. The request is complete only
   when fresh findings and alarms both explain the actual detection.

Acceptance checks include a port match, package match, absence condition,
short-circuited OR, process alarm, masked arguments, aggregation, multiple
hosts/versions, rule update/retirement, missing bundle, legacy data, import,
expired history, scope denial, and narrow-screen/keyboard navigation.
Verify a historical result still opens its original rule after publication
of a replacement and that unrelated host/rule content cannot be fetched.
Run the repository gates and browser checks before any implementation PR.
Update component documentation in each implementation change.
