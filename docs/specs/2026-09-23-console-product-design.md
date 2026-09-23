# OpenVIBES Console Product Design

Status: draft for review, 2026-09-23. Technical companion:
[`2026-09-23-console-technical-design.md`](2026-09-23-console-technical-design.md).

## 1. Product Position

The console is a quiet, high-density operational workspace for security and
platform teams. It should help a person answer three questions quickly:

1. What needs attention?
2. Which hosts and observations are involved?
3. What trust-changing action is safe to take?

It is not a generic analytics dashboard, an incident-management product, or a
replacement for the organisation's monitoring system. The first release is
desktop-first, responsive to tablet width, and intentionally read-heavy.

The product must never imply more certainty than the platform has:

- `current_findings` means the latest observation for an agent/rule pair. It
  does not prove that the condition is still present. The UI says **Latest
  observed matches**, never "open," "active," "resolved," or "remediated."
- `last_seen_at` supports **Seen recently**, **Offline**, **Never seen**, and
  **Revoked**. It does not support "Healthy" until agent health reporting
  exists.
- No observed matches is not proof of compliance or absence of vulnerability.
- Evidence currently names fact keys, not captured fact values or a forensic
  snapshot.
- Rule-set assignment is local to each agent, so the platform must not claim
  to know which agents are evaluating a bundle.

## 2. People and Jobs

| Persona | Primary jobs | First-release needs |
|---|---|---|
| Security analyst | Find serious recent matches, narrow the set, inspect evidence and provenance, pivot among observation, agent, and rule | Overview, findings, agent context; no trust-changing access needed |
| Platform operator | Understand fleet contact state, enroll or revoke agents, publish signed bundles | Agents, enrollment, rule sets, deliberate confirmations |
| Security administrator | Decide which local users may see or change what, later bind IdP groups, and review privileged activity | Access control and audit log |
| Read-only auditor | Establish who authenticated or changed trust state and when | Immutable audit presentation and scoped read access |

Built-in Viewer, Analyst, Operator, and Admin roles align with these jobs.
Custom roles remain possible, but product pages describe capabilities rather
than role names because custom roles can combine them differently.

## 3. Information Architecture

Navigation follows operator tasks rather than internal service boundaries:

```text
Overview

Investigate
├── Findings
└── Agents

Operate
├── Enrollment
└── Rule sets

Administration
├── Access control
└── Audit log

User menu
├── Session and account
└── Sign out
```

When a user has more than one authorised asset-group scope, a scope selector
appears in the top bar. Scope is a server-enforced authorisation boundary, not
a browser-only filter. It is hidden until tags and asset groups really exist.

Filters, stable sort, selected scope, and active tab belong in the URL. The
current pagination cursor may also appear there for back/forward navigation,
but is bound to the current authorisation context and is omitted by Copy view.
A copied view therefore shares the query, not a caller-specific position.

## 4. First-Release Page Inventory

| Page | Purpose | Principal permission |
|---|---|---|
| Sign in and password change | Local username/password first; OIDC, SAML, and MFA are later adapters | Public/session |
| Overview | Permission-aware fleet and observation summary | Each panel is independently gated |
| Findings list | Browse latest observed matches and bounded history; filter by triage state and assignee | `findings.read` |
| Finding detail | Exact observation, provenance, and first-release analyst triage | `findings.read`; triage uses `findings.triage` |
| Agents list | Browse Seen recently, Offline, Never seen, and Revoked agents | `agents.read` |
| Agent detail | Identity, contact, versions, certificate metadata, latest observed matches | `agents.read`; revoke uses `agents.revoke` |
| Enrollment tokens | List safe metadata; create and revoke tokens | `tokens.read`, `tokens.create`, `tokens.revoke` |
| Rule sets | Browse signed bundle versions, issuer, validity, and expiry | `rules.read` |
| Rule upload preview | Verify an already signed envelope before publication | `rules.upload` |
| Access control | Roles, user/group bindings, scopes, effective access | `rbac.read`, `rbac.manage` |
| Service accounts | Create/disable API identities and issue/revoke expiring tokens | `service_accounts.read`, `service_accounts.manage` |
| Audit log | Search authentication and privileged-action events; show the effective retention policy | `audit.read`; policy changes use `audit.retention.manage` |

Explicitly excluded from the first release: deployment-package builder,
correlation/incidents, CMDB, inventory explorer, remediation workflow,
report builder, custom dashboards, bulk agent revocation, web-based rule trust
key or CA key management, and mobile administration.

A System Status page waits for a reliable service-health contract. A failed
console database request is not a monitoring system.

## 5. Core Workflows

### 5.1 Investigate a serious observation

1. The analyst signs in with a locally managed username and password.
2. Overview shows critical latest observations in the effective scope.
3. The analyst opens Findings with the relevant filters already applied.
4. They refine by severity, confidence, last-observed window, rule, agent,
   origin, or authentication state.
5. Detail shows the message, exact times, evidence keys, rule version, scan ID,
   and provenance.
6. The analyst pivots to the related agent or rule set.

Finding detail always includes: "This is the latest observed match, not a
remediation status."

Online observations link to their enrolled agent. Imported observations may
have no `agent_id`; those show the unauthenticated `install_id`, optional
hostname, import provenance, and no dead agent link. Imported installations
are visible only to a globally authorised findings reader until a later,
audited association contract exists.

### 5.2 Investigate and revoke a silent agent

1. The operator opens Agents filtered to Offline.
2. They search using an operator label or tags when those are available.
3. Detail shows last contact, enrollment, scanner version, capabilities,
   certificate validity, and latest observed matches.
4. If compromise or decommissioning is confirmed, they choose Revoke.
5. A confirmation explains the impact and requires typing `REVOKE`.
6. Success appears only after the database change and audit event commit.

The impact text says that the agent receives `identity_revoked` on its next
request and needs a new enrollment token to re-enroll.

### 5.3 Enroll a host

1. The operator opens Enrollment and chooses Create token.
2. They enter a human label and accept the safe single-use, short-expiry
   defaults unless policy permits something else.
3. They review expiry and maximum uses, then create the token.
4. The plaintext secret appears exactly once with a Copy action.
5. The operator confirms that it has been stored before dismissing the result.
6. The list later changes from unused to used and links to the new agent.

The secret never reappears in lists, detail, audit, logs, browser history, or
an error message. If the first successful response is lost, retry reports that
the token exists but its secret is unavailable; the operator revokes it and
creates a new one.

### 5.4 Publish an offline-signed rule bundle

1. The operator selects a signed envelope.
2. The server validates size, signature, trusted issuer, rule-set identity,
   monotonic version, digest, and validity window.
3. A preview compares current and proposed version, issuer, digest, creation,
   and expiry.
4. The operator confirms publication.
5. The audited result identifies the stored version.

The UI says: "OpenVIBES stores this signed envelope; it does not sign or alter
it." Private signing keys never enter the platform.

### 5.5 Grant scoped access

1. The administrator chooses a local user. A later OIDC/SAML release may also
   expose a stable IdP group identity.
2. They bind a built-in or custom role.
3. They choose whole-platform or an asset-group scope.
4. The UI summarises effective permissions and the assets the scope selects.
5. The administrator confirms and receives the committed audit event.

There is no optimistic or client-only access state. Scope changes are trust
changes and take effect only after the server commits them.

### 5.6 Change agent tags

1. A globally authorised administrator opens the agent's Access tags panel.
2. They add or remove an exact `key=value` tag.
3. The server previews which asset groups and bindings would gain or lose the
   agent under the proposed tag set.
4. The administrator reviews the authorisation impact and confirms.
5. Tag change, affected-membership audit detail, and the success event commit
   together.

Tag editing is not ordinary asset metadata editing: it changes who can access
the agent and its observations. The first release implements this exact-tag
workflow and its authorisation-impact preview. CMDB integration may automate
tag sources later without changing the access semantics.

### 5.7 Triage an observed match

Analyst triage is part of the first release. From finding detail, an authorised
analyst can change workflow state, assign an analyst, and add a bounded note.
The UI always separates the human workflow state from detector truth: a human
state never makes an observation "resolved" or proves the condition absent.

Every transition is audited and protected by `If-Match`; a stale page must
reload before overwriting another analyst's work. Section 13 defines the
approved states and re-observation behaviour.

### 5.8 Change audit retention

Audit events are retained for 365 days by default. A globally authorised
administrator can change the retention period from the Audit log page. The
review step shows the current and proposed cutoff and warns when a reduction
will make older events eligible for deletion. The change uses `If-Match`, is
itself audited, and does not synchronously delete rows in the web request.

## 6. Page Behaviour and Data Presentation

### 6.1 Overview

Overview is a short attention queue, not a wall of charts. Permission-gated
summary panels show:

- Seen recently, Offline, Never seen, and Revoked agent counts;
- latest observed matches by severity;
- items needing attention, such as critical observations, offline groups, or
  rule bundles nearing expiry;
- the exact data refresh time.

Cards link to the corresponding pre-filtered list. Missing permission removes
the panel rather than replacing its value with zero.

### 6.2 Lists and tables

All substantial lists use server-side filtering, sorting, and cursor
pagination. The browser never downloads 50,000 agents or retained finding
history to filter locally.

- Default page size: 50; bounded maximum: 100.
- Tables use ordinary semantic HTML, not a spreadsheet grid.
- The identifying column remains visible in a horizontally scrollable region
  at narrow widths; important columns are not silently hidden.
- Row names are links. Secondary actions live in a keyboard-operable menu.
- Relative time is paired with an exact, timezone-labelled timestamp.
- Imported, unauthenticated observations are explicitly marked.
- Free-text host search uses the indexed, optional OS-reported hostname from
  authenticated heartbeats and never falls back to an unbounded scan.

### 6.3 Destructive and trust-changing actions

Revoke, publish, binding changes, and secret creation use a review step. The
dialog names the object, consequence, required permission, and audit effect.
The control locks after submission, and the result must say whether the server
committed the action. Stale or unavailable preconditions disable the action.

Bulk revocation is deliberately absent from the first release.

## 7. Loading, Empty, Error, and Stale States

| State | Required behaviour |
|---|---|
| First load | Shape-matched skeletons; never fake zero counts; affected region has `aria-busy` |
| Background refresh | Keep the last successful content visible and show a quiet Updating indicator |
| Empty installation | Explain what is absent and offer a permission-gated next action such as Create enrollment token |
| Empty filter result | Preserve filters and offer Clear filters; do not show onboarding copy |
| No findings | Say "No matches observed in this scope and time range," never "No vulnerabilities" or "Compliant" |
| Partial failure | Keep successful panels; failed panel shows Retry and a non-sensitive request ID |
| Initial error | Plain language, Retry, last-known timestamp when available, and request ID; no database or secret detail |
| Stale data | Keep last successful data and show its timestamp; distinguish console staleness from old agent contact |
| Session expired | Preserve only the safe destination route; never retain a secret or trust-changing form value |
| Unauthorised route | Name the missing capability without revealing out-of-scope object existence |
| Mid-session permission loss | Server response wins; show 403 without optimistic success |
| Mutation failure | Retain context and make commit state unambiguous; prevent duplicate submission |

An object outside a caller's asset scope appears not found rather than
confirming that it exists.

## 8. Accessibility Acceptance Criteria

Target WCAG 2.2 AA.

- Complete keyboard operation, visible focus, skip link, landmarks, logical
  headings, and correct focus return after dialogs.
- Dialogs have accessible names, describe consequences, and trap focus.
- Severity, connectivity, origin, authentication, and token states use text
  and icons; colour is supplementary.
- Tables retain native semantics, labelled filters, announced sorting, a
  textual page result such as "50 shown, more available," and
  keyboard-accessible row actions. Exact totals appear only when a dedicated
  bounded summary supplies them.
- Minimum 4.5:1 body-text contrast and 3:1 component/focus contrast.
- Usable at 200% zoom, tablet width, forced colours, and reduced motion.
- Auto-refresh never steals focus or floods screen-reader live regions.
- Session-expiry warning is perceivable and keyboard operable.
- Any future chart has an equivalent table or textual summary.
- Password validation, change, recovery guidance, and lockout messaging work
  without mouse, colour, or timing assumptions. Later TOTP/WebAuthn flows meet
  the same requirement.

Automated accessibility checks are necessary but do not replace keyboard and
screen-reader review.

## 9. Visual Language

The intended tone is a **quiet command centre**:

- neutral slate/charcoal structure, warm off-white surfaces, one restrained
  brand accent, and semantic colours reserved for meaning;
- no neon "cybersecurity" styling, gradients, decorative threat maps, or
  oversized vanity metrics;
- dense but breathable tables on an 8 px spacing grid;
- system sans-serif for content; monospace only for IDs, versions, hashes,
  certificate serials, and other machine identifiers;
- tabular numerals for counts and timestamps;
- separate icon vocabularies for severity and contact state so Offline is not
  visually confused with Critical.

Suggested severity treatment, always paired with text and an icon:

| Severity | Colour direction | Icon direction |
|---|---|---|
| Critical | burgundy | stop/octagon |
| High | red-orange | warning triangle |
| Medium | amber | diamond |
| Low | blue | down marker |
| Informational | neutral grey | information circle |

Light presentation is sufficient for the first release. Design tokens should
make an accessible dark theme possible later without delaying behaviour.
Fonts, icons, scripts, and styles are served locally; there are no runtime CDN
dependencies.

## 10. Low-Fidelity Wireframes

### Overview

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ OpenVIBES     Scope: Production ▾     Refreshed 10:42:18     A. User ▾ │
├─────────────┬────────────────────────────────────────────────────────────┤
│ Overview    │ OVERVIEW                                      [Refresh]   │
│             │ ┌───────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐  │
│ Findings    │ │Agents 18k │ │Offline 37│ │Revoked 12│ │Never seen 4 │  │
│ Agents      │ └───────────┘ └──────────┘ └──────────┘ └─────────────┘  │
│             │                                                          │
│ Enrollment  │ LATEST OBSERVED MATCHES                                  │
│ Rule sets   │ Critical 14  High 231  Medium 1,803  Low 4,112           │
│             │ Latest observed is not a remediation status.             │
│ Access      │                                                          │
│ Audit       │ ATTENTION                                                 │
│             │ Critical  SSH exposed · agent…91ad         4 min ago     │
│             │ Offline   19 agents in Stockholm          31 min ago     │
│             │ Expiring  baseline-linux v42               in 6 days     │
└─────────────┴────────────────────────────────────────────────────────────┘
```

### Findings

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ FINDINGS                                                   [Refresh]     │
│ Latest observed matches | History                                        │
│ Search [________________] Severity [All ▾] Last observed [24 hours ▾]    │
│ Origin [All ▾] Auth [All ▾]                             [Clear filters]  │
│                                                                          │
│ 50 shown · more available · Production scope           Sort: Recent ▾     │
│ ┌─────────┬────────────────────┬─────────────┬──────────┬──────┬────────┐ │
│ │Severity │Message / rule      │Agent        │Last seen │Conf. │Origin  │ │
│ ├─────────┼────────────────────┼─────────────┼──────────┼──────┼────────┤ │
│ │Critical │SSH exposed         │agent…91ad   │4 min ago │ 95%  │Online  │ │
│ │High     │Unexpected process  │agent…0e12   │11 min ago│ 82%  │Import* │ │
│ └─────────┴────────────────────┴─────────────┴──────────┴──────┴────────┘ │
│ * Imported observations are unauthenticated.              [Next page →] │
└──────────────────────────────────────────────────────────────────────────┘
```

### Agent detail

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ Agents / agent.7b2…91ad                                                  │
│ agent.7b2…91ad                       [Seen recently]         [Revoke…]  │
│                                                                          │
│ Last contact  4 min ago      Enrolled       2026-08-17                  │
│ Scanner       0.4.0          Capabilities   findings, heartbeat         │
│ Certificate   expires Oct 14 Platform state Active                      │
│                                                                          │
│ Latest observed matches                                                 │
│ Critical  network.ssh.exposed       First Sep 21     Last 4 min ago     │
│ High      process.unexpected        First Sep 23     Last 8 min ago     │
│                                                                          │
│ Certificates                                                            │
│ 8f:2a:…:19       Issued Sep 14       Expires Oct 14       Current       │
└──────────────────────────────────────────────────────────────────────────┘
```

### One-time enrollment token

```text
┌────────────────────── Create enrollment token ───────────────────────────┐
│ Label          [Stockholm web-042____________________]                  │
│ Expires        [24 hours ▾]                                             │
│ Maximum uses   [1____]  Single use is the safest default.               │
│ This action is audited. The token will be shown once.                   │
│                                                [Cancel] [Create token]   │
└──────────────────────────────────────────────────────────────────────────┘

┌────────────────────────── Token created ─────────────────────────────────┐
│ Store this token now. It cannot be displayed again.                     │
│ [ ovt_•••••••••••••••••••••••••••••••••••••••••••• ] [Copy]         │
│ ☐ I have stored the token securely                         [Done]       │
└──────────────────────────────────────────────────────────────────────────┘
```

### Signed bundle verification

```text
┌──────────────────── Publish signed rule bundle ──────────────────────────┐
│ baseline-linux-v43.json                         [Verified signature ✓]   │
│                                                                          │
│                       Current                 Proposed                    │
│ Rule set              baseline-linux          baseline-linux             │
│ Version               42                      43                         │
│ Issuer                prod-rule-key-2         prod-rule-key-2            │
│ Expires               Sep 29                  Dec 22                     │
│ Digest                31ad…8ce                94bf…1a2                   │
│                                                                          │
│ OpenVIBES stores this envelope; it does not sign or alter it.            │
│                                                [Cancel] [Publish v43]    │
└──────────────────────────────────────────────────────────────────────────┘
```

## 11. Seeded Design Data

Frontend work begins with deterministic API-backed data sets, not hard-coded
component fixtures:

- empty installation;
- small mixed fleet containing every contact state, severity, origin, and
  permission;
- 50,000-agent scale data to prove server pagination and bounded rendering;
- stale and partially unavailable resources;
- Viewer, Analyst, Operator, scoped Operator, and Admin access;
- expired session and mid-session permission removal;
- invalid, expired, rollback, and valid signed-bundle previews.

Seed data must not invent production capabilities or fields the agreed API
does not have.

## 12. Product and Data Gaps

1. A UUID-only agent identity is unusable at 50,000 hosts. The heartbeat
   protocol now carries an optional OS-reported hostname as a spoofable
   operator label; PM3 must store/index its latest present value. Manual tags
   provide first-release asset grouping until CMDB integration exists.
2. `current_findings` records no match end. Analyst triage is approved for the
   first release; its approved human workflow states remain explicitly
   separate from detector truth and are defined in section 13.
3. Asset-group scope is planned but tag/group storage does not exist. Reserve
   the affordance; do not fake it in the browser.
4. Rule bundles and trusted keys are absent from migration 0001.
5. The existing `current_findings` row lacks the full observation fields
   needed by a useful detail view.
6. Evidence contains identifiers of supporting fact keys, not their values.

These gaps do not block the shell, seeded workflows, or read-model design.
They do bound what production wiring may honestly show.

## 13. Approved Triage State Contract

The first-release state model is:

```text
Open → Investigating → Mitigated
                    ├→ Accepted Risk (required expiry)
                    └→ False Positive (scoped to the current rule version)
```

- A new observation after **Mitigated** automatically returns to Open
  and records that it reopened.
- **Accepted Risk** remains until its required expiry, then returns to Open on
  the next observation.
- **False Positive** remains for the same rule version; a newer rule version
  returns to Open.
- Investigating stays assigned across new observations.
- Mitigated, Accepted Risk, and False Positive require a note. Every transition
  and assignment change is audited.

These are human workflow states only. None asserts that the underlying
condition has cleared.

## 14. Approved Audit Retention

The default audit retention is 365 days and is administrator-configurable.
The effective period and calculated cutoff are visible on the Audit log page.
Retention cleanup runs asynchronously in bounded maintenance batches; events
at or newer than the cutoff remain immutable. Audit export remains a separate
first-release decision.
