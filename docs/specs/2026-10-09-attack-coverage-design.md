# MITRE ATT&CK mapping and coverage

Decision (user, 2026-10-09): every rule maps to MITRE ATT&CK, and the
console shows which tactics and techniques the platform's rules cover.
Answers: ATT&CK IDs on the rule, kill chain derived from the tactic; all
rules (baseline findings, baseline alarms, the site's own rules); a matrix
above a rule list, with a kill-chain toggle.

## 1. Wire: an optional `attack` field on a rule (protocol first)

```json
{"id":"alarm.web_server.shell", "...": "...",
 "attack":[{"tactic":"TA0002","technique":"T1059.004"},
           {"tactic":"TA0001","technique":"T1190"}]}
```

- `attack`: optional array, 1–16 items. Each item has `tactic`
  (`^TA[0-9]{4}$`, required) and `technique` (`^T[0-9]{4}(\.[0-9]{3})?$`,
  optional: a rule may claim a tactic without a technique). Pairs, not two
  lists, because one technique can sit under several tactics (T1078 is in
  four) and the rule means one of them.
- No duplicates; order is the author's (first = primary).
- Allowed on both `snapshot` and `process_event` rules.
- It is signed with the rule like every other field.
- **Compatibility, checked 2026-10-09:** the agent's `Rule` struct does not
  deny unknown fields, and its budgeted parser walks unknown fields within
  the same limits. `rules-check` and `alarms-check`, pinned at the oldest
  supported agent, passed with the field on every rule. Old agents ignore
  it, so no agent release and no envelope change.
- `openvibes-core` (agent repository) gains
  `attack: Option<Vec<AttackRef>>` with `skip_serializing_if`. This is
  needed even though agents ignore the field: the platform stores drafts as
  `openvibes_core::Rule` JSON, and an older struct would drop `attack` on
  the round trip. The platform moves its pin in the same change.

## 2. ATT&CK reference data

- Ship one ATT&CK Enterprise release as a small generated JSON file in the
  platform (`crates/openvibes-console/data/attack-enterprise.json`): tactics
  (id, name, matrix order) and techniques (id, name, tactic ids,
  deprecated/revoked flag). A script builds it from MITRE's
  `enterprise-attack` STIX bundle at a pinned version; no fetch at run
  time (offline installs work).
- Platforms: Linux, Windows and macOS techniques are kept; the matrix can
  filter by platform later (rule sets per OS, decision 2026-10-09).
- Attribution as MITRE's terms of use require, in the console's About text
  and the data file's README.
- Unknown or revoked IDs are not an error in the console: they show as the
  raw ID with "not in ATT&CK vX". `rules-check`, `alarms-check` and the
  console's draft validation refuse unknown IDs at authoring time, so
  signed sets stay clean.

## 3. Kill chain, derived

One fixed table in the console, from ATT&CK tactic to Lockheed Martin
Cyber Kill Chain phase:

| Kill-chain phase | ATT&CK tactics |
|---|---|
| Reconnaissance | Reconnaissance (TA0043) |
| Weaponization | Resource Development (TA0042) |
| Delivery | Initial Access (TA0001) |
| Exploitation | Execution (TA0002) |
| Installation | Persistence (TA0003), Privilege Escalation (TA0004), Defense Evasion (TA0005) |
| Command and Control | Command and Control (TA0011) |
| Actions on Objectives | Credential Access (TA0006), Discovery (TA0007), Lateral Movement (TA0008), Collection (TA0009), Exfiltration (TA0010), Impact (TA0040) |

Rules never carry a kill-chain phase themselves, so the two views cannot
disagree.

## 4. Platform

- **Source of rules.** Published bundles (`rule_bundles`, current version
  per set, parsed once and cached per bundle digest) plus the site's drafts,
  marked as drafts. A retired set is left out.
- **API.** `GET /api/v1/rules/coverage` (permission `rules.read`):
  `{attack_version, tactics:[{id,name,phase}], rules:[{rule_set_id,
  rule_id, title, kind, severity, draft, attack:[{tactic, technique,
  technique_name}]}]}`. The browser builds the matrix and the counts from
  it; at 512 rules per set there is no need for server-side aggregation.
  OpenAPI and the TypeScript client are regenerated.
- **Console page: Coverage** (under Rules).
  - Matrix: one column per tactic in ATT&CK order; cells are covered
    techniques with a rule count, sub-techniques under their parent.
    Uncovered tactics show an empty column, so gaps are visible. Clicking a
    cell filters the list below; a second click clears it.
  - Toggle ATT&CK | Kill chain: the kill-chain view groups the same cells
    into the seven phases of §3.
  - Filters: findings / alarms, rule set, include drafts.
  - Rule list (`DataTable`): rule, set, kind, severity, tactics,
    techniques; a row opens the rule.
  - Rules without a mapping are counted ("4 rules not mapped") and are one
    click from the list.
- **Elsewhere.** Alarm and finding details show the rule's techniques as
  chips linking to the Coverage page filtered to that technique. The rule
  editor (site rules) gets a picker: search by ID or name, pick a tactic
  for techniques that have several.
- **Assistant.** The coverage endpoint is read-only rule metadata and may be
  offered as an assistant lookup later; not in this change.

## 5. Rules repository

- Map all 41 baseline and 5 alarm rules. Exposure rules mostly map to
  Initial Access with T1190 (Exploit Public-Facing Application) or T1133
  (External Remote Services); remote-login services also map to Lateral
  Movement with T1021 (Remote Services). Each mapping is reviewed with the
  maintainer in the pull request.
- The checkers refuse an unknown or revoked ID (§2) and a malformed item.
  The ATT&CK data file is copied from the platform, like
  `sign-rpms.sh`.
- Mapping changes the signed bytes, so the next release re-signs (version
  4 if #12 ships as 3).

## 6. Order of work

1. Protocol: schema field, fixtures (one valid, invalid cases), PLAN entry.
2. Agent repository: `AttackRef` in `openvibes-core`, parser tests (field
   kept on round trip, and ignored by evaluation).
3. Rules: mappings plus checker validation.
4. Platform: move the pin, data file and generator, coverage endpoint,
   Coverage page, chips, editor picker, demo data, e2e.

## 7. Out of scope

Other frameworks (D3FEND, CAPEC, NIST CSF); ATT&CK for ICS or Mobile;
coverage weighted by data sources; automatic mapping suggestions.
