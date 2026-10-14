# Rule-set assignment: the project's sets reach every agent, switched per group

Date: 2026-10-14. Design decisions by the user, the same day. This
completes step 5 of `2026-10-09-hardening-rules-design.md`. That spec's
"the platform writes the choice into the agent configuration it serves"
(§4, §6) is replaced by the mechanism below; remote agent settings were
offered and not chosen.

## 1. Goal

Hardening L1 and L2 (and later sets of the project) run on the right hosts
with **no host-side step**: no `agent.toml` edit, no re-run of the install
line. An admin switches a set per asset group in the console; agents follow
on their next scan. Hosts enrolled before hardening existed get it by
updating the agent.

## 2. Decisions (user, 2026-10-14)

1. The agent package knows the project's own rule sets and their public
   keys. The platform decides per host which of them apply.
2. A host in several groups: **on wins**. Any group of the host with the
   set on turns it on.
3. **Both switchable.** Each assignable set has a default (L1 on, L2 off),
   and every group can override it either way.
4. A set switched off for a host **closes its open findings** there, with
   the note "rule set no longer assigned to this host" (history kept).
   Switching it back on finds them again on the next scan.

## 3. The agent: project sets (agent)

- The agent carries a fixed table, compiled in, of the project's sets:
  id, issuer, public key, OS family, and whether the set is
  **assignable**.

  | Set | OS family | Assignable |
  |---|---|---|
  | `baseline` | any | no |
  | `baseline-alarms` | Linux | no |
  | `hardening-linux-l1` | Linux | yes |
  | `hardening-linux-l2` | Linux | yes |

  The key is the project's offline rule key (`openvibes-1`), the one the
  rules repository signs every set with. A rotation ships in an agent
  release, which is how keys reach hosts out of band today.
- With a `distribution_url`, the agent adds every project set of its own
  OS family that `agent.toml` does not name. A `[[rule_sets]]` entry with
  the same id wins: its keys and `restricted` are used, never merged. With
  no platform, nothing is added (local-only agents keep exactly their
  configuration).
- `restricted` for an added set follows today's default: restricted,
  except `baseline-alarms`.
- **A set the platform does not publish is quiet.** For an added set, a
  `404` means "not offered here". The agent then runs nothing for it and
  raises no health problem: an older platform, or one without the rules
  package, sees no change. Configured sets keep today's behaviour.

## 4. Protocol P20: "not assigned"

- `POST /v1/rule-bundle` gains one answer: **`410 Gone`, no body**, which
  means this set is not assigned to this host.
- On `410` for an **assignable** project set, the agent:
  - stops evaluating the set;
  - deletes its stored bundle, so an expiry no longer keeps it alive;
  - reports it in health as `not_assigned`.

  It asks again on every scan, so switching the set back on takes effect
  on the next scan.
- A `410` for any other set (baseline, alarms, site sets, or a configured
  entry) is a refused answer, like any other `4xx`. A platform cannot
  silently remove the baseline.
- The health report's per-set state gains `not_assigned` (P12 extension).
- Fixtures cover both cases: an assignable set answered with `410`, and a
  `410` for a non-assignable set.

## 5. The platform

**Assignment** (store, migration):

- `rule_set_assignment` (set id, default on/off) holds a row per
  assignable set: `hardening-linux-l1` on, `hardening-linux-l2` off.
- `rule_set_group_assignment` (set id, asset group id, on/off) holds the
  group overrides. Deleting a group deletes its rows.
- A host's state for a set:
  1. on, if any group the host matches (tags match all selectors, as for
     access) says on;
  2. else off, if any of its groups says off;
  3. else the set's default.
- Changes are audited (`rules.assignment.change`) with who, the set, the
  group and the old and new value.

**Distribution:**

- The handler keeps the authenticated agent id, which it already gets and
  discards today.
- For an assignable set whose state for that host is off, it answers
  `410`. Every other path is unchanged.
- Its database role gains `SELECT` on the assignment tables, on
  `console_agent_tags` and on `console_asset_group_selectors` (read only).

**Findings close by themselves:**

- When an agent's heartbeat health reports a set as `not_assigned`, ingest
  closes that host's open findings from the set. They resolve with the
  note "rule set no longer assigned to this host" by the system actor, the
  same way other automatic closes are recorded.
- The agent's own report is the trigger, so findings close only when the
  host has really stopped running the set.

**Shipping and publishing:**

- The rules RPM installs `hardening-linux-l1.{json,key}` beside the
  baseline's files, and later L2's (rules repository).
- Setup and the rules package trigger (`helper rules-apply`) trust and
  publish every stem present: baseline, alarms, and then each hardening
  set, as today. A missing file is skipped, so L2 publishes once it exists.

## 6. The console

The screens go through full-screen mockups in the companion, key by key,
before the plan's console task.

- **Settings › Rule sets:** for each assignable set, its default and the
  groups that override it, each with an on/off switch. An unpublished set
  shows as "not available yet", for example L2 until the rules exist.
- **Host page:** one line reads "Hardening: L1 on · L2 off". It comes from
  the agent's per-set health:
  - a set waiting for the first scan shows "pending";
  - missing root facts show "Hardening facts unavailable" with the cause,
    as in the hardening spec.
- Compliance findings and Coverage need no change: they already filter
  and group by rule set.

## 7. Order of work

1. **Protocol P20:** the `410` answer, `not_assigned` in health, fixtures.
2. **Agent:** the project-set table, adding sets, a quiet `404` for added
   sets, `410` handling, health. This ships in the next agent release.
3. **Rules:** the RPM ships hardening L1, and its component page says it
   is signed.
4. **Platform:**
   - migration and store assignment;
   - distribution `410`;
   - ingest closing findings;
   - Setup and `rules-apply` publishing the hardening stems;
   - the console screens, after the mockups.
5. **Lab:** a Fedora and a Debian host with the new agent. Check:
   - L1 findings appear;
   - switching L1 off for the host's group gives `410`, health shows
     `not_assigned`, and the findings close;
   - switching it on brings them back;
   - an old agent is unaffected.

## 8. Out of scope

- The L2 rules themselves (rules repository, its own work).
- Site sets through this mechanism: they still need their pasted lines.
- Remote agent settings.
- Windows and macOS hardening.
- Per-host switches (groups only, as decided).
