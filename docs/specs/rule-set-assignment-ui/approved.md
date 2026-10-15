# Rule-set assignment: approved console screens

Spec: `../2026-10-14-rule-set-assignment-design.md` §6. All eight screens
were approved by the user on 2026-10-15 ("LGTM").

The mockups are real console pages, captured from the demo build, with the
new parts edited in. To regenerate them:

```sh
python3 gen.py base OUT_DIR
```

`base/` holds the captured page HTML, the demo build's stylesheet and the
brand files. Each page's caption bar says what was clicked.

1. **Settings › Rule sets list.** The two hardening sets are rows, and a new
   **Runs on** column sits before State:
   - baseline: "All hosts"
   - baseline-alarms: "Linux"
   - hardening-linux-l1: "Linux · 1 group off"
   - hardening-linux-l2: "Off · 1 group on"
   - site: "Hosts that trust its key"

   The form is the default (Linux, or Off) plus the number of groups that
   differ from it. An unpublished set shows "—" for version, signer and
   expiry, and its State is the plain badge **Not published**. Rule-set
   names never wrap.
2. **Rule-set panel, hardening-linux-l1.** The header, then key-value rows
   (Signed by, Expires, Source "OpenVIBES rules package (43 checks,
   Level 1)"). Then a new section **Where it runs**, inside the panel body:
   - The Switch "On for Linux hosts by default".
   - "Runs on **N** Linux hosts · off on **M**."
   - A compact table of group overrides: Group, Matches (selector tags),
     Hosts (number), Runs. The Runs column holds a switch and an ×
     (remove: that group follows the default again).
   - A small **+ Add group** button.
   - One explanation line: "A host runs it when any of its groups has it
     on; otherwise when the default is on. Hosts follow on their next scan.
     Switching it off ends that host's findings from this set (their triage
     stays)."

   Published versions follow, as today.
3. **Rule-set panel, hardening-linux-l2 (not published).** The badge reads
   **Not published**. A bordered note reads: "**Not available yet.** This
   platform has no L2 set yet: it comes with a later rules package.
   Switches you set now are kept and apply when it is published." The
   switches can be set. With no overrides, the panel says "No group differs
   from the default." There is no Published versions section.
4. **+ Add group.** It adds an inline row to the overrides table:
   - a group select, offering only groups not listed yet;
   - the group's selector tags and host count;
   - a Segmented control On | Off, with the opposite of the default
     preselected;
   - the buttons **Add** (primary) and **Cancel**.
5. **Added.** The row joins the table. The console toast reads
   "hardening-linux-l2 is now on for Lab", and the change is audited
   (`rules.assignment.change`).
6. **Host panel › Details.** A new key-value row **Hardening** sits after
   Threat alarms, for example "L1 off (Production) · L2 off". The group in
   brackets is the reason when a group decides it. In the Rule sets
   section, a set the host reports `not_assigned` shows the plain badge
   **Not assigned** and the subtle text "off for <group>".
7. **Lab host.** The Hardening row reads "L1 on · L2 on (Lab) · waits until
   published" for a set switched on but not published. Between a switch and
   the host's next scan the line says **pending** for that set.
8. **Root facts missing.** Under the Hardening row, a full-width warning
   badge **Hardening facts unavailable** is followed by: "The agent's
   root-facts helper has not reported for N days
   (openvibes-agent-facts.timer), so checks that read root-only files show
   as unavailable, not failed."
