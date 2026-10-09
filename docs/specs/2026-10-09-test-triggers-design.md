# Test triggers for alarms and findings

Decision (user, 2026-10-09): a regular user can make their own host raise a
harmless alarm and a harmless finding to see that the whole pipeline works,
like the EICAR test file for antivirus. The trigger exercises the real path
(kernel event or scan, agent, signed rule, delivery, ingest, console), so a
missing audit rule, an unloaded rule set or a delivery problem shows up as
"no test result".

## 1. `openvibes-test` (agent repository)

- A small separate binary in the agent package, `/usr/bin/openvibes-test`,
  mode 0755, runnable by any user. It reads nothing and writes nothing but
  its own output; it never talks to the agent or the platform. The agent
  still never spawns processes (`std::process::Command` stays banned).
- The name is 14 bytes, under the kernel's 15-byte `comm` limit, so
  `process.names` and the alarm's `process.name` both see it in full.
- `openvibes-test alarm`: prints what to expect and exits 0. Its start is
  the process event.
  > Started the OpenVIBES test program. Within a few seconds the console
  > should show "OpenVIBES test alarm" for this host. Nothing there? Check
  > that alarms are on for this host (Host page, Health).
- `openvibes-test finding`: stays running so the next scan sees it, then
  exits on Ctrl-C, SIGTERM or after `--minutes` (default 120, at most 1440).
  It cannot read the agent's configuration (0640, agent group), so it
  cannot know when the next scan is; it says the default (hourly) and that
  the Host page shows the result. It sleeps, so it costs nothing.
- `openvibes-test --help`; unknown arguments exit 2.
- Windows and macOS: the same program, packaged when those agents are.

## 2. Test rules (rules repository)

- `baseline-alarms`: `alarm.openvibes.test`, severity `info`,
  confidence 100, `programs: ["openvibes-test"]`, expression
  `event['process.name'] == 'openvibes-test'`, message "The OpenVIBES
  test program ran; alarms work on this host."
- `baseline`: `test.openvibes.running`, severity `info`, confidence 100,
  `'openvibes-test' in facts['process.names']`, message "The OpenVIBES test
  program is running; findings work on this host." Uses only an allowlisted
  fact, so the oldest supported agent evaluates it.
- Both get test cases (match and near misses such as `openvibes-tester`)
  and no ATT&CK mapping (they cover nothing; the Coverage page leaves them
  out).
- Anyone can start a program named `openvibes-test`, which is the point; a
  user can therefore also raise info-level test events on purpose. They are
  harmless and clearly labelled (§3).

## 3. Platform

- **Which rules are tests.** A fixed list in the platform:
  (`baseline-alarms`, `alarm.openvibes.test`) and (`baseline`,
  `test.openvibes.running`). Only those exact pairs from the baseline sets
  count; an operator's own rule with the same id does not.
- **Auto-close.** Ingest stores a test alarm as `mitigated` with the
  note "Test: closed automatically", and a recurrence does not reopen it,
  so it never needs triage and stays out of the active list, the menu count
  and the dashboard (shown with "Include resolved"). A test finding is not
  closed through triage (that would fight the automatic reopen of P13
  matches): it ends by itself when `openvibes-test finding` stops. Both
  carry a Test badge in the lists.
- **Host page.** A "Last test" line: when the last test alarm and test
  finding arrived ("Alarm OK 2 min ago · Finding not seen yet"), with a
  one-line hint and the two commands to copy.
- **Retention.** Normal retention; "Last test" reads the newest row.

## 4. Order of work

1. Agent: the `openvibes-test` crate/binary, its packaging, docs page.
2. Rules: the two test rules and cases (next signed version).
3. Platform: test-rule list, ingest auto-close, filters and badge, Host
   page "Last test", demo data, e2e.

## 5. Out of scope

Triggering a test from the console (agents only pull; that needs an agent
command channel); tests for each individual rule (the console's rule test
against a host's facts already covers authoring).
