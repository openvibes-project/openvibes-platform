# panels/alarms

The panel for one threat alarm.

| File | What it does |
|---|---|
| `AlarmPanel.tsx` | The alarm in the shared triage detail template: process, state, assignee, case, Suppress… or its waiting request with Withdraw. |
| `DetectionEvidence.tsx` | The evidence section: how the alarm was detected and its ATT&CK pairs. |
| `SuppressForm.tsx` | "Suppress…" and its form (screen 12): what, where, for and a required reason; Request when approval is on. `SuppressDialog` also serves "Ask again…" prefilled. |

More: [docs/components/console-detection.md](../../../../../../docs/components/console-detection.md)
