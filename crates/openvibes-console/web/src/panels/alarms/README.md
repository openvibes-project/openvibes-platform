# panels/alarms

Pieces an alarm's page (`views/investigate/alarm/`) and other places share. The alarm panel is gone: an alarm is a page (screen 30).

| File | What it does |
|---|---|
| `DetectionEvidence.tsx` | The evidence section: how an alarm or finding was detected and its ATT&CK pairs. |
| `SuppressForm.tsx` | "Suppress…" and its form (screen 12): what, where, for and a required reason; Request when approval is on. `SuppressDialog` also serves "Ask again…" prefilled. |

More: [docs/components/console-detection.md](../../../../../../docs/components/console-detection.md)
