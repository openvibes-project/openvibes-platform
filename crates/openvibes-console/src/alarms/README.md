# src/alarms

Alarms in the console: the alarm list, one alarm with its process tree and triage, suppressions, and the detection evidence behind alarms and findings. Bulk triage (`/v1/alarms/bulk`) lives with the other triage code in `compliance/bulk.rs`.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules, the public names of its types, and `routes()`: the paths this area serves. |
| `alarm.rs` | Threat alarms: list, one alarm with its process tree, triage. |
| `list.rs` | `GET /v1/alarm-list`: the Alarms list's parameters, validation and the call into the store. |
| `list_types.rs` | The Alarms list answer: rows, per-value counts, the summary line. |
| `summary.rs` | `GET /v1/alarms/{id}/summary`: an alarm's page above the fold, with each action by its permission on the alarm's host. |
| `summary_types.rs` | The alarm page answer: the alarm, tiles, rule text, commands seen, hourly starts, Related, `can`. |
| `suppressions.rs` | Alarm suppressions: list, the suppress form's options, a new request. |
| `suppression_decisions.rs` | Approve, reject, withdraw and remove a suppression. |
| `suppression_types.rs` | The suppression bodies and view with the caller's `can_*` flags, and the refusal each store outcome maps to. |
| `detection.rs` | A finding's or alarm's original detection inputs and rule. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
