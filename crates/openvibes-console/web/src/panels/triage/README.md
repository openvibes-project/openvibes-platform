# panels/triage

The triage actions that alarms, compliance checks and vulnerabilities share (their pages are under `views/investigate/`).

| File | What it does |
|---|---|
| `TriageDetail.tsx` | `HistoryTab`: one item's triage changes (an alarm's page). |
| `BulkBar.tsx` | The triage actions (state, assignee, add to case) for selected rows or one item. |
| `bulk.ts` | Logic for a bulk action: request body, refusal checks, result sentence. |
| `triage.ts` | The triage form's fields in the shape the API wants. |

More: [docs/components/console-triage.md](../../../../../../docs/components/console-triage.md)
