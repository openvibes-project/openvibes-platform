# panels/triage

The triage actions and detail layout that alarms, compliance findings and vulnerabilities share.

| File | What it does |
|---|---|
| `TriageDetail.tsx` | The one detail template: header actions, summary, tabs. |
| `BulkBar.tsx` | The triage actions (state, assignee, add to case) for selected rows or one item. |
| `bulk.ts` | Logic for a bulk action: request body, refusal checks, result sentence. |
| `triage.ts` | The triage form's fields in the shape the API wants. |

More: [docs/components/console-triage.md](../../../../../../docs/components/console-triage.md)
