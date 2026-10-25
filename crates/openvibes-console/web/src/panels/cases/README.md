# panels/cases

The pieces of cases other pages reuse: the control that puts items into a case, the case badges, and the case logic without React. A case itself is a page (approved screen 32): [views/investigate/case](../../views/investigate/case/README.md).

| File | What it does |
|---|---|
| `AddToCase.tsx` | The "Add to case" button on alarms, findings, vulnerabilities, hosts and software. |
| `CaseBadge.tsx` | Marks list rows that are in an open case; a case's status badge ("Closed · mitigated" on a case closed before step 5d). |
| `cases.ts` | Case logic without React: item kinds, list query, closing rules, request bodies. |

More: [docs/components/console-cases.md](../../../../../../docs/components/console-cases.md)
