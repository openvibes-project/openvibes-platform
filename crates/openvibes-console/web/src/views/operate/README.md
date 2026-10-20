# views/operate

Screens for working on rules and noise.

| File | What it does |
|---|---|
| `Coverage.tsx` | MITRE ATT&CK coverage of the rules: matrix and rule list. |
| `coverage.ts` | Logic for Coverage.tsx: matrix columns and filtering, unit-tested. |
| `SiteRules.tsx` | The site's own compliance and alarm rules (drafts). |
| `AlarmSuppressions.tsx` | Alarm suppressions with approvals (screen 14): By status, Recent changes, one card per status. |
| `SuppressionRow.tsx` | One suppression: chips, reason, would-close, badge and its actions (Approve, Reject…, Withdraw, Remove…, Ask again…). |

More: [docs/components/console-detection.md](../../../../../../docs/components/console-detection.md)
