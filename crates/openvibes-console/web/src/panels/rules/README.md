# panels/rules

Panels for rule sets and the site's own rules.

| File | What it does |
|---|---|
| `RuleSetPanel.tsx` | A rule set: its versions, where it runs, and publishing a bundle. |
| `WhereItRuns.tsx` | The "Where it runs" section: default switch and group overrides. |
| `ruleAssignment.ts` | Logic for WhereItRuns.tsx without React, unit-tested. |
| `SiteRulePanel.tsx` | One site rule: a form with a live check, saved as a draft. |

More: [docs/components/rule-set-assignment.md](../../../../../../docs/components/rule-set-assignment.md)
