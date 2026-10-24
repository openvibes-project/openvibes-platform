# views/investigate/check

A check's page (approved screen 28; roles spec §10.3, step 5c rulings 8-17), at `/compliance/{rule_set_id}/{rule_id}`: one rule of a rule set over its failing and passing hosts in reach. It replaces the old finding panel; old links (`?open=finding:SET/RULE`, `nav.open({kind: "finding"})` from dashboards, the host page, cases, the audit log, the palette and the assistant) come here, through `pagePath` in `app/location.ts`.

| File | What it does |
|---|---|
| `CheckPage.tsx` | The page: header (Set state, Assign and Add to case on the check's open failing hosts, Ask about this, ⋯ Export and Copy link), four tiles (failing on, passing, first seen, the last 14 days as bars); Export's CSV rows. |
| `CheckCards.tsx` | Why it matters, How to fix (else a link to the rule set), Details, History; Hosts (All, Failing, Passing; evidence as `fact = value` and the file; View evidence opens the observation and why it triggered; ticks on failing rows and a bulk bar on host and check pairs, Reopen included) and Related (port, service, same area). |

More: [docs/components/console-compliance.md](../../../../../../../docs/components/console-compliance.md), [docs/components/console-web.md](../../../../../../../docs/components/console-web.md)
