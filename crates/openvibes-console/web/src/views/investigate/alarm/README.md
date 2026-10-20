# views/investigate/alarm

An alarm's page (approved screen 30; roles spec §10.3), at `/alarms/{id}`. It replaces the old alarm panel and its tabs, keeping everything they showed.

| File | What it does |
|---|---|
| `AlarmPage.tsx` | The page: header (Set state, Assign, Suppress…, Ask about this, ⋯ Export and Copy link), four tiles, and the cards; reads the summary route and the waiting suppression request; Export's CSV rows. |
| `AlarmCards.tsx` | What happened (rule text, evidence), Details (decision with Reopen, rule, case, suppression with a waiting request and Withdraw), History; Commands seen (Suppress this command… on the usual one, Add to case on one seen once), Process chain, Last 24 hours, Related. |

More: [docs/components/console-alarms.md](../../../../../../../docs/components/console-alarms.md)
