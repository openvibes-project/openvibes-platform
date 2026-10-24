# src/compliance

Compliance in the console: the latest findings and finding groups, history, triage, bulk triage and triage detail.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules, the public names of its types, and `routes()`: the paths this area serves. |
| `latest.rs` | The finding summary, the latest findings list and one finding. |
| `groups.rs` | Findings grouped by rule, and the endpoints of one group. |
| `group_triage.rs` | Triage of every endpoint in one finding group at once. |
| `triage.rs` | One finding's triage: read and update. |
| `list_page.rs`, `list_page_types.rs` | `GET /v1/compliance-list`: the list by check, its parameters, validation, answer types and the call into the store. |
| `page.rs`, `page_types.rs` | `GET /v1/compliance/checks/{rule_set_id}/{rule_id}/summary` and `/hosts`: a check's page, its actions and answer types. |
| `evidence.rs` | `fact_file`: the file the agent read a fact from, shown beside evidence. |
| `history.rs` | Finding history: the list and one event. |
| `bulk.rs` | Bulk triage of alarms, findings or vulnerabilities. |
| `bulk/` | The bulk "suppress" action. |
| `triage_detail.rs` | Triage in the detail view and the History tab. |
| `types.rs` | Request and response types of findings, groups, history and triage. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
