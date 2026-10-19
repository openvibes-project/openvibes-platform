# src/vulnerabilities

Vulnerabilities in the console: the summary, the prioritised list and advisory detail. Bulk triage (`/v1/vulnerabilities/bulk`) and one host's triage of an advisory live with the other triage code in `compliance/bulk.rs` and `compliance/triage_detail.rs`.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules, the public names of its types, and `routes()`: the paths this area serves. |
| `summary.rs` | The vulnerability summary. |
| `list.rs` | The vulnerability list and the views its rows are built from. |
| `cpe.rs` | CPE findings: matches of installed software against CPE names. |
| `advisory.rs` | One advisory: its CVE enrichment and the hosts it affects. |
| `types.rs` | Request and response types of vulnerabilities and advisories. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
