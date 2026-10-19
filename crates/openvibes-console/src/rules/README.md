# src/rules

Rules over `/api/v1`: rule sets and their signed bundles, which asset groups run each set, the site's draft rules and their publishing, testing a rule on one host, and ATT&CK coverage.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules, the public names of its types, and `routes()`: the paths this area serves. |
| `bundles.rs` | Rule sets, bundle history, and previewing and publishing an uploaded signed bundle. |
| `bundle_types.rs` | Request and response types of rule sets and bundles. |
| `envelope.rs` | Verifies a signed envelope's bytes against the set's trusted keys; the digest shown to the operator. |
| `assignment.rs` | Which asset groups run each assignable rule set; the rules reader check. |
| `drafts.rs` | List, check, save and delete the site's draft rules. |
| `draft_types.rs` | Request and response types of drafts, changes and publishing. |
| `draft_check.rs` | Checks a draft with the agent's own loader code and the program caps. |
| `draft_publish.rs` | What publishing would change, and the signer round trip that publishes the drafts. |
| `test_on_host.rs` | Tests a rule against one host's facts. |
| `coverage.rs` | MITRE ATT&CK coverage of the published rules and the bundled catalog. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
