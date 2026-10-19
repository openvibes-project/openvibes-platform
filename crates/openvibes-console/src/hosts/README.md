# src/hosts

Hosts in the console: the agent list, summary, detail and certificates, revoking an agent, enrollment tokens, the agent install package and command, software, ports and services, live presence, the site rule-set fleet, host groups and host labels.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules, the public names of its types, and `routes()`: the paths this area serves. |
| `agents.rs` | The agent list, summary and detail, and revoking an agent. |
| `certificates.rs` | An agent's certificates. |
| `enrollment.rs` | Enrollment tokens: list, read, create, revoke. |
| `install.rs` | The agent install package and command endpoints. |
| `agent_package.rs` | Renders the agent install package and command. |
| `software.rs` | Installed software, per host and fleet-wide. |
| `software_types.rs` | Response types of the software endpoints. |
| `ports.rs` | Open ports and running services, per host and fleet-wide. |
| `presence.rs` | Live agent presence as a server-sent event stream. |
| `site_fleet.rs` | Which hosts run the site's own rule sets, and how current they are. |
| `groups.rs` | Host groups: list, page, member hosts, create, edit, delete and the preview before saving (spec §5.1). |
| `group_checks.rs` | The host-group handlers' rule and pick checks, and the store's outcomes as answers. |
| `groups_types.rs` | Request and response types of host groups and labels. |
| `group_words.rs` | `membership_sentence`: a group's membership in one plain sentence, shared with rule-set assignment. |
| `labels.rs` | Host labels: read, add and remove (spec §5.2). |
| `types.rs` | Request and response types of hosts, certificates and enrollment tokens. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
