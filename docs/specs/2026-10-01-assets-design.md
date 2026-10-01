# Assets v1: Host page and fleet Software view — design

Board epic #93. User, 2026-10-01: an asset list showing installed software
even without vulnerabilities; a Host page with everything about one host;
the same information aggregated for all hosts ("how many hosts have X").
Scope chosen: **v1, console and API only** (option A, #1584). Open ports
and running processes are later; they need agents to report them (a
protocol change).

## 1. What is stored already

- `agents`: identity, hostname, status, OS (`os_id`, `os_version`,
  `os_release`), `running_kernel`, scanner version, last contact, P12
  health, tags; imported hosts are agents with status `imported`.
- `package_versions` (one row per distinct manager/name/epoch/version/
  release/arch, fleet-wide) and `host_packages` (agent ↔ version links),
  replaced on each inventory report or change set (P8/P11). Indexes:
  `host_packages_version`, `package_versions_name`.
- Findings, alarms and vulnerabilities per agent, each already filterable
  by host in the console API (`findings/latest`, `alarms?agent_id=`,
  `vulnerabilities?host=`).

No migration is needed beyond, at most, one index (§4).

## 2. Console API (new routes, `agents.read`, scoped like agents)

- `GET /api/v1/agents/{agent_id}/packages?q=&cursor=&limit=` — the host's
  installed packages, sorted by name: manager, name, epoch, version,
  release, arch, and `vulnerable` (the host has an open vulnerability on
  this package version). Outside the scope: 404. `q` matches the name
  (case-insensitive substring).
- `GET /api/v1/software?q=&vulnerable=&cursor=&limit=` — packages across
  the caller's visible hosts, one row per (manager, name): `hosts` (how
  many visible hosts have any version), `versions` (distinct versions in
  use), `vulnerable_hosts`. Sorted by name; keyset cursor on
  (manager, name). A scoped caller's counts include only their hosts, so
  counts never reveal hosts outside the scope.
- `GET /api/v1/software/{manager}/{name}?cursor=&limit=` — the versions in
  use with their host counts and, paged, the hosts (agent id, hostname,
  version, last contact). 404 when no visible host has it.

OpenAPI snapshot and generated client updated, as usual.

## 3. Console UI

- **Hosts** (today's Agents view, same path `/agents`, relabelled; the
  palette and docs say Hosts). The row opens the **Host page** (the agent
  panel, widened into sections):
  - Overview: hostname, status, OS and running kernel, agent version and
    health, first and last contact, tags.
  - **Software**: the host's packages with a filter box and "vulnerable
    only"; a package links to its Software detail.
  - Findings, **Alarms**, Vulnerabilities for this host (each a compact
    list linking to the existing panels/views filtered to the host).
  - Certificates (as today).
- **Software** (new view `/software`, Investigate group): name, hosts,
  versions, vulnerable hosts; filter by name and "vulnerable only". A row
  opens the package panel: versions in use with host counts, and the hosts
  (each opens its Host page).
- Demo data and demo routes follow the server's rules; e2e for both views.

## 4. Cost and limits

The fleet aggregate is a GROUP BY over `host_packages` joined to visible
agents: about hosts × packages rows (1,000 × 2,000 = 2 M) per page
request. With keyset paging by name and the existing indexes this stays
well under a second on the reference VM; measure in the PR and add an
index on `package_versions (manager, name)` only if the plan needs it.

## 5. Delivery

1. API PR: store reads (`console_inventory.rs`), routes, scope and
   permission tests, OpenAPI.
2. Console PR: Hosts relabel and Host page sections, Software view and
   panel, demo data, e2e.

## 6. Later (not v1)

Open ports and listening services, running processes (agents report them:
protocol first), software "first seen / last changed" history, export.
