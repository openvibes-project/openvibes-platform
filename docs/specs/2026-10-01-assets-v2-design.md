# Assets v2: open ports and running services — design

Board epic #93. User, 2026-10-01 (#1683, option A): open ports and running
services per host, plus fleet lists, reported by agents. Builds on Assets
v1 (`2026-10-01-assets-design.md`).

## 1. What the agent can see today

- **Ports** (`ports` collector): every bound TCP listener and UDP socket
  from `/proc/net/{tcp,tcp6,udp,udp6}` (world-readable): protocol, address,
  port, exposed (non-loopback) or local. Used only as rule facts now.
- **Processes** (`processes` collector): short names only.
- **Visible without privilege (as built):** each socket's owning systemd
  **service**. `sock_diag` (netlink) gives every socket's cgroup id, which
  is the cgroup directory's inode; walking the world-readable
  `/sys/fs/cgroup` maps it to the unit. The program is named too when that
  unit runs a single program. A socket only pid 1 holds (socket
  activation, no daemon yet) shows program `systemd` and no service.
- **Visible without privilege:** running services from the cgroup tree and
  each process's name, command line and user (`/proc/<pid>/comm`,
  `cmdline`, `status`).
- **Needs privilege:** the exact owning process when a unit runs several
  programs. That needs socket inode → `/proc/<pid>/fd/*` of other users,
  which takes **both** `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE` (the fd
  links are ptrace-checked; tested in a container). The agent runs as
  `openvibes_agent` with only `CAP_AUDIT_READ`.

## 2. Who owns a port? (decided: B, the user, 2026-10-01, #1737)

**By default, no new privilege:** every port shows its owning service from
`sock_diag` cgroups, with the program where the unit runs only one, and the
report says `owners: partial`.

**Opt-in for exact programs:** a documented drop-in, `owners.conf`
(shipped as `%doc` and never enabled), adds `CAP_DAC_READ_SEARCH` **and**
`CAP_SYS_PTRACE`. Together they are **near-root** if the agent were
compromised: the agent could read any file and any process's memory. The
packaging page says so in those words. With it, a capped fd walk (the
listeners' own units first, then the system services, with a 1,000-link
backstop) names the exact program, and `owners: complete` means every
holder that exists was found. Cost on the CI VM: about 3 ms per scan by
default and about 10 ms with the opt-in (accepted: hourly, and only on
hosts that chose it).

History: C (opt-in `CAP_DAC_READ_SEARCH` only, #1688) was replaced when
testing showed the second capability is needed and the cgroup route gives
services without privilege (`decisions.md`, 2026-10-01).

## 3. Protocol P15 `HostServices` (openvibes-protocol first)

`POST /v1/services` (mTLS, gzip as P11), sent after a scan when the
content digest changed, and at least daily:

```json
{ "schema_version": 1, "agent_id": "agent.1", "collected_at_unix_ms": 1790604131000,
  "sha256": "…", "owners": "partial", "truncated": false,
  "listeners": [ { "protocol": "tcp", "address": "0.0.0.0", "port": 443,
                   "exposed": true, "service": "nginx.service", "program": "nginx" } ],
  "services": [ { "unit": "nginx.service", "programs": ["nginx"], "processes": 5,
                  "user": "root" } ] }
```

`service`/`program` on a listener are optional (absent = not visible).
`owners` is `complete` or `partial`; `truncated` (optional, absent =
false) says the agent cut a list to fit, in digest order. Limits (the
protocol is the source of truth): 4,096 listeners, 2,048 services, 512 KiB
uncompressed.

**Robustness:** names the agent reads from cgroups or `comm` are under an
ordinary user's control, so an invalid one is dropped **per field**
(`service`, `program` or `user` becomes absent) and never fails the whole
document. Ingest records a refused report (400/413) on the host, and the
Ports tab shows "last report refused" with the reason until a good one
arrives. UDP
client sockets on ephemeral ports are left out (bound to a port ≥ the
local ephemeral range with no peer) so the list is servers only.

## 4. Platform

- **Store:** `host_listeners` and `host_services`, replaced per report
  (like `host_packages`); `agents.services_sha256`, `services_at`,
  `services_owners` and the last refusal. Additive migration.
- **Console API (`agents.read`, scoped):** `GET /api/v1/agents/{id}/services`
  (listeners and services); fleet: `GET /api/v1/ports`
  (port/protocol → hosts exposing it, with services where known) and
  `GET /api/v1/services` (unit → hosts running it).
- **Console UI:** Host page tabs **Ports** and **Services**; fleet views
  **Ports** ("443/tcp exposed on 14 hosts") and **Services** under Software
  (Assets group); exposed ports highlighted.

## 5. Cost

One extra read of the socket tables and the cgroup tree per scan (already
hourly); report only on change. Budget: < 5 ms CPU per scan on the
reference VM, report < 20 KiB gzip for a typical host.

## 6. Delivery

1. protocol P15 (schemas, fixtures, contract); 2. agent collector +
delivery and the opt-in drop-in; 3. platform store, ingest,
API; 4. console UI. One PR each.
