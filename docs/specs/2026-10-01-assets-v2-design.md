# Assets v2: open ports and running services — design

Board epic #93. User, 2026-10-01 (#1683, option A): open ports and running
services per host, plus fleet lists, reported by agents. Builds on Assets
v1 (`2026-10-01-assets-design.md`).

## 1. What the agent can see today

- **Ports** (`ports` collector): every bound TCP listener and UDP socket
  from `/proc/net/{tcp,tcp6,udp,udp6}` (world-readable): protocol, address,
  port, exposed (non-loopback) or local. Used only as rule facts now.
- **Processes** (`processes` collector): short names only.
- **Not visible without more privilege:** which process owns a socket.
  The mapping goes socket inode → `/proc/<pid>/fd/*`, which only the owner
  or a process with `CAP_DAC_READ_SEARCH`/`CAP_SYS_PTRACE` can read. The
  agent runs as `openvibes_agent` with only `CAP_AUDIT_READ`.
- **Visible without privilege:** running systemd services from the cgroup
  tree (`/sys/fs/cgroup/system.slice/<unit>.service/cgroup.procs`, world-
  readable) and each process's unit (`/proc/<pid>/cgroup`), name and
  command line (`/proc/<pid>/comm`, `cmdline`), user (`status`).

## 2. Decision for the user: who owns a port?

- **A. No new privilege (recommended).** Ports are listed with protocol,
  address, exposed/local; the owning service is filled in only where the
  agent can prove it without privilege (its own sockets; and for systemd
  socket-activated units, the unit's `ListenStream=` from the unit file).
  Most ports show "owner not visible". Services are listed separately.
- **B. Add `CAP_DAC_READ_SEARCH`** to the agent: every port gets its
  owning process and service. Cost: the agent can then read any file on
  the host (the capability bypasses read permission checks) — a much
  larger blast radius if the agent were compromised, against the "light,
  least privilege" principle.
- **C. Opt-in B:** A by default; an admin who wants owners enables a
  drop-in that adds the capability, documented with its risk.

## 3. Protocol P15 `HostServices` (openvibes-protocol first)

`POST /v1/services` (mTLS, gzip as P11), sent after a scan when the
content digest changed, and at least daily:

```json
{ "schema_version": 1, "agent_id": "agent.1", "collected_at_unix_ms": 1790604131000,
  "sha256": "…",
  "listeners": [ { "protocol": "tcp", "address": "0.0.0.0", "port": 443,
                   "exposed": true, "service": "nginx.service", "program": "nginx" } ],
  "services": [ { "unit": "nginx.service", "programs": ["nginx"], "processes": 5,
                  "user": "root" } ] }
```

`service`/`program` on a listener are optional (absent = not visible).
Limits: 4,096 listeners, 2,048 services, 256 KiB uncompressed. UDP
client sockets on ephemeral ports are left out (bound to a port ≥ the
local ephemeral range with no peer) so the list is servers only.

## 4. Platform

- **Store:** `host_listeners` and `host_services`, replaced per report
  (like `host_packages`); `agents.services_at`. Additive migration.
- **Console API (`agents.read`, scoped):** `GET /api/v1/agents/{id}/listeners`,
  `GET /api/v1/agents/{id}/services`; fleet: `GET /api/v1/ports`
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
delivery (+ the capability change if B/C); 3. platform store, ingest,
API; 4. console UI. One PR each.
