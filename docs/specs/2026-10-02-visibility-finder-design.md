# Visibility finder: opt-in network discovery by agents — design draft

Board #122 (epic #93). User, 2026-10-02 (item 9): agents can map the
network around them, like nmap: find other hosts and their open ports.
Found hosts go to an **Unmanaged** list (many will be TVs, lights and
printers). It must be strictly opt-in and controlled from the platform:
include and exclude networks, which agents scan, and rate limits.

This is a draft for the user's decisions (§9). Nothing is built until
they are made. Protocol first, as always: the policy and the report are
new contracts (P16).

## 1. What it is, and what it is not

- **Is:** an inventory aid. "What is on my network that has no agent?"
  Each finding is an address, the hardware address when the agent shares
  a link with it, and which of a short list of TCP ports accept a
  connection.
- **Is not:** a vulnerability scanner. There is no banner grabbing, no
  service probing and no payloads in v1. A connection is opened and closed
  at once. Version detection and "what runs on 8080" are a later,
  separate decision (§10).
- **Is not on by default:** an agent that hasn't been opted in **locally**
  never scans, whatever the platform says (§4).

## 2. How hosts are found (privileges)

The agent runs as `openvibes_agent` with only `CAP_AUDIT_READ`, no
`unsafe` code, and `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
AF_NETLINK`. Discovery must fit that.

| Method | Finds | Privilege | Notes |
|---|---|---|---|
| **Neighbour table** (netlink `RTM_GETNEIGH`) | Hosts the agent's machine has recently talked to on its own links: IP and MAC | none | Passive, free, no packets sent. Misses hosts nobody talked to. |
| **TCP connect** to a short port list | Hosts with any of those ports open, and which | none | What `nmap -sT` does. A full handshake per open port, logged by the target as a connection. |
| ICMP echo via an unprivileged ping socket | Hosts that answer ping | none if `net.ipv4.ping_group_range` covers the agent's group (Fedora's default does; Debian's doesn't) | Needs a crate for `SOCK_DGRAM`/`IPPROTO_ICMP` (`socket2`, safe API). Many hosts drop ping. |
| Raw SYN ("half-open", `nmap -sS`) | Same as connect, stealthier | `CAP_NET_RAW` | Adds a capability to an always-on root-adjacent daemon, and raw packet code. **Not proposed.** |
| ARP sweep | Every live host on the local link | `CAP_NET_RAW` | Same objection. A connect sweep fills the neighbour table as a side effect, so reading it afterwards gets most of the benefit without privilege. |

**Proposal (decision 1, A):** the neighbour table plus a TCP connect sweep.
After a sweep, the agent reads the neighbour table again: every host that
answered ARP for the sweep shows up with its MAC, **even with no port
open**. On the agent's own subnets this finds nearly everything with no
new privilege. Beyond a router, only hosts with an open port are found,
which is acceptable for v1.

Ports, default list (16): 22, 23, 53, 80, 443, 445, 554, 1883, 3389,
5000, 5353 (TCP), 8008, 8080, 8443, 9100, 62078. That covers SSH, Telnet,
web UIs, SMB, RTSP cameras, MQTT, RDP, casting, printers and phones. The
policy may replace the list (§3, at most 64 ports).

## 3. The scan policy (protocol P16)

A scan only happens when an agent holds a **valid, signed scan policy**
that names it. The policy is a new signed envelope kind, verified by the
same loader as rule bundles (domain-separated preimage, expiry, rollback
floor), with its own trust key and set id `scan-policy`.

```json
{
  "schema_version": 1,
  "scans": [
    {
      "id": "office-lan",
      "agents": ["agent.7f3c…"],
      "include": ["192.168.1.0/24"],
      "exclude": ["192.168.1.1/32"],
      "ports": [22, 80, 443, 445, 9100],
      "interval_hours": 24,
      "window_utc": ["01:00", "05:00"],
      "rate_per_second": 20
    }
  ]
}
```

- `agents` names agent ids; an agent ignores scans that don't name it.
  The platform picks agents per network (decision 4).
- `include` / `exclude` are CIDRs; exclude wins.
- Expiry is short (**7 days**) and the platform re-signs while a scan is
  enabled, so **a stopped or disconnected platform stops all scanning
  within a week** with nothing to clean up on agents. Disabling a scan in
  the console publishes a new policy version without it, which agents
  fetch on their next rule check.
- Who signs it is decision 2.

## 4. Limits the agent enforces (not the policy)

The policy is trusted only up to ceilings fixed in the agent, so a
compromised platform or signing key can't turn the fleet into an attack
tool:

- **Local opt-in.** `agent.toml` needs `[discovery] enabled = true`.
  Without it, policies are ignored, and health says "scan policy received;
  discovery not enabled on this host". install.sh and Setup can write it
  (`--discovery`), but never by default.
- **Address ceiling (decision 3).** By default only private and
  link-local space (RFC 1918, RFC 6598 CGNAT, fc00::/7, fe80::/10) **and**
  only networks the agent's host has a route to without its default
  gateway, plus anything `agent.toml` lists in `[discovery]
  extra_networks`. Public addresses are never scanned unless listed there
  locally.
- **Size:** at most 4,096 addresses per scan and 65,536 per day; IPv6
  only by the neighbour table (a /64 can't be swept).
- **Rate:** at most 50 new connections a second (policy may ask for
  less), at most 32 in flight, a 1.5 s connect timeout, and a jittered
  start inside the window.
- **Ports:** at most 64 per scan; no UDP in v1.
- **Each sweep is logged** in the agent's journal (scan id, address
  count, duration, hosts found) and counted in health.

## 5. The report (protocol P16)

`POST /v1/discovery` (mTLS, gzip, idempotent by digest like P15), sent
after each sweep and when the neighbour table changes (at most hourly):

- the reporting agent's own interfaces: name, addresses, prefix, MAC;
- per found host: IP, MAC (if on a shared link), first and last seen by
  this agent, open ports, and how it was found (`neighbour`, `connect`).

Limits: at most 4,096 hosts and 64 ports each per report; a report over
the limit is cut and marked `truncated`, like P15.

Every agent (scanning or not) also reports its interface addresses in the
heartbeat (a small additive P12 field), so the platform can tell which
found addresses are **managed** hosts.

## 6. Platform

- **Store:** `discovered_hosts` keyed by MAC when known, else by IP per
  network. A row has first/last seen, last addresses, open ports, which
  agents saw it, a user label and a state (`new`, `known`, `ignored`).
  Rows unseen for 30 days age out.
- **Matching:** a found address or MAC that belongs to an enrolled agent
  is managed and never listed as unmanaged.
- **Vendor:** the MAC's OUI is looked up from a bundled IEEE list
  (platform-side, offline), so a row says "Philips Lighting" or
  "Raspberry Pi Trading". Hostnames come from reverse DNS **on the
  platform**, only if the user turns it on.
- **Console:**
  - a fleet **Unmanaged** view: address, vendor, open ports, last seen,
    seen by, label. Actions: label it ("Living-room TV"), mark it known,
    ignore it, or "Install an agent" (shows the agent command);
  - a **Discovery** settings page (admins only, new permission
    `discovery.manage`): networks with include/exclude, which agents
    scan, ports, window, rate, on/off. It shows a cost line before
    saving: "about 4,096 connections over 3 minutes, once a day, from
    agent X";
  - the Host page gets a "Seen on the network" line for managed hosts;
  - an Overview tile "New unmanaged devices (7 days)".
- **Audit:** every policy change is an audit row (who, what changed), and
  the policy history is kept.

## 7. Cost

- **A /24 with 16 ports** is 4,096 connections. At 20 a second that's
  about 3.5 minutes, once a day. The agent's CPU is negligible (it waits
  on sockets); memory is bounded by 32 in-flight sockets plus the result
  (≤ 4,096 rows). The network carries roughly 4,096 SYNs plus replies,
  under 1 MB.
- **The neighbour table** costs one netlink dump, hourly.
- **Platform:** one report per scanning agent per day, plus small hourly
  neighbour updates. Storage is one row per device.

## 8. Safety and etiquette

- **Only your networks.** Scanning networks you don't own or manage can
  be illegal and trips intrusion detection. The settings page says so,
  and defaults (§4) keep scans on private networks the host is directly
  on.
- **One scanner per network** (decision 4, A): the platform names one
  agent per network, so twenty laptops on the office LAN don't each sweep
  it.
- **Gentle:** low rate, a night window, jitter, connections closed at
  once, no retries within a sweep, and no scanning of the gateway's
  management ports unless included explicitly (the default list skips
  nothing, but the gateway can be excluded with one click).
- **Fragile devices:** some IoT and medical devices misbehave even under
  a connect scan. Excludes exist for them, and the docs say to exclude
  such ranges.
- **Visible:** sweeps are logged on the agent and audited on the
  platform. Nothing is hidden from the host's own administrator.
- **Stop switch:** turning discovery off in the console stops new sweeps
  at the agents' next rule check; expiry (§3) stops them within 7 days
  even if the platform is gone. Removing `[discovery]` locally stops them
  at once.

## 9. Decisions for the user

**1. How hosts are found**
- A) Neighbour table plus a TCP connect sweep: no new privilege
  (recommended).
- B) A, plus ICMP ping through unprivileged ping sockets: finds hosts with
  no open port beyond the local link, but needs a sysctl on Debian/Ubuntu
  and a new crate.
- C) Raw SYN and ARP sweeps: the most complete, but adds `CAP_NET_RAW` to
  the agent.

**2. Who signs the scan policy**
- A) The online signer (#107), after the admin re-types their password,
  like site rules. Changes are quick from the console (recommended).
- B) The offline organisation key, like the baseline rules. Safest, but
  every change means signing on the admin's machine.
- C) Unsigned, over mTLS only. Simplest, but a platform compromise could
  start scans immediately (still inside §4's ceilings).

**3. Which addresses may ever be scanned**
- A) Private and link-local ranges the host is directly on, plus networks
  listed in `agent.toml` (recommended).
- B) Any private range, routed or not.
- C) Whatever the policy says (public included).

**4. Which agents scan a network**
- A) The platform picks one agent per network; the admin can change it
  (recommended).
- B) Every opted-in agent scans its own networks.

## 10. Later (not v1)

UDP discovery (mDNS, SSDP: lists TVs and speakers by name), service and
version detection on open ports, linking unmanaged devices to
vulnerability data, alerting on a new device appearing, and scanning on a
schedule per network rather than per scan.

## 11. Delivery (after the decisions)

1. Protocol: P16 scan policy and discovery report schemas, fixtures, the
   heartbeat interfaces field, limits.
2. Agent: `[discovery]` config and ceilings, policy loading, neighbour
   table reader, connect sweeper, report delivery, health lines; tests
   against a namespace with fake hosts, and a cost run.
3. Platform: store, ingest, OUI list, console API (`discovery.manage`,
   scoped reads), policy signing and publishing.
4. Console: Unmanaged view, Discovery settings, Host page line, Overview
   tile, demo and e2e.
