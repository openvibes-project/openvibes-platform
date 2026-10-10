# Network device alarms (UniFi IPS/IDS first)

Design session with the user, 2026-10-10. Network devices send security
events to the platform; the first device is a Ubiquiti UniFi Cloud Gateway
Max (UCG Max). **Not a SIEM:** the platform keeps only events that are
alarms and drops everything else on arrival, with counters.

Decisions (user):

1. **Version 1: router events become alarms** on the existing Alarms
   screen, with the same triage, cases and suppressions. **Direction:**
   editable rules decide per event to alarm, keep in a short timeline, or
   drop (a later spec).
2. **A small separate receiver**, `openvibes-netlog`, on the platform host.
   Not inside ingest (unauthenticated UDP stays away from the agents'
   mTLS service) and not relayed by agents (agent footprint unchanged).
3. **IPS/IDS threats only** in version 1. Admin access and firewall events
   wait for rules.
4. **Backend first.** Console screens (Devices, device alarms) follow
   mockups in a separate design step; until then the console hides device
   alarms (section 6).

## 1. What UniFi sends

UniFi Network (8.5+) → Settings → Control Plane → Integrations → Activity
Logging (Syslog) → **SIEM Server**. The only settings are content
categories, a debug switch, a server address and a port (default 514).
Transport is **plain UDP syslog, CEF payload**: no TLS, no TCP, no
authentication. Example IPS line (Graylog's UniFi content pack, Network
9.4.19; replaced by lines from the user's UCG Max when captured):

```
CEF:0|Ubiquiti|UniFi Network|9.4.19|201|Threat Detected and Blocked|7|proto=TCP
src=81.181.129.172 spt=54321 dst=192.168.0.233 dpt=443 UNIFIcategory=Security
UNIFIsubCategory=Intrusion Prevention UNIFIhost=Office-UDM-Pro
UNIFIdeviceMac=84:78:48:80:0d:86 UNIFIdeviceName=Office-UDM-Pro
UNIFIdeviceModel=UDM-Pro UNIFIdeviceIp=192.168.0.1 UNIFIrisk=medium
UNIFIipsSignature=ET DROP Dshield Block Listed Source group 1
UNIFIipsSignatureId=2402000 msg=A network intrusion attempt has been detected and blocked.
```

**Real line from the user's UCG Max** (UniFi Network 10.6.106, gateway
5.1.33; `curl -A "BlackSun" http://www.example.com`, 2026-10-10; MAC and
hostname replaced; fixture `crates/openvibes-netlog/tests/fixtures/ucgmax-ips-blacksun.cef`):

```
Oct 10 17:36:00 gateway CEF:0|Ubiquiti|UniFi Network|10.6.106|201|Threat Detected and Blocked|9|
UNIFIcategory=Security UNIFIhost=gateway proto=TCP spt=36216 dpt=80 act=blocked app=HTTP
UNIFIrisk=high UNIFIpolicyName=Malicious User Agents UNIFIpolicyType=IDS/IPS
UNIFIdirection=outgoing ... UNIFIdeviceModel=UCG-Max UNIFIdeviceIp=192.168.1.1
src=192.168.1.10 dst=172.66.147.243 UNIFIsrcZone=Internal UNIFIdstDomain=www.example.com
... UNIFIflowStartTime=Oct 10, 2026 at 5:36:00.239 PM ...
UNIFIipsSignature=ET USER_AGENTS Suspicious User Agent (BlackSun) UNIFIipsSignatureId=2008983
UNIFIutcTime=2026-10-10T15:36:00.493Z msg=A network intrusion attempt from 192.168.1.10 to ...
```

Differences from the Graylog example that the design follows: **no
`UNIFIsubCategory`** (the IPS marker is `UNIFIpolicyType=IDS/IPS` and the
signature id), the syslog header has no `<PRI>`, the action is CEF's
standard `act`, and there are `UNIFIpolicyName`, `UNIFIdirection` and
`UNIFIdstDomain`. Values contain spaces and commas.

(One line on the wire, preceded by a syslog header.) Captured from the
user's UCG Max (2026-10-10, all categories and Debug Logs on): most
traffic is **plain RFC 3164 syslog** from the gateway OS (syslog-ng,
charon, earlyoom), not CEF, e.g.
`<30>Oct 10 17:13:35 limebox limebox charon[9728]: 15[ENC] generating ...`.
It is dropped first and cheaply (`not_cef`). Some UniFi OS admin
events are reported to be malformed CEF; the parser must tolerate them.

## 2. Data flow

```
UCG Max ──UDP 514, CEF──▶ openvibes-netlog
  1. sender IP is an active device?      no → count unknown_sender, drop
  2. no "CEF:0|" in the message?           → count not_cef, drop
  3. parse syslog + CEF (≤ 8 KiB, strict)  bad → count unparsed, drop
  4. Ubiquiti, UNIFIcategory=Security and a UNIFIipsSignatureId?
                                          no → count per (class, policyType), drop
  5. UNIFIdeviceIp, when present, = device IP?  no → count mismatch, drop
  6. collapse in memory: device + signature_id + src within 10 min
  7. every ~5 s: one transaction inserts new alarms, updates count/last_seen
```

- **The socket is never connected** to a sender: a router that restarts
  its log daemon sends from a new source port (seen with `nc -ul`, which
  locks onto the first port and went silent, 2026-10-10).
- **Bounded everywhere.** Fixed receive buffer (8 KiB; longer datagrams are
  truncated by the kernel and counted unparsed). One task reads the socket;
  parsing is synchronous and cheap. The collapse map holds at most 2,000
  keys; beyond it, new keys are dropped and counted (`collapse_full`).
- **Database down:** unstored alarms stay in the collapse map (at most
  `max_collapse_keys`; new keys beyond it are dropped and counted),
  retried every batch. UDP cannot ask the sender to
  resend, so nothing more durable is promised.
- **Counters** are kept per device in memory and flushed with each batch to
  `devices` (section 4): `received`, `alarms`, `not_cef`, `unparsed`, `dropped_other`,
  `mismatch`; plus host-level `unknown_sender` and `collapse_full`. The
  per-(class, subCategory) drop counts are kept as a small jsonb map on the
  device (at most 64 keys) so the user can see what else the router sends
  before rules are written.
- **Footprint target:** under 10 MB RSS, near-zero idle CPU; measured in the
  lab under a 10,000 packets/s flood (section 8).

## 3. Event → alarm mapping

| Alarm field | Value |
|---|---|
| `source` | `device` |
| `device_id` | the matched device |
| `alarm_id` | UUID generated by netlog |
| `rule_set_id` / `rule_id` / versions | `device-unifi` / `ips.<UNIFIipsSignatureId>` / 0 / 0 |
| `severity` | `UNIFIrisk` through a fixed table (low, medium, high, critical 1:1; `suspicious` → medium; further values added from captured fixtures); absent or unknown → CEF severity 0–3 low, 4–6 medium, 7–8 high, 9–10 critical, and an unknown value is counted in `dropped_classes` as `risk:<value>` |
| `confidence` | 80 |
| `message` | `<UNIFIipsSignature>: <msg>` |
| `network` (jsonb) | `action` (`act`, else `blocked` if the CEF name contains "Blocked", else `detected`), `proto`, `app`, `src`, `spt`, `dst`, `dpt`, `dst_domain`, `direction`, `policy`, `policy_type`, `signature`, `signature_id`, `device_model` (each text ≤ 256, ports optional for ICMP) |
| `first_seen` / `last_seen` / `count` | from collapsing; time is the receive time (device clocks are not trusted) |

The raw line is not stored. `UNIFIutcTime` is ignored: the receive time
is used (device clocks are not trusted).

**All fields are hostile input** (anyone can send UDP):

- `src`, `dst` parse as IP addresses; ports as 0–65535; `signature_id` as
  digits (≤ 12). Any failure → unparsed.
- Text fields (`signature`, `msg`, `device_model`, `proto`) at most 256
  characters, control characters removed, CEF escapes (`\=`, `\\`, `\n`)
  decoded once.
- The parser never panics on any byte input (property test, section 8).
- Device alarms are **excluded from assistant lookups**, like agent alarms:
  signature text comes from the network and may carry prompt injection.

## 4. Storage (next free migration number, additive)

- `devices`: `id` (bigint identity), `name` (1–64), `kind` (`unifi`),
  `address` (inet, unique among active devices), `created_by`, `created_at`,
  `removed_by`/`removed_at` (a removed device keeps its row: alarms point at it),
  `last_seen`, the counters of section 2, `dropped_classes` jsonb.
- `alarms`: add `source text NOT NULL DEFAULT 'agent' CHECK (source IN
  ('agent','device'))`, `device_id bigint REFERENCES devices`, `network
  jsonb`; drop NOT NULL on `agent_id`, `process`, `ancestors`; add a CHECK:
  `agent` rows have `agent_id`, `process`, `ancestors` and no `device_id`;
  `device` rows have `device_id`, `network` and no `agent_id`. Existing rows
  are untouched (default `agent`). Index `(device_id, alarm_id)` for the
  lookup before insert, like `(agent_id, alarm_id)`.
- `alarm_suppressions`: scopes `device` (one device, `device_id`) and
  `signature` (any device); both key on `rule_set_id`/`rule_id` as today.
  Netlog marks matching new alarms `false_positive` as ingest does.
- Retention, partitions, triage history and case links apply unchanged.
- Role `openvibes-netlog`: SELECT on `devices` and `alarm_suppressions`;
  UPDATE of counter columns and `last_seen` on `devices`; SELECT, INSERT,
  UPDATE on `alarms`; INSERT on `alarm_triage_history` (suppression
  closes). Nothing else.

## 5. The `openvibes-netlog` service

- New crate and binary, its own sysusers entry, systemd unit and
  `/etc/openvibes/netlog.toml` (strict TOML): `listen` (default
  `0.0.0.0:514`), `health_listen` (loopback), `database_url`,
  `batch_seconds` (5, 1–60), `collapse_minutes` (10, 1–1440),
  `max_collapse_keys` (2,000). The collapse map is also the retry
  buffer: alarms not yet stored stay in it, so the database being down
  is bounded by the same limit (no separate `max_pending`).
- Port 514 needs `AmbientCapabilities=CAP_NET_BIND_SERVICE` only; the unit
  is otherwise hardened like ingest.
- Devices are re-read every 30 s and on SIGHUP, so a newly added device
  works without a restart.
- `/health` and `/ready` on loopback like ingest; `/ready` fails while the
  database is unreachable.
- **Always on, like the other services** (user, 2026-10-10): Setup's
  Services step enables it. With no devices it idles and drops every
  packet as `unknown_sender`. Adding a device is only a database row, so
  the CLI now and the console later need no root.

## 6. Devices: add, firewall, console

- **Adding a device** (version 1: `openvibes-admin device add --name
  "UCG Max" --kind unifi --address 192.168.1.1`, then the console screen
  from the mockups; `device list`, `device remove`). End users get the
  console path; the admin command exists for the lab and tests.
- **Firewall: OpenVIBES does not open 514/udp** (user, 2026-10-10): how
  ports are opened differs per installation, so 514/udp is documented
  with the other platform ports and the user opens it. OpenVIBES gives a
  **heads-up** instead:
  - a device with no packet 10 minutes after it was added shows
    "No events received yet: check the router's SIEM server setting
    (this host, port 514) and that UDP 514 is open in this host's
    firewall" (`device list` now, the Devices screen later), and a device
    that did send but has been silent for a day shows the same advice
    (its SIEM setting or this host's firewall changed);
  - Setup's readiness step, when firewalld runs and 514/udp is not open
    in the default zone, prints the same warning without failing.
  Fedora Workstation's default zone blocks UDP below 1025 (seen on the
  user's machine, 2026-10-10).
- **Console until the mockups land:** alarm list, detail, counts and
  dashboards read `source = 'agent'` only, so nothing that expects a
  process breaks. The device screens and device alarms in the Alarms list
  are designed next, with mockups.

## 7. Security notes (stated, not hidden)

- Identity is the sender IP. A host on the LAN can spoof the router's
  address and create alarms (a source-IP firewall rule would not stop
  this either: the spoofed packet carries the router's address).
  Mitigations: registered-sender filter, `UNIFIdeviceIp` cross-check, strict parsing, bounded memory, alarms only
  (no actions are taken on them). This is the ceiling of what UniFi's UDP
  export allows.
- Events cross the LAN in clear text; they carry IPs and signature names,
  not credentials.
- A flood is bounded by the receive buffer, collapse map and pending limit;
  ingest and the console are separate processes and unaffected.

## 8. Testing

- **Parser unit tests:** fixtures from the user's UCG Max (captured with
  `nc -ul 514`), the Graylog line, malformed admin CEF, truncated and
  oversized packets, wrong vendor, missing fields, bad IPs and ports.
- **Property test:** arbitrary bytes never panic and never produce an
  alarm with an unvalidated field.
- **Integration test** (`scripts/test-db.sh`): send UDP to a running
  netlog; check the alarm row, collapsing, the `UNIFIdeviceIp` mismatch,
  unknown senders, suppressions and counters; database stopped → pending
  limit, then recovery.
- **Migration test:** existing agent alarms unchanged; the CHECK refuses
  mixed rows.
- **Lab:** a VM replays captured lines with `socat`; RSS and CPU are
  measured idle and under a 10,000 packets/s flood.
- Component pages: `docs/components/openvibes-netlog.md`, updates to
  `platform-store.md` and `openvibes-admin.md`.

## 9. Later (not in this spec)

- Console: Devices screen, device alarms in the Alarms list and detail
  (mockups first).
- Rules over device events (alarm, timeline, drop), admin access and
  firewall events, a short network-event timeline.
- Other vendors (OPNsense, pfSense, MikroTik) as new `kind`s.
