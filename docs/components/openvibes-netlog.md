# openvibes-netlog

## Purpose

Network device alarms (spec
`docs/specs/2026-10-10-network-device-alarms-design.md`). Routers and firewalls
send their security events here, and the ones that matter become alarms on the
existing Alarms screen, with the same triage, cases and suppressions. **It is
not a SIEM:** only IPS/IDS events from registered devices are kept. Everything
else is dropped as it arrives and only counted. Version 1 understands one
device kind, `unifi`: UniFi Network's SIEM Server export (CEF over plain UDP
syslog).

## Run

`openvibes-netlog [--config /etc/openvibes/netlog.toml]`. Logs go to stderr as
JSON (journald).

- **SIGINT** (the unit's `KillSignal`): stops receiving, stores what it holds,
  then exits 0.
- **SIGHUP** (`systemctl reload`): reloads the device list. It is also reloaded
  every 30 seconds, so a device added with `openvibes-admin device add` (or,
  later, in the console) needs no signal.

Setup's Services step enables it with ingest. With no devices it idles and
drops every packet as an unknown sender.

## Configuration

Strict TOML; unknown keys are refused.

| Key | Default | Range |
|---|---|---|
| `database_url` | required | the `openvibes-netlog` role |
| `listen` | `0.0.0.0:514` | UDP syslog address; the router's SIEM server port |
| `health_listen` | `127.0.0.1:18484` | loopback only (`/health`, `/ready`) |
| `batch_seconds` | 5 | 1 to 60; how often alarms and counters are stored |
| `collapse_minutes` | 10 | 1 to 1440; quiet window per device, signature and source |
| `max_collapse_keys` | 2000 | 1 to 5000 (fits the unit's `MemoryMax=64M`); open alarms held in memory (also the retry buffer) |

**Port 514/udp is not opened by OpenVIBES.** How ports are opened differs per
installation, so open it the way your host manages its firewall. Setup's
readiness step warns when firewalld runs and 514/udp is closed. `device list`
says when a device has sent nothing 10 minutes after it was added, or has
been silent for a day.

## Interfaces

- **In:** UDP datagrams on `listen`, up to 8 KiB each. The socket is never
  connected, so a router that restarts its log daemon and sends from a new
  source port keeps working.
- **Out:** PostgreSQL as `openvibes-netlog`, writing
  `platform_store::device_alarms::insert_batch` and
  `platform_store::devices::flush`. The role has column grants only: it never
  reads an agent alarm's process, notes or assignee (schema 46).
- **Health:** `/health` is always 200. `/ready` is 200 when the database
  answers at the current schema.

Modules:
- `cef`: datagram → CEF fields. Bounded and never panics.
- `unifi`: CEF → an IPS event or a drop reason, plus all field validation.
- `collapse`: the in-memory collapse map.
- `handle`: one datagram.
- `service`: the loop.

## Data flow

1. Sender IP is an active device? If not, count it as `unknown_sender` (logged
   per flush) and drop it.
2. No `CEF:0|` in the datagram? Count `not_cef` and drop it. This is plain
   syslog, which is most of what a gateway sends.
3. CEF that doesn't parse (at most 64 keys, valid UTF-8, a correct header)?
   Count `unparsed`.
4. Not Ubiquiti with `UNIFIcategory=Security` and a `UNIFIipsSignatureId`?
   Count `dropped_other`, plus a `class:policyType` key in `dropped_classes`
   (at most 64 keys).
5. `UNIFIdeviceIp` present and not the device's address? Count `mismatch`.
6. Fields that fail validation (IPs, ports 0–65535, a numeric signature ID of
   at most 12 digits)? Count `unparsed`.
7. Collapse: the same device, signature and source within `collapse_minutes`
   of the last event (sliding) raise `count` and `last_seen` on one alarm.
   Every `batch_seconds`, one transaction stores the alarms that changed;
   counters follow.

## What becomes an alarm

| Alarm field | Value |
|---|---|
| `source`, `device_id` | `device`, the sender |
| `rule_set_id` / `rule_id` | `device-unifi` / `ips.<signature id>`, versions 0 |
| `severity` | `UNIFIrisk`: low, medium/suspicious, high, critical. Otherwise CEF severity: 0–3 low, 4–6 medium, 7–8 high, 9–10 critical. Unknown risk values are counted as `risk:<value>` |
| `confidence` | 80 |
| `message` | `<UNIFIipsSignature>: <msg>` |
| `network` | `action` (`act`), `proto`, `app`, `src`, `spt`, `dst`, `dpt`, `dst_domain`, `direction`, `policy`, `policy_type`, `signature`, `signature_id`, `device_model` |

Text is at most 256 characters with control characters removed. Ports are
absent for ICMP. Times are receive times; `UNIFIutcTime` is ignored. The raw
line is never stored. Suppressions with scope `device` (one device) or
`signature` (any device) close a new alarm as a false positive. A recurrence
reopens a mitigated alarm, as for agent alarms. Device alarms are not offered
to the assistant: signature text comes from the network.

## Router settings changes

| Change on the router | Effect | Handled by |
|---|---|---|
| Any save (log daemon restart) | new UDP source port | `recv_from`, never `connect` |
| Categories or Debug Logs toggled | more or less plain syslog and other classes | `not_cef`, `dropped_classes` |
| Firmware or Network app upgrade | CEF keys change (`UNIFIsubCategory` before, `UNIFIpolicyType` now) | classification keys only on category + signature ID; both formats tested |
| SIEM server address or port changed away | silence | `device list` heads-up after a day |

## Failure behaviour

- **Database down:** unstored alarms stay in the collapse map and are retried
  every batch. Unstored entries are never expired or evicted. When every key
  is unstored and the map is full, new keys are dropped (`collapse_full`,
  logged).
- **Flood:** reading, parsing and collapsing are bounded. When the map is
  full, the oldest *stored* entry is evicted, so a spoofed flood of distinct
  sources cannot hide a new alarm while the database is up. A flush that takes
  a while leaves datagrams in the kernel's receive buffer; beyond it, the
  kernel drops them.
- **A day with no `alarms` partition** (maintenance not run): those alarms are
  skipped and counted (`unstorable`, logged). The rest of the batch is stored.
- **Startup:** devices are loaded before the first datagram is read.

## Footprint

Measured 2026-10-10 (`docs/sizing.md`): 4.2 MB binary; 4.9 MB RSS idle and
5.1 MB under 10,000 datagrams/s from one source; 20 MB under a spoofed flood
with a new source on every datagram (twice the 10 MB target), with about
6,400 datagrams/s taken and the rest dropped by the kernel. Idle CPU 0.

## Security notes

Identity is the sender IP, because UniFi's export is plain UDP with no
authentication. A host on the LAN can spoof the router's address and create
alarms. A source-IP firewall rule wouldn't stop this either, since the spoofed
packet carries the router's address.

Mitigations:
- the registered-sender filter;
- the `UNIFIdeviceIp` cross-check;
- strict parsing;
- bounded memory;
- alarms only: no action is ever taken on them.

Events cross the LAN in clear text. They carry IPs and signature names, not
credentials.

## How to test

- Unit tests: `cargo test -p openvibes-netlog --lib`. They cover the real UCG
  Max line (`tests/fixtures/ucgmax-ips-blacksun.cef`, MAC and hostname
  replaced), the older Graylog-quoted format, plain syslog, broken input, a
  20,000-round mutation loop, severity, collapse, eviction and caps.
- Integration test: `eval "$(scripts/test-db.sh)"; cargo test -p
  openvibes-netlog --test udp`. It runs a live service on loopback and checks
  two source ports, an unknown sender, collapsing and the counters.
- By hand: run `socat -u UDP-RECV:514 -` on the platform host to see what the
  router sends. Don't use `nc -ul`: it locks onto the first source port and
  goes silent after a router restart. A safe IPS trigger is
  `curl -A "BlackSun" http://www.example.com` from a LAN client.
