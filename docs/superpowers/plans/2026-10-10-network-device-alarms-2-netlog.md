# Network Device Alarms, Part 2: `openvibes-netlog` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A small UDP service that receives UniFi syslog, keeps only IPS/IDS events from registered devices, collapses them and stores them as alarms.

**Architecture:** A new crate `crates/openvibes-netlog` (library + binary) with four modules:
- `cef`: datagram → CEF fields; pure and bounded.
- `unifi`: CEF → IPS event or a drop reason; pure; all validation happens here.
- `collapse`: in-memory collapse, which doubles as the retry buffer.
- `service`: one `tokio::select!` loop over the socket, a flush tick, a device reload tick and SIGHUP, plus the loopback health server.

It is shaped like `openvibes-vulns`.

**Tech Stack:** Rust 2024, tokio (`net`, `signal`, `time`), axum (health), platform-store (Part 1), platform-config, serde, serde_json, chrono, tracing. No new dependencies.

**Spec:** `docs/specs/2026-10-10-network-device-alarms-design.md` (platform #266). Needs Part 1 (`-1-store.md`) merged into the branch first.

## Global Constraints

- `listen` defaults to `0.0.0.0:514`, and `health_listen` to `127.0.0.1:18484`, which must be loopback.
- `batch_seconds`: default 5, range 1–60. `collapse_minutes`: default 10, range 1–1440. `max_collapse_keys`: default 2,000, range 1–100,000.
- Datagrams are read into an 8 KiB buffer. The socket is **never connected**: always `recv_from`.
- Text fields are at most 256 characters with control characters removed. `proto` is at most 16 and `device_model` at most 64. The class keys in `dropped_classes` are at most 64 characters, and `risk:<value>` at most 32 for the value.
- `confidence` is always 80. `rule_set_id` is `device-unifi` (`platform_store::device_alarms::RULE_SET`) and `rule_id` is `ips.<signature_id>`.
- The receive time is the event time. `UNIFIutcTime` is ignored.
- `clippy.toml` disallows `std::process::Command`, and this crate needs none. Workspace lints apply (`[lints] workspace = true`).
- Fixtures (committed with the spec):
  - `crates/openvibes-netlog/tests/fixtures/ucgmax-ips-blacksun.cef`: the real UCG Max IPS line, with MAC and hostname replaced.
  - `crates/openvibes-netlog/tests/fixtures/ucgmax-syslog.txt`: a real non-CEF line.

## Router settings changes (user, 2026-10-10)

Changing the UniFi Activity Logging settings restarts the gateway's
syslog-ng (seen at 17:24:15 in the capture) and changes what it sends.
Each case and where it is handled:

| Change on the router | Effect | Handled by |
|---|---|---|
| Any save (daemon restart) | new UDP source port | `recv_from`, never `connect` (Task 8 test sends from two ports) |
| Categories or Debug Logs toggled | more or fewer plain syslog / other CEF classes | `not_cef` and `dropped_classes` counters (Task 7) |
| Firmware/Network app upgrade | CEF keys change (older firmware has `UNIFIsubCategory`, newer has `UNIFIpolicyType`) | classification keys on `UNIFIcategory=Security` + `UNIFIipsSignatureId` only; both formats tested (Task 6) |
| SIEM server address or port changed away | silence | `devices::heads_up` → `SILENT` after a day (Part 1, Task 2) |
| SIEM switched off and on again | restart, new port | same as the first row |

## Review Focus

1. **The router restarts its log daemon and sends from a new source port.** Alarms keep arriving. Test: the integration test sends from two sockets with the same IP (Task 8).
2. **A CEF value that contains spaces, commas and `:`** (`UNIFIflowStartTime=Oct 10, 2026 at 5:36:00.239 PM`). It stays one value, and the next key still parses. Test: the real fixture (Task 5).
3. **A registered sender floods random class IDs.** Memory stays bounded: per-flush `classes` keeps at most 64 keys, and the collapse map is capped. Test in Task 7.
4. **An IPS line without ports** (ICMP). It is still an alarm, with ports absent. Test in Task 6.
5. **The database is down for minutes.** Alarms wait in the collapse map, nothing grows beyond `max_collapse_keys`, and they are stored once the database is back. Test in Task 7 (unit level: `stored` is never called, and entries stay dirty and are never expired).

---

### Task 5: Crate skeleton and `cef` parser

**Files:**
- Create: `crates/openvibes-netlog/Cargo.toml`, `crates/openvibes-netlog/src/lib.rs`, `crates/openvibes-netlog/src/cef.rs`
- Modify: root `Cargo.toml` `members` (add `"crates/openvibes-netlog"` after `"crates/openvibes-vulns"`)

**Interfaces:**
- Produces: `pub const MAX_DATAGRAM: usize = 8192`; `pub enum Parsed { NotCef, Unparsed, Cef(Cef) }`; `#[derive(Clone, Debug, Default, PartialEq, Eq)] pub struct Cef { pub vendor: String, pub product: String, pub device_version: String, pub class_id: String, pub name: String, pub severity: String, pub ext: BTreeMap<String, String> }`; `pub fn parse(datagram: &[u8]) -> Parsed`.

- [ ] **Step 1: Create the crate**

`crates/openvibes-netlog/Cargo.toml`:

```toml
[package]
name = "openvibes-netlog"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
axum.workspace = true
chrono.workspace = true
platform-config = { path = "../platform-config" }
platform-store = { path = "../platform-store" }
serde.workspace = true
serde_json.workspace = true
tokio.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true

[dev-dependencies]
deadpool-postgres.workspace = true

[lints]
workspace = true
```

`src/lib.rs`:

```rust
#![forbid(unsafe_code)]

//! `openvibes-netlog`: UniFi IPS/IDS events over syslog (CEF, UDP) become
//! alarms (spec 2026-10-10-network-device-alarms).

pub mod cef;
```

- [ ] **Step 2: Write the failing tests** (bottom of `src/cef.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = include_str!("../tests/fixtures/ucgmax-ips-blacksun.cef");
    const SYSLOG: &str = include_str!("../tests/fixtures/ucgmax-syslog.txt");

    #[test]
    fn the_real_ucg_max_line_parses() {
        let Parsed::Cef(cef) = parse(REAL.as_bytes()) else { panic!("not parsed") };
        assert_eq!((cef.vendor.as_str(), cef.class_id.as_str(), cef.severity.as_str()), ("Ubiquiti", "201", "9"));
        assert_eq!(cef.name, "Threat Detected and Blocked");
        assert_eq!(cef.ext["UNIFIipsSignatureId"], "2008983");
        assert_eq!(cef.ext["UNIFIipsSignature"], "ET USER_AGENTS Suspicious User Agent (BlackSun)");
        assert_eq!(cef.ext["UNIFIflowStartTime"], "Oct 10, 2026 at 5:36:00.239 PM");
        assert_eq!(cef.ext["msg"], "A network intrusion attempt from 192.168.1.10 to 172.66.147.243 has been detected and blocked.");
        assert_eq!(cef.ext["UNIFIpolicyType"], "IDS/IPS");
    }

    #[test]
    fn plain_syslog_is_not_cef() {
        assert_eq!(parse(SYSLOG.as_bytes()), Parsed::NotCef);
    }

    #[test]
    fn escapes_are_decoded_once() {
        let Parsed::Cef(cef) = parse(br"<14>x CEF:0|V\|x|P|1|2|N|3|a=1\=2 b=c\\d e=f\ng") else { panic!() };
        assert_eq!(cef.vendor, "V|x");
        assert_eq!((cef.ext["a"].as_str(), cef.ext["b"].as_str(), cef.ext["e"].as_str()), ("1=2", r"c\d", "f\ng"));
    }

    #[test]
    fn broken_input_is_unparsed() {
        for bad in [
            &b"CEF:0|only|three|fields"[..],
            b"CEF:0|a|b|c|d|e|f|junk before key=v",
            b"CEF:0|a|b|c|d|e|f|k=1 k=2",
            b"CEF:0|a|b|c|d|e|f|k=\xff",
            b"CEF:0|a|b|c|d|e|f|trailing\\",
        ] {
            assert_eq!(parse(bad), Parsed::Unparsed, "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn more_than_64_keys_is_unparsed() {
        let ext: Vec<String> = (0..65).map(|n| format!("k{n}=v")).collect();
        let line = format!("CEF:0|a|b|c|d|e|f|{}", ext.join(" "));
        assert_eq!(parse(line.as_bytes()), Parsed::Unparsed);
    }

    #[test]
    fn mutated_input_never_panics() {
        // ponytail: a fixed xorshift mutation loop, not a fuzzer; cargo-fuzz
        // if the parser grows.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for round in 0..20_000_usize {
            let mut buf = if round % 2 == 0 { REAL.as_bytes().to_vec() } else { b"CEF:0|a|b|c|d|e|f|k=v".to_vec() };
            for _ in 0..=(round % 8) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let pos = usize::try_from(x % (buf.len() as u64 + 1)).unwrap_or(0);
                match x % 3 {
                    0 => buf.insert(pos, (x >> 8) as u8),
                    1 if !buf.is_empty() => {
                        buf.remove(pos.min(buf.len() - 1));
                    }
                    _ if pos < buf.len() => buf[pos] = (x >> 16) as u8,
                    _ => {}
                }
            }
            let _ = parse(&buf);
        }
    }
}
```

- [ ] **Step 3: Run them to make sure they fail**

Run: `cargo test -p openvibes-netlog cef`
Expected: FAIL to compile, `cannot find function parse`.

- [ ] **Step 4: Implement `cef.rs`** (above the tests)

```rust
//! Syslog datagrams that carry CEF (`CEF:0|vendor|product|version|class|
//! name|severity|key=value ...`). The syslog header is not parsed: CEF
//! starts at the first `CEF:0|`. Bounded: at most one datagram
//! (`MAX_DATAGRAM`) and 64 extension keys; never panics.

use std::collections::BTreeMap;

/// Receive buffer; longer datagrams are truncated and fail to parse.
pub const MAX_DATAGRAM: usize = 8192;
const MAX_KEYS: usize = 64;

/// What a datagram is.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// No `CEF:0|` in it (plain syslog).
    NotCef,
    /// CEF that does not parse.
    Unparsed,
    Cef(Cef),
}

/// One CEF event, escapes decoded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cef {
    pub vendor: String,
    pub product: String,
    pub device_version: String,
    pub class_id: String,
    pub name: String,
    pub severity: String,
    pub ext: BTreeMap<String, String>,
}

#[must_use]
pub fn parse(datagram: &[u8]) -> Parsed {
    const MARK: &[u8] = b"CEF:0|";
    let Some(at) = datagram.windows(MARK.len()).position(|w| w == MARK) else {
        return Parsed::NotCef;
    };
    let Ok(text) = std::str::from_utf8(&datagram[at + MARK.len()..]) else {
        return Parsed::Unparsed;
    };
    match cef(text.trim_end_matches(['\n', '\r', '\0'])) {
        Some(cef) => Parsed::Cef(cef),
        None => Parsed::Unparsed,
    }
}

/// Six header fields (`\|` and `\\` escaped), then the extension.
fn cef(text: &str) -> Option<Cef> {
    let mut fields = Vec::with_capacity(6);
    let mut current = String::new();
    let mut chars = text.char_indices();
    let mut rest = None;
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                (_, e @ ('|' | '\\')) => current.push(e),
                (_, e) => {
                    current.push('\\');
                    current.push(e);
                }
            },
            '|' => {
                fields.push(std::mem::take(&mut current));
                if fields.len() == 6 {
                    rest = Some(&text[i + 1..]);
                    break;
                }
            }
            c => current.push(c),
        }
    }
    let [vendor, product, device_version, class_id, name, severity]: [String; 6] = fields.try_into().ok()?;
    Some(Cef { vendor, product, device_version, class_id, name, severity, ext: extensions(rest?)? })
}

/// `key=value` pairs: a key is `[A-Za-z0-9_]+` at the start or after a
/// space, followed by an unescaped `=`; a value runs to the next key.
fn extensions(s: &str) -> Option<BTreeMap<String, String>> {
    let b = s.as_bytes();
    let mut keys: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if i == 0 || b[i - 1] == b' ' {
            let mut j = i;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                j += 1;
            }
            if j > i && j < b.len() && b[j] == b'=' {
                keys.push((i, j));
                if keys.len() > MAX_KEYS {
                    return None;
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    let start = keys.first().map_or(b.len(), |&(k, _)| k);
    if !s[..start].trim().is_empty() {
        return None;
    }
    let mut ext = BTreeMap::new();
    for (n, &(k, eq)) in keys.iter().enumerate() {
        let end = keys.get(n + 1).map_or(b.len(), |&(next, _)| next);
        let value = unescape(s[eq + 1..end].trim_end_matches(' '))?;
        if ext.insert(s[k..eq].to_owned(), value).is_some() {
            return None;
        }
    }
    Some(ext)
}

/// `\=`, `\\`, `\n`, `\r`; any other escape is kept as written; a trailing
/// lone backslash is refused.
fn unescape(v: &str) -> Option<String> {
    let mut out = String::with_capacity(v.len());
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            e @ ('=' | '\\') => out.push(e),
            e => {
                out.push('\\');
                out.push(e);
            }
        }
    }
    Some(out)
}
```

Byte offsets `i`, `j` and `end` always fall on ASCII bytes (a space, a key character or `=`), so the `&s[..]` slices are on character boundaries. The fixture line ends with a newline; `trim_end_matches` removes it.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p openvibes-netlog && cargo clippy -p openvibes-netlog --all-targets -- -D warnings`
Expected: PASS. If clippy rejects `(x >> 8) as u8` (`cast_possible_truncation` is pedantic, not in `all`), use `x.to_le_bytes()[1]`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/openvibes-netlog
git commit -m "Netlog: crate and bounded CEF parser"
```

---

### Task 6: `unifi` classification

**Files:**
- Create: `crates/openvibes-netlog/src/unifi.rs`
- Modify: `src/lib.rs` (`pub mod unifi;`)

**Interfaces:**
- Consumes: `cef::Cef`.
- Produces:
  - `#[derive(Clone, Debug, PartialEq, Eq)] pub struct Ips { pub action: String, pub proto: String, pub app: String, pub src: IpAddr, pub spt: Option<u16>, pub dst: IpAddr, pub dpt: Option<u16>, pub dst_domain: String, pub direction: String, pub policy: String, pub policy_type: String, pub signature: String, pub signature_id: String, pub device_model: String, pub severity: &'static str, pub unknown_risk: Option<String>, pub message: String }`
  - `impl Ips { pub fn network(&self) -> serde_json::Value }`
  - `#[derive(Debug, PartialEq, Eq)] pub enum Outcome { Ips(Box<Ips>), Other(String), Mismatch, Unparsed }`
  - `pub fn classify(cef: &Cef, device: IpAddr) -> Outcome`
  - `pub fn severity(risk: Option<&str>, cef_severity: &str) -> (&'static str, Option<String>)`
  - `pub fn clean(s: &str, max: usize) -> String`

- [ ] **Step 1: Write the failing tests** (bottom of `src/unifi.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cef::{Parsed, parse};

    const REAL: &str = include_str!("../tests/fixtures/ucgmax-ips-blacksun.cef");
    const ROUTER: &str = "192.168.1.1";

    fn cef(line: &str) -> Cef {
        let Parsed::Cef(cef) = parse(line.as_bytes()) else { panic!("not CEF") };
        cef
    }

    fn router() -> IpAddr {
        ROUTER.parse().unwrap()
    }

    #[test]
    fn the_real_line_is_an_ips_alarm() {
        let Outcome::Ips(ips) = classify(&cef(REAL), router()) else { panic!("not IPS") };
        assert_eq!(ips.action, "blocked");
        assert_eq!((ips.severity, ips.unknown_risk.as_deref()), ("high", None));
        assert_eq!(ips.signature_id, "2008983");
        assert_eq!(ips.src.to_string(), "192.168.1.10");
        assert_eq!((ips.spt, ips.dpt), (Some(36216), Some(80)));
        assert_eq!((ips.direction.as_str(), ips.policy.as_str(), ips.dst_domain.as_str()), ("outgoing", "Malicious User Agents", "www.example.com"));
        assert_eq!(ips.message, "ET USER_AGENTS Suspicious User Agent (BlackSun): A network intrusion attempt from 192.168.1.10 to 172.66.147.243 has been detected and blocked.");
        assert_eq!(ips.network()["signature_id"], "2008983");
    }

    #[test]
    fn the_older_graylog_format_with_sub_category_is_an_ips_alarm_too() {
        // UniFi Network 9.4.19 as quoted by Graylog's content pack: has
        // UNIFIsubCategory, no UNIFIpolicyType, no act.
        let old = "<14>Oct 10 17:08:29 pandora CEF:0|Ubiquiti|UniFi Network|9.4.19|201|Threat Detected and Blocked|7|proto=TCP src=81.181.129.172 spt=54321 dst=192.168.0.233 dpt=443 UNIFIcategory=Security UNIFIsubCategory=Intrusion Prevention UNIFIhost=Office-UDM-Pro UNIFIdeviceMac=84:78:48:80:0d:86 UNIFIdeviceName=Office-UDM-Pro UNIFIdeviceModel=UDM-Pro UNIFIdeviceIp=192.168.0.1 UNIFIrisk=medium UNIFIipsSignature=ET DROP Dshield Block Listed Source group 1 UNIFIipsSignatureId=2402000 msg=A network intrusion attempt has been detected and blocked.";
        let Outcome::Ips(ips) = classify(&cef(old), "192.168.0.1".parse().unwrap()) else { panic!("not IPS") };
        assert_eq!((ips.action.as_str(), ips.severity, ips.signature_id.as_str()), ("blocked", "medium", "2402000"));
    }

    #[test]
    fn a_wrong_device_ip_is_a_mismatch() {
        assert_eq!(classify(&cef(REAL), "10.0.0.1".parse().unwrap()), Outcome::Mismatch);
    }

    #[test]
    fn security_without_a_signature_and_other_vendors_are_other() {
        let admin = "CEF:0|Ubiquiti|UniFi Network|10.6.106|544|Admin Accessed UniFi Network|1|UNIFIcategory=System UNIFIsubCategory=Admin";
        assert_eq!(classify(&cef(admin), router()), Outcome::Other("544:Admin".into()));
        let other = REAL.replace("|Ubiquiti|", "|Acme|");
        assert!(matches!(classify(&cef(&other), router()), Outcome::Other(_)));
    }

    #[test]
    fn icmp_without_ports_is_still_an_alarm_but_a_bad_port_is_unparsed() {
        let icmp = REAL.replace("spt=36216 dpt=80 ", "").replace("proto=TCP", "proto=ICMP");
        let Outcome::Ips(ips) = classify(&cef(&icmp), router()) else { panic!() };
        assert_eq!((ips.spt, ips.dpt), (None, None));
        assert_eq!(classify(&cef(&REAL.replace("spt=36216", "spt=99999")), router()), Outcome::Unparsed);
        assert_eq!(classify(&cef(&REAL.replace("src=192.168.1.10", "src=nope")), router()), Outcome::Unparsed);
        assert_eq!(classify(&cef(&REAL.replace("SignatureId=2008983", "SignatureId=12a")), router()), Outcome::Unparsed);
    }

    #[test]
    fn severity_maps_known_risks_and_falls_back_to_cef_severity() {
        assert_eq!(severity(Some("high"), "9"), ("high", None));
        assert_eq!(severity(Some("Suspicious"), "7"), ("medium", None));
        assert_eq!(severity(Some("concerning"), "7"), ("high", Some("concerning".into())));
        assert_eq!(severity(None, "2"), ("low", None));
        assert_eq!(severity(None, "10"), ("critical", None));
        assert_eq!(severity(None, "x"), ("medium", None));
    }

    #[test]
    fn clean_removes_controls_and_caps_length() {
        assert_eq!(clean("a\u{1b}[31mb\n", 256), "a[31mb");
        assert_eq!(clean(&"é".repeat(300), 256).chars().count(), 256);
    }
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-netlog unifi`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `unifi.rs`**

```rust
//! UniFi CEF → an IPS/IDS event or the reason it is dropped (spec §2–3).
//! Every field is hostile input (anyone can send UDP): addresses and ports
//! parse strictly, text is cleaned and capped.

use std::net::IpAddr;

use crate::cef::Cef;

/// One IPS/IDS event, validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ips {
    pub action: String,
    pub proto: String,
    pub app: String,
    pub src: IpAddr,
    pub spt: Option<u16>,
    pub dst: IpAddr,
    pub dpt: Option<u16>,
    pub dst_domain: String,
    pub direction: String,
    pub policy: String,
    pub policy_type: String,
    pub signature: String,
    pub signature_id: String,
    pub device_model: String,
    pub severity: &'static str,
    /// `UNIFIrisk` when it is not in the table (counted as `risk:<value>`).
    pub unknown_risk: Option<String>,
    pub message: String,
}

impl Ips {
    /// The alarm's `network` column.
    #[must_use]
    pub fn network(&self) -> serde_json::Value {
        serde_json::json!({
            "action": self.action, "proto": self.proto, "app": self.app,
            "src": self.src.to_string(), "spt": self.spt,
            "dst": self.dst.to_string(), "dpt": self.dpt,
            "dst_domain": self.dst_domain, "direction": self.direction,
            "policy": self.policy, "policy_type": self.policy_type,
            "signature": self.signature, "signature_id": self.signature_id,
            "device_model": self.device_model,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Ips(Box<Ips>),
    /// Not an IPS/IDS event; the class key it is counted under.
    Other(String),
    /// `UNIFIdeviceIp` is not the sender's registered address.
    Mismatch,
    /// An IPS/IDS event whose fields do not validate.
    Unparsed,
}

#[must_use]
pub fn classify(cef: &Cef, device: IpAddr) -> Outcome {
    let get = |k: &str| cef.ext.get(k).map(String::as_str);
    let ips = cef.vendor == "Ubiquiti" && get("UNIFIcategory") == Some("Security") && get("UNIFIipsSignatureId").is_some();
    if !ips {
        let kind = get("UNIFIpolicyType").or(get("UNIFIsubCategory")).unwrap_or("");
        return Outcome::Other(clean(&format!("{}:{kind}", cef.class_id), 64));
    }
    if let Some(ip) = get("UNIFIdeviceIp")
        && ip.parse::<IpAddr>().ok() != Some(device)
    {
        return Outcome::Mismatch;
    }
    match fields(cef) {
        Some(ips) => Outcome::Ips(Box::new(ips)),
        None => Outcome::Unparsed,
    }
}

fn port(v: Option<&str>) -> Option<Option<u16>> {
    match v {
        None => Some(None),
        Some(v) => v.parse().ok().map(Some),
    }
}

fn fields(cef: &Cef) -> Option<Ips> {
    let get = |k: &str| cef.ext.get(k).map(String::as_str);
    let text = |k: &str| clean(get(k).unwrap_or(""), 256);
    let signature_id = get("UNIFIipsSignatureId")?;
    if signature_id.is_empty() || signature_id.len() > 12 || !signature_id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let signature = clean(get("UNIFIipsSignature").unwrap_or(&cef.name), 256);
    let msg = text("msg");
    let (severity, unknown_risk) = severity(get("UNIFIrisk"), &cef.severity);
    let action = match get("act") {
        Some(act) => clean(act, 32),
        None if cef.name.contains("Blocked") => "blocked".into(),
        None => "detected".into(),
    };
    let message = if msg.is_empty() { signature.clone() } else { clean(&format!("{signature}: {msg}"), 256) };
    Some(Ips {
        action,
        proto: clean(get("proto").unwrap_or(""), 16),
        app: text("app"),
        src: get("src")?.parse().ok()?,
        spt: port(get("spt"))?,
        dst: get("dst")?.parse().ok()?,
        dpt: port(get("dpt"))?,
        dst_domain: text("UNIFIdstDomain"),
        direction: text("UNIFIdirection"),
        policy: text("UNIFIpolicyName"),
        policy_type: text("UNIFIpolicyType"),
        signature,
        signature_id: signature_id.to_owned(),
        device_model: clean(get("UNIFIdeviceModel").unwrap_or(""), 64),
        severity,
        unknown_risk,
        message,
    })
}

/// `UNIFIrisk` through the table; otherwise CEF severity 0–3 low, 4–6
/// medium, 7–8 high, 9–10 critical (anything else medium), with the unknown
/// risk value returned for counting.
#[must_use]
pub fn severity(risk: Option<&str>, cef_severity: &str) -> (&'static str, Option<String>) {
    let known = match risk.map(str::to_ascii_lowercase).as_deref() {
        Some("low") => Some("low"),
        Some("medium" | "suspicious") => Some("medium"),
        Some("high") => Some("high"),
        Some("critical") => Some("critical"),
        _ => None,
    };
    if let Some(known) = known {
        return (known, None);
    }
    let fallback = match cef_severity.trim().parse::<u8>() {
        Ok(0..=3) => "low",
        Ok(4..=6) => "medium",
        Ok(7..=8) => "high",
        Ok(9..=10) => "critical",
        _ => "medium",
    };
    (fallback, risk.map(|r| clean(r, 32)))
}

/// Control characters removed, at most `max` characters.
#[must_use]
pub fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}
```

The admin-event string in the test is invented to stand in for a non-IPS event. Once captured lines include one, replace it with a real line.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p openvibes-netlog && cargo clippy -p openvibes-netlog --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-netlog/src
git commit -m "Netlog: UniFi IPS classification, severity table, field validation"
```

---

### Task 7: `collapse` and the per-datagram handler

**Files:**
- Create: `crates/openvibes-netlog/src/collapse.rs`, `crates/openvibes-netlog/src/handle.rs`
- Modify: `src/lib.rs` (`pub mod collapse; pub mod handle;`)

**Interfaces:**
- Consumes: `unifi::{classify, Ips, Outcome}`, `cef::{parse, Parsed}`, `platform_store::device_alarms::DeviceAlarm`, `platform_store::devices::Counters`.
- Produces:
  - `pub struct Collapser`, with `pub fn new(window: chrono::Duration, max_keys: usize) -> Self`, `pub fn add(&mut self, device_id: i64, ips: &Ips, now: DateTime<Utc>) -> bool` (false when full), `pub fn dirty(&self) -> Vec<DeviceAlarm>`, `pub fn stored(&mut self, batch: &[DeviceAlarm])`, `pub fn len(&self) -> usize`, `pub fn is_empty(&self) -> bool`
  - `#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)] pub struct HostCounters { pub unknown_sender: u64, pub collapse_full: u64, pub unstorable: u64 }`
  - `pub const MAX_CLASSES: usize = 64`
  - `pub fn handle(datagram: &[u8], sender: IpAddr, now: DateTime<Utc>, devices: &HashMap<IpAddr, i64>, counters: &mut HashMap<i64, Counters>, collapser: &mut Collapser, host: &mut HostCounters)`

- [ ] **Step 1: Write the failing tests** (bottom of `src/handle.rs`)

```rust
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::{Duration, Utc};

    use super::*;
    use crate::collapse::Collapser;

    const REAL: &str = include_str!("../tests/fixtures/ucgmax-ips-blacksun.cef");
    const SYSLOG: &str = include_str!("../tests/fixtures/ucgmax-syslog.txt");

    struct World {
        devices: HashMap<IpAddr, i64>,
        counters: HashMap<i64, Counters>,
        collapser: Collapser,
        host: HostCounters,
    }

    impl World {
        fn new(max_keys: usize) -> Self {
            Self {
                devices: HashMap::from([("192.168.1.1".parse().unwrap(), 7)]),
                counters: HashMap::new(),
                collapser: Collapser::new(Duration::minutes(10), max_keys),
                host: HostCounters::default(),
            }
        }
        fn send(&mut self, line: &str, from: &str, now: DateTime<Utc>) {
            handle(line.as_bytes(), from.parse().unwrap(), now, &self.devices, &mut self.counters, &mut self.collapser, &mut self.host);
        }
    }

    #[test]
    fn repeats_collapse_and_every_datagram_is_counted() {
        let mut w = World::new(100);
        let now = Utc::now();
        w.send(REAL, "192.168.1.1", now);
        w.send(REAL, "192.168.1.1", now + Duration::seconds(1));
        w.send(SYSLOG, "192.168.1.1", now);
        w.send(REAL, "192.168.1.99", now);
        let dirty = w.collapser.dirty();
        assert_eq!(dirty.len(), 1);
        assert_eq!((dirty[0].count, dirty[0].rule_id.as_str(), dirty[0].confidence), (2, "ips.2008983", 80));
        let c = &w.counters[&7];
        assert_eq!((c.received, c.alarms, c.not_cef), (3, 2, 1));
        assert_eq!(w.host.unknown_sender, 1);
    }

    #[test]
    fn a_new_alarm_after_the_quiet_window_and_stored_entries_expire() {
        let mut w = World::new(100);
        let now = Utc::now();
        w.send(REAL, "192.168.1.1", now);
        let batch = w.collapser.dirty();
        w.collapser.stored(&batch);
        w.send(REAL, "192.168.1.1", now + Duration::minutes(11));
        let dirty = w.collapser.dirty();
        assert_eq!(dirty.len(), 1);
        assert_ne!(dirty[0].alarm_id, batch[0].alarm_id);
    }

    #[test]
    fn unstored_alarms_never_expire_and_the_map_is_capped() {
        let mut w = World::new(2);
        let now = Utc::now();
        for n in 0..5 {
            let line = REAL.replace("src=192.168.1.10", &format!("src=10.0.0.{n}"));
            w.send(&line, "192.168.1.1", now + Duration::minutes(20 * n));
        }
        assert_eq!(w.collapser.len(), 2, "database down: the first two wait, the rest are dropped");
        assert_eq!(w.host.collapse_full, 3);
    }

    #[test]
    fn class_keys_per_flush_are_capped() {
        let mut w = World::new(100);
        for n in 0..200 {
            let line = format!("CEF:0|Ubiquiti|UniFi Network|1|{n}|x|1|UNIFIcategory=System");
            w.send(&line, "192.168.1.1", Utc::now());
        }
        assert_eq!(w.counters[&7].classes.len(), MAX_CLASSES);
        assert_eq!(w.counters[&7].dropped_other, 200);
    }
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-netlog handle`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `collapse.rs`**

```rust
//! Same device + signature + source within `window` of the last event is
//! one alarm (sliding: a scan that keeps going stays one alarm, quiet by
//! default). The map is also the retry buffer: a dirty entry (not yet
//! stored) never expires, and a full map drops new keys.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use chrono::{DateTime, Duration, Utc};
use platform_store::device_alarms::DeviceAlarm;

use crate::unifi::Ips;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct Key {
    device_id: i64,
    signature_id: String,
    src: IpAddr,
}

struct Entry {
    alarm: DeviceAlarm,
    dirty: bool,
}

pub struct Collapser {
    window: Duration,
    max_keys: usize,
    open: HashMap<Key, Entry>,
}

impl Collapser {
    #[must_use]
    pub fn new(window: Duration, max_keys: usize) -> Self {
        Self { window, max_keys, open: HashMap::new() }
    }

    /// Counts `ips` into its alarm; false when the map is full.
    pub fn add(&mut self, device_id: i64, ips: &Ips, now: DateTime<Utc>) -> bool {
        let window = self.window;
        self.open.retain(|_, e| e.dirty || e.alarm.last_seen + window > now);
        let key = Key { device_id, signature_id: ips.signature_id.clone(), src: ips.src };
        if let Some(entry) = self.open.get_mut(&key) {
            entry.alarm.count += 1;
            entry.alarm.last_seen = now;
            entry.alarm.network = ips.network();
            entry.dirty = true;
            return true;
        }
        if self.open.len() >= self.max_keys {
            return false;
        }
        let alarm = DeviceAlarm {
            device_id,
            alarm_id: format!("{}/{}/{}", ips.signature_id, ips.src, now.timestamp_millis()),
            rule_id: format!("ips.{}", ips.signature_id),
            severity: ips.severity.to_owned(),
            confidence: 80,
            message: ips.message.clone(),
            first_seen: now,
            last_seen: now,
            count: 1,
            network: ips.network(),
        };
        self.open.insert(key, Entry { alarm, dirty: true });
        true
    }

    /// Alarms changed since they were last stored.
    #[must_use]
    pub fn dirty(&self) -> Vec<DeviceAlarm> {
        self.open.values().filter(|e| e.dirty).map(|e| e.alarm.clone()).collect()
    }

    /// `batch` (from [`Self::dirty`]) is stored: entries that did not change
    /// since are clean.
    pub fn stored(&mut self, batch: &[DeviceAlarm]) {
        let done: HashSet<(i64, &str, i64)> = batch.iter().map(|a| (a.device_id, a.alarm_id.as_str(), a.count)).collect();
        for entry in self.open.values_mut() {
            if done.contains(&(entry.alarm.device_id, entry.alarm.alarm_id.as_str(), entry.alarm.count)) {
                entry.dirty = false;
            }
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.open.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }
}
```

`retain` on every `add` is O(keys), at most 2,000 by default. `// ponytail: expire on add, O(keys); a time wheel if max_collapse_keys grows past ~100k.`

- [ ] **Step 4: Implement `handle.rs`** (above the tests)

```rust
//! One datagram: sender filter, parse, classify, collapse, count.

use std::{collections::HashMap, net::IpAddr};

use chrono::{DateTime, Utc};
use platform_store::devices::Counters;

use crate::{
    cef::{Parsed, parse},
    collapse::Collapser,
    unifi::{Outcome, classify},
};

/// Class keys kept per device between flushes (the stored map is capped
/// at the same size).
pub const MAX_CLASSES: usize = 64;

/// Drops that belong to no device; logged at each flush.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostCounters {
    pub unknown_sender: u64,
    pub collapse_full: u64,
    pub unstorable: u64,
}

fn bump(classes: &mut std::collections::BTreeMap<String, i64>, key: String) {
    if classes.len() < MAX_CLASSES || classes.contains_key(&key) {
        *classes.entry(key).or_default() += 1;
    }
}

pub fn handle(
    datagram: &[u8],
    sender: IpAddr,
    now: DateTime<Utc>,
    devices: &HashMap<IpAddr, i64>,
    counters: &mut HashMap<i64, Counters>,
    collapser: &mut Collapser,
    host: &mut HostCounters,
) {
    let sender = sender.to_canonical();
    let Some(&id) = devices.get(&sender) else {
        host.unknown_sender += 1;
        return;
    };
    let c = counters.entry(id).or_default();
    c.received += 1;
    c.last_seen = Some(now);
    match parse(datagram) {
        Parsed::NotCef => c.not_cef += 1,
        Parsed::Unparsed => c.unparsed += 1,
        Parsed::Cef(cef) => match classify(&cef, sender) {
            Outcome::Other(key) => {
                c.dropped_other += 1;
                bump(&mut c.classes, key);
            }
            Outcome::Mismatch => c.mismatch += 1,
            Outcome::Unparsed => c.unparsed += 1,
            Outcome::Ips(ips) => {
                if let Some(risk) = &ips.unknown_risk {
                    bump(&mut c.classes, format!("risk:{risk}"));
                }
                if collapser.add(id, &ips, now) {
                    c.alarms += 1;
                } else {
                    host.collapse_full += 1;
                }
            }
        },
    }
}
```

Clippy may flag `handle` for `too_many_arguments` (7 is the default limit, so it's at the edge). If it does, add `#[allow(clippy::too_many_arguments, reason = "the loop's state, passed apart so it can be tested")]`.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p openvibes-netlog && cargo clippy -p openvibes-netlog --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/openvibes-netlog/src
git commit -m "Netlog: collapse (sliding window, retry buffer) and datagram handler"
```

---

### Task 8: Config, service loop, binary, UDP integration test

**Files:**
- Create: `crates/openvibes-netlog/src/config.rs`, `src/service.rs`, `src/main.rs`, `crates/openvibes-netlog/tests/udp.rs`
- Modify: `src/lib.rs` (`pub mod config; pub mod service;`)

**Interfaces:**
- Consumes: everything above, plus `platform_store::{connect_sized, devices, device_alarms, schema_version, SCHEMA_VERSION}`.
- Produces:
  - `pub struct NetlogConfig { pub database_url: String, pub listen: SocketAddr, pub health_listen: SocketAddr, pub batch_seconds: u64, pub collapse_minutes: u64, pub max_collapse_keys: usize }`, with `validate(&self) -> Result<(), String>` and `pub fn load_config(path: &Path) -> Result<NetlogConfig, String>`
  - `pub async fn run(config: NetlogConfig, socket: tokio::net::UdpSocket, health: tokio::net::TcpListener, shutdown: impl Future<Output = ()>) -> Result<(), String>`
  - The binary `openvibes-netlog [--config PATH]`, with default config `/etc/openvibes/netlog.toml`

- [ ] **Step 1: Write the failing integration test** `tests/udp.rs`

```rust
//! A running netlog against a test database: alarms, collapse, counters,
//! unknown senders, a new source port after a log daemon restart.

#[path = "../../platform-store/tests/common/mod.rs"]
mod common;

use std::time::Duration;

use chrono::Utc;
use common::TestDb;
use openvibes_netlog::{config::NetlogConfig, service};
use tokio::net::{TcpListener, UdpSocket};

const REAL: &str = include_str!("fixtures/ucgmax-ips-blacksun.cef");
const SYSLOG: &str = include_str!("fixtures/ucgmax-syslog.txt");

#[tokio::test]
async fn ips_lines_from_a_registered_device_become_one_alarm() {
    let db = TestDb::create().await;
    let admin = db.pool.get().await.unwrap();
    {
        let mut c = db.pool.get().await.unwrap();
        platform_store::migrate(&mut c).await.unwrap();
    }
    platform_store::ensure_partitions(&admin, Utc::now().date_naive() - chrono::Duration::days(1), 3)
        .await
        .unwrap();
    let device = platform_store::devices::add(&admin, "UCG Max", "unifi", "127.0.0.1".parse().unwrap(), "t", Utc::now())
        .await
        .unwrap()
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let health = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = NetlogConfig {
        database_url: db.url(),
        listen: addr,
        health_listen: health.local_addr().unwrap(),
        batch_seconds: 1,
        collapse_minutes: 10,
        max_collapse_keys: 100,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(service::run(config, socket, health, async {
        let _ = stopped.await;
    }));
    let line = REAL.replace("UNIFIdeviceIp=192.168.1.1", "UNIFIdeviceIp=127.0.0.1");
    // The first log daemon, then a restarted one on a new source port.
    for _ in 0..2 {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(line.as_bytes(), addr).await.unwrap();
        sender.send_to(SYSLOG.as_bytes(), addr).await.unwrap();
    }
    let stranger = UdpSocket::bind("127.0.0.2:0").await.unwrap();
    stranger.send_to(line.as_bytes(), addr).await.unwrap();
    let mut seen = 0_i64;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Some(row) = admin.query_opt("SELECT count FROM alarms WHERE device_id = $1", &[&device]).await.unwrap() {
            seen = row.get(0);
            if seen == 2 {
                break;
            }
        }
    }
    assert_eq!(seen, 2, "two IPS lines, one alarm");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let d = platform_store::devices::list(&admin).await.unwrap().remove(0);
    assert_eq!((d.received, d.alarms, d.not_cef), (4, 2, 2));
    let _ = stop.send(());
    task.await.unwrap().unwrap();
    db.drop().await;
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cargo test -p openvibes-netlog --test udp`
Expected: FAIL to compile, `unresolved import openvibes_netlog::config`.

- [ ] **Step 3: Implement `config.rs`**

```rust
//! `/etc/openvibes/netlog.toml`.

use std::{net::SocketAddr, path::Path};

use serde::Deserialize;

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 514))
}
fn default_health() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 18484))
}
fn default_batch() -> u64 {
    5
}
fn default_collapse() -> u64 {
    10
}
fn default_keys() -> usize {
    2000
}

/// Service configuration; unknown keys are refused.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetlogConfig {
    /// PostgreSQL connection for the `openvibes-netlog` role.
    pub database_url: String,
    /// UDP syslog listener.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Loopback health listener (`/health`, `/ready`).
    #[serde(default = "default_health")]
    pub health_listen: SocketAddr,
    #[serde(default = "default_batch")]
    pub batch_seconds: u64,
    #[serde(default = "default_collapse")]
    pub collapse_minutes: u64,
    #[serde(default = "default_keys")]
    pub max_collapse_keys: usize,
}

impl NetlogConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.health_listen.ip().is_loopback() {
            return Err("health_listen must be a loopback address".into());
        }
        if !(1..=60).contains(&self.batch_seconds) {
            return Err("batch_seconds must be 1 to 60".into());
        }
        if !(1..=1440).contains(&self.collapse_minutes) {
            return Err("collapse_minutes must be 1 to 1440".into());
        }
        if !(1..=100_000).contains(&self.max_collapse_keys) {
            return Err("max_collapse_keys must be 1 to 100000".into());
        }
        Ok(())
    }
}

pub fn load_config(path: &Path) -> Result<NetlogConfig, String> {
    let config: NetlogConfig = platform_config::load(path).map_err(|error| error.to_string())?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_ranges() {
        let c: NetlogConfig = toml_from("database_url = \"postgresql:///x\"");
        assert_eq!((c.listen.port(), c.health_listen.port(), c.max_collapse_keys), (514, 18484, 2000));
        assert!(c.validate().is_ok());
        let mut bad = c.clone();
        bad.health_listen = "0.0.0.0:18484".parse().unwrap();
        assert!(bad.validate().is_err());
        let mut bad = c;
        bad.batch_seconds = 0;
        assert!(bad.validate().is_err());
    }

    fn toml_from(s: &str) -> NetlogConfig {
        let dir = std::env::temp_dir().join(format!("netlog-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("netlog.toml");
        std::fs::write(&path, s).unwrap();
        let c = platform_config::load(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        c
    }
}
```

- [ ] **Step 4: Implement `service.rs`**

```rust
//! The loop: datagrams, a flush every `batch_seconds`, devices reloaded
//! every 30 s and on SIGHUP. One task, so no locks; a slow flush leaves
//! datagrams in the kernel's receive buffer.
// ponytail: single task; split receive and store if a flush ever takes
// longer than the socket buffer covers.

use std::{collections::HashMap, future::Future, net::IpAddr, time::Duration};

use axum::{Router, extract::State, http::StatusCode, routing::get};
use chrono::Utc;
use platform_store::{Pool, device_alarms, devices::{self, Counters}};
use tokio::{
    net::{TcpListener, UdpSocket},
    signal::unix::{SignalKind, signal},
};

use crate::{
    cef::MAX_DATAGRAM,
    collapse::Collapser,
    config::NetlogConfig,
    handle::{HostCounters, handle},
};

pub async fn run(
    config: NetlogConfig,
    socket: UdpSocket,
    health: TcpListener,
    shutdown: impl Future<Output = ()>,
) -> Result<(), String> {
    config.validate()?;
    let pool = platform_store::connect_sized(&config.database_url, 2)
        .await
        .map_err(|error| error.to_string())?;
    let health_pool = pool.clone();
    let health_task = tokio::spawn(async move {
        let app = Router::new()
            .route("/health", get(|| async { StatusCode::OK }))
            .route("/ready", get(ready))
            .with_state(health_pool);
        let _ = axum::serve(health, app).await;
    });
    let window = chrono::Duration::minutes(i64::try_from(config.collapse_minutes).unwrap_or(10));
    let mut collapser = Collapser::new(window, config.max_collapse_keys);
    let mut known: HashMap<IpAddr, i64> = HashMap::new();
    let mut counters: HashMap<i64, Counters> = HashMap::new();
    let mut host = HostCounters::default();
    let mut buf = vec![0_u8; MAX_DATAGRAM];
    let mut flush = tokio::time::interval(Duration::from_secs(config.batch_seconds));
    let mut reload = tokio::time::interval(Duration::from_secs(30));
    let mut hup = signal(SignalKind::hangup()).map_err(|error| format!("SIGHUP: {error}"))?;
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            received = socket.recv_from(&mut buf) => {
                if let Ok((n, from)) = received {
                    handle(&buf[..n], from.ip(), Utc::now(), &known, &mut counters, &mut collapser, &mut host);
                }
            }
            _ = flush.tick() => store(&pool, &mut counters, &mut collapser, &mut host).await,
            _ = reload.tick() => load_devices(&pool, &mut known).await,
            _ = hup.recv() => load_devices(&pool, &mut known).await,
        }
    }
    store(&pool, &mut counters, &mut collapser, &mut host).await;
    health_task.abort();
    Ok(())
}

async fn load_devices(pool: &Pool, known: &mut HashMap<IpAddr, i64>) {
    let Ok(client) = pool.get().await else {
        tracing::warn!("database unavailable; devices not reloaded");
        return;
    };
    match devices::active(&client).await {
        Ok(list) => *known = list.into_iter().map(|(id, address)| (address, id)).collect(),
        Err(error) => tracing::warn!(%error, "devices not reloaded"),
    }
}

/// Alarms first (they matter most), then counters. Whatever fails stays in
/// memory for the next tick.
async fn store(pool: &Pool, counters: &mut HashMap<i64, Counters>, collapser: &mut Collapser, host: &mut HostCounters) {
    let Ok(mut client) = pool.get().await else {
        tracing::warn!(waiting = collapser.dirty().len(), "database unavailable; alarms kept for the next try");
        return;
    };
    let batch = collapser.dirty();
    if !batch.is_empty() {
        match device_alarms::insert_batch(&mut client, &batch, Utc::now()).await {
            Ok(done) => {
                collapser.stored(&batch);
                host.unstorable += u64::from(done.unstorable);
            }
            Err(error) => {
                tracing::warn!(%error, "storing device alarms failed; kept for the next try");
                return;
            }
        }
    }
    let ids: Vec<i64> = counters.keys().copied().collect();
    for id in ids {
        if devices::flush(&mut client, id, &counters[&id]).await.is_ok() {
            counters.remove(&id);
        }
    }
    if *host != HostCounters::default() {
        tracing::info!(
            unknown_sender = host.unknown_sender,
            collapse_full = host.collapse_full,
            unstorable = host.unstorable,
            "netlog dropped datagrams"
        );
        *host = HostCounters::default();
    }
}

async fn ready(State(pool): State<Pool>) -> StatusCode {
    let Ok(client) = pool.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    match platform_store::schema_version(&client).await {
        Ok(Some(version)) if version == platform_store::SCHEMA_VERSION => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}
```

If `platform_store::Pool` isn't re-exported under that name, use `deadpool_postgres::Pool` (it is re-exported at `crates/platform-store/src/lib.rs:75`).

- [ ] **Step 5: Implement `main.rs`**

```rust
#![forbid(unsafe_code)]

//! `openvibes-netlog [--config PATH]`: network device events (UniFi
//! IPS/IDS over syslog) become alarms.

use std::{path::PathBuf, process::ExitCode};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let path = match (args.next().as_deref(), args.next(), args.next()) {
        (None, None, None) => PathBuf::from("/etc/openvibes/netlog.toml"),
        (Some("--config"), Some(path), None) => PathBuf::from(path),
        _ => {
            eprintln!("usage: openvibes-netlog [--config PATH]");
            return ExitCode::from(2);
        }
    };
    tracing_subscriber::fmt().json().with_writer(std::io::stderr).init();
    let config = match openvibes_netlog::config::load_config(&path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("openvibes-netlog: invalid netlog configuration: {error}");
            return ExitCode::FAILURE;
        }
    };
    let socket = match tokio::net::UdpSocket::bind(config.listen).await {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("openvibes-netlog: cannot bind {}: {error}", config.listen);
            return ExitCode::FAILURE;
        }
    };
    let health = match tokio::net::TcpListener::bind(config.health_listen).await {
        Ok(listener) => listener,
        Err(_) => {
            eprintln!("openvibes-netlog: cannot bind the health listener");
            return ExitCode::FAILURE;
        }
    };
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    match openvibes_netlog::service::run(config, socket, health, shutdown).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openvibes-netlog: {error}");
            ExitCode::FAILURE
        }
    }
}
```

`current_thread` keeps the footprint small, and one loop needs no more.

- [ ] **Step 6: Run everything**

Run: `cargo test -p openvibes-netlog && cargo clippy -p openvibes-netlog --all-targets -- -D warnings && cargo fmt --all --check`
Expected: PASS. The integration test needs `eval "$(scripts/test-db.sh)"` and the loopback alias 127.0.0.2. That exists on Linux, where all of 127/8 is loopback.

- [ ] **Step 7: Commit**

```bash
git add crates/openvibes-netlog
git commit -m "Netlog: config, service loop, binary, UDP integration test"
```
