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
    let ips = cef.vendor == "Ubiquiti"
        && get("UNIFIcategory") == Some("Security")
        && get("UNIFIipsSignatureId").is_some();
    if !ips {
        let kind = get("UNIFIpolicyType")
            .or(get("UNIFIsubCategory"))
            .unwrap_or("");
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
    if signature_id.is_empty()
        || signature_id.len() > 12
        || !signature_id.bytes().all(|b| b.is_ascii_digit())
    {
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
    let message = if msg.is_empty() {
        signature.clone()
    } else {
        clean(&format!("{signature}: {msg}"), 256)
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cef::{Parsed, parse};

    const REAL: &str = include_str!("../tests/fixtures/ucgmax-ips-blacksun.cef");
    const ROUTER: &str = "192.168.1.1";

    fn cef(line: &str) -> Cef {
        let Parsed::Cef(cef) = parse(line.as_bytes()) else {
            panic!("not CEF")
        };
        cef
    }

    fn router() -> IpAddr {
        ROUTER.parse().unwrap()
    }

    #[test]
    fn the_real_line_is_an_ips_alarm() {
        let Outcome::Ips(ips) = classify(&cef(REAL), router()) else {
            panic!("not IPS")
        };
        assert_eq!(ips.action, "blocked");
        assert_eq!((ips.severity, ips.unknown_risk.as_deref()), ("high", None));
        assert_eq!(ips.signature_id, "2008983");
        assert_eq!(ips.src.to_string(), "192.168.1.10");
        assert_eq!((ips.spt, ips.dpt), (Some(36216), Some(80)));
        assert_eq!(
            (
                ips.direction.as_str(),
                ips.policy.as_str(),
                ips.dst_domain.as_str()
            ),
            ("outgoing", "Malicious User Agents", "www.example.com")
        );
        assert_eq!(
            ips.message,
            "ET USER_AGENTS Suspicious User Agent (BlackSun): A network intrusion attempt from 192.168.1.10 to 172.66.147.243 has been detected and blocked."
        );
        assert_eq!(ips.network()["signature_id"], "2008983");
    }

    #[test]
    fn the_older_graylog_format_with_sub_category_is_an_ips_alarm_too() {
        // UniFi Network 9.4.19 as quoted by Graylog's content pack: has
        // UNIFIsubCategory, no UNIFIpolicyType, no act.
        let old = "<14>Oct 10 17:08:29 pandora CEF:0|Ubiquiti|UniFi Network|9.4.19|201|Threat Detected and Blocked|7|proto=TCP src=81.181.129.172 spt=54321 dst=192.168.0.233 dpt=443 UNIFIcategory=Security UNIFIsubCategory=Intrusion Prevention UNIFIhost=Office-UDM-Pro UNIFIdeviceMac=84:78:48:80:0d:86 UNIFIdeviceName=Office-UDM-Pro UNIFIdeviceModel=UDM-Pro UNIFIdeviceIp=192.168.0.1 UNIFIrisk=medium UNIFIipsSignature=ET DROP Dshield Block Listed Source group 1 UNIFIipsSignatureId=2402000 msg=A network intrusion attempt has been detected and blocked.";
        let Outcome::Ips(ips) = classify(&cef(old), "192.168.0.1".parse().unwrap()) else {
            panic!("not IPS")
        };
        assert_eq!(
            (ips.action.as_str(), ips.severity, ips.signature_id.as_str()),
            ("blocked", "medium", "2402000")
        );
    }

    #[test]
    fn a_wrong_device_ip_is_a_mismatch() {
        assert_eq!(
            classify(&cef(REAL), "10.0.0.1".parse().unwrap()),
            Outcome::Mismatch
        );
    }

    #[test]
    fn security_without_a_signature_and_other_vendors_are_other() {
        let admin = "CEF:0|Ubiquiti|UniFi Network|10.6.106|544|Admin Accessed UniFi Network|1|UNIFIcategory=System UNIFIsubCategory=Admin";
        assert_eq!(
            classify(&cef(admin), router()),
            Outcome::Other("544:Admin".into())
        );
        let other = REAL.replace("|Ubiquiti|", "|Acme|");
        assert!(matches!(
            classify(&cef(&other), router()),
            Outcome::Other(_)
        ));
    }

    #[test]
    fn icmp_without_ports_is_still_an_alarm_but_a_bad_port_is_unparsed() {
        let icmp = REAL
            .replace("spt=36216 dpt=80 ", "")
            .replace("proto=TCP", "proto=ICMP");
        let Outcome::Ips(ips) = classify(&cef(&icmp), router()) else {
            panic!()
        };
        assert_eq!((ips.spt, ips.dpt), (None, None));
        assert_eq!(
            classify(&cef(&REAL.replace("spt=36216", "spt=99999")), router()),
            Outcome::Unparsed
        );
        assert_eq!(
            classify(
                &cef(&REAL.replace("src=192.168.1.10", "src=nope")),
                router()
            ),
            Outcome::Unparsed
        );
        assert_eq!(
            classify(
                &cef(&REAL.replace("SignatureId=2008983", "SignatureId=12a")),
                router()
            ),
            Outcome::Unparsed
        );
    }

    #[test]
    fn severity_maps_known_risks_and_falls_back_to_cef_severity() {
        assert_eq!(severity(Some("high"), "9"), ("high", None));
        assert_eq!(severity(Some("Suspicious"), "7"), ("medium", None));
        assert_eq!(
            severity(Some("concerning"), "7"),
            ("high", Some("concerning".into()))
        );
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
