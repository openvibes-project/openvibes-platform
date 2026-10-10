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
    let [vendor, product, device_version, class_id, name, severity]: [String; 6] =
        fields.try_into().ok()?;
    Some(Cef {
        vendor,
        product,
        device_version,
        class_id,
        name,
        severity,
        ext: extensions(rest?)?,
    })
}

/// `key=value` pairs: a key is `[A-Za-z0-9_]+` at the start or after a
/// space, followed by an unescaped `=`; a value runs to the next key, and
/// `msg` to the end.
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
                // Free text: producers leave `=` unescaped in it, and
                // UniFi puts it last, so it runs to the end of the line.
                // ponytail: msg-last is UniFi's layout; another vendor may
                // need its own rule.
                if &s[i..j] == "msg" {
                    break;
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

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = include_str!("../tests/fixtures/ucgmax-ips-blacksun.cef");
    const SYSLOG: &str = include_str!("../tests/fixtures/ucgmax-syslog.txt");

    #[test]
    fn the_real_ucg_max_line_parses() {
        let Parsed::Cef(cef) = parse(REAL.as_bytes()) else {
            panic!("not parsed")
        };
        assert_eq!(
            (
                cef.vendor.as_str(),
                cef.class_id.as_str(),
                cef.severity.as_str()
            ),
            ("Ubiquiti", "201", "9")
        );
        assert_eq!(cef.name, "Threat Detected and Blocked");
        assert_eq!(cef.ext["UNIFIipsSignatureId"], "2008983");
        assert_eq!(
            cef.ext["UNIFIipsSignature"],
            "ET USER_AGENTS Suspicious User Agent (BlackSun)"
        );
        assert_eq!(
            cef.ext["UNIFIflowStartTime"],
            "Oct 10, 2026 at 5:36:00.239 PM"
        );
        assert_eq!(
            cef.ext["msg"],
            "A network intrusion attempt from 192.168.1.10 to 172.66.147.243 has been detected and blocked."
        );
        assert_eq!(cef.ext["UNIFIpolicyType"], "IDS/IPS");
    }

    #[test]
    fn plain_syslog_is_not_cef() {
        assert_eq!(parse(SYSLOG.as_bytes()), Parsed::NotCef);
    }

    #[test]
    fn escapes_are_decoded_once() {
        let Parsed::Cef(cef) = parse(br"<14>x CEF:0|V\|x|P|1|2|N|3|a=1\=2 b=c\\d e=f\ng") else {
            panic!()
        };
        assert_eq!(cef.vendor, "V|x");
        assert_eq!(
            (
                cef.ext["a"].as_str(),
                cef.ext["b"].as_str(),
                cef.ext["e"].as_str()
            ),
            ("1=2", r"c\d", "f\ng")
        );
    }

    #[test]
    fn msg_takes_the_rest_even_with_an_unescaped_equals_sign() {
        // Review 2026-10-10: malformed producers write `=` unescaped in the
        // free text; UniFi puts msg last.
        let Parsed::Cef(cef) = parse(b"CEF:0|a|b|c|d|e|f|k=v msg=see url=http://x/?a=1 k=2") else {
            panic!()
        };
        assert_eq!(cef.ext["msg"], "see url=http://x/?a=1 k=2");
        assert_eq!(cef.ext["k"], "v");
        assert!(!cef.ext.contains_key("url"));
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
            assert_eq!(
                parse(bad),
                Parsed::Unparsed,
                "{}",
                String::from_utf8_lossy(bad)
            );
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
            let mut buf = if round % 2 == 0 {
                REAL.as_bytes().to_vec()
            } else {
                b"CEF:0|a|b|c|d|e|f|k=v".to_vec()
            };
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
