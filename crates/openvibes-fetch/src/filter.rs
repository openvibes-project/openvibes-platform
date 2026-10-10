//! The query filter: the security core of web search. A query that could
//! carry internal data out is refused before any request is made.

use crate::protocol::Refusal;
use std::net::Ipv6Addr;

/// Longest query allowed, in characters.
const MAX_QUERY: usize = 200;

/// True for a public advisory identifier that may be fetched at level 1:
/// an uppercase prefix of 2-8 letters, `-`, at least 3 digits, then another
/// `-` or `:` part (so `CVE-2026` alone is not an ID), only `[A-Za-z0-9:-]`,
/// at most 64 characters.
pub fn is_public_id(id: &str) -> bool {
    let Some((prefix, rest)) = id.split_once('-') else {
        return false;
    };
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '-')
        && (2..=8).contains(&prefix.len())
        && prefix.chars().all(|c| c.is_ascii_uppercase())
        && digits >= 3
        && rest[digits..].starts_with(['-', ':'])
}

/// Refuses (`Blocked`) a query that is too long, contains a URL scheme, an
/// IP address, a MAC address or any `deny` term (already lowercase: agent
/// IDs, host and user names, internal domains). Matching is case-insensitive
/// and by substring, so a FQDN or a host name inside a longer word is caught.
pub fn check_query(query: &str, deny: &[String]) -> Result<(), Refusal> {
    let q = query.to_lowercase();
    if q.chars().count() > MAX_QUERY
        || q.contains("://")
        || deny.iter().any(|d| !d.is_empty() && q.contains(d.as_str()))
        || q.split(|c: char| c.is_whitespace() || ",;()\"'[]<>=/".contains(c))
            .map(|t| t.trim_end_matches(['.', ':']))
            .any(|t| is_ipv4(t) || is_ipv6(t) || is_mac(t))
    {
        return Err(Refusal::Blocked);
    }
    Ok(())
}

fn is_ipv4(t: &str) -> bool {
    let host = t.rsplit_once(':').map_or(t, |(h, p)| {
        if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) {
            h
        } else {
            t
        }
    });
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u8>().is_ok()
        })
}

fn is_ipv6(t: &str) -> bool {
    t.matches(':').count() >= 2 && t.parse::<Ipv6Addr>().is_ok()
}

fn is_mac(t: &str) -> bool {
    [':', '-'].iter().any(|&sep| {
        let g: Vec<&str> = t.split(sep).collect();
        g.len() == 6
            && g.iter()
                .all(|x| x.len() == 2 && x.bytes().all(|b| b.is_ascii_hexdigit()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn deny() -> Vec<String> {
        [
            "web-01",
            "agent.00000000-0000-4000-8000-000000000001",
            "alex",
            "corp.example",
        ]
        .map(String::from)
        .to_vec()
    }
    #[test]
    fn filter_refuses_internal_names_in_any_form() {
        for q in [
            "openssh WEB-01 regression",
            "web-01.corp.example ssh",
            "mail.corp.example exploit",
            "10.0.0.5:22 vulnerable",
            "fe80::1 ssh",
            "aa:bb:cc:dd:ee:ff",
            "see https://x.test",
            "agent.00000000-0000-4000-8000-000000000001",
            "alex password reset",
            "AA-BB-CC-DD-EE-FF",
            "[fe80::1]:22 ssh",
            "host=10.0.0.5.",
            "(192.168.1.1)",
        ] {
            assert_eq!(check_query(q, &deny()), Err(Refusal::Blocked), "{q}");
        }
        assert_eq!(
            check_query(&"a".repeat(201), &deny()),
            Err(Refusal::Blocked)
        );
        assert_eq!(
            check_query("CVE-2026-1234 mitigation workaround", &deny()),
            Ok(())
        );
        assert_eq!(check_query("openssh 9.8 regression", &deny()), Ok(()));
        for q in [
            "openssh 9.8.1 regression",
            "version 1.2.3.4.5 notes",
            "www.example.org docs",
            "256.1.1.1 bad",
        ] {
            assert_eq!(check_query(q, &deny()), Ok(()), "{q}");
        }
    }
    #[test]
    fn only_public_ids_go_to_level_one() {
        for id in [
            "CVE-2026-1234",
            "FEDORA-2026-6261b26f4e",
            "ALSA-2026:1234",
            "DSA-5912-1",
            "USN-7101-1",
        ] {
            assert!(is_public_id(id), "{id}");
        }
        for id in [
            "web-01",
            "CVE-2026",
            "cve-2026-1234 x",
            "../etc/passwd",
            "FEDORA-2026-6261b26f4e/../x",
        ] {
            assert!(!is_public_id(id), "{id}");
        }
    }
}
