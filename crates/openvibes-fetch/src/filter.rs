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

/// `id` with its prefix (up to the first `-`) uppercased, the rest kept:
/// `cve-2024-6387` becomes `CVE-2024-6387`, as [`is_public_id`] wants.
pub fn upper_prefix(id: &str) -> String {
    match id.split_once('-') {
        Some((prefix, rest)) => format!("{}-{rest}", prefix.to_ascii_uppercase()),
        None => id.to_owned(),
    }
}

/// Refuses (`Blocked`) a query that is too long, contains a URL (`://`,
/// `scheme:/`, `scheme:\`, any `%XX`), full-width or non-ASCII-digit
/// look-alikes, an IPv4/IPv6/MAC address in any surroundings, or any `deny`
/// term (agent IDs, host and user names, internal domains) as a whole word.
/// Matching is case-insensitive; deny terms are lowercased here.
pub fn check_query(query: &str, deny: &[String]) -> Result<(), Refusal> {
    let q = query.to_lowercase();
    let n = q
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[dot]", ".");
    if q.chars().count() > MAX_QUERY
        || q.contains("://")
        || q.chars().any(|c| {
            ('\u{ff00}'..='\u{ffef}').contains(&c)
                || ('\u{1d400}'..='\u{1d7ff}').contains(&c)
                || (!c.is_ascii() && c.is_numeric())
        })
        || has_scheme_slash(&q)
        || q.as_bytes()
            .windows(3)
            .any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
        || deny.iter().any(|d| {
            let d = d.to_lowercase();
            has_word(&q, &d) || has_word(&n, &d)
        })
        || runs(&n, |c| c.is_ascii_digit() || c == '.').any(|(_, r)| is_ipv4(r))
        || runs(&n, |c| c.is_ascii_hexdigit() || c == ':' || c == '.')
            .any(|(i, r)| is_ipv6(&n, i, r))
        || runs(&n, |c| {
            c.is_ascii_hexdigit() || matches!(c, ':' | '.' | '-')
        })
        .any(|(_, r)| is_mac(r))
    {
        return Err(Refusal::Blocked);
    }
    Ok(())
}

/// Maximal runs of characters satisfying `f`, with their byte offsets.
fn runs(q: &str, f: impl Fn(char) -> bool) -> impl Iterator<Item = (usize, &str)> {
    let mut start = None;
    let mut out = Vec::new();
    for (i, c) in q.char_indices() {
        match (f(c), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                out.push((s, &q[s..i]));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push((s, &q[s..]));
    }
    out.into_iter()
}

/// `scheme:/` or `scheme:\`: a URL without `://`.
fn has_scheme_slash(q: &str) -> bool {
    q.match_indices([':'].as_slice()).any(|(i, _)| {
        matches!(q[i + 1..].chars().next(), Some('/' | '\\'))
            && q[..i]
                .chars()
                .rev()
                .take(2)
                .filter(char::is_ascii_alphabetic)
                .count()
                == 2
    })
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// `term` occurs in `q` not embedded in a longer word.
fn has_word(q: &str, term: &str) -> bool {
    if term.is_empty() {
        return false;
    }
    let mut from = 0;
    while let Some(p) = q[from..].find(term) {
        let (s, e) = (from + p, from + p + term.len());
        if !q[..s].chars().next_back().is_some_and(is_word_char)
            && !q[e..].chars().next().is_some_and(is_word_char)
        {
            return true;
        }
        from = s + q[s..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// Four consecutive dot-separated parts of 1-3 digits, each at most 255.
fn is_ipv4(run: &str) -> bool {
    let parts: Vec<&str> = run.split('.').collect();
    parts.windows(4).any(|w| {
        w.iter().all(|p| {
            (1..=3).contains(&p.len())
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u8>().is_ok()
        })
    })
}

/// Any sub-run of a hex/colon/dot run that parses as IPv6 (`ip:fe80::1`,
/// `fe80::`, `::1`). A sub-run glued to a preceding letter or digit must start
/// with a 4-digit group (or have 8 groups), reach the end of the run (trailing
/// `.`/`:` aside) and be
/// followed by a non-alphanumeric: `srcfe80::1` is caught, `std::dead` is not.
fn is_ipv6(q: &str, off: usize, run: &str) -> bool {
    if run.matches(':').count() < 2 {
        return false;
    }
    let glued = |at: usize| {
        q[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric())
    };
    let ends_word = !q[off + run.len()..]
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric());
    let strong =
        |c: &str| c.matches(':').count() == 7 || c.split(':').next().is_some_and(|g| g.len() == 4);
    // Sentence punctuation after a glued address (`srcfe80::1.`) still ends it.
    let end = run.trim_end_matches(['.', ':']).len();
    (0..run.len()).any(|s| {
        let g = glued(off + s);
        !(g && run.as_bytes()[s] == b':')
            && (s + 1..=run.len()).any(|e| {
                let c = &run[s..e];
                c.bytes().any(|b| b.is_ascii_hexdigit())
                    && c.matches(':').count() >= 2
                    && (!g || ((e == run.len() || e == end) && ends_word && strong(c)))
                    && c.parse::<Ipv6Addr>().is_ok()
            })
    })
}

/// Six 2-hex groups joined by `:` or `-`, or three 4-hex groups joined by `.`.
fn is_mac(run: &str) -> bool {
    let hex = |g: &&str, n: usize| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit());
    [(':', 6, 2), ('-', 6, 2), ('.', 3, 4)]
        .iter()
        .any(|&(sep, count, n)| {
            let g: Vec<&str> = run.split(sep).collect();
            g.windows(count).any(|w| w.iter().all(|x| hex(x, n)))
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
            "www.example.org docs",
            "256.1.1.1 bad",
        ] {
            assert_eq!(check_query(q, &deny()), Ok(()), "{q}");
        }
    }
    fn blocked(qs: &[&str], deny: &[String]) {
        for q in qs {
            assert_eq!(check_query(q, deny), Err(Refusal::Blocked), "{q}");
        }
    }
    #[test]
    fn addresses_are_found_whatever_surrounds_them() {
        blocked(
            &[
                "ssh root@10.0.0.5 denied",
                "ip:10.0.0.5",
                "10.0.0.5-10.0.0.9",
                "10.0.0.5?",
                "mac=aa:bb:cc:dd:ee:ff!",
                "ip:fe80::1",
                "x@2001:db8::1!",
                "999.10.0.0.5",
            ],
            &deny(),
        );
    }
    #[test]
    fn ipv6_zone_trailing_colons_and_cisco_mac() {
        blocked(
            &[
                "2001:db8::",
                "fe80::",
                "fe80::1%eth0",
                "aabb.ccdd.eeff",
                "mac aa-bb-cc-dd-ee-ff!",
                "::1",
            ],
            &deny(),
        );
    }
    #[test]
    fn deny_terms_are_lowercased_here_and_match_whole_words() {
        let up = vec!["WEB-01".to_string(), "Corp.Example".to_string()];
        blocked(&["web-01 crash", "mail.corp.example"], &up);
        let d: Vec<String> = ["al", "db", "admin"].map(String::from).to_vec();
        blocked(&["admin panel exploit", "the db crashed", "al, hi"], &d);
        for q in ["algorithm choice", "mongodb index", "xadmin"] {
            assert_eq!(check_query(q, &d), Ok(()), "{q}");
        }
    }
    #[test]
    fn lookalikes_and_url_forms_without_scheme_separator() {
        blocked(
            &[
                "\u{ff37}\u{ff25}\u{ff22}-01 bug",
                "10.0.0.\u{ff15} x",
                "ip \u{0665}.1.1.1",
                "file:/etc/passwd",
                "https:\\\\x",
                "a%2e%2e b",
                "%41",
            ],
            &deny(),
        );
    }
    #[test]
    fn ordinary_queries_still_pass() {
        for q in [
            "ssh -o setting",
            "chrome 126.0.6478.126",
            "apache 2.4.62 fix",
            "std::vector push",
        ] {
            assert_eq!(check_query(q, &deny()), Ok(()), "{q}");
        }
    }
    #[test]
    fn round_two_evasions() {
        blocked(
            &[
                "web-01_logs",
                "web-01_access.log error",
                "_web-01",
                "srcfe80::1",
                "x2001:db8:1:2:3:4:5:6",
                "10[.]0[.]0[.]5",
                "10(.)0(.)0(.)5",
                "10[dot]0[dot]0[dot]5",
                "\u{1d430}\u{1d41e}\u{1d41b}-01",
            ],
            &deny(),
        );
        for q in [
            "std::vector",
            "cafe:babe",
            "fix: abc",
            "c:\\windows\\system32 error",
            "Foo::bar",
        ] {
            assert_eq!(check_query(q, &deny()), Ok(()), "{q}");
        }
        blocked(&["file:/etc/passwd", "https:\\\\x"], &deny());
    }
    #[test]
    fn round_three() {
        for q in [
            "Self::default",
            "Arc::default",
            "Rc::default",
            "u32::default",
            "i64::default",
            "std::decay_t",
            "std::decay_t error",
            "std::dead",
        ] {
            assert_eq!(check_query(q, &deny()), Ok(()), "{q}");
        }
        blocked(
            &["srcfe80::1", "x2001:db8:1:2:3:4:5:6", "hostfe80::1%eth0"],
            &deny(),
        );
        let d = vec!["corp.example".to_string()];
        blocked(&["mail[.]corp[.]example", "corp[dot]example"], &d);
    }
    #[test]
    fn round_four_sentence_final_glued_ipv6() {
        blocked(
            &[
                "hostfe80::1.",
                "srcfe80::1.",
                "srcfd00::1.",
                "x2001:db8:1:2:3:4:5:6.",
                "srcfe80::1:",
                "fe80::1.",
            ],
            &deny(),
        );
        for q in ["Self::default.", "std::vector."] {
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
    #[test]
    fn a_short_host_name_is_refused_when_the_fleet_reports_an_fqdn() {
        let deny: Vec<String> = vec!["web-01.corp.example".into(), "web-01".into()];
        blocked(&["web-01 openssh error"], &deny);
    }
    #[test]
    fn the_id_prefix_is_uppercased_and_the_rest_kept() {
        assert_eq!(upper_prefix("cve-2024-6387"), "CVE-2024-6387");
        assert_eq!(
            upper_prefix("fedora-2026-6261b26f4e"),
            "FEDORA-2026-6261b26f4e"
        );
        assert_eq!(upper_prefix("web01"), "web01");
    }
}
