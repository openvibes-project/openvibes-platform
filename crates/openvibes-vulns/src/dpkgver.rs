//! dpkg version order, exactly as dpkg's `dpkg_version_compare` and
//! `verrevcmp` (Debian Policy §5.6.12): epoch, then upstream version, then
//! revision.

use std::cmp::Ordering;

/// Sort weight of one character: `~` before everything (even the end),
/// the end next, then letters, then other symbols; digits are compared
/// as numbers elsewhere.
fn weight(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(b'~') => -1,
        Some(c) => i32::from(c) + 256,
    }
}

/// dpkg's `verrevcmp` on one part (upstream or revision): alternating
/// non-digit runs (by weight) and digit runs (numerically).
fn verrevcmp(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    let digit = |s: &[u8]| s.first().is_some_and(u8::is_ascii_digit);
    while !a.is_empty() || !b.is_empty() {
        while (!a.is_empty() && !digit(a)) || (!b.is_empty() && !digit(b)) {
            let (wa, wb) = (weight(a.first().copied()), weight(b.first().copied()));
            if wa != wb {
                return wa.cmp(&wb);
            }
            a = a.get(1..).unwrap_or_default();
            b = b.get(1..).unwrap_or_default();
        }
        while a.first() == Some(&b'0') {
            a = &a[1..];
        }
        while b.first() == Some(&b'0') {
            b = &b[1..];
        }
        let mut first_difference = Ordering::Equal;
        while digit(a) && digit(b) {
            if first_difference == Ordering::Equal {
                first_difference = a[0].cmp(&b[0]);
            }
            a = &a[1..];
            b = &b[1..];
        }
        if digit(a) {
            return Ordering::Greater;
        }
        if digit(b) {
            return Ordering::Less;
        }
        if first_difference != Ordering::Equal {
            return first_difference;
        }
    }
    Ordering::Equal
}

/// Splits `[epoch:]upstream[-revision]`. A missing or non-numeric epoch is
/// 0 (dpkg refuses the latter; here it simply sorts); the revision is what
/// follows the last hyphen.
fn split(version: &str) -> (u64, &str, &str) {
    let (epoch, rest) = match version.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
            (epoch.parse().unwrap_or(u64::MAX), rest)
        }
        _ => (0, version),
    };
    match rest.rsplit_once('-') {
        Some((upstream, revision)) => (epoch, upstream, revision),
        None => (epoch, rest, ""),
    }
}

/// Compares two full Debian versions (`[epoch:]upstream[-revision]`).
#[must_use]
pub fn compare(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = split(a);
    let (eb, ub, rb) = split(b);
    ea.cmp(&eb)
        .then_with(|| verrevcmp(ua, ub))
        .then_with(|| verrevcmp(ra, rb))
}
