//! RPM version order, exactly as `rpmvercmp` and `rpmVersionCompare`.

use std::cmp::Ordering;

/// Compares two version or release strings the way RPM does: separators
/// are skipped, `~` sorts before anything (even the end), `^` after the end
/// but before anything else, digit runs compare numerically and beat letter
/// runs, letter runs compare bytewise.
#[must_use]
pub fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (mut one, mut two) = (a.as_bytes(), b.as_bytes());
    let separator = |c: u8| !c.is_ascii_alphanumeric() && c != b'~' && c != b'^';
    while !one.is_empty() || !two.is_empty() {
        while one.first().is_some_and(|&c| separator(c)) {
            one = &one[1..];
        }
        while two.first().is_some_and(|&c| separator(c)) {
            two = &two[1..];
        }
        // Tilde: sorts before everything, including the end.
        match (one.first() == Some(&b'~'), two.first() == Some(&b'~')) {
            (true, true) => {
                one = &one[1..];
                two = &two[1..];
                continue;
            }
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            (false, false) => {}
        }
        // Caret: sorts after the end, before anything else.
        if one.first() == Some(&b'^') || two.first() == Some(&b'^') {
            if one.is_empty() {
                return Ordering::Less;
            }
            if two.is_empty() {
                return Ordering::Greater;
            }
            if one[0] != b'^' {
                return Ordering::Greater;
            }
            if two[0] != b'^' {
                return Ordering::Less;
            }
            one = &one[1..];
            two = &two[1..];
            continue;
        }
        if one.is_empty() || two.is_empty() {
            break;
        }
        let numeric = one[0].is_ascii_digit();
        let class = |c: &u8| {
            if numeric {
                c.is_ascii_digit()
            } else {
                c.is_ascii_alphabetic()
            }
        };
        let split = |s: &[u8]| s.iter().position(|c| !class(c)).unwrap_or(s.len());
        let (seg_one, rest_one) = one.split_at(split(one));
        let (seg_two, rest_two) = two.split_at(split(two));
        // Segments of different kinds: a number beats letters.
        if seg_two.is_empty() {
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let order = if numeric {
            let trim = |s: &[u8]| {
                let start = s.iter().position(|&c| c != b'0').unwrap_or(s.len());
                s[start..].to_vec()
            };
            let (x, y) = (trim(seg_one), trim(seg_two));
            x.len().cmp(&y.len()).then_with(|| x.cmp(&y))
        } else {
            seg_one.cmp(seg_two)
        };
        if order != Ordering::Equal {
            return order;
        }
        one = rest_one;
        two = rest_two;
    }
    match (one.is_empty(), two.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        _ => Ordering::Greater,
    }
}

/// Compares epoch, then version, then release, as RPM orders packages.
#[must_use]
pub fn compare_evr(a: (u32, &str, &str), b: (u32, &str, &str)) -> Ordering {
    a.0.cmp(&b.0)
        .then_with(|| rpmvercmp(a.1, b.1))
        .then_with(|| rpmvercmp(a.2, b.2))
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering::{self, Equal, Greater, Less};

    use super::{compare_evr, rpmvercmp};

    /// RPM's own vectors (rpm tests/rpmvercmp.at).
    const VECTORS: &[(&str, &str, Ordering)] = &[
        ("1.0", "1.0", Equal),
        ("1.0", "2.0", Less),
        ("2.0", "1.0", Greater),
        ("2.0.1", "2.0.1", Equal),
        ("2.0", "2.0.1", Less),
        ("2.0.1", "2.0", Greater),
        ("2.0.1a", "2.0.1a", Equal),
        ("2.0.1a", "2.0.1", Greater),
        ("2.0.1", "2.0.1a", Less),
        ("5.5p1", "5.5p1", Equal),
        ("5.5p1", "5.5p2", Less),
        ("5.5p2", "5.5p1", Greater),
        ("5.5p10", "5.5p10", Equal),
        ("5.5p1", "5.5p10", Less),
        ("5.5p10", "5.5p1", Greater),
        ("10xyz", "10.1xyz", Less),
        ("10.1xyz", "10xyz", Greater),
        ("xyz10", "xyz10", Equal),
        ("xyz10", "xyz10.1", Less),
        ("xyz10.1", "xyz10", Greater),
        ("xyz.4", "xyz.4", Equal),
        ("xyz.4", "8", Less),
        ("8", "xyz.4", Greater),
        ("xyz.4", "2", Less),
        ("2", "xyz.4", Greater),
        ("5.5p2", "5.6p1", Less),
        ("5.6p1", "5.5p2", Greater),
        ("5.6p1", "6.5p1", Less),
        ("6.5p1", "5.6p1", Greater),
        ("6.0.rc1", "6.0", Greater),
        ("6.0", "6.0.rc1", Less),
        ("10b2", "10a1", Greater),
        ("10a2", "10b2", Less),
        ("1.0aa", "1.0aa", Equal),
        ("1.0a", "1.0aa", Less),
        ("1.0aa", "1.0a", Greater),
        ("10.0001", "10.0001", Equal),
        ("10.0001", "10.1", Equal),
        ("10.1", "10.0001", Equal),
        ("10.0001", "10.0039", Less),
        ("10.0039", "10.0001", Greater),
        ("4.999.9", "5.0", Less),
        ("5.0", "4.999.9", Greater),
        ("20101121", "20101121", Equal),
        ("20101121", "20101122", Less),
        ("20101122", "20101121", Greater),
        ("2_0", "2_0", Equal),
        ("2.0", "2_0", Equal),
        ("2_0", "2.0", Equal),
        ("a", "a", Equal),
        ("a+", "a+", Equal),
        ("a+", "a_", Equal),
        ("a_", "a+", Equal),
        ("+a", "+a", Equal),
        ("+a", "_a", Equal),
        ("_a", "+a", Equal),
        ("+_", "+_", Equal),
        ("_+", "+_", Equal),
        ("_+", "_+", Equal),
        ("+", "_", Equal),
        ("_", "+", Equal),
        ("1.0~rc1", "1.0~rc1", Equal),
        ("1.0~rc1", "1.0", Less),
        ("1.0", "1.0~rc1", Greater),
        ("1.0~rc1", "1.0~rc2", Less),
        ("1.0~rc2", "1.0~rc1", Greater),
        ("1.0~rc1~git123", "1.0~rc1~git123", Equal),
        ("1.0~rc1~git123", "1.0~rc1", Less),
        ("1.0~rc1", "1.0~rc1~git123", Greater),
        ("1.0^", "1.0^", Equal),
        ("1.0^", "1.0", Greater),
        ("1.0", "1.0^", Less),
        ("1.0^git1", "1.0^git1", Equal),
        ("1.0^git1", "1.0", Greater),
        ("1.0", "1.0^git1", Less),
        ("1.0^git1", "1.0^git2", Less),
        ("1.0^git2", "1.0^git1", Greater),
        ("1.0^git1", "1.01", Less),
        ("1.01", "1.0^git1", Greater),
        ("1.0^20160101", "1.0^20160101", Equal),
        ("1.0^20160101", "1.0.1", Less),
        ("1.0.1", "1.0^20160101", Greater),
        ("1.0^20160101^git1", "1.0^20160101^git1", Equal),
        ("1.0^20160102", "1.0^20160101^git1", Greater),
        ("1.0^20160101^git1", "1.0^20160102", Less),
        ("1.0~rc1^git1", "1.0~rc1^git1", Equal),
        ("1.0~rc1^git1", "1.0~rc1", Greater),
        ("1.0~rc1", "1.0~rc1^git1", Less),
        ("1.0^git1~pre", "1.0^git1~pre", Equal),
        ("1.0^git1", "1.0^git1~pre", Greater),
        ("1.0^git1~pre", "1.0^git1", Less),
    ];

    #[test]
    fn matches_rpm_vectors() {
        for &(a, b, expected) in VECTORS {
            assert_eq!(rpmvercmp(a, b), expected, "{a} vs {b}");
        }
    }

    #[test]
    fn epoch_then_version_then_release() {
        assert_eq!(
            compare_evr((1, "1.0", "1"), (0, "2.0", "1")),
            Greater,
            "epoch wins"
        );
        assert_eq!(compare_evr((0, "2.0", "1"), (0, "2.0", "2")), Less);
        assert_eq!(
            compare_evr((0, "3.5.1", "2.fc44"), (0, "3.5.1", "10.fc44")),
            Less
        );
        assert_eq!(
            compare_evr((0, "3.5.1", "2.fc44"), (0, "3.5.1", "2.fc44")),
            Equal
        );
    }
}
