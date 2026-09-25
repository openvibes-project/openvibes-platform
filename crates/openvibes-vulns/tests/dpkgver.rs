//! dpkg version order: Debian Policy §5.6.12 and dpkg's own
//! `lib/dpkg/t/t-version.c` cases.

use std::cmp::Ordering::{self, Equal, Greater, Less};

use openvibes_vulns::dpkgver::compare;

fn check(a: &str, b: &str, want: Ordering) {
    assert_eq!(compare(a, b), want, "{a} vs {b}");
    assert_eq!(compare(b, a), want.reverse(), "{b} vs {a}");
}

#[test]
fn epoch_upstream_and_revision() {
    check("1.0", "1.0", Equal);
    check("0:1.0", "1.0", Equal);
    check("1:0.1", "2.0", Greater);
    check("1.0-1", "1.0-2", Less);
    check("1.0-1", "1.0-01", Equal);
    check("1.0", "1.0-0", Equal);
    check("1.2.3-1", "1.2.4-1", Less);
    check("1.10", "1.9", Greater);
    check("1.0-1ubuntu1", "1.0-1", Greater);
    check("2:1.0", "1:9.9", Greater);
    // A hyphen belongs to the upstream version when more follow.
    check("1.0-2-3", "1.0-2-2", Greater);
}

#[test]
fn tilde_sorts_first_letters_before_other_symbols() {
    check("1.0~rc1", "1.0", Less);
    check("1.0~rc1", "1.0~rc2", Less);
    check("~~", "~~a", Less);
    check("~~a", "~", Less);
    check("~", "", Less);
    check("1.0", "1.0+b1", Less);
    check("1.0a", "1.0+", Less);
    check("1.0a", "1.0b", Less);
    check("1.0.", "1.0a", Greater);
    check("3.12.3-1ubuntu0.8", "3.12.3-1ubuntu0.8+b1", Less);
    check("9.6p1-3ubuntu13.5", "9.6p1-3ubuntu13.10", Less);
    check("2.17-1", "2.40-2", Less);
}

#[test]
fn malformed_versions_compare_without_panicking() {
    // Garbage in: an ordering, never a panic.
    let _ = compare("", "");
    let _ = compare(":", "-");
    let _ = compare("abc:1", "1");
    let _ = compare("1:", "1");
}
