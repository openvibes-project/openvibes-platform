//! Package versions as the Software pages show them: `epoch:version-release`
//! (epoch and release only when present) and an order that reads the digit
//! runs as numbers, so `10.1` is newer than `9.9`. Not a distribution's own
//! comparison: the pages use it for a range ("1.0 to 1.3") and for naming the
//! newest version on a host.

/// A version split into runs of digits (compared as numbers) and other text,
/// so that `10.1` sorts after `9.9`.
pub(crate) fn natural(version: &str) -> Natural {
    let mut out = Vec::new();
    let mut rest = version;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let (number, tail) = rest.split_at(digits);
        let text = tail
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(tail.len());
        out.push((number.parse().unwrap_or(0), tail[..text].to_owned()));
        rest = &tail[text..];
    }
    out
}

/// `epoch:version-release`, with the epoch only when it is not 0 and the
/// release only when there is one.
#[must_use]
pub fn full_version(epoch: i64, version: &str, release: &str) -> String {
    let epoch = if epoch > 0 {
        format!("{epoch}:")
    } else {
        String::new()
    };
    let release = if release.is_empty() {
        String::new()
    } else {
        format!("-{release}")
    };
    format!("{epoch}{version}{release}")
}

/// A version split by [`natural`].
pub(crate) type Natural = Vec<(u64, String)>;

/// A version's sort key: epoch, then version, then release.
pub(crate) fn order_key(epoch: i64, version: &str, release: &str) -> (i64, Natural, Natural) {
    (epoch, natural(version), natural(release))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_by_their_numbers() {
        assert!(natural("10.1") > natural("9.9"));
        assert!(natural("9.2p1") < natural("9.10p1"));
        assert_eq!(natural("1.0"), natural("1.0"));
    }

    #[test]
    fn a_version_is_written_with_what_it_has() {
        assert_eq!(full_version(0, "3.0.2", ""), "3.0.2");
        assert_eq!(full_version(0, "3.0.2", "1.fc40"), "3.0.2-1.fc40");
        assert_eq!(full_version(2, "1.4", "3"), "2:1.4-3");
    }

    #[test]
    fn the_epoch_decides_first() {
        assert!(order_key(1, "1.0", "1") > order_key(0, "9.9", "9"));
        assert!(order_key(0, "1.10", "1") > order_key(0, "1.9", "1"));
    }
}
