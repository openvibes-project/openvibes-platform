//! Agent version order (roles plan 2026-10-20, ruling 7): the Rust twin of
//! the SQL `console_version_older` (migration 57), tested against the same
//! table. Numeric segments are compared (the shorter padded with zeros), a
//! pre-release is older than its release, build metadata is ignored.

/// The numeric segments and whether it is a pre-release; `None` when empty
/// or any segment is not 1–9 digits.
fn parts(version: &str) -> Option<(Vec<u32>, bool)> {
    let plain = version.split('+').next().unwrap_or_default();
    let (core, pre) = plain
        .split_once('-')
        .map_or((plain, false), |(core, _)| (core, true));
    let segments = core
        .split('.')
        .map(|s| {
            (!s.is_empty() && s.len() <= 9 && s.bytes().all(|b| b.is_ascii_digit()))
                .then(|| s.parse().ok())
                .flatten()
        })
        .collect::<Option<Vec<u32>>>()?;
    Some((segments, pre))
}

/// Whether `version` is older than `latest`; `None` when either is unknown.
#[must_use]
pub fn older(version: &str, latest: &str) -> Option<bool> {
    let (a, a_pre) = parts(version)?;
    let (b, b_pre) = parts(latest)?;
    let len = a.len().max(b.len());
    let at = |v: &[u32], i: usize| v.get(i).copied().unwrap_or(0);
    let order = (0..len)
        .map(|i| at(&a, i).cmp(&at(&b, i)))
        .find(|o| o.is_ne());
    Some(order.map_or(a_pre && !b_pre, std::cmp::Ordering::is_lt))
}
