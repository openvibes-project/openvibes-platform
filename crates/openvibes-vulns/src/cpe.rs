//! CPE matching (spec `docs/specs/2026-10-06-cpe-matching-design.md`):
//! installed Fedora packages checked against the upstream version ranges
//! NVD lists per product, for CVEs no Fedora advisory covers. Findings are
//! lower-confidence by design: NVD speaks of upstream versions, and Fedora
//! may have patched.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use chrono::{DateTime, Utc};
use platform_store::{
    Client, StoreError,
    cpe::{self, Applicability, InstalledName, NewFinding, ReleaseVersion},
};

use crate::rpmver::rpmvercmp;

/// Highest confidence a CPE finding gets.
pub const MAX_CONFIDENCE: i16 = 75;

/// Package (or source package) names that are not their CPE product's
/// name. A product named here is kept and matched as an alias.
const ALIASES: &[(&str, &str)] = &[
    ("curl", "libcurl"),
    ("libcurl", "curl"),
    ("httpd", "http_server"),
    ("python3", "python"),
    ("python3-libs", "python"),
    ("python3-devel", "python"),
    ("qemu-kvm", "qemu"),
    ("qemu-system-x86", "qemu"),
    ("vim-minimal", "vim"),
    ("vim-enhanced", "vim"),
    ("java-17-openjdk", "openjdk"),
    ("java-21-openjdk", "openjdk"),
    ("openssh-server", "openssh"),
    ("openssh-clients", "openssh"),
    ("libxml2", "libxml2"),
    ("pcre2", "pcre2"),
    ("sqlite-libs", "sqlite"),
    ("openssl-libs", "openssl"),
    ("glibc-common", "glibc"),
    ("gnutls", "gnutls"),
];

/// Suffixes of subpackages named after their source (`openssl-libs`).
const SUFFIXES: &[&str] = &[
    "-libs", "-devel", "-common", "-static", "-tools", "-data", "-core", "-utils", "-minimal",
    "-server", "-client", "-clients",
];

/// How a package was tied to a CPE product.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Tie {
    /// An alias or a subpackage's base name.
    Derived,
    /// The package's or its source package's own name.
    Exact,
}

/// A name as CPE products spell it: lower case, `_` for `-`.
#[must_use]
pub fn product_key(name: &str) -> String {
    name.to_ascii_lowercase().replace('-', "_")
}

/// The CPE products a package could be, and how each is tied to it.
fn products_of(name: &str, source: Option<&str>) -> BTreeMap<String, Tie> {
    let mut found: BTreeMap<String, Tie> = BTreeMap::new();
    let mut add = |product: String, tie: Tie| {
        let slot = found.entry(product).or_insert(tie);
        *slot = (*slot).max(tie);
    };
    add(product_key(name), Tie::Exact);
    for own in std::iter::once(name).chain(source) {
        if let Some(source) = source.filter(|_| own == name) {
            add(product_key(source), Tie::Exact);
        }
        for suffix in SUFFIXES {
            if let Some(base) = own.strip_suffix(suffix) {
                add(product_key(base), Tie::Derived);
            }
        }
        for (from, product) in ALIASES {
            if own == *from {
                add((*product).to_owned(), Tie::Derived);
            }
        }
    }
    found
}

/// Every CPE product some installed package could be: the products whose
/// NVD ranges are worth keeping.
#[must_use]
pub fn wanted_products(installed: &[InstalledName]) -> Vec<String> {
    let set: BTreeSet<String> = installed
        .iter()
        .filter(|p| !is_kernel(&p.name))
        .flat_map(|p| products_of(&p.name, p.source.as_deref()).into_keys())
        .collect();
    set.into_iter().collect()
}

fn is_kernel(name: &str) -> bool {
    name == "kernel" || name.starts_with("kernel-")
}

/// Whether `version` (upstream) is inside the range.
fn in_range(version: &str, range: &Applicability) -> bool {
    range
        .introduced
        .as_deref()
        .is_none_or(|from| rpmvercmp(version, from) != Ordering::Less)
        && range
            .fixed
            .as_deref()
            .is_none_or(|fixed| rpmvercmp(version, fixed) == Ordering::Less)
        && range
            .last_affected
            .as_deref()
            .is_none_or(|last| rpmvercmp(version, last) != Ordering::Greater)
}

/// The range as text: `from 7.69.0 before 8.4.0`, `1.2.3 only`, ...
fn range_text(range: &Applicability) -> String {
    match (&range.introduced, &range.fixed, &range.last_affected) {
        (Some(from), _, Some(last)) if from == last => format!("{from} only"),
        (from, fixed, last) => {
            let mut text = Vec::new();
            if let Some(from) = from {
                text.push(format!("from {from}"));
            }
            if let Some(fixed) = fixed {
                text.push(format!("before {fixed}"));
            }
            if let Some(last) = last {
                text.push(format!("through {last}"));
            }
            if text.is_empty() {
                "all versions".to_owned()
            } else {
                text.join(" ")
            }
        }
    }
}

/// Findings for a release: each installed package version inside an
/// applicable range, for CVEs not in `advised`. Pure.
#[must_use]
pub fn evaluate(
    os_version: &str,
    versions: &[ReleaseVersion],
    ranges: &[Applicability],
    advised: &BTreeSet<String>,
) -> Vec<NewFinding> {
    let mut by_product: BTreeMap<&str, Vec<&Applicability>> = BTreeMap::new();
    for range in ranges.iter().filter(|r| !advised.contains(&r.cve_id)) {
        by_product.entry(&range.product).or_default().push(range);
    }
    // Best finding per (version, CVE, product): the strongest tie and range.
    let mut best: BTreeMap<(i64, &str, &str), NewFinding> = BTreeMap::new();
    for version in versions.iter().filter(|v| !is_kernel(&v.name)) {
        for (product, tie) in products_of(&version.name, version.source.as_deref()) {
            let Some(candidates) = by_product.get(product.as_str()) else {
                continue;
            };
            for range in candidates {
                if !in_range(&version.version, range) {
                    continue;
                }
                let exact_version =
                    range.introduced.is_some() && range.introduced == range.last_affected;
                let listed = range.fedora.iter().any(|r| r == os_version);
                let mut confidence = if tie == Tie::Exact && !exact_version {
                    60
                } else {
                    55
                };
                if listed {
                    confidence += 15;
                }
                let confidence = confidence.min(MAX_CONFIDENCE);
                let key = (version.id, range.cve_id.as_str(), range.product.as_str());
                if best.get(&key).is_some_and(|f| f.confidence >= confidence) {
                    continue;
                }
                let mut basis = format!(
                    "NVD lists {}:{} {} as affected by {}, and the installed {} {} is in that \
                     range. No Fedora {os_version} advisory names this CVE (yet), and NVD's \
                     ranges are for the upstream project, so Fedora may have patched it.",
                    range.vendor,
                    range.product,
                    range_text(range),
                    range.cve_id,
                    version.name,
                    version.version,
                );
                if listed {
                    basis.push_str(&format!(
                        " NVD also lists Fedora {os_version} itself as affected."
                    ));
                }
                best.insert(
                    key,
                    NewFinding {
                        package_version_id: version.id,
                        cve_id: range.cve_id.clone(),
                        product: range.product.clone(),
                        package: version.name.clone(),
                        installed: version.installed.clone(),
                        range_text: range_text(range),
                        confidence,
                        basis,
                        cvss: range.cvss,
                    },
                );
            }
        }
    }
    best.into_values().collect()
}

/// Recomputes a Fedora release's CPE findings from the stored ranges.
/// Returns how many there are.
pub async fn refresh(
    client: &mut Client,
    os_id: &str,
    os_version: &str,
    now: DateTime<Utc>,
) -> Result<usize, StoreError> {
    let versions = cpe::release_versions(client, os_id, os_version).await?;
    let installed: Vec<InstalledName> = versions
        .iter()
        .map(|v| InstalledName {
            name: v.name.clone(),
            source: v.source.clone(),
        })
        .collect();
    let products = wanted_products(&installed);
    let ranges = cpe::applicability_for(client, &products).await?;
    let advised = cpe::advised_cves(client, os_id, os_version).await?;
    let findings = evaluate(os_version, &versions, &ranges, &advised);
    cpe::replace_findings(client, os_version, &findings, now).await
}

/// Makes sure NVD ranges are kept for every product an installed package
/// could be. Returns whether a product is new, in which case NVD has to be
/// read again from the start (older CVEs of it were dropped when read).
pub async fn ensure_products(client: &Client, os_id: &str) -> Result<bool, StoreError> {
    let installed = cpe::installed_names(client, os_id).await?;
    let products = wanted_products(&installed);
    Ok(cpe::add_products(client, &products).await? > 0)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use platform_store::cpe::{Applicability, ReleaseVersion};

    use super::{Tie, evaluate, product_key, products_of};

    fn range(
        cve: &str,
        product: &str,
        from: Option<&str>,
        fixed: Option<&str>,
        last: Option<&str>,
    ) -> Applicability {
        Applicability {
            cve_id: cve.into(),
            vendor: "v".into(),
            product: product.into(),
            introduced: from.map(Into::into),
            fixed: fixed.map(Into::into),
            last_affected: last.map(Into::into),
            cvss: Some(7.5),
            fedora: Vec::new(),
        }
    }

    fn version(id: i64, name: &str, source: Option<&str>, v: &str) -> ReleaseVersion {
        ReleaseVersion {
            id,
            name: name.into(),
            source: source.map(Into::into),
            version: v.into(),
            installed: format!("0:{v}-1.fc44"),
        }
    }

    #[test]
    fn products_of_a_package() {
        let found = products_of("openssl-libs", Some("openssl"));
        assert_eq!(found.get("openssl"), Some(&Tie::Exact));
        assert_eq!(found.get("openssl_libs"), Some(&Tie::Exact));
        assert_eq!(
            products_of("libcurl", Some("curl")).get("curl"),
            Some(&Tie::Exact)
        );
        assert_eq!(
            products_of("curl", None).get("libcurl"),
            Some(&Tie::Derived)
        );
        assert_eq!(product_key("Python-Requests"), "python_requests");
    }

    #[test]
    fn ranges_have_the_right_bounds() {
        let ranges = [range(
            "CVE-2023-38545",
            "libcurl",
            Some("7.69.0"),
            Some("8.4.0"),
            None,
        )];
        let at = |v: &str| {
            evaluate(
                "44",
                &[version(1, "libcurl", Some("curl"), v)],
                &ranges,
                &BTreeSet::new(),
            )
        };
        assert_eq!(at("7.68.9").len(), 0);
        assert_eq!(at("7.69.0").len(), 1);
        assert_eq!(at("8.3.0").len(), 1);
        assert_eq!(at("8.4.0").len(), 0);
        assert_eq!(at("8.10.1").len(), 0);
        let through = [range("CVE-1", "xz", None, None, Some("5.6.1"))];
        let at = |v: &str| {
            evaluate(
                "44",
                &[version(1, "xz", None, v)],
                &through,
                &BTreeSet::new(),
            )
        };
        assert_eq!((at("5.6.1").len(), at("5.6.2").len()), (1, 0));
    }

    #[test]
    fn advisory_suppresses_and_confidence_follows_the_tie() {
        let ranges = [range("CVE-1", "openssl", None, Some("9"), None)];
        let versions = [
            version(1, "openssl", None, "3.0"),
            version(2, "openssl-libs", Some("openssl"), "3.0"),
        ];
        let found = evaluate("44", &versions, &ranges, &BTreeSet::new());
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|f| f.confidence == 60));
        let advised: BTreeSet<String> = ["CVE-1".to_owned()].into();
        assert!(evaluate("44", &versions, &ranges, &advised).is_empty());
        // An alias is weaker; NVD listing the release adds 15, capped at 75.
        let mut alias = range("CVE-2", "http_server", None, Some("9"), None);
        let found = evaluate(
            "44",
            &[version(3, "httpd", None, "2.4")],
            std::slice::from_ref(&alias),
            &BTreeSet::new(),
        );
        assert_eq!(found[0].confidence, 55);
        alias.fedora = vec!["44".into()];
        let found = evaluate(
            "44",
            &[version(3, "httpd", None, "2.4")],
            &[alias],
            &BTreeSet::new(),
        );
        assert_eq!(found[0].confidence, 70);
    }

    #[test]
    fn kernels_are_left_to_their_vendor() {
        let ranges = [range("CVE-1", "kernel", None, Some("9"), None)];
        assert!(
            evaluate(
                "44",
                &[version(1, "kernel-core", None, "6.1")],
                &ranges,
                &BTreeSet::new()
            )
            .is_empty()
        );
    }
}
