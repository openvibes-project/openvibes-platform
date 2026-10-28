use crate::{Applies, Definition, Kind, Text};

/// Every vulnerability-service key starts with this.
pub const PREFIX: &str = "vulns.";
/// Minutes between feed checks.
pub const CHECK_INTERVAL_MINUTES: &str = "vulns.check_interval_minutes";
/// Fedora mirror list template.
pub const METALINK_URL: &str = "vulns.metalink_url";
/// Repository architecture.
pub const ARCH: &str = "vulns.arch";
/// Outbound proxy.
pub const PROXY_URL: &str = "vulns.proxy_url";
/// Largest feed download, in MiB.
pub const MAX_DOWNLOAD_MIB: &str = "vulns.max_download_mib";
/// CISA KEV catalog.
pub const KEV_URL: &str = "vulns.kev_url";
/// FIRST EPSS scores.
pub const EPSS_URL: &str = "vulns.epss_url";
/// NVD CVE API.
pub const NVD_URL: &str = "vulns.nvd_url";
/// ENISA EUVD.
pub const EUVD_URL: &str = "vulns.euvd_url";
/// OSV.dev bucket.
pub const OSV_URL: &str = "vulns.osv_url";
/// Largest OSV download, in MiB.
pub const OSV_MAX_DOWNLOAD_MIB: &str = "vulns.osv_max_download_mib";
/// NVD API key (a secret).
pub const NVD_API_KEY: &str = "vulns.nvd_api_key";

const SECTION: &str = "Vulnerability feeds";

pub(crate) static DEFINITIONS: [Definition; 12] = [
    Definition {
        key: CHECK_INTERVAL_MINUTES,
        section: SECTION,
        label: "Check for new advisories every",
        help: "Minutes between feed checks, 15 to 1440. A check downloads only what changed.",
        kind: Kind::Int {
            min: 15,
            max: 1440,
            default: 60,
        },
        applies: Applies::Live,
    },
    Definition {
        key: METALINK_URL,
        section: SECTION,
        label: "Fedora mirror list",
        help: "Where Fedora's advisories come from. {release} and {arch} are filled in.",
        kind: Kind::Text {
            check: Text::HttpsUrl,
            default: "https://mirrors.fedoraproject.org/metalink?repo=updates-released-f{release}&arch={arch}",
        },
        applies: Applies::Live,
    },
    Definition {
        key: ARCH,
        section: SECTION,
        label: "Repository architecture",
        help: "The advisory feed for this architecture is read; it covers every architecture.",
        kind: Kind::Text {
            check: Text::Arch,
            default: "x86_64",
        },
        applies: Applies::Live,
    },
    Definition {
        key: PROXY_URL,
        section: SECTION,
        label: "Outbound proxy",
        help: "Every feed download goes through this proxy, e.g. http://proxy.example:3128. Empty means none.",
        kind: Kind::Text {
            check: Text::ProxyOrEmpty,
            default: "",
        },
        applies: Applies::Live,
    },
    Definition {
        key: MAX_DOWNLOAD_MIB,
        section: SECTION,
        label: "Largest feed download (MiB)",
        help: "A compressed feed bigger than this is refused.",
        kind: Kind::Int {
            min: 1,
            max: 1024,
            default: 64,
        },
        applies: Applies::Live,
    },
    Definition {
        key: KEV_URL,
        section: SECTION,
        label: "CISA known exploited list",
        help: "Marks CVEs that attackers are using.",
        kind: Kind::Text {
            check: Text::HttpsUrlOrEmpty,
            default: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        },
        applies: Applies::Live,
    },
    Definition {
        key: EPSS_URL,
        section: SECTION,
        label: "EPSS scores",
        help: "FIRST's likelihood that a CVE is exploited.",
        kind: Kind::Text {
            check: Text::HttpsUrlOrEmpty,
            default: "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        },
        applies: Applies::Live,
    },
    Definition {
        key: NVD_URL,
        section: SECTION,
        label: "NVD CVE API",
        help: "Scores and affected products for CVEs.",
        kind: Kind::Text {
            check: Text::HttpsUrlOrEmpty,
            default: "https://services.nvd.nist.gov/rest/json/cves/2.0",
        },
        applies: Applies::Live,
    },
    Definition {
        key: NVD_API_KEY,
        section: SECTION,
        label: "NVD API key",
        help: "Raises the NVD rate limit tenfold. Stored apart; it is never shown again.",
        kind: Kind::Secret,
        applies: Applies::Live,
    },
    Definition {
        key: EUVD_URL,
        section: SECTION,
        label: "ENISA EUVD",
        help: "The European vulnerability database.",
        kind: Kind::Text {
            check: Text::HttpsUrlOrEmpty,
            default: "https://euvdservices.enisa.europa.eu/api/search",
        },
        applies: Applies::Live,
    },
    Definition {
        key: OSV_URL,
        section: SECTION,
        label: "OSV.dev",
        help: "Advisories for Debian, Ubuntu, Rocky Linux and AlmaLinux.",
        kind: Kind::Text {
            check: Text::HttpsUrlOrEmpty,
            default: "https://osv-vulnerabilities.storage.googleapis.com",
        },
        applies: Applies::Live,
    },
    Definition {
        key: OSV_MAX_DOWNLOAD_MIB,
        section: SECTION,
        label: "Largest OSV download (MiB)",
        help: "Ubuntu's is about 760 MiB.",
        kind: Kind::Int {
            min: 1,
            max: 8192,
            default: 2048,
        },
        applies: Applies::Live,
    },
];
