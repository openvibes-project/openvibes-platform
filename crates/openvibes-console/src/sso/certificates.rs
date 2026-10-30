//! The identity provider's pasted signing certificates.

use chrono::{DateTime, Duration, Utc};
use platform_pki::{first_certificate, not_after, not_before, sha256_fingerprint};
use serde::Serialize;
use utoipa::ToSchema;

const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";

/// One certificate as shown under the setting.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct IdpCertificateView {
    /// SHA-256 of the certificate, uppercase hex in pairs separated by colons.
    pub fingerprint: String,
    /// Start of validity (RFC 3339).
    pub not_before: String,
    /// End of validity (RFC 3339).
    pub not_after: String,
    /// Whether it has expired now.
    pub expired: bool,
}

/// Each certificate of `text` (possibly empty), or the words to show. A
/// certificate must be valid now when `strict` (a new value); a stored one
/// that has since expired is still listed, marked expired.
///
/// # Errors
/// A block that is not a certificate, the same certificate twice, and when
/// `strict` an expired or not yet valid one.
pub(crate) fn summaries(
    text: &str,
    now: DateTime<Utc>,
    strict: bool,
) -> Result<Vec<IdpCertificateView>, String> {
    let mut seen = Vec::new();
    let mut views = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let Some(len) = rest[start..].find(END) else {
            return Err("A certificate is cut off".into());
        };
        // Pasted text is often indented; the parser wants bare lines.
        let block = rest[start..start + len + END.len()]
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("\n");
        let block = block.as_str();
        rest = &rest[start + len + END.len()..];
        let number = views.len() + 1;
        let unreadable = || format!("Certificate {number} cannot be read");
        let pem = first_certificate(block).map_err(|_| unreadable())?;
        let digest = sha256_fingerprint(&pem).map_err(|_| unreadable())?;
        let (from, until) = (
            not_before(&pem).map_err(|_| unreadable())?,
            not_after(&pem).map_err(|_| unreadable())?,
        );
        if strict && until <= now {
            return Err(format!("Certificate {number} has expired"));
        }
        if strict && from > now + Duration::minutes(2) {
            return Err(format!("Certificate {number} is not valid yet"));
        }
        if seen.contains(&digest) {
            return Err(format!("Certificate {number} is listed twice"));
        }
        seen.push(digest);
        views.push(IdpCertificateView {
            fingerprint: digest
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(":"),
            not_before: from.to_rfc3339(),
            not_after: until.to_rfc3339(),
            expired: until <= now,
        });
    }
    Ok(views)
}
