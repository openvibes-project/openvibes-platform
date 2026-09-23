//! CA certificates the platform issues under. Public material only.

use chrono::{DateTime, Utc};

use crate::{Client, StoreError};

/// A recorded CA certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaCertificate {
    /// SHA-256 of the certificate DER.
    pub fingerprint_sha256: [u8; 32],
    /// `root` or `intermediate`.
    pub role: String,
    /// The certificate.
    pub pem: String,
    /// End of validity.
    pub not_after: DateTime<Utc>,
}

/// Records a CA certificate; recording the same certificate again is a
/// no-op.
pub async fn record(
    client: &Client,
    role: &str,
    fingerprint: [u8; 32],
    pem: &str,
    not_after: DateTime<Utc>,
) -> Result<(), StoreError> {
    client
        .execute(
            "INSERT INTO ca_certificates (fingerprint_sha256, role, pem, not_after)
             VALUES ($1, $2, $3, $4) ON CONFLICT (fingerprint_sha256) DO NOTHING",
            &[&fingerprint.as_slice(), &role, &pem, &not_after],
        )
        .await?;
    Ok(())
}

/// Every recorded CA certificate, newest expiry first.
pub async fn list(client: &Client) -> Result<Vec<CaCertificate>, StoreError> {
    let rows = client
        .query(
            "SELECT fingerprint_sha256, role, pem, not_after FROM ca_certificates
             ORDER BY not_after DESC",
            &[],
        )
        .await?;
    rows.iter()
        .map(|row| {
            let fingerprint: Vec<u8> = row.get(0);
            Ok(CaCertificate {
                fingerprint_sha256: fingerprint.try_into().map_err(|_| StoreError::Query)?,
                role: row.get(1),
                pem: row.get(2),
                not_after: row.get(3),
            })
        })
        .collect()
}
