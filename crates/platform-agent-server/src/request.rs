use openvibes_core::{ResourceLimits, Validate};
use serde::de::DeserializeOwned;

use crate::ApiError;

/// Largest request body, the V1 document limit.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Largest `/v1/inventory` body, the V1 inventory document limit (M1 limits
/// review); every other path keeps [`MAX_BODY_BYTES`].
pub const MAX_INVENTORY_BYTES: usize = ResourceLimits::V1.inventory_document_bytes;

/// The body limit for a request path.
#[must_use]
pub fn body_limit(path: &str) -> usize {
    if path == "/v1/inventory" {
        MAX_INVENTORY_BYTES
    } else {
        MAX_BODY_BYTES
    }
}

/// Parses a request body into its protocol type and validates it against
/// the V1 limits. Anything else is 400; the input is never echoed.
pub fn parse<T: DeserializeOwned + Validate>(body: &[u8]) -> Result<T, ApiError> {
    parse_with_limit(body, MAX_BODY_BYTES)
}

/// [`parse`] with another body limit (inventories).
pub fn parse_with_limit<T: DeserializeOwned + Validate>(
    body: &[u8],
    limit: usize,
) -> Result<T, ApiError> {
    if body.len() > limit {
        return Err(ApiError::BadRequest);
    }
    let value: T = serde_json::from_slice(body).map_err(|_| ApiError::BadRequest)?;
    value
        .validate(ResourceLimits::V1)
        .map_err(|_| ApiError::BadRequest)?;
    Ok(value)
}
