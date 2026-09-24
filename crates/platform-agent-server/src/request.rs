use openvibes_core::{ResourceLimits, Validate};
use serde::de::DeserializeOwned;

use crate::ApiError;

/// Largest request body, the V1 document limit.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Parses a request body into its protocol type and validates it against
/// the V1 limits. Anything else is 400; the input is never echoed.
pub fn parse<T: DeserializeOwned + Validate>(body: &[u8]) -> Result<T, ApiError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(ApiError::BadRequest);
    }
    let value: T = serde_json::from_slice(body).map_err(|_| ApiError::BadRequest)?;
    value
        .validate(ResourceLimits::V1)
        .map_err(|_| ApiError::BadRequest)?;
    Ok(value)
}
