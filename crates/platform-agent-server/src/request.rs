use openvibes_core::{ResourceLimits, Validate};
use serde::de::DeserializeOwned;

use crate::ApiError;

/// Largest request body, the V1 document limit.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Largest `/v1/inventory` body, the V1 inventory document limit (M1 limits
/// review); every other path keeps [`MAX_BODY_BYTES`].
pub const MAX_INVENTORY_BYTES: usize = ResourceLimits::V1.inventory_document_bytes;

/// The inventory endpoints: the full report (P8) and changes (P11). Both
/// take up to [`MAX_INVENTORY_BYTES`], gzip bodies, and the longer deadline.
pub const INVENTORY_PATHS: [&str; 2] = ["/v1/inventory", "/v1/inventory/changes"];

/// The body limit for a request path.
#[must_use]
pub fn body_limit(path: &str) -> usize {
    if INVENTORY_PATHS.contains(&path) {
        MAX_INVENTORY_BYTES
    } else {
        MAX_BODY_BYTES
    }
}

/// An inventory body as sent: gzip (`Content-Encoding: gzip`, P11) or
/// plain. Decompresses as a stream and refuses more than `limit` bytes of
/// output, so a small body cannot make the server allocate more.
pub fn decoded_body<'a>(
    headers: &axum::http::HeaderMap,
    body: &'a [u8],
    limit: usize,
) -> Result<std::borrow::Cow<'a, [u8]>, ApiError> {
    use std::io::Read;
    let encoding = headers
        .get(axum::http::header::CONTENT_ENCODING)
        .map(|value| value.to_str().map_err(|_| ApiError::BadRequest))
        .transpose()?
        .map(str::trim);
    match encoding {
        None => Ok(body.into()),
        Some(value) if value.eq_ignore_ascii_case("identity") => Ok(body.into()),
        Some(value) if value.eq_ignore_ascii_case("gzip") => {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(body)
                .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
                .read_to_end(&mut out)
                .map_err(|_| ApiError::BadRequest)?;
            if out.len() > limit {
                return Err(ApiError::BadRequest);
            }
            Ok(out.into())
        }
        Some(_) => Err(ApiError::BadRequest),
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use axum::http::{HeaderMap, HeaderValue, header::CONTENT_ENCODING};

    use super::{ApiError, decoded_body};

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn encoded(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn gzip_and_plain_bodies_are_read() {
        assert_eq!(&*decoded_body(&HeaderMap::new(), b"{}", 10).unwrap(), b"{}");
        assert_eq!(
            &*decoded_body(&encoded("identity"), b"{}", 10).unwrap(),
            b"{}"
        );
        assert_eq!(
            &*decoded_body(&encoded("GZIP"), &gzip(b"{\"a\":1}"), 10).unwrap(),
            b"{\"a\":1}"
        );
    }

    #[test]
    fn a_bomb_a_broken_stream_and_other_encodings_are_refused() {
        let bomb = gzip(&vec![0; 9 * 1024 * 1024]);
        assert!(bomb.len() < 64 * 1024, "small on the wire");
        assert_eq!(
            decoded_body(&encoded("gzip"), &bomb, 8 * 1024 * 1024).unwrap_err(),
            ApiError::BadRequest
        );
        assert_eq!(
            decoded_body(&encoded("gzip"), b"not gzip", 10).unwrap_err(),
            ApiError::BadRequest
        );
        assert_eq!(
            decoded_body(&encoded("br"), b"{}", 10).unwrap_err(),
            ApiError::BadRequest
        );
    }
}
