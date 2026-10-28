//! One request in, one response out, one process (or one connection) per
//! upload. A request is a JSON line (the crop) then the picture's bytes to the
//! end of the stream. A response is a JSON line then the large and the small
//! image's bytes.

use serde::{Deserialize, Serialize};

use crate::{Crop, MAX_BYTES, Output, Refusal};

/// More than the JSON line can take.
const MAX_HEADER: usize = 1024;
/// Most bytes of a request.
pub const MAX_REQUEST: usize = MAX_BYTES + MAX_HEADER;

/// The first line of a response.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Header {
    /// Converted; the bytes of the two images follow.
    Ok {
        /// Length of the 256 px image.
        large: usize,
        /// Length of the 64 px image.
        small: usize,
        /// Whether they are animated.
        animated: bool,
    },
    /// Not converted.
    Refused {
        /// Why.
        code: Refusal,
    },
}

/// A request as bytes.
pub fn request(crop: Crop, picture: &[u8]) -> Vec<u8> {
    let mut out = serde_json::to_vec(&crop).unwrap_or_default();
    out.push(b'\n');
    out.extend_from_slice(picture);
    out
}

/// Splits a request into the crop and the picture.
pub fn parse_request(bytes: &[u8]) -> Result<(Crop, &[u8]), Refusal> {
    let line = bytes
        .iter()
        .take(MAX_HEADER)
        .position(|byte| *byte == b'\n')
        .ok_or(Refusal::Crop)?;
    let crop = serde_json::from_slice(&bytes[..line]).map_err(|_| Refusal::Crop)?;
    Ok((crop, &bytes[line + 1..]))
}

/// A response as bytes.
pub fn response(result: Result<Output, Refusal>) -> Vec<u8> {
    let (header, rest) = match result {
        Ok(output) => (
            Header::Ok {
                large: output.large.len(),
                small: output.small.len(),
                animated: output.animated,
            },
            [output.large, output.small].concat(),
        ),
        Err(code) => (Header::Refused { code }, Vec::new()),
    };
    let mut out = serde_json::to_vec(&header).unwrap_or_default();
    out.push(b'\n');
    out.extend_from_slice(&rest);
    out
}

/// Splits a response into the result and the two images.
pub fn parse_response(bytes: &[u8]) -> Option<Result<Output, Refusal>> {
    let line = bytes.iter().position(|byte| *byte == b'\n')?;
    let header: Header = serde_json::from_slice(&bytes[..line]).ok()?;
    let body = &bytes[line + 1..];
    match header {
        Header::Refused { code } => Some(Err(code)),
        Header::Ok {
            large,
            small,
            animated,
        } => {
            if body.len() != large.checked_add(small)? {
                return None;
            }
            Some(Ok(Output {
                large: body[..large].to_vec(),
                small: body[large..].to_vec(),
                animated,
            }))
        }
    }
}

/// What the helper does with one request.
#[cfg(feature = "decode")]
pub fn handle(request: &[u8]) -> Vec<u8> {
    response(parse_request(request).and_then(|(crop, picture)| crate::convert(picture, crop)))
}
