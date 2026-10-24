use axum::http::{HeaderMap, StatusCode};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::DateTime;
use platform_store::console_cases::{self as store, CaseSummary};

use crate::{ProblemDetails, http::headers::parse_if_match_version};

pub(super) fn encode_cursor(case: &CaseSummary) -> String {
    URL_SAFE_NO_PAD.encode(format!(
        "{}.{}",
        case.updated_at.timestamp_micros(),
        case.case_id
    ))
}

pub(super) fn decode_cursor(text: &str) -> Option<store::CaseCursor> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    let (micros, id) = std::str::from_utf8(&bytes).ok()?.split_once('.')?;
    Some((
        DateTime::from_timestamp_micros(micros.parse().ok()?)?,
        id.to_owned(),
    ))
}

/// A title without the spaces around it; the store checks the rest.
pub(super) fn title(raw: &str) -> &str {
    raw.trim()
}

/// A resolution or outcome note without the spaces around it; a blank one
/// is as good as none.
pub(super) fn blank_is_absent(note: Option<&str>) -> Option<&str> {
    note.map(str::trim).filter(|note| !note.is_empty())
}

/// The answer to a change that states no usable `If-Match`, or its version.
pub(super) fn precondition(headers: &HeaderMap) -> Result<i64, ProblemDetails> {
    match parse_if_match_version(headers) {
        Ok(Some(version)) => Ok(version),
        Ok(None) => Err(ProblemDetails::new(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "If-Match is required",
        )),
        Err(()) => Err(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_precondition",
            "If-Match must contain one quoted version",
        )),
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::decode_cursor;

    #[test]
    fn a_cursor_round_trips_and_garbage_is_refused() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let at = Utc.with_ymd_and_hms(2026, 10, 4, 12, 0, 0).unwrap();
        let text = URL_SAFE_NO_PAD.encode(format!(
            "{}.{}",
            at.timestamp_micros(),
            "11111111-1111-4111-8111-111111111111"
        ));
        assert_eq!(
            decode_cursor(&text),
            Some((at, "11111111-1111-4111-8111-111111111111".to_owned()))
        );
        for bad in [
            "",
            "!!",
            &URL_SAFE_NO_PAD.encode("no-dot"),
            &URL_SAFE_NO_PAD.encode("x.y"),
        ] {
            assert_eq!(decode_cursor(bad), None, "{bad:?}");
        }
    }
}
