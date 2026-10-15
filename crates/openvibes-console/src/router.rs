use axum::{
    http::{HeaderMap, HeaderValue, header},
    response::Response,
};

pub(crate) fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub(crate) fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

pub(crate) fn valid_agent_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

pub(crate) fn parse_if_match_version(headers: &HeaderMap) -> Result<Option<i64>, ()> {
    let values = headers.get_all(header::IF_MATCH);
    let mut iter = values.iter();
    let Some(value) = iter.next() else {
        return Ok(None);
    };
    if iter.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    let version = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(())?;
    if version.is_empty() || !version.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    let version = version.parse::<i64>().map_err(|_| ())?;
    (version > 0).then_some(Some(version)).ok_or(())
}

pub(crate) fn parse_if_match_zero_version(headers: &HeaderMap) -> Result<Option<i64>, ()> {
    let values = headers.get_all(header::IF_MATCH);
    let mut iter = values.iter();
    let Some(value) = iter.next() else {
        return Ok(None);
    };
    if iter.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    let version = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(())?;
    if version.is_empty() || !version.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    Ok(Some(version.parse::<i64>().map_err(|_| ())?))
}
