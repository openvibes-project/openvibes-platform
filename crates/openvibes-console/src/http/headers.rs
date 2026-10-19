//! Response and request headers several areas share: the no-store cache
//! header, and parsing a version out of `If-Match`.

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
