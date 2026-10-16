//! Behind a reverse proxy: only the trusted proxy may connect, and the
//! client address it forwards.

use std::{collections::HashSet, net::IpAddr};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware,
    response::{IntoResponse, Response},
};

use super::listeners::TrustedPeer;

/// Client address parsed from a header supplied by an authenticated proxy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TrustedProxyClient {
    pub source: Option<IpAddr>,
}

pub(super) struct TrustedProxyPeers {
    pub(super) addresses: HashSet<IpAddr>,
    pub(super) uids: HashSet<u32>,
}

pub(super) async fn trusted_proxy_only(
    State(allowed): State<std::sync::Arc<TrustedProxyPeers>>,
    mut request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let trusted = request
        .extensions()
        .get::<ConnectInfo<TrustedPeer>>()
        .is_some_and(|ConnectInfo(peer)| peer.is_allowed(&allowed.addresses, &allowed.uids));
    if trusted {
        let source = trusted_forwarded_address(request.headers());
        request
            .extensions_mut()
            .insert(TrustedProxyClient { source });
        next.run(request).await
    } else {
        let mut response = StatusCode::FORBIDDEN.into_response();
        response
            .headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-store"));
        response
    }
}

fn trusted_forwarded_address(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(|value| value.trim().parse().ok())
}

#[cfg(test)]
mod trusted_proxy_header_tests {
    use super::trusted_forwarded_address;
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::IpAddr;

    #[test]
    fn uses_the_last_forwarded_ip_from_the_authenticated_proxy() {
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.23"));
        headers.append("x-forwarded-for", HeaderValue::from_static("192.0.2.8"));
        assert_eq!(
            trusted_forwarded_address(&headers),
            Some("192.0.2.8".parse::<IpAddr>().unwrap())
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("192.0.2.8, 198.51.100.4"),
        );
        assert_eq!(
            trusted_forwarded_address(&headers),
            Some("198.51.100.4".parse::<IpAddr>().unwrap())
        );
        headers.insert("x-forwarded-for", HeaderValue::from_static("host.invalid"));
        assert_eq!(trusted_forwarded_address(&headers), None);
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("192.0.2.8, invalid"),
        );
        assert_eq!(trusted_forwarded_address(&headers), None);
    }
}
