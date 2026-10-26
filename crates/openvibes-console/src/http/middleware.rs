//! Middleware on every console listener: body and concurrency limits,
//! deadlines, request logging, security headers, and the `Host` checks with
//! their 421 page.

use std::sync::Arc;

use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
};
use tokio::{sync::Semaphore, time::timeout};

use super::{
    AuthHttpState,
    problem::{ProblemDetails, next_request_id, problem_response},
};

const MAX_REQUEST_BODY_BYTES: usize = 1_048_576;
const MAX_IN_FLIGHT_REQUESTS: usize = 128;
const REQUEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);
// The orchestrator bounds each question (`Settings::longest`: at most 15
// minutes for the model plus 30 s per internet lookup, 20.5 minutes in all)
// and answers 504 itself; this is only a backstop.
const ASSISTANT_REQUEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(1_260);
/// Time past the orchestrator's own question deadline before the console
/// gives up, so the orchestrator ends the answer first.
const ASSISTANT_ANSWER_MARGIN: std::time::Duration = std::time::Duration::from_secs(5);

/// The console's backstop for one answer: the question's hard bound (the
/// tuned deadline plus its internet lookups, `Settings::longest`) plus a
/// margin, never a fixed cap that would cut off a slow host's answer.
pub(crate) fn assistant_answer_timeout(
    question_deadline: std::time::Duration,
) -> std::time::Duration {
    question_deadline + ASSISTANT_ANSWER_MARGIN
}

// ponytail: one shared router cap; split API and asset budgets if one starves the other.
pub(super) fn with_request_limits(router: Router) -> Router {
    router
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            Arc::new(Semaphore::new(MAX_IN_FLIGHT_REQUESTS)),
            request_limits,
        ))
        .layer(middleware::map_response(public_security_headers))
        .layer(middleware::from_fn(request_logging))
}

async fn request_logging(request: axum::extract::Request, next: middleware::Next) -> Response {
    let method = request.method().clone();
    let path = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|matched| matched.as_str())
        .unwrap_or("unmatched")
        .to_owned();
    let mut response = next.run(request).await;
    let request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(next_request_id);
    response.headers_mut().insert(
        "x-request-id",
        request_id
            .parse()
            .expect("generated request IDs are valid headers"),
    );
    tracing::info!(
        request_id = %request_id,
        method = %method,
        path = %path,
        status = response.status().as_u16(),
        "console request completed"
    );
    response
}

async fn request_limits(
    axum::extract::State(capacity): axum::extract::State<Arc<Semaphore>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let Ok(_permit) = capacity.try_acquire_owned() else {
        return problem_response(ProblemDetails::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "request_capacity_exceeded",
            "The console is temporarily at capacity",
        ));
    };
    let deadline = if request.uri().path().starts_with("/api/v1/assistant/") {
        ASSISTANT_REQUEST_DEADLINE
    } else {
        REQUEST_DEADLINE
    };
    match timeout(deadline, next.run(request)).await {
        Ok(response) => response,
        // Not 408: browsers silently resend a request answered 408, which
        // then hits the per-user assistant lock and hides this error.
        Err(_) => problem_response(ProblemDetails::new(
            StatusCode::GATEWAY_TIMEOUT,
            "request_timed_out",
            "The request exceeded its time limit",
        )),
    }
}

pub(super) async fn loopback_host_only(
    request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let allowed = request
        .headers()
        .get(header::HOST)
        .is_none_or(|host| host.to_str().is_ok_and(is_loopback_host));
    if allowed {
        next.run(request).await
    } else {
        let mut response = StatusCode::MISDIRECTED_REQUEST.into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

/// Whether `host` (lowercase) is one of `hosts`: exactly, or under a
/// certificate's wildcard `*.x.y`, which covers one label more (`a.x.y`,
/// not `x.y` or `a.b.x.y`), at the same port as written.
pub(crate) fn host_served(hosts: &[String], host: &str) -> bool {
    hosts.iter().any(|served| {
        served == host
            || served.strip_prefix('*').is_some_and(|suffix| {
                host.strip_suffix(suffix)
                    .is_some_and(|label| !label.is_empty() && !label.contains(['.', ':', '[']))
            })
    })
}

pub(super) async fn authenticated_host_only(
    State(state): State<AuthHttpState>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    // The 421 page's own look loads under any name: fixed files, no data.
    // This layer is outside the others, so both answers get the console's
    // security headers here (CSP, nosniff, framing; reviewer on #116).
    if let Some(response) = misdirected_asset(request.uri().path()) {
        return public_security_headers(response).await;
    }
    let allowed = request.headers().get(header::HOST).is_none_or(|host| {
        host.to_str()
            .is_ok_and(|host| host_served(&state.allowed_hosts, &host.to_ascii_lowercase()))
    });
    if allowed {
        next.run(request).await
    } else {
        public_security_headers(misdirected(&state.public_origin)).await
    }
}

/// 421 for a name this console does not serve: a short page with the right
/// address, never a blank one (board #71). Still refused, so a hostile name
/// resolving here (DNS rebinding) reads nothing.
fn misdirected(public_origin: &str) -> Response {
    let origin = html_escape(public_origin);
    // Board #81: the sign-in page's look (its own stylesheet and wordmarks,
    // as the console's CSP allows no inline style) and plain words.
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>OpenVIBES: wrong address</title>\
         <link rel=\"stylesheet\" href=\"/misdirected/page.css\"></head><body>\
         <main class=\"signin\"><div class=\"signin__card\"><picture>\
         <source srcset=\"/misdirected/wordmark-dark.svg\" media=\"(prefers-color-scheme: dark)\">\
         <img class=\"signin__logo\" src=\"/misdirected/wordmark-light.svg\" alt=\"OpenVIBES\">\
         </picture><h1>Wrong address</h1>\
         <p>This OpenVIBES console does not answer to the address you opened.</p>\
         <a class=\"button\" href=\"{origin}/\">Open the console</a>\
         <p class=\"address\">{origin}</p>\
         <p class=\"hint\">If that link does not open from where you are, ask whoever set up \
         OpenVIBES which address to use.</p></div></main></body></html>"
    );
    let mut response = (StatusCode::MISDIRECTED_REQUEST, body).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

/// The 421 page's stylesheet and wordmarks, by exact path.
fn misdirected_asset(path: &str) -> Option<Response> {
    let (body, kind): (&'static str, &'static str) = match path {
        "/misdirected/page.css" => (include_str!("misdirected.css"), "text/css; charset=utf-8"),
        "/misdirected/wordmark-light.svg" => (
            include_str!("../../web/public/brand/openvibes-wordmark-light.svg"),
            "image/svg+xml",
        ),
        "/misdirected/wordmark-dark.svg" => (
            include_str!("../../web/public/brand/openvibes-wordmark-dark.svg"),
            "image/svg+xml",
        ),
        _ => return None,
    };
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(kind));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    Some(response)
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The origin a browser request must carry: `https://` + the `Host` it was
/// sent to (already one this console serves), or `public_origin` without one.
pub(crate) fn request_origin(state: &AuthHttpState, headers: &axum::http::HeaderMap) -> String {
    headers
        .get(header::HOST)
        .and_then(|host| host.to_str().ok())
        .map_or_else(
            || state.public_origin.to_string(),
            |host| format!("https://{host}"),
        )
}

/// `localhost`, `127.0.0.1`, or `[::1]`, with or without a port.
fn is_loopback_host(host: &str) -> bool {
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map_or("", |(name, _)| name),
        None => host.rsplit_once(':').map_or(host, |(name, _)| name),
    };
    name.eq_ignore_ascii_case("localhost") || name == "127.0.0.1" || name == "::1"
}

async fn public_security_headers(mut response: Response) -> Response {
    const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
    const PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");
    const FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");

    // Enforce the complete browser policy on every public response.
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; img-src 'self'; font-src 'none'; connect-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; worker-src 'none'; manifest-src 'self'",
        ),
    );
    response
        .headers_mut()
        .insert(FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        PERMISSIONS_POLICY,
        HeaderValue::from_static("camera=(), geolocation=(), microphone=(), payment=(), usb=()"),
    );
    response
}

#[cfg(test)]
mod host_served_tests {
    use super::host_served;

    #[test]
    fn a_wildcard_covers_one_label_at_its_port() {
        let hosts = ["*.x.y:443".to_owned(), "*.x.y".to_owned(), "x.z".to_owned()];
        for host in ["a.x.y", "a.x.y:443", "x.z"] {
            assert!(host_served(&hosts, host), "{host}");
        }
        for host in [
            "x.y",
            ".x.y",
            "a.b.x.y",
            "a.b.x.y:443",
            "a.x.y:8443",
            "a.x.z",
            "evil-x.y",
        ] {
            assert!(!host_served(&hosts, host), "{host}");
        }
    }
}

#[cfg(test)]
mod request_deadline_tests {
    use axum::{Router, body::Body, http::Request, routing::get};
    use tower::ServiceExt;

    use super::{StatusCode, with_request_limits};

    async fn status_after(path: &'static str, wait: u64) -> StatusCode {
        let app = with_request_limits(Router::new().route(
            path,
            get(move || async move {
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
            }),
        ));
        let request = Request::get(path).body(Body::empty()).unwrap();
        app.oneshot(request).await.unwrap().status()
    }

    #[tokio::test(start_paused = true)]
    async fn a_timed_out_request_is_504_not_408_which_browsers_resend() {
        assert_eq!(
            status_after("/api/v1/slow", 16).await,
            StatusCode::GATEWAY_TIMEOUT
        );
    }

    #[test]
    fn the_answer_timeout_follows_the_tuned_deadline_and_fits_the_request_deadline() {
        use super::{ASSISTANT_REQUEST_DEADLINE, assistant_answer_timeout};
        use std::time::Duration;
        // A 4-vCPU host tuned to 72 s per call, 7 calls: far past 30 s.
        let tuned = Duration::from_secs(72 * 7);
        assert!(assistant_answer_timeout(tuned) > tuned);
        // The longest question (15 minutes, 8 lookups, each one an internet
        // lookup) still ends inside the request deadline, so the
        // orchestrator answers before either cap.
        let longest = platform_assistant::Settings {
            mode: platform_assistant::probe::ResolvedMode::Native,
            budget: platform_assistant::Profile::Small.budget(),
            max_lookups: 8,
            deadline: Duration::from_secs(900),
            now: chrono::Utc::now(),
        }
        .longest();
        assert_eq!(longest, Duration::from_secs(900 + 11 * 30));
        assert!(assistant_answer_timeout(longest) <= ASSISTANT_REQUEST_DEADLINE);
    }

    #[tokio::test(start_paused = true)]
    async fn an_assistant_answer_may_take_longer_than_30_seconds() {
        assert_eq!(
            status_after("/api/v1/assistant/messages", 120).await,
            StatusCode::OK
        );
    }
}
