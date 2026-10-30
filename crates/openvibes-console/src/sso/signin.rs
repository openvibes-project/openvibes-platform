//! Signing in through the identity provider (spec 2026-10-29 §4–§6).
//!
//! The browser is sent to the identity provider with a request we remember
//! (single use, five minutes, tied to this browser by a cookie). The
//! response must come back to the same browser, answer that request, be
//! signed by a current certificate and pass the checks below. Whatever goes
//! wrong, the person sees the same page and the audit log records why.

use std::sync::Mutex;

use axum::{
    Form,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration, Utc};
use platform_store::{console_auth, console_sso};
use ring::rand::{SecureRandom, SystemRandom};
use samael::{schema::Assertion, service_provider::Error as SamlError};
use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroize;

use super::provider::{self, Config};
use crate::access::auth::{
    SessionSecret, named_cookie, session_cookie, session_csrf, session_digest,
};
use crate::access::login::bounded_user_agent;
use crate::http::AuthHttpState;

const COOKIE: &str = "__Host-openvibes-saml";
/// Where a person lands after a refused or failed sign-in.
const FAILED: &str = "/login?sso=failed";
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_GROUPS: usize = 200;
const REQUEST_MINUTES: i64 = 5;

/// Libxml2 and xmlsec keep process-wide state; one check at a time.
static XMLSEC: Mutex<()> = Mutex::new(());

fn random(bytes: usize) -> Option<Vec<u8>> {
    let mut out = vec![0; bytes];
    SystemRandom::new().fill(&mut out).ok()?;
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn go(location: &str) -> Response {
    let mut response = (StatusCode::SEE_OTHER, ()).into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location).expect("fixed location"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn clear_cookie(response: &mut Response) {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-openvibes-saml=; Secure; HttpOnly; SameSite=None; Path=/; Max-Age=0",
        ),
    );
}

async fn stored(state: &AuthHttpState) -> Option<std::collections::HashMap<String, Value>> {
    let client = state.pool.get().await.ok()?;
    platform_store::console_settings::values(&client).await.ok()
}

/// Whether the login page should offer single sign-on.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct SsoStatus {
    /// Single sign-on is on and complete.
    pub enabled: bool,
}

/// Whether single sign-on can be used now (for the login page).
#[utoipa::path(get, path = "/auth/v1/sso", tag = "authentication",
    responses((status = 200, description = "Whether single sign-on is offered", body = SsoStatus)))]
pub(crate) async fn status(State(state): State<AuthHttpState>) -> Response {
    let enabled = state.public_origin_valid
        && stored(&state)
            .await
            .and_then(|stored| provider::config(&stored, Utc::now()))
            .is_some();
    let mut response = axum::Json(SsoStatus { enabled }).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Starts a sign-in: remembers the request and sends the browser on.
#[utoipa::path(get, path = "/auth/saml/start", tag = "authentication",
    responses((status = 302, description = "To the identity provider, or back to the login page"),
        (status = 503, description = "Too many sign-ins waiting")))]
pub(crate) async fn start(State(state): State<AuthHttpState>) -> Response {
    let now = Utc::now();
    if !state.public_origin_valid {
        return go(FAILED);
    }
    let Some(stored) = stored(&state).await else {
        return go(FAILED);
    };
    let Some(config) = provider::config(&stored, now) else {
        return go(FAILED);
    };
    let (Some(id), Some(relay), Some(browser)) = (random(16), random(24), random(32)) else {
        return go(FAILED);
    };
    let request_id = format!("_{}", hex(&id));
    let relay = URL_SAFE_NO_PAD.encode(relay);
    let browser = URL_SAFE_NO_PAD.encode(browser);
    let sp = provider::provider(&config, &state.public_origin);
    let Ok(mut request) = sp.make_authentication_request(&config.sso_url) else {
        return go(FAILED);
    };
    request.id = request_id.clone();
    let Ok(Some(url)) = request.redirect(&relay) else {
        return go(FAILED);
    };
    let Ok(client) = state.pool.get().await else {
        return go(FAILED);
    };
    let relay_hash = session_digest(&relay);
    let browser_hash = session_digest(&browser);
    match console_sso::start_request(
        &client,
        &console_sso::NewRequest {
            relay_sha256: &relay_hash,
            request_id: &request_id,
            browser_sha256: &browser_hash,
            now,
            expires_at: now + Duration::minutes(REQUEST_MINUTES),
        },
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Err(_) => return go(FAILED),
    }
    let mut response = (StatusCode::FOUND, ()).into_response();
    let (Ok(location), Ok(cookie)) = (
        HeaderValue::from_str(url.as_str()),
        HeaderValue::from_str(&format!(
            "{COOKIE}={browser}; Secure; HttpOnly; SameSite=None; Path=/; Max-Age={}",
            REQUEST_MINUTES * 60
        )),
    ) else {
        return go(FAILED);
    };
    response.headers_mut().insert(header::LOCATION, location);
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The identity provider's answer, posted by the browser.
#[derive(Deserialize)]
pub(crate) struct AcsForm {
    #[serde(rename = "SAMLResponse")]
    response: Option<String>,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

/// Receives the response and signs the person in.
#[utoipa::path(post, path = "/auth/saml/acs", tag = "authentication",
    responses((status = 303, description = "To the console signed in, or to the login page")))]
pub(crate) async fn acs(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Form(form): Form<AcsForm>,
) -> Response {
    let mut response = match sign_in(&state, &headers, form).await {
        Ok(session_cookie) => {
            let mut response = go("/");
            if let Ok(value) = HeaderValue::from_str(&session_cookie) {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
            response
        }
        Err(reason) => {
            record_refusal(&state, &headers, reason).await;
            go(FAILED)
        }
    };
    clear_cookie(&mut response);
    response
}

async fn record_refusal(state: &AuthHttpState, headers: &HeaderMap, reason: &'static str) {
    let Ok(client) = state.pool.get().await else {
        return;
    };
    let user_agent = bounded_user_agent(headers);
    let context = console_auth::AuditContext {
        request_id: None,
        source_address: None,
        user_agent: user_agent.as_deref(),
    };
    let _ = console_sso::refuse(&client, &context, reason).await;
}

/// The reason code is a fixed word; it is the only thing recorded about why.
async fn sign_in(
    state: &AuthHttpState,
    headers: &HeaderMap,
    form: AcsForm,
) -> Result<String, &'static str> {
    let now = Utc::now();
    let (Some(encoded), Some(relay)) = (form.response, form.relay_state) else {
        return Err("incomplete");
    };
    let browser = match named_cookie(headers, COOKIE) {
        Ok(Some(secret)) => session_digest(secret.expose_secret()),
        _ => return Err("other_browser"),
    };
    let stored = stored(state).await.ok_or("unavailable")?;
    let config = provider::config(&stored, now).ok_or("sso_off")?;
    let mut client = state.pool.get().await.map_err(|_| "unavailable")?;
    let request_id = console_sso::take_request(&client, &session_digest(&relay), &browser, now)
        .await
        .map_err(|_| "unavailable")?
        .ok_or("unknown_request")?;
    let xml = decode(&encoded)?;
    let assertion = verify(&config, &state.public_origin, &xml, &request_id)?;
    let facts = facts(&config, &assertion, &state.public_origin)?;
    let not_on_or_after = assertion
        .conditions
        .as_ref()
        .and_then(|conditions| conditions.not_on_or_after)
        .ok_or("invalid_response")?;
    let outcome = console_sso::sign_in(
        &mut client,
        &console_sso::Person {
            issuer: &config.idp_entity_id,
            subject: &facts.subject,
            display_name: &facts.display_name,
            email: facts.email.as_deref(),
            assertion_id: &assertion.id,
            assertion_expires_at: console_sso::remember_until(not_on_or_after),
            groups: &facts.groups,
            now,
        },
    )
    .await
    .map_err(|_| "unavailable")?;
    let (user_id, auth_generation) = match outcome {
        console_sso::SignIn::Allowed {
            user_id,
            auth_generation,
            ..
        } => (user_id, auth_generation),
        console_sso::SignIn::Replay => return Err("replay"),
        console_sso::SignIn::NoRole => return Err("no_role"),
        console_sso::SignIn::Disabled => return Err("disabled"),
    };
    let secret = SessionSecret::generate().map_err(|_| "unavailable")?;
    let (csrf_token, csrf_hash) = session_csrf(secret.cookie_value());
    drop(csrf_token);
    let session_hash = session_digest(secret.cookie_value());
    let user_agent = bounded_user_agent(headers);
    let created = console_auth::create_session(
        &mut client,
        &console_auth::NewSession {
            session_sha256: &session_hash,
            previous_session_sha256: None,
            csrf_sha256: &csrf_hash,
            user_id: &user_id,
            auth_generation,
            now,
            idle_expires_at: now + Duration::minutes(30),
            absolute_expires_at: now + Duration::hours(8),
            authentication_method: "saml",
            audit: console_auth::AuditContext {
                request_id: None,
                source_address: None,
                user_agent: user_agent.as_deref(),
            },
        },
    )
    .await
    .map_err(|_| "unavailable")?;
    if !created {
        return Err("disabled");
    }
    let mut cookie = session_cookie(&secret);
    let result = cookie.clone();
    cookie.zeroize();
    Ok(result)
}

/// Base64, within the size limit, without a document type declaration or
/// entity (so nothing is fetched or expanded).
fn decode(encoded: &str) -> Result<String, &'static str> {
    if encoded.len() > MAX_RESPONSE_BYTES * 2 {
        return Err("too_large");
    }
    let compact: String = encoded.split_whitespace().collect();
    let bytes = STANDARD.decode(compact).map_err(|_| "invalid_response")?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err("too_large");
    }
    let xml = String::from_utf8(bytes).map_err(|_| "invalid_response")?;
    let upper = xml.to_ascii_uppercase();
    if upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY") {
        return Err("invalid_response");
    }
    Ok(xml)
}

fn verify(
    config: &Config,
    public_origin: &str,
    xml: &str,
    request_id: &str,
) -> Result<Assertion, &'static str> {
    let sp = provider::provider(config, public_origin);
    let guard = XMLSEC
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let result = sp.parse_xml_response(xml, Some(&[request_id]));
    drop(guard);
    result.map_err(|error| match error {
        SamlError::FailedToValidateSignature => "bad_signature",
        SamlError::ResponseInResponseToInvalid { .. }
        | SamlError::AssertionInResponseToInvalid { .. } => "wrong_request",
        SamlError::DestinationValidationError { .. }
        | SamlError::AssertionRecipientMismatch { .. } => "wrong_destination",
        SamlError::AssertionConditionAudienceRestrictionFailed { .. } => "wrong_audience",
        SamlError::AssertionIssuerMismatch { .. } | SamlError::ResponseIssuerMismatch { .. } => {
            "wrong_issuer"
        }
        SamlError::AssertionExpired { .. }
        | SamlError::ResponseExpired { .. }
        | SamlError::AssertionConditionExpired { .. }
        | SamlError::AssertionConditionExpiredBefore { .. }
        | SamlError::AssertionSubjectConfirmationExpired { .. }
        | SamlError::AssertionSubjectConfirmationExpiredBefore { .. } => "expired",
        SamlError::ResponseBadStatusCode { .. } => "idp_refused",
        _ => "invalid_response",
    })
}

struct Facts {
    subject: String,
    display_name: String,
    email: Option<String>,
    groups: Vec<String>,
}

/// The parts of a checked assertion we use. A missing audience restriction
/// or end time is a refusal here: the library only checks them if present.
fn facts(
    config: &Config,
    assertion: &Assertion,
    public_origin: &str,
) -> Result<Facts, &'static str> {
    let ours = super::service_provider::addresses(public_origin);
    let conditions = assertion.conditions.as_ref().ok_or("invalid_response")?;
    if conditions.not_on_or_after.is_none() {
        return Err("invalid_response");
    }
    let audience = conditions
        .audience_restrictions
        .iter()
        .flatten()
        .any(|restriction| restriction.audience.contains(&ours.entity_id));
    if !audience {
        return Err("wrong_audience");
    }
    let subject = assertion
        .subject
        .as_ref()
        .and_then(|subject| subject.name_id.as_ref())
        .map(|name| name.value.trim().to_owned())
        .filter(|value| !value.is_empty() && value.chars().count() <= 512)
        .ok_or("invalid_response")?;
    let values = |name: &str| -> Vec<String> {
        assertion
            .attribute_statements
            .iter()
            .flatten()
            .flat_map(|statement| &statement.attributes)
            .filter(|attribute| {
                attribute.name.as_deref() == Some(name)
                    || attribute.friendly_name.as_deref() == Some(name)
            })
            .flat_map(|attribute| &attribute.values)
            .filter_map(|value| value.value.as_deref())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect()
    };
    let mut groups: Vec<String> = values(&config.group_attribute)
        .into_iter()
        .filter(|group| group.chars().count() <= 256)
        .map(|group| group.to_lowercase())
        .collect();
    groups.sort();
    groups.dedup();
    groups.truncate(MAX_GROUPS);
    let email = values(&config.email_attribute)
        .into_iter()
        .next()
        .filter(|email| plausible_email(email));
    let display_name = values(&config.name_attribute)
        .into_iter()
        .next()
        .or_else(|| email.clone())
        .unwrap_or_else(|| subject.clone());
    let display_name: String = display_name.chars().take(160).collect();
    Ok(Facts {
        subject,
        display_name,
        email,
        groups,
    })
}

fn plausible_email(email: &str) -> bool {
    email.len() <= 254
        && !email.chars().any(char::is_whitespace)
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && !domain.is_empty() && !domain.contains('@')
        })
}
