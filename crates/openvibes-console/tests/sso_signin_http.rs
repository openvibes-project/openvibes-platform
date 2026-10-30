//! Signing in through the identity provider: a good response signs the
//! person in with roles from their groups, and every kind of bad response
//! gets the same answer while the audit log keeps the reason.

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use platform_store::console_roles::Reach;
use samael::{
    crypto::{CertificateDer, Crypto, CryptoProvider},
    idp::{
        CertificateParams, IdentityProvider,
        response_builder::{ResponseAttribute, build_response_template},
        sp_extractor::RequiredAttribute,
    },
    traits::ToXml,
};
use serde_json::json;
use tower::ServiceExt;

mod common;
use common::{http::ORIGIN, people::Fx};

const IDP: &str = "https://idp.example/metadata";
const SSO_URL: &str = "https://idp.example/sso";
const AUDIENCE: &str = "https://console.example/auth/saml/metadata";
const ACS: &str = "https://console.example/auth/saml/acs";

struct Idp {
    provider: IdentityProvider,
    cert: CertificateDer,
}

impl Idp {
    fn new(days: u32) -> Self {
        let provider =
            IdentityProvider::generate_new(samael::idp::KeyType::Rsa(samael::idp::Rsa::Rsa2048))
                .unwrap();
        let cert = provider
            .create_certificate(&CertificateParams {
                common_name: "idp.example",
                issuer_name: "idp.example",
                days_until_expiration: days,
            })
            .unwrap();
        Self { provider, cert }
    }

    fn pem(&self) -> String {
        let body = STANDARD.encode(self.cert.der_data());
        let lines: Vec<&str> = body
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect();
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            lines.join("\n")
        )
    }
}

/// What a test may break in an otherwise good response.
#[derive(Clone)]
struct Answer<'a> {
    name_id: &'a str,
    groups: &'a [&'a str],
    audience: &'a str,
    recipient: &'a str,
    destination: &'a str,
    issuer: &'a str,
    request_id: Option<&'a str>,
    issued: chrono::DateTime<Utc>,
    sha1: bool,
    unsigned: bool,
    no_end: bool,
    no_audience: bool,
}

impl<'a> Answer<'a> {
    fn good(name_id: &'a str, groups: &'a [&'a str]) -> Self {
        Self {
            name_id,
            groups,
            audience: AUDIENCE,
            recipient: ACS,
            destination: ACS,
            issuer: IDP,
            request_id: None,
            issued: Utc::now(),
            sha1: false,
            unsigned: false,
            no_end: false,
            no_audience: false,
        }
    }
}

fn signed(idp: &Idp, answer: &Answer<'_>, request_id: &str) -> String {
    let attributes = [
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "displayName".into(),
                format: None,
            },
            value: "Pat Example",
        },
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "email".into(),
                format: None,
            },
            value: "pat@example.com",
        },
    ];
    let mut response = build_response_template(
        &idp.cert,
        answer.name_id,
        answer.audience,
        answer.issuer,
        answer.destination,
        answer.request_id.unwrap_or(request_id),
        &attributes,
    );
    response.issue_instant = answer.issued;
    if !answer.sha1 {
        let signature = response.signature.as_mut().unwrap();
        signature.signed_info.reference[0].digest_method.algorithm =
            samael::signature::DigestAlgorithm::Sha256;
    }
    let assertion = response.assertion.as_mut().unwrap();
    assertion.issue_instant = answer.issued;
    let end = Some(answer.issued + Duration::minutes(5));
    assertion.conditions.as_mut().unwrap().not_on_or_after = if answer.no_end { None } else { end };
    if answer.no_audience {
        assertion.conditions.as_mut().unwrap().audience_restrictions = None;
    }
    let confirmation = &mut assertion
        .subject
        .as_mut()
        .unwrap()
        .subject_confirmations
        .as_mut()
        .unwrap()[0];
    let data = confirmation.subject_confirmation_data.as_mut().unwrap();
    data.not_on_or_after = end;
    data.recipient = Some(answer.recipient.to_owned());
    let statement = &mut assertion.attribute_statements.as_mut().unwrap()[0];
    for group in answer.groups {
        statement.attributes.push(samael::attribute::Attribute {
            friendly_name: None,
            name: Some("groups".into()),
            name_format: None,
            values: vec![samael::attribute::AttributeValue {
                attribute_type: Some("xs:string".into()),
                value: Some((*group).into()),
            }],
        });
    }
    if answer.unsigned {
        response.signature = None;
        return response.to_string().unwrap();
    }
    Crypto::sign_xml(
        response.to_string().unwrap(),
        idp.provider.export_private_key_der().unwrap().as_slice(),
    )
    .unwrap()
}

fn percent(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

/// Builds the response for one started sign-in.
type Maker<'a> = Box<dyn Fn(&Started) -> String + 'a>;

struct Started {
    relay: String,
    cookie: String,
    request_id: String,
}

async fn start(fx: &Fx) -> Started {
    let response = fx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/saml/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(location.starts_with(SSO_URL), "{location}");
    assert!(location.contains("SAMLRequest="));
    let relay = location
        .split('&')
        .find_map(|part| part.strip_prefix("RelayState="))
        .unwrap()
        .to_owned();
    let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(set_cookie.contains("SameSite=None") && set_cookie.contains("Secure"));
    let cookie = set_cookie.split(';').next().unwrap().to_owned();
    let client = fx.db.pool.get().await.unwrap();
    let request_id: String = client
        .query_one(
            "SELECT request_id FROM console_saml_requests ORDER BY created_at DESC LIMIT 1",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    Started {
        relay,
        cookie,
        request_id,
    }
}

async fn post(fx: &Fx, xml: &str, relay: &str, cookie: Option<&str>) -> axum::response::Response {
    let body = format!(
        "SAMLResponse={}&RelayState={}",
        percent(&STANDARD.encode(xml)),
        percent(relay)
    );
    let mut request = Request::builder()
        .method("POST")
        .uri("/auth/saml/acs")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ORIGIN, "https://idp.example");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    fx.router
        .clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

async fn configure(fx: &Fx, idp: &Idp) {
    for (key, value) in [
        ("sso.idp_entity_id", json!(IDP)),
        ("sso.idp_sso_url", json!(SSO_URL)),
        ("sso.idp_certificates", json!(idp.pem())),
        ("sso.enabled", json!(true)),
    ] {
        let (status, body) = fx
            .call(
                &fx.admin,
                "PATCH",
                &format!("/api/v1/settings/{key}"),
                Some(json!({"value": value})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{key}: {body}");
    }
}

async fn reasons(fx: &Fx) -> Vec<String> {
    let client = fx.db.pool.get().await.unwrap();
    client
        .query(
            "SELECT reason_code FROM audit_log WHERE action = 'auth.saml.refused' ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

async fn sso_users(fx: &Fx) -> i64 {
    let client = fx.db.pool.get().await.unwrap();
    client
        .query_one("SELECT count(*) FROM console_sso_users", &[])
        .await
        .unwrap()
        .get(0)
}

fn refused(response: &axum::response::Response) -> bool {
    response.status() == StatusCode::SEE_OTHER
        && response.headers()[header::LOCATION] == "/login?sso=failed"
        && !response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|value| {
                value
                    .to_str()
                    .unwrap()
                    .starts_with("__Host-openvibes-session=")
            })
}

#[tokio::test]
async fn a_good_response_signs_in_with_roles_from_groups() {
    let Some(fx) = Fx::new().await else { return };
    fx.role("Analyst", &["hosts.read"], Reach::All).await;
    let idp = Idp::new(30);
    configure(&fx, &idp).await;

    let (status, body) = fx.call(&fx.admin, "GET", "/auth/v1/sso", None).await;
    assert_eq!((status, &body["enabled"]), (StatusCode::OK, &json!(true)));

    let started = start(&fx).await;
    let xml = signed(
        &idp,
        &Answer::good("pat-1", &["analyst", "Unrelated"]),
        &started.request_id,
    );
    let response = post(&fx, &xml, &started.relay, Some(&started.cookie)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/");
    let session = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|value| {
            let value = value.to_str().unwrap();
            value
                .starts_with("__Host-openvibes-session=")
                .then(|| value.split(';').next().unwrap().to_owned())
        })
        .expect("a session cookie");
    let (status, me) = fx
        .call(&(session, String::new()), "GET", "/api/v1/session", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["principal"]["display_name"], "Pat Example");
    assert_eq!(me["authentication_method"], "saml");

    let client = fx.db.pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT u.auth_source, u.email, b.source, r.display_name
             FROM console_sso_users s JOIN console_users u USING (user_id)
             JOIN console_role_bindings b ON b.user_id = u.user_id AND b.revoked_at IS NULL
             JOIN console_roles r USING (role_id)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "sso");
    assert_eq!(row.get::<_, String>(1), "pat@example.com");
    assert_eq!(row.get::<_, String>(2), "sso");
    assert_eq!(row.get::<_, String>(3), "Analyst");
    let method: String = client
        .query_one("SELECT authentication_method FROM audit_log WHERE action = 'auth.login.succeeded' ORDER BY id DESC LIMIT 1", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(method, "saml");

    // an administrator cannot edit what the next sign-in would overwrite
    let user_id: String = client
        .query_one("SELECT user_id::text FROM console_sso_users", &[])
        .await
        .unwrap()
        .get(0);
    let (status, body) = fx
        .call(
            &fx.admin,
            "PATCH",
            &format!("/api/v1/users/{user_id}"),
            Some(json!({"display_name": "Other"})),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("managed_by_sso"))
    );
    let (status, body) = fx
        .call(
            &fx.admin,
            "PUT",
            &format!("/api/v1/users/{user_id}/roles/admin"),
            None,
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("managed_by_sso"))
    );

    // the same response again: the request was used up
    let again = post(&fx, &xml, &started.relay, Some(&started.cookie)).await;
    assert!(refused(&again));
    assert_eq!(reasons(&fx).await, ["unknown_request"]);
    fx.db.drop().await;
}

#[tokio::test]
async fn every_bad_response_is_refused_alike_and_creates_nobody() {
    let Some(fx) = Fx::new().await else { return };
    fx.role("Analyst", &["hosts.read"], Reach::All).await;
    let idp = Idp::new(30);
    configure(&fx, &idp).await;
    let other = Idp::new(30);
    let groups = ["Analyst"];
    let good = Answer::good("pat-9", &groups);
    let mut expected = Vec::new();

    // (the response, the reason the log should hold)
    let cases: Vec<(&str, Maker)> = vec![
        (
            "bad_signature",
            Box::new(|s| signed(&other, &good, &s.request_id)),
        ),
        (
            "bad_signature",
            Box::new(|s| signed(&idp, &good, &s.request_id).replace("pat-9", "pat-8")),
        ),
        (
            "bad_signature",
            Box::new(|s| {
                signed(
                    &idp,
                    &Answer {
                        sha1: true,
                        ..good.clone()
                    },
                    &s.request_id,
                )
            }),
        ),
        (
            "wrong_audience",
            Box::new(|s| {
                signed(
                    &idp,
                    &Answer {
                        audience: "https://elsewhere.example/",
                        ..good.clone()
                    },
                    &s.request_id,
                )
            }),
        ),
        (
            "wrong_destination",
            Box::new(|s| {
                signed(
                    &idp,
                    &Answer {
                        destination: "https://elsewhere.example/acs",
                        ..good.clone()
                    },
                    &s.request_id,
                )
            }),
        ),
        (
            "wrong_destination",
            Box::new(|s| {
                signed(
                    &idp,
                    &Answer {
                        recipient: "https://elsewhere.example/acs",
                        ..good.clone()
                    },
                    &s.request_id,
                )
            }),
        ),
        (
            "wrong_request",
            Box::new(|s| {
                signed(
                    &idp,
                    &Answer {
                        request_id: Some("_someone-elses-request"),
                        ..good.clone()
                    },
                    &s.request_id,
                )
            }),
        ),
        (
            "wrong_issuer",
            Box::new(|s| {
                signed(
                    &idp,
                    &Answer {
                        issuer: "https://other.example/",
                        ..good.clone()
                    },
                    &s.request_id,
                )
            }),
        ),
        (
            "expired",
            Box::new(|s| {
                signed(
                    &idp,
                    &Answer {
                        issued: Utc::now() - Duration::hours(1),
                        ..good.clone()
                    },
                    &s.request_id,
                )
            }),
        ),
        (
            "no_role",
            Box::new(|s| signed(&idp, &Answer::good("pat-9", &["Unrelated"]), &s.request_id)),
        ),
        (
            "invalid_response",
            Box::new(|s| {
                format!(
                    "<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>{}",
                    signed(&idp, &good, &s.request_id)
                )
            }),
        ),
        ("bad_signature", Box::new(|_| "<not-saml/>".to_owned())),
    ];
    for (reason, make) in &cases {
        let started = start(&fx).await;
        let xml = make(&started);
        let response = post(&fx, &xml, &started.relay, Some(&started.cookie)).await;
        assert!(refused(&response), "{reason}");
        expected.push((*reason).to_owned());
    }

    // another browser, no cookie, a made-up relay token
    let started = start(&fx).await;
    let xml = signed(&idp, &good, &started.request_id);
    assert!(refused(&post(&fx, &xml, &started.relay, None).await));
    expected.push("other_browser".into());
    assert!(refused(
        &post(
            &fx,
            &xml,
            &started.relay,
            Some("__Host-openvibes-saml=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        )
        .await
    ));
    expected.push("unknown_request".into());
    assert!(refused(
        &post(&fx, &xml, "made-up", Some(&started.cookie)).await
    ));
    expected.push("unknown_request".into());

    assert_eq!(reasons(&fx).await, expected);
    assert_eq!(sso_users(&fx).await, 0);

    // turned off: starting goes back to the login page, a response is refused
    let (status, _) = fx
        .call(
            &fx.admin,
            "PATCH",
            "/api/v1/settings/sso.enabled",
            Some(json!({"value": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let response = fx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/saml/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()[header::LOCATION], "/login?sso=failed");
    let _ = ORIGIN;
    fx.db.drop().await;
}

#[tokio::test]
async fn roles_follow_the_groups_and_manual_roles_survive() {
    let Some(fx) = Fx::new().await else { return };
    let analyst = fx.role("Analyst", &["hosts.read"], Reach::All).await;
    let viewer = fx.role("Viewer", &["hosts.read"], Reach::All).await;
    let idp = Idp::new(30);
    configure(&fx, &idp).await;
    let client = fx.db.pool.get().await.unwrap();
    let active = || async {
        let rows = client
            .query(
                "SELECT b.role_id, b.source FROM console_role_bindings b
                 JOIN console_sso_users s USING (user_id) WHERE b.revoked_at IS NULL ORDER BY 1",
                &[],
            )
            .await
            .unwrap();
        rows.iter()
            .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
            .collect::<Vec<_>>()
    };
    let attempt = |groups: &'static [&'static str]| {
        let fx = &fx;
        let idp = &idp;
        async move {
            let started = start(fx).await;
            let xml = signed(idp, &Answer::good("pat-7", groups), &started.request_id);
            post(fx, &xml, &started.relay, Some(&started.cookie)).await
        }
    };

    assert!(!refused(&attempt(&["Analyst"]).await));
    assert_eq!(active().await, [(analyst.clone(), "sso".to_owned())]);

    // a role granted by hand
    client
        .execute(
            "INSERT INTO console_role_bindings (binding_id, user_id, role_id, created_at, created_by)
             SELECT gen_random_uuid(), user_id, $1, now(), 'test' FROM console_sso_users",
            &[&viewer],
        )
        .await
        .unwrap();
    // dropped from the group: the identity provider's role goes, the manual one stays and they get in
    assert!(!refused(&attempt(&["Unrelated"]).await));
    assert_eq!(active().await, [(viewer.clone(), "manual".to_owned())]);

    // with no role left at all they are refused
    client.execute("UPDATE console_role_bindings SET revoked_at = now(), revoked_by = 'test' WHERE revoked_at IS NULL AND role_id = $1", &[&viewer]).await.unwrap();
    assert!(refused(&attempt(&["Unrelated"]).await));
    assert_eq!(reasons(&fx).await, ["no_role"]);

    // an administrator disables them: refused even in a matching group
    client.execute("UPDATE console_users SET enabled = false, disabled_at = now() WHERE user_id IN (SELECT user_id FROM console_sso_users)", &[]).await.unwrap();
    assert!(refused(&attempt(&["Analyst"]).await));
    assert_eq!(reasons(&fx).await, ["no_role", "disabled"]);
    drop(client);
    fx.db.drop().await;
}
