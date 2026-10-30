//! Our side of a sign-in, built from the stored settings on every request so
//! a change applies at once. Anything short of a complete, current setup
//! gives no provider: the check never falls back to accepting an unsigned
//! response.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use platform_settings::sso_keys;
use samael::{
    crypto::AllowedSignatureAlgorithm,
    key_info::{KeyInfo, X509Data},
    metadata::{EntityDescriptor, IdpSsoDescriptor, KeyDescriptor},
    service_provider::ServiceProvider,
};
use serde_json::Value;

use super::{certificates::current_bodies, service_provider::addresses};

/// What the identity provider and the settings page decide.
pub(super) struct Config {
    pub(super) idp_entity_id: String,
    pub(super) sso_url: String,
    pub(super) group_attribute: String,
    pub(super) name_attribute: String,
    pub(super) email_attribute: String,
    certificates: Vec<String>,
}

fn text(stored: &HashMap<String, Value>, key: &str) -> String {
    stored
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            platform_settings::find(key)
                .and_then(|definition| definition.default_value().as_str().map(str::to_owned))
        })
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// The settings when single sign-on is on and complete: the entity ID, the
/// sign-in address and at least one certificate valid now.
pub(super) fn config(stored: &HashMap<String, Value>, now: DateTime<Utc>) -> Option<Config> {
    if stored.get(sso_keys::ENABLED).and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let idp_entity_id = text(stored, sso_keys::IDP_ENTITY_ID);
    let sso_url = text(stored, sso_keys::IDP_SSO_URL);
    let certificates = current_bodies(&text(stored, sso_keys::IDP_CERTIFICATES), now);
    if idp_entity_id.is_empty() || sso_url.is_empty() || certificates.is_empty() {
        return None;
    }
    Some(Config {
        idp_entity_id,
        sso_url,
        group_attribute: text(stored, sso_keys::GROUP_ATTRIBUTE),
        name_attribute: text(stored, sso_keys::NAME_ATTRIBUTE),
        email_attribute: text(stored, sso_keys::EMAIL_ATTRIBUTE),
        certificates,
    })
}

/// The checker for one response. Only strong signature algorithms count,
/// and a response the identity provider started on its own is refused.
pub(super) fn provider(config: &Config, public_origin: &str) -> ServiceProvider {
    let ours = addresses(public_origin);
    let key_descriptors = config
        .certificates
        .iter()
        .map(|body| KeyDescriptor {
            key_use: Some("signing".to_owned()),
            key_info: KeyInfo {
                id: None,
                x509_data: Some(X509Data {
                    certificates: vec![body.clone()],
                }),
            },
            encryption_methods: None,
        })
        .collect();
    ServiceProvider {
        entity_id: Some(ours.entity_id),
        acs_url: Some(ours.acs_url),
        metadata_url: Some(ours.metadata_url),
        slo_url: None,
        idp_metadata: EntityDescriptor {
            entity_id: Some(config.idp_entity_id.clone()),
            idp_sso_descriptors: Some(vec![IdpSsoDescriptor {
                id: None,
                valid_until: None,
                cache_duration: None,
                protocol_support_enumeration: None,
                error_url: None,
                signature: None,
                key_descriptors,
                organization: None,
                contact_people: Vec::new(),
                artifact_resolution_service: Vec::new(),
                single_logout_services: Vec::new(),
                manage_name_id_services: Vec::new(),
                name_id_formats: Vec::new(),
                want_authn_requests_signed: None,
                single_sign_on_services: Vec::new(),
                name_id_mapping_services: Vec::new(),
                assertion_id_request_services: Vec::new(),
                attribute_profiles: Vec::new(),
                attributes: Vec::new(),
            }]),
            ..EntityDescriptor::default()
        },
        allow_idp_initiated: false,
        force_authn: false,
        max_issue_delay: Duration::seconds(300),
        max_clock_skew: Duration::seconds(120),
        allowed_signature_algorithms: Some(vec![
            AllowedSignatureAlgorithm::RsaSha256,
            AllowedSignatureAlgorithm::RsaSha384,
            AllowedSignatureAlgorithm::RsaSha512,
            AllowedSignatureAlgorithm::EcdsaSha256,
            AllowedSignatureAlgorithm::EcdsaSha384,
        ]),
        ..ServiceProvider::default()
    }
}
