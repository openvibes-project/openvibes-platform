use crate::{Applies, Definition, Kind, Text};

/// Whether single sign-on is on.
pub const ENABLED: &str = "sso.enabled";
/// The identity provider's entity ID.
pub const IDP_ENTITY_ID: &str = "sso.idp_entity_id";
/// Where the browser is sent to sign in.
pub const IDP_SSO_URL: &str = "sso.idp_sso_url";
/// The identity provider's signing certificates (PEM).
pub const IDP_CERTIFICATES: &str = "sso.idp_certificates";
/// The attribute that carries the groups.
pub const GROUP_ATTRIBUTE: &str = "sso.group_attribute";
/// The attribute that carries the display name.
pub const NAME_ATTRIBUTE: &str = "sso.name_attribute";
/// The attribute that carries the email address.
pub const EMAIL_ATTRIBUTE: &str = "sso.email_attribute";
/// Days without a sign-in before a single sign-on user is removed.
pub const REMOVE_INACTIVE_DAYS: &str = "sso.remove_inactive_days";

const SECTION: &str = "Single sign-on";

pub(crate) static DEFINITIONS: [Definition; 8] = [
    Definition {
        key: ENABLED,
        section: SECTION,
        label: "Single sign-on",
        help: "Needs the entity ID, sign-in address and a current certificate below. Signing in with it arrives in a later release; until then this switch changes nothing. The local admin always signs in with a password.",
        kind: Kind::Bool { default: false },
        applies: Applies::Live,
    },
    Definition {
        key: IDP_ENTITY_ID,
        section: SECTION,
        label: "Identity provider entity ID",
        help: "The identity provider's name for itself, from its metadata (Issuer).",
        kind: Kind::Text {
            check: Text::Plain,
            default: "",
        },
        applies: Applies::Live,
    },
    Definition {
        key: IDP_SSO_URL,
        section: SECTION,
        label: "Sign-in address",
        help: "The identity provider's single sign-on address (https; plain http only for this machine, for testing).",
        kind: Kind::Text {
            check: Text::HttpsUrlOrEmpty,
            default: "",
        },
        applies: Applies::Live,
    },
    Definition {
        key: IDP_CERTIFICATES,
        section: SECTION,
        label: "Identity provider signing certificates",
        help: "Public certificate(s) in PEM form that sign its responses. Add the new one before the old one expires (up to three).",
        kind: Kind::Text {
            check: Text::CertificatesOrEmpty,
            default: "",
        },
        applies: Applies::Live,
    },
    Definition {
        key: GROUP_ATTRIBUTE,
        section: SECTION,
        label: "Group attribute name",
        help: "The attribute that lists a person's groups. A group named like a role gives that role.",
        kind: Kind::Text {
            check: Text::Plain,
            default: "groups",
        },
        applies: Applies::Live,
    },
    Definition {
        key: NAME_ATTRIBUTE,
        section: SECTION,
        label: "Name attribute name",
        help: "The attribute that holds the person's display name.",
        kind: Kind::Text {
            check: Text::Plain,
            default: "displayName",
        },
        applies: Applies::Live,
    },
    Definition {
        key: EMAIL_ATTRIBUTE,
        section: SECTION,
        label: "Email attribute name",
        help: "The attribute that holds the person's email address.",
        kind: Kind::Text {
            check: Text::Plain,
            default: "email",
        },
        applies: Applies::Live,
    },
    Definition {
        key: REMOVE_INACTIVE_DAYS,
        section: SECTION,
        label: "Remove inactive single sign-on users",
        help: "Days without a sign-in before a single sign-on user is removed. Takes effect once single sign-on is set up.",
        kind: Kind::Int {
            min: 1,
            max: 3650,
            default: 90,
        },
        applies: Applies::Live,
    },
];
