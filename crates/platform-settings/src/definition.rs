use serde_json::Value;

/// When a changed value reaches the service that uses it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Applies {
    /// Within about a minute, without a restart.
    Live,
    /// At the service's next start.
    Restart,
}

/// What a text setting must look like.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Text {
    /// An HTTPS address.
    HttpsUrl,
    /// An HTTPS address; empty turns the source off.
    HttpsUrlOrEmpty,
    /// An `http://` or `https://` address; empty means none.
    ProxyOrEmpty,
    /// An architecture name such as `x86_64`.
    Arch,
}

/// A setting's type and limits.
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    /// On or off.
    Bool {
        /// The value when nobody changed it.
        default: bool,
    },
    /// A whole number.
    Int {
        /// Smallest value.
        min: i64,
        /// Largest value.
        max: i64,
        /// The value when nobody changed it.
        default: i64,
    },
    /// A line of text.
    Text {
        /// What it must look like.
        check: Text,
        /// The value when nobody changed it (the service's built-in one).
        default: &'static str,
    },
    /// A secret: stored apart, never shown again.
    Secret,
}

/// One setting.
#[derive(Clone, Copy, Debug)]
pub struct Definition {
    /// The key, such as `vulns.check_interval_minutes`.
    pub key: &'static str,
    /// The section it is shown under.
    pub section: &'static str,
    /// Short name.
    pub label: &'static str,
    /// One-sentence explanation.
    pub help: &'static str,
    /// Its type.
    pub kind: Kind,
    /// When a change reaches the service.
    pub applies: Applies,
}

const MAX_TEXT: usize = 2048;
const MAX_SECRET: usize = 512;

impl Definition {
    /// The default as JSON; a secret has none.
    #[must_use]
    pub fn default_value(&self) -> Value {
        match self.kind {
            Kind::Bool { default } => default.into(),
            Kind::Int { default, .. } => default.into(),
            Kind::Text { default, .. } => default.into(),
            Kind::Secret => Value::Null,
        }
    }

    /// Whether this setting is a secret.
    #[must_use]
    pub fn is_secret(&self) -> bool {
        matches!(self.kind, Kind::Secret)
    }

    /// The kind's name in the API.
    #[must_use]
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            Kind::Bool { .. } => "bool",
            Kind::Int { .. } => "int",
            Kind::Text { .. } => "text",
            Kind::Secret => "secret",
        }
    }

    /// Whether `value` fits this setting's type and range.
    ///
    /// # Errors
    /// The words to show next to the field.
    pub fn check(&self, value: &Value) -> Result<(), String> {
        match self.kind {
            Kind::Bool { .. } if value.is_boolean() => Ok(()),
            Kind::Bool { .. } => Err("Use true or false".into()),
            Kind::Int { min, max, .. } => match value.as_i64() {
                Some(n) if (min..=max).contains(&n) => Ok(()),
                _ => Err(format!("Use a whole number from {min} to {max}")),
            },
            Kind::Text { check, .. } => match value.as_str() {
                Some(text) => check_text(check, text),
                None => Err("Use text".into()),
            },
            Kind::Secret => match value.as_str() {
                Some(text) if text.trim().is_empty() => Err("Type the value, or remove it".into()),
                Some(text) if text.len() > MAX_SECRET || text.chars().any(char::is_control) => {
                    Err("Use one line of at most 512 characters".into())
                }
                Some(_) => Ok(()),
                None => Err("Use text".into()),
            },
        }
    }
}

fn check_text(check: Text, text: &str) -> Result<(), String> {
    if text.len() > MAX_TEXT || text.chars().any(|c| c.is_control() || c == ' ') {
        return Err("Use one line without spaces".into());
    }
    match check {
        Text::HttpsUrl if text.is_empty() => Err("This cannot be empty".into()),
        Text::HttpsUrl | Text::HttpsUrlOrEmpty => match text {
            "" => Ok(()),
            _ if is_https(text) || is_loopback_http(text) => Ok(()),
            _ => Err(
                "Use an address that starts with https://, or leave it empty to turn it off".into(),
            ),
        },
        Text::ProxyOrEmpty => match text {
            "" => Ok(()),
            _ if text.starts_with("http://") || text.starts_with("https://") => Ok(()),
            _ => Err("Use an address like http://proxy.example:3128, or leave it empty".into()),
        },
        Text::Arch => {
            if !text.is_empty() && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                Ok(())
            } else {
                Err("Use an architecture name like x86_64".into())
            }
        }
    }
}

fn is_https(text: &str) -> bool {
    text.strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty())
}

/// Plain HTTP only on loopback (the services' own rule, for their tests).
fn is_loopback_http(text: &str) -> bool {
    ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| {
            text.strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        })
}
