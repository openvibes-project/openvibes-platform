//! The `[assistant]` configuration section and its validation (spec §3, §7,
//! §8). Parsing accepts the raw TOML shape; [`AssistantConfig::validate`]
//! applies every rule, reads the secret and certificate files once, and
//! returns the checked [`Assistant`] the rest of the crate uses.

use std::{
    fmt,
    fs::File,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;

/// Largest API key, certificate, or key file read.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Longest API key accepted.
const MAX_API_KEY: usize = 4096;
/// Longest model name accepted.
const MAX_MODEL: usize = 256;

/// How much of each question is sent to the backend, chosen for the
/// hardware it runs on (spec §8).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// CPU and a 2–4B model.
    #[default]
    Small,
    /// A GPU or an 8–14B model.
    Medium,
    /// A remote GPU server or a provider.
    Large,
}

/// The budget a [`Profile`] sets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    /// Most prompt tokens sent per request.
    pub prompt_tokens: u32,
    /// Most tokens the backend may write per answer.
    pub output_tokens: u32,
    /// Most items each lookup result carries.
    pub result_items: u32,
}

impl Profile {
    /// This profile's budget.
    #[must_use]
    pub const fn budget(self) -> Budget {
        match self {
            Self::Small => Budget {
                prompt_tokens: 2_000,
                output_tokens: 300,
                result_items: 10,
            },
            Self::Medium => Budget {
                prompt_tokens: 8_000,
                output_tokens: 800,
                result_items: 25,
            },
            Self::Large => Budget {
                prompt_tokens: 32_000,
                output_tokens: 1_500,
                result_items: 50,
            },
        }
    }
}

/// How the model asks for a lookup (spec §5).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LookupMode {
    /// Chosen by the capability probe.
    #[default]
    Auto,
    /// The API's tool calls.
    Native,
    /// Output constrained to a JSON schema.
    JsonSchema,
    /// Instructions only, validated afterwards.
    Prompted,
}

/// Where a remote backend runs, as the administrator declares it (spec §7).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum DataLocation {
    /// A server on the operator's own network.
    OwnNetwork,
    /// A third party's service.
    External,
}

/// Where the backend runs, from its URL and the declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Location {
    /// A loopback address on the platform host (options A and B).
    Local,
    /// Another host on the operator's network (option C).
    OwnNetwork,
    /// A third party (option D); prompts leave the organisation.
    External,
}

/// The `[assistant]` section as written. Unknown keys are refused.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantConfig {
    /// Off by default; nothing runs or connects until enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Prompt budget for the backend's hardware.
    #[serde(default)]
    pub profile: Profile,
    /// How lookups are requested; `auto` lets the probe choose.
    #[serde(default)]
    pub lookup_mode: LookupMode,
    /// Days a conversation is kept, 1 to 3650 (default 30).
    pub conversation_retention_days: Option<u32>,
    /// Lookups per question, 1 to 8 (default 4).
    pub max_lookups: Option<u32>,
    /// Questions one user may ask per hour, 1 to 1000 (default 30).
    pub questions_per_user_per_hour: Option<u32>,
    /// Questions answered at once, 1 to 64 (default 1 local, 4 remote).
    pub concurrency: Option<u32>,
    /// The model backend; required when enabled.
    pub backend: Option<BackendConfig>,
}

/// `[assistant.backend]` as written.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendConfig {
    /// Base URL of an OpenAI-compatible API, e.g. `http://127.0.0.1:8080/v1`.
    pub url: String,
    /// Model name sent with each request.
    pub model: String,
    /// File holding the API key, owner-only.
    pub api_key_file: Option<PathBuf>,
    /// PEM bundle of the CAs trusted for the backend (required for
    /// `own-network`; without it an `external` backend uses public roots).
    pub ca_file: Option<PathBuf>,
    /// PEM client certificate chain for mutual TLS.
    pub client_certificate_file: Option<PathBuf>,
    /// PEM private key for mutual TLS, owner-only.
    pub client_key_file: Option<PathBuf>,
    /// Must be `true` for a backend that is not on loopback.
    #[serde(default)]
    pub allow_remote: bool,
    /// Required for a remote backend.
    pub data_location: Option<DataLocation>,
    /// Replace hostnames, agent IDs, and addresses before sending (default
    /// on for `external`, off otherwise).
    pub pseudonymize: Option<bool>,
    /// Outbound proxy for a remote backend; the environment is never used.
    pub proxy_url: Option<String>,
    /// Seconds one request may take, 2 to 600 (default 60 local, 120 remote).
    pub deadline_seconds: Option<u64>,
}

/// A configuration rule that failed. Messages name the setting, never its
/// value or a file's content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// Enabled without `[assistant.backend]`.
    MissingBackend,
    /// `url` is not an `http(s)://host[:port][/path]` URL without user info,
    /// query, fragment, or trailing slash.
    InvalidUrl,
    /// Plain HTTP to a host other than loopback.
    PlainHttpRemote,
    /// A remote backend without `allow_remote = true`.
    RemoteNotAllowed,
    /// A remote backend without `data_location`.
    DataLocationRequired,
    /// `data_location` or `proxy_url` on a loopback backend.
    RemoteSettingOnLocal,
    /// An `own-network` backend without `ca_file`.
    CaRequired,
    /// Client certificate and key must come together, over HTTPS.
    ClientIdentityIncomplete,
    /// A configured file path is not absolute.
    RelativePath,
    /// A secret file is readable by group or others.
    SecretFileInsecure,
    /// A file is missing, oversized, or holds no usable content.
    FileInvalid,
    /// `model` is empty, too long, or has control characters.
    InvalidModel,
    /// `proxy_url` is not a valid proxy URL.
    InvalidProxy,
    /// A number is outside its documented range.
    OutOfRange(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBackend => f.write_str("assistant: enabled without [assistant.backend]"),
            Self::InvalidUrl => f.write_str(
                "assistant.backend.url must be http(s)://host[:port][/path] without user info, query, or trailing slash",
            ),
            Self::PlainHttpRemote => {
                f.write_str("assistant.backend.url must use https unless it is a loopback address")
            }
            Self::RemoteNotAllowed => f.write_str(
                "assistant.backend.url is not loopback: set allow_remote = true to send prompts to it",
            ),
            Self::DataLocationRequired => f.write_str(
                "assistant.backend.data_location must be \"own-network\" or \"external\" for a remote backend",
            ),
            Self::RemoteSettingOnLocal => f.write_str(
                "assistant.backend.data_location and proxy_url apply only to a remote backend",
            ),
            Self::CaRequired => {
                f.write_str("assistant.backend.ca_file is required for an own-network backend")
            }
            Self::ClientIdentityIncomplete => f.write_str(
                "assistant.backend.client_certificate_file and client_key_file come together, over https",
            ),
            Self::RelativePath => f.write_str("assistant: configured paths must be absolute"),
            Self::SecretFileInsecure => f.write_str(
                "assistant: api_key_file and client_key_file must not be readable by group or others",
            ),
            Self::FileInvalid => {
                f.write_str("assistant: a configured file is missing, too large, or invalid")
            }
            Self::InvalidModel => f.write_str("assistant.backend.model is empty or invalid"),
            Self::InvalidProxy => f.write_str("assistant.backend.proxy_url is invalid"),
            Self::OutOfRange(name) => write!(f, "assistant: {name} is out of range"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// A checked configuration.
#[derive(Clone, Debug)]
pub struct Assistant {
    /// Whether the assistant is on.
    pub enabled: bool,
    /// Prompt budget.
    pub profile: Profile,
    /// Configured lookup mode (`auto` until probed).
    pub lookup_mode: LookupMode,
    /// Days a conversation is kept.
    pub conversation_retention_days: u32,
    /// Lookups per question.
    pub max_lookups: u32,
    /// Questions per user per hour.
    pub questions_per_user_per_hour: u32,
    /// The backend, present when enabled.
    pub backend: Option<Backend>,
}

/// A checked backend, with its secrets and certificates read.
#[derive(Clone)]
pub struct Backend {
    /// Base URL without a trailing slash.
    pub base_url: String,
    /// Where it runs.
    pub location: Location,
    /// Model name.
    pub model: String,
    /// Whether identifying values are replaced before sending.
    pub pseudonymize: bool,
    /// Questions answered at once.
    pub concurrency: u32,
    /// Time one request may take.
    pub deadline: Duration,
    /// Explicit proxy for a remote backend.
    pub proxy_url: Option<String>,
    pub(crate) api_key: Option<String>,
    pub(crate) ca_pem: Option<Vec<u8>>,
    pub(crate) client_identity: Option<(Vec<u8>, Vec<u8>)>,
}

impl fmt::Debug for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Backend")
            .field("base_url", &self.base_url)
            .field("location", &self.location)
            .field("model", &self.model)
            .field("pseudonymize", &self.pseudonymize)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("client_identity", &self.client_identity.is_some())
            .finish_non_exhaustive()
    }
}

fn in_range(
    value: Option<u32>,
    default: u32,
    range: std::ops::RangeInclusive<u32>,
    name: &'static str,
) -> Result<u32, ConfigError> {
    let value = value.unwrap_or(default);
    if range.contains(&value) {
        Ok(value)
    } else {
        Err(ConfigError::OutOfRange(name))
    }
}

impl AssistantConfig {
    /// Applies every rule and reads the configured files.
    pub fn validate(&self) -> Result<Assistant, ConfigError> {
        let backend = match (&self.backend, self.enabled) {
            (Some(backend), _) => Some(backend.validate(self.concurrency)?),
            (None, true) => return Err(ConfigError::MissingBackend),
            (None, false) => None,
        };
        Ok(Assistant {
            enabled: self.enabled,
            profile: self.profile,
            lookup_mode: self.lookup_mode,
            conversation_retention_days: in_range(
                self.conversation_retention_days,
                30,
                1..=3650,
                "conversation_retention_days",
            )?,
            max_lookups: in_range(self.max_lookups, 4, 1..=8, "max_lookups")?,
            questions_per_user_per_hour: in_range(
                self.questions_per_user_per_hour,
                30,
                1..=1000,
                "questions_per_user_per_hour",
            )?,
            backend,
        })
    }
}

impl BackendConfig {
    fn validate(&self, concurrency: Option<u32>) -> Result<Backend, ConfigError> {
        let url = parse_url(&self.url)?;
        let location = match (url.loopback, self.data_location) {
            (true, None) => Location::Local,
            (true, Some(_)) => return Err(ConfigError::RemoteSettingOnLocal),
            (false, _) if !url.https => return Err(ConfigError::PlainHttpRemote),
            (false, _) if !self.allow_remote => return Err(ConfigError::RemoteNotAllowed),
            (false, None) => return Err(ConfigError::DataLocationRequired),
            (false, Some(DataLocation::OwnNetwork)) => Location::OwnNetwork,
            (false, Some(DataLocation::External)) => Location::External,
        };
        let local = location == Location::Local;
        if local && self.proxy_url.is_some() {
            return Err(ConfigError::RemoteSettingOnLocal);
        }
        if location == Location::OwnNetwork && self.ca_file.is_none() {
            return Err(ConfigError::CaRequired);
        }
        let model = self.model.trim();
        if model.is_empty() || model.len() > MAX_MODEL || model.chars().any(char::is_control) {
            return Err(ConfigError::InvalidModel);
        }
        if let Some(proxy) = &self.proxy_url {
            ureq::Proxy::new(proxy).map_err(|_| ConfigError::InvalidProxy)?;
        }
        let paths = [
            &self.api_key_file,
            &self.ca_file,
            &self.client_certificate_file,
            &self.client_key_file,
        ];
        if paths
            .iter()
            .flat_map(|path| path.as_deref())
            .any(|path| !path.is_absolute())
        {
            return Err(ConfigError::RelativePath);
        }
        let api_key = self
            .api_key_file
            .as_deref()
            .map(|path| {
                let text = String::from_utf8(read_file(path, true)?)
                    .map_err(|_| ConfigError::FileInvalid)?;
                let key = text.trim();
                let usable = !key.is_empty()
                    && key.len() <= MAX_API_KEY
                    && key.bytes().all(|byte| byte.is_ascii_graphic());
                usable
                    .then(|| key.to_owned())
                    .ok_or(ConfigError::FileInvalid)
            })
            .transpose()?;
        let ca_pem = self
            .ca_file
            .as_deref()
            .map(|path| read_file(path, false))
            .transpose()?;
        let client_identity = match (&self.client_certificate_file, &self.client_key_file) {
            (None, None) => None,
            (Some(cert), Some(key)) if url.https => {
                Some((read_file(cert, false)?, read_file(key, true)?))
            }
            _ => return Err(ConfigError::ClientIdentityIncomplete),
        };
        let deadline = self
            .deadline_seconds
            .unwrap_or(if local { 60 } else { 120 });
        if !(2..=600).contains(&deadline) {
            return Err(ConfigError::OutOfRange("deadline_seconds"));
        }
        Ok(Backend {
            base_url: url.base,
            location,
            model: model.to_owned(),
            pseudonymize: self.pseudonymize.unwrap_or(location == Location::External),
            concurrency: in_range(
                concurrency,
                if local { 1 } else { 4 },
                1..=64,
                "concurrency",
            )?,
            deadline: Duration::from_secs(deadline),
            proxy_url: self.proxy_url.clone(),
            api_key,
            ca_pem,
            client_identity,
        })
    }
}

/// A checked base URL.
struct ParsedUrl {
    base: String,
    https: bool,
    loopback: bool,
}

/// Accepts `http(s)://host[:port][/path]`: no user info, query, fragment,
/// or trailing slash. Loopback means `localhost`, `127.0.0.0/8`, or `::1`.
fn parse_url(url: &str) -> Result<ParsedUrl, ConfigError> {
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(ConfigError::InvalidUrl);
    };
    if url.ends_with('/')
        || url.contains(['?', '#', '@'])
        || url.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(ConfigError::InvalidUrl);
    }
    let authority = rest.split('/').next().unwrap_or("");
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6.split_once(']').ok_or(ConfigError::InvalidUrl)?;
        (host, after.strip_prefix(':'))
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() || port.is_some_and(|port| port.parse::<u16>().map_or(true, |p| p == 0)) {
        return Err(ConfigError::InvalidUrl);
    }
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    Ok(ParsedUrl {
        base: url.to_owned(),
        https,
        loopback,
    })
}

/// Reads a regular file of at most 1 MiB; a `secret` must be owner-only.
fn read_file(path: &Path, secret: bool) -> Result<Vec<u8>, ConfigError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    // O_NONBLOCK (Linux): a FIFO in place of the file cannot hang startup.
    #[cfg(target_os = "linux")]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, 0o4000);
    let file: File = options.open(path).map_err(|_| ConfigError::FileInvalid)?;
    let metadata = file.metadata().map_err(|_| ConfigError::FileInvalid)?;
    if !metadata.is_file() {
        return Err(ConfigError::FileInvalid);
    }
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError::SecretFileInsecure);
        }
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigError::FileInvalid)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(ConfigError::FileInvalid);
    }
    Ok(bytes)
}
