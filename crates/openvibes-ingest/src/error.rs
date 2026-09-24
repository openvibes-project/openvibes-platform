use std::fmt;

/// Startup failures; messages never include file contents or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestError {
    /// The configuration is missing, invalid, or out of range.
    Config,
    /// A certificate or key file is unreadable or invalid.
    Tls,
    /// The database is unreachable at startup.
    Database,
    /// A listener could not be bound.
    Listen,
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Config => "invalid ingest configuration",
            Self::Tls => "invalid TLS or CA certificate or key file",
            Self::Database => "database unavailable",
            Self::Listen => "cannot bind a listener",
        })
    }
}

impl std::error::Error for IngestError {}

impl From<platform_agent_server::ServerError> for IngestError {
    fn from(error: platform_agent_server::ServerError) -> Self {
        use platform_agent_server::ServerError as E;
        match error {
            E::Config => Self::Config,
            E::Tls => Self::Tls,
            E::Database => Self::Database,
            E::Listen => Self::Listen,
        }
    }
}
