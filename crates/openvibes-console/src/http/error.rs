use std::{fmt, io};

/// Errors that prevent the C0 console process from starting or continuing.
#[derive(Debug)]
pub enum ConsoleError {
    /// Configuration is absent, malformed, or unsafe.
    Config,
    /// The configured authentication store is unavailable or has the wrong schema.
    Store(platform_store::StoreError),
    /// The console cannot serve authentication until the current migrations are applied.
    SchemaVersion {
        /// Schema version present in the database, if any.
        actual: Option<i32>,
        /// Schema version required by this binary.
        expected: i32,
    },
    /// A listener could not be bound or served.
    Io(io::Error),
}

impl fmt::Display for ConsoleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config => formatter.write_str("invalid console configuration"),
            Self::Store(error) => write!(formatter, "console authentication store failed: {error}"),
            Self::SchemaVersion { actual, expected } => write!(
                formatter,
                "console requires schema version {expected}, found {actual:?}; apply platform migrations"
            ),
            Self::Io(error) => write!(formatter, "console listener failed: {error}"),
        }
    }
}

impl std::error::Error for ConsoleError {}

impl From<io::Error> for ConsoleError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<platform_store::StoreError> for ConsoleError {
    fn from(error: platform_store::StoreError) -> Self {
        Self::Store(error)
    }
}
