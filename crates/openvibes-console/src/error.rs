use std::{fmt, io};

/// Errors that prevent the C0 console process from starting or continuing.
#[derive(Debug)]
pub enum ConsoleError {
    /// Configuration is absent, malformed, or unsafe.
    Config,
    /// A listener could not be bound or served.
    Io(io::Error),
}

impl fmt::Display for ConsoleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config => formatter.write_str("invalid console configuration"),
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
