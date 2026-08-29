//! Typed errors — preserves `io::ErrorKind` for circuit breakers.

/// Crate result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Core error — typed, no `String` wrapper at `error.rs:7` placeholder.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("config: {0}")]
    Config(String),

    #[error("validation: {0}")]
    Validation(String),

    #[error("upstream {0} unavailable: {1}")]
    Upstream(String, #[source] std::io::Error),

    #[error("auth failed")]
    Auth,

    #[error("tls: {0}")]
    Tls(String),
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Self::Config(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Self::Config(s.to_string())
    }
}
