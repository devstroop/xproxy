//! Placeholder config — extend per crate needs.

/// Top-level proxy configuration (boilerplate only).
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Address to bind, e.g. `127.0.0.1:8080`.
    pub listen_addr: Option<String>,
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }
}
