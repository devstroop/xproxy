//! Minimal lean config — extend only after Discussion #4 consensus.

use serde::{Deserialize, Serialize};

/// Deployment mode — no pre-decision beyond `both` default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Both,
    Forward,
    Reverse,
}

/// Top-level config — lean, validated, env+file merge is caller's responsibility for now.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    /// Deployment mode.
    pub mode: Mode,

    /// Forward listen address, e.g. `0.0.0.0:3128`. `None` disables forward when mode allows.
    pub listen_forward: Option<String>,

    /// Reverse listen address, e.g. `0.0.0.0:8080`. `None` disables reverse when mode allows.
    pub listen_reverse: Option<String>,

    /// Request timeout in ms. Must be 1000..=300000, default 30000.
    pub timeout_ms: Option<u64>,
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate after deserialization. Keeps `core` free of `tokio`/`rustls` deps.
    pub fn validate(&self) -> crate::Result<()> {
        let timeout = self.timeout_ms.unwrap_or(30_000);
        if !(1_000..=300_000).contains(&timeout) {
            return Err(crate::Error::Validation(format!(
                "timeout_ms {timeout} out of range 1000..=300000"
            )));
        }
        if let (Some(a), Some(b)) = (&self.listen_forward, &self.listen_reverse)
            && a == b
        {
            return Err(crate::Error::Validation(format!(
                "listen_forward and listen_reverse must differ, both are {a}"
            )));
        }
        for addr in [&self.listen_forward, &self.listen_reverse].into_iter().flatten() {
            if addr.parse::<std::net::SocketAddr>().is_err() {
                return Err(crate::Error::Validation(format!("invalid socket addr `{addr}`")));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ok_defaults() {
        let cfg = Config::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_same_listen() {
        let cfg = Config {
            listen_forward: Some("0.0.0.0:8080".into()),
            listen_reverse: Some("0.0.0.0:8080".into()),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
