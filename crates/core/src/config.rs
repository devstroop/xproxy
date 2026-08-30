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

    /// Trusted proxies — CIDRs that are allowed to send `X-Forwarded-For` etc. Empty = strip all.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    /// CA certificate path for forward MITM (external `ca.crt` preferred).
    #[serde(default)]
    pub ca_cert: Option<String>,

    /// CA private key path for forward MITM (external `ca.key` preferred, `chmod 600`).
    #[serde(default)]
    pub ca_key: Option<String>,

    /// Whether to generate CA via `rcgen` if missing (dev-only, `false` default).
    #[serde(default)]
    pub generate_ca: bool,
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
        for cidr in &self.trusted_proxies {
            if cidr.parse::<crate::net::Cidr>().is_err() {
                return Err(crate::Error::Validation(format!(
                    "invalid trusted_proxies cidr `{cidr}`"
                )));
            }
        }
        match (&self.ca_cert, &self.ca_key) {
            (Some(c), Some(k)) => {
                if c.trim().is_empty() || k.trim().is_empty() {
                    return Err(crate::Error::Validation(
                        "ca_cert and ca_key must be non-empty".into(),
                    ));
                }
            }
            (None, None) => {}
            _ => {
                return Err(crate::Error::Validation(
                    "both ca_cert and ca_key must be set together".into(),
                ));
            }
        }
        Ok(())
    }

    /// Parsed CIDRs for `trusted_proxies`. Empty on parse error (validate first).
    pub fn trusted_proxies_cidrs(&self) -> Vec<crate::net::Cidr> {
        self.trusted_proxies.iter().filter_map(|s| s.parse().ok()).collect()
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
