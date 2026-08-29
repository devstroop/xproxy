pub mod router;

pub use router::{Route, RouteTable, SharedTable};

use xproxy_core::{Config, Proxy, ProxyMode};

/// Reverse proxy stub.
#[derive(Debug, Clone)]
pub struct ReverseProxy {
    config: Config,
}

impl ReverseProxy {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl Proxy for ReverseProxy {
    fn mode(&self) -> ProxyMode {
        ProxyMode::Reverse
    }

    fn name(&self) -> &'static str {
        "reverse"
    }
}
