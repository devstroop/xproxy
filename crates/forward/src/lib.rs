pub mod demux;

pub use demux::{Protocol, dispatch, peek_protocol};

use xproxy_core::{Config, Proxy, ProxyMode};

/// Forward proxy stub.
#[derive(Debug, Clone)]
pub struct ForwardProxy {
    config: Config,
}

impl ForwardProxy {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl Proxy for ForwardProxy {
    fn mode(&self) -> ProxyMode {
        ProxyMode::Forward
    }

    fn name(&self) -> &'static str {
        "forward"
    }
}
