pub mod demux;
pub mod dns;

pub use demux::{Protocol, dispatch, peek_protocol};
pub use dns::{ResolveMode, http_connect_is_remote, should_resolve_remotely};

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
