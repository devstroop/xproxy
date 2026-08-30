pub mod ca;
pub mod connect;
pub mod demux;
pub mod dns;
pub mod http;
pub mod socks;

pub use ca::{Ca, fingerprint};
pub use connect::{
    ConnectTarget, DEFAULT_ALLOW_PORTS, is_port_allowed, parse_target, validate_target,
};
pub use demux::{Protocol, dispatch, peek_protocol};
pub use dns::{ResolveMode, http_connect_is_remote, should_resolve_remotely};
pub use http::{
    append_via, append_via_req, forwarding_client, is_absolute_form, strip_hop_headers,
};
pub use socks::{AuthMethod, SocksCommand, SocksVersion, check_basic_auth};

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
