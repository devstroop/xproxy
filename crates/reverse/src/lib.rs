pub mod concurrency;
pub mod headers;
pub mod health;
pub mod limits;
pub mod router;
pub mod selector;
pub mod tls;

pub use concurrency::ConcurrencyLimiter;
pub use headers::{is_client_trusted, sanitize_headers, sanitize_request};
pub use health::{HealthChecker, UpstreamHealth};
pub use limits::{IDLE_TIMEOUT, IpBlacklist, IpRateLimiter, concurrency_limit};
pub use router::{Route, RouteTable, SharedTable};
pub use selector::{P2c, RoundRobin, Selector, Upstream};
pub use tls::TlsTermination;

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
