//! CONNECT handling — allowlist + private-IP deny + timeout.

use std::net::IpAddr;

use xproxy_core::net::is_private_ip;

/// Default allowed CONNECT ports — prevents `*:25` spam relay.
pub const DEFAULT_ALLOW_PORTS: &[u16] = &[443, 8443];

/// CONNECT target after parsing `host:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTarget {
    pub host: String,
    pub port: u16,
}

impl ConnectTarget {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self { host: host.into(), port }
    }
}

/// Parse `host:port` string. Host may be domain or IP, no validation beyond split.
pub fn parse_target(s: &str) -> Option<ConnectTarget> {
    let (host, port_str) = s.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some(ConnectTarget::new(host, port))
}

/// Check if port is in allowlist.
pub fn is_port_allowed(port: u16, allowlist: &[u16]) -> bool {
    allowlist.contains(&port)
}

/// Check if host is private IP (if host parses as IP) — used for SSRF guard.
/// For domain hosts, checks `deny_private` via DNS not done here; caller should resolve and check IP.
pub fn is_private_target(target: &ConnectTarget, deny_private: bool) -> bool {
    if !deny_private {
        return false;
    }
    if target.host == "localhost" || target.host.ends_with(".local") {
        return true;
    }
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return is_private_ip(ip);
    }
    false
}

/// Validate CONNECT target against policy.
pub fn validate_target(
    target: &ConnectTarget,
    allowlist: &[u16],
    deny_private: bool,
) -> Result<(), String> {
    if !is_port_allowed(target.port, allowlist) {
        return Err(format!("port {} not allowed", target.port));
    }
    if is_private_target(target, deny_private) {
        return Err(format!("private target {} denied", target.host));
    }
    Ok(())
}

/// CONNECT timeouts — used with `tokio::time::timeout`.
pub const CONNECT_TIMEOUT_SECS: u64 = 300;
pub const ACCEPT_IDLE_SECS: u64 = 10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ok() {
        let t = parse_target("example.com:443").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
        assert_eq!(parse_target("10.0.0.1:8443").unwrap().port, 8443);
        assert!(parse_target("example.com").is_none());
        assert!(parse_target(":443").is_none());
    }

    #[test]
    fn port_allow() {
        assert!(is_port_allowed(443, DEFAULT_ALLOW_PORTS));
        assert!(is_port_allowed(8443, DEFAULT_ALLOW_PORTS));
        assert!(!is_port_allowed(25, DEFAULT_ALLOW_PORTS));
    }

    #[test]
    fn private_deny() {
        let t = ConnectTarget::new("10.0.0.1", 443);
        assert!(is_private_target(&t, true));
        assert!(!is_private_target(&t, false));
        let t2 = ConnectTarget::new("8.8.8.8", 443);
        assert!(!is_private_target(&t2, true));
        let t3 = ConnectTarget::new("localhost", 443);
        assert!(is_private_target(&t3, true));
        let t4 = ConnectTarget::new("example.com", 443);
        assert!(!is_private_target(&t4, true));
    }

    #[test]
    fn validate_ok_and_reject() {
        let t = ConnectTarget::new("example.com", 443);
        assert!(validate_target(&t, DEFAULT_ALLOW_PORTS, true).is_ok());
        let t2 = ConnectTarget::new("example.com", 25);
        assert!(validate_target(&t2, DEFAULT_ALLOW_PORTS, true).is_err());
        let t3 = ConnectTarget::new("10.0.0.1", 443);
        assert!(validate_target(&t3, DEFAULT_ALLOW_PORTS, true).is_err());
        assert!(validate_target(&t3, DEFAULT_ALLOW_PORTS, false).is_ok());
    }
}
