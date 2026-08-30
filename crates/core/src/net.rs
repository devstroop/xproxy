//! Lean net helpers — no heavy deps, pure functions.

use std::{net::IpAddr, str::FromStr};

/// Check if IP is private/range-blocked for SSRF guard (RFC1918 + loopback + link-local + unique-local).
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.octets()[0] == 0
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1])) // CGNAT
                || v4.is_multicast()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || v6.is_unspecified()
        }
    }
}

/// Strip hop-by-hop headers if present (case-insensitive via http crate if available, here string list).
pub fn hop_headers() -> &'static [&'static str] {
    &[
        "proxy-connection",
        "keep-alive",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
}

/// CIDR network for `trusted_proxies` — `10.0.0.0/8`, `192.168.1.0/24`, `::1/128`, or bare IP (`1.2.3.4` → `/32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn new(network: IpAddr, prefix: u8) -> Result<Self, String> {
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(format!("prefix {prefix} out of range for {network}"));
        }
        let network = Self::apply_mask(network, prefix);
        Ok(Self { network, prefix })
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask =
                    if self.prefix == 32 { u32::MAX } else { u32::MAX << (32 - self.prefix) };
                let net_u32 = u32::from(net);
                let addr_u32 = u32::from(addr);
                (net_u32 & mask) == (addr_u32 & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask =
                    if self.prefix == 128 { u128::MAX } else { u128::MAX << (128 - self.prefix) };
                let net_u128 = u128::from(net);
                let addr_u128 = u128::from(addr);
                (net_u128 & mask) == (addr_u128 & mask)
            }
            _ => false,
        }
    }

    fn apply_mask(ip: IpAddr, prefix: u8) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => {
                if prefix == 0 {
                    return IpAddr::V4(std::net::Ipv4Addr::from(0));
                }
                let mask = if prefix == 32 { u32::MAX } else { u32::MAX << (32 - prefix) };
                let masked = u32::from(v4) & mask;
                IpAddr::V4(std::net::Ipv4Addr::from(masked))
            }
            IpAddr::V6(v6) => {
                if prefix == 0 {
                    return IpAddr::V6(std::net::Ipv6Addr::from(0));
                }
                let mask = if prefix == 128 { u128::MAX } else { u128::MAX << (128 - prefix) };
                let masked = u128::from(v6) & mask;
                IpAddr::V6(std::net::Ipv6Addr::from(masked))
            }
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let ip: IpAddr = ip_str.parse().map_err(|e| format!("invalid cidr ip `{s}`: {e}"))?;
            let prefix: u8 =
                prefix_str.parse().map_err(|e| format!("invalid cidr prefix `{s}`: {e}"))?;
            Self::new(ip, prefix)
        } else {
            let ip: IpAddr = s.parse().map_err(|e| format!("invalid cidr ip `{s}`: {e}"))?;
            let prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Self::new(ip, prefix)
        }
    }
}

impl FromStr for Cidr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// Whether `client_ip` is in any of `trusted` CIDRs. Empty list means not trusted (strip all).
pub fn is_trusted(client_ip: IpAddr, trusted: &[Cidr]) -> bool {
    trusted.iter().any(|c| c.contains(client_ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn private_v4() {
        assert!(is_private_ip(IpAddr::from_str("10.0.0.1").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("192.168.1.1").unwrap()));
        assert!(!is_private_ip(IpAddr::from_str("8.8.8.8").unwrap()));
    }

    #[test]
    fn private_v6() {
        assert!(is_private_ip(IpAddr::from_str("::1").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("fc00::1").unwrap()));
        assert!(!is_private_ip(IpAddr::from_str("2001:db8::1").unwrap()));
    }

    #[test]
    fn cidr_v4_contains() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(IpAddr::from_str("10.1.2.3").unwrap()));
        assert!(!c.contains(IpAddr::from_str("11.0.0.1").unwrap()));
        assert!(!c.contains(IpAddr::from_str("::1").unwrap()));
        let single = Cidr::parse("1.2.3.4").unwrap();
        assert_eq!(single.prefix(), 32);
        assert!(single.contains(IpAddr::from_str("1.2.3.4").unwrap()));
        assert!(!single.contains(IpAddr::from_str("1.2.3.5").unwrap()));
    }

    #[test]
    fn cidr_v6_contains() {
        let c = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains(IpAddr::from_str("2001:db8::1").unwrap()));
        assert!(!c.contains(IpAddr::from_str("2001:db9::1").unwrap()));
        let loopback = Cidr::parse("::1/128").unwrap();
        assert!(loopback.contains(IpAddr::from_str("::1").unwrap()));
        assert!(!loopback.contains(IpAddr::from_str("::2").unwrap()));
    }

    #[test]
    fn cidr_zero_prefix() {
        let c = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(c.contains(IpAddr::from_str("1.2.3.4").unwrap()));
        assert!(c.contains(IpAddr::from_str("8.8.8.8").unwrap()));
    }

    #[test]
    fn is_trusted_helper() {
        let trusted = vec![Cidr::parse("10.0.0.0/8").unwrap()];
        assert!(is_trusted(IpAddr::from_str("10.1.1.1").unwrap(), &trusted));
        assert!(!is_trusted(IpAddr::from_str("192.168.1.1").unwrap(), &trusted));
        assert!(!is_trusted(IpAddr::from_str("10.1.1.1").unwrap(), &[]));
    }
}
