//! Lean net helpers — no heavy deps, pure functions.

use std::net::IpAddr;

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
}
