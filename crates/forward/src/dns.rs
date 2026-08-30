//! DNS — socks5h remote vs local.

/// Resolve mode for SOCKS5 domain (0x03).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveMode {
    /// Remote — proxy resolves via `ToSocketAddrs` (socks5h, avoids local leak).
    Remote,
    /// Local — client resolves (leak, not recommended).
    Local,
}

impl ResolveMode {
    pub fn parse_opt(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "remote" | "socks5h" => Some(Self::Remote),
            "local" | "socks5" => Some(Self::Local),
            _ => None,
        }
    }

    pub fn is_remote(self) -> bool {
        matches!(self, Self::Remote)
    }
}

impl std::str::FromStr for ResolveMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_opt(s).ok_or_else(|| format!("unknown resolve mode {s}"))
    }
}

/// Whether given SOCKS5 address type should be resolved remotely.
/// `0x01` IPv4, `0x03` Domain, `0x04` IPv6 — only Domain benefits from remote.
pub fn should_resolve_remotely(mode: ResolveMode, addr_type: u8) -> bool {
    mode.is_remote() && addr_type == 0x03
}

/// Decide DNS for HTTP CONNECT — always remote (proxy dials).
pub fn http_connect_is_remote() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parse() {
        assert_eq!(ResolveMode::parse_opt("remote"), Some(ResolveMode::Remote));
        assert_eq!(ResolveMode::parse_opt("socks5h"), Some(ResolveMode::Remote));
        assert_eq!(ResolveMode::parse_opt("local"), Some(ResolveMode::Local));
        assert_eq!(ResolveMode::parse_opt("socks5"), Some(ResolveMode::Local));
        assert_eq!(ResolveMode::parse_opt("other"), None);
        assert_eq!("remote".parse::<ResolveMode>().unwrap(), ResolveMode::Remote);
        assert!("other".parse::<ResolveMode>().is_err());
    }

    #[test]
    fn remote_only_domain() {
        assert!(should_resolve_remotely(ResolveMode::Remote, 0x03));
        assert!(!should_resolve_remotely(ResolveMode::Remote, 0x01));
        assert!(!should_resolve_remotely(ResolveMode::Remote, 0x04));
        assert!(!should_resolve_remotely(ResolveMode::Local, 0x03));
    }

    #[test]
    fn http_is_remote() {
        assert!(http_connect_is_remote());
    }
}
