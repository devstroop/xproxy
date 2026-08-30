//! SOCKS — SOCKS5-only, Basic 407, reject BIND/UDP.

use base64::{Engine as _, engine::general_purpose::STANDARD};

/// SOCKS version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksVersion {
    V4 = 0x04,
    V5 = 0x05,
}

/// SOCKS5 auth method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    NoAuth = 0x00,
    GssApi = 0x01,
    Password = 0x02,
    NoAcceptable = 0xFF,
}

/// SOCKS command — only CONNECT allowed, BIND/UDP rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl SocksCommand {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Connect),
            0x02 => Some(Self::Bind),
            0x03 => Some(Self::UdpAssociate),
            _ => None,
        }
    }

    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Connect)
    }
}

/// Basic auth check for `Proxy-Authorization: Basic ...`.
/// Returns true if header matches expected `user:pass` (via base64).
pub fn check_basic_auth(header: Option<&str>, expected_user: &str, expected_pass: &str) -> bool {
    let Some(h) = header else {
        return false;
    };
    let h = h.trim();
    let Some(b64) = h.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = STANDARD.decode(b64.trim()) else {
        return false;
    };
    let Ok(cred) = String::from_utf8(decoded) else {
        return false;
    };
    let expected = format!("{expected_user}:{expected_pass}");
    cred == expected
}

/// Whether to allow anonymous when `allow_anonymous` is false.
pub fn is_anonymous_allowed(allow_anonymous: bool, has_auth: bool) -> bool {
    allow_anonymous || has_auth
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_allowed() {
        assert!(SocksCommand::Connect.is_allowed());
        assert!(!SocksCommand::Bind.is_allowed());
        assert!(!SocksCommand::UdpAssociate.is_allowed());
        assert_eq!(SocksCommand::from_u8(0x01), Some(SocksCommand::Connect));
        assert_eq!(SocksCommand::from_u8(0x05), None);
    }

    #[test]
    fn basic_auth() {
        let user = "admin";
        let pass = "secret";
        let cred = format!("{user}:{pass}");
        let enc = STANDARD.encode(cred);
        let header = format!("Basic {enc}");
        assert!(check_basic_auth(Some(&header), user, pass));
        assert!(!check_basic_auth(Some("Basic wrong"), user, pass));
        assert!(!check_basic_auth(None, user, pass));
        assert!(!check_basic_auth(Some("Bearer token"), user, pass));
    }

    #[test]
    fn anonymous() {
        assert!(is_anonymous_allowed(true, false));
        assert!(!is_anonymous_allowed(false, false));
        assert!(is_anonymous_allowed(false, true));
    }
}
