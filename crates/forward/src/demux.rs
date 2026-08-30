//! TCP demux — peek dispatch for forward proxy.

use tokio::net::TcpStream;

/// Protocol detected via peek.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// SOCKS4 (0x04) or SOCKS5 (0x05).
    Socks,
    /// `CONNECT host:443 HTTP/1.1`
    HttpConnect,
    /// Absolute-form `GET http://host/...`
    HttpAbsolute,
    /// Unknown / not forward proxy protocol.
    Unknown,
}

/// Peek first bytes without consuming to decide dispatch.
///
/// - `0x05` / `0x04` at byte 0 → `Socks`
/// - ASCII `CONNECT ` → `HttpConnect`
/// - ASCII `GET http://`, `POST http://`, etc. → `HttpAbsolute`
/// - Otherwise → `Unknown`
pub fn peek_protocol(buf: &[u8]) -> Protocol {
    if buf.is_empty() {
        return Protocol::Unknown;
    }
    if buf[0] == 0x05 || buf[0] == 0x04 {
        return Protocol::Socks;
    }
    // Check for CONNECT
    if buf.starts_with(b"CONNECT ") {
        return Protocol::HttpConnect;
    }
    // Check for absolute-form HTTP methods with `http://` or `https://`
    const METHODS: &[&[u8]] =
        &[b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"TRACE "];
    for m in METHODS {
        if buf.starts_with(m) {
            let rest = &buf[m.len()..];
            if rest.starts_with(b"http://") || rest.starts_with(b"https://") {
                return Protocol::HttpAbsolute;
            }
            // Still HTTP but not absolute-form — treat as unknown for forward (origin-form is reverse).
            return Protocol::Unknown;
        }
    }
    Protocol::Unknown
}

/// Peek from `TcpStream` without consuming. Returns `Protocol::Unknown` on empty/peek error.
pub async fn dispatch(stream: &TcpStream) -> Protocol {
    let mut buf = [0u8; 16];
    match stream.peek(&mut buf).await {
        Ok(0) => Protocol::Unknown,
        Ok(n) => peek_protocol(&buf[..n]),
        Err(_) => Protocol::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks() {
        assert_eq!(peek_protocol(&[0x05, 0x01, 0x00]), Protocol::Socks);
        assert_eq!(peek_protocol(&[0x04, 0x01]), Protocol::Socks);
    }

    #[test]
    fn connect() {
        assert_eq!(peek_protocol(b"CONNECT example.com:443 HTTP/1.1\r\n"), Protocol::HttpConnect);
    }

    #[test]
    fn http_absolute() {
        assert_eq!(peek_protocol(b"GET http://example.com/ HTTP/1.1\r\n"), Protocol::HttpAbsolute);
        assert_eq!(
            peek_protocol(b"POST https://example.com/api HTTP/1.1\r\n"),
            Protocol::HttpAbsolute
        );
    }

    #[test]
    fn http_origin_form_is_unknown() {
        assert_eq!(peek_protocol(b"GET /path HTTP/1.1\r\n"), Protocol::Unknown);
    }

    #[test]
    fn unknown() {
        assert_eq!(peek_protocol(b""), Protocol::Unknown);
        assert_eq!(peek_protocol(b"PRI * HTTP/2.0\r\n"), Protocol::Unknown);
    }
}
