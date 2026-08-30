//! Strict Host/HeaderValue validation — prevent CRLF/host spoof.
//!
//! Uses `http::HeaderValue` strict parsing, rejects `\r`/`\n` in host/path,
//! and validates Host via `Authority`. CRLF host → 400.

use http::HeaderValue;

/// Validate a header name/value pair strictly via `http` crate.
pub fn validate_header(name: &str, value: &str) -> crate::Result<()> {
    if name.contains('\r') || name.contains('\n') {
        return Err(crate::Error::Validation(format!("header name contains CRLF: {name:?}")));
    }
    if value.contains('\r') || value.contains('\n') {
        return Err(crate::Error::Validation(format!("header value contains CRLF: {value:?}")));
    }
    // HeaderValue strict (rejects control chars)
    HeaderValue::from_str(value)
        .map_err(|e| crate::Error::Validation(format!("invalid header value {value:?}: {e}")))?;
    // HeaderName strict
    let _: http::HeaderName = name
        .parse()
        .map_err(|e| crate::Error::Validation(format!("invalid header name {name:?}: {e}")))?;
    Ok(())
}

/// Validate Host header strictly — `HeaderValue` + `Authority`, no CRLF.
pub fn validate_host(host: &str) -> crate::Result<()> {
    if host.is_empty() {
        return Err(crate::Error::Validation("host is empty".into()));
    }
    if host.contains('\r') || host.contains('\n') {
        return Err(crate::Error::Validation(format!("host contains CRLF: {host:?}")));
    }
    // HeaderValue strict — rejects \r\n and control chars
    HeaderValue::from_str(host)
        .map_err(|e| crate::Error::Validation(format!("invalid host HeaderValue {host:?}: {e}")))?;
    // Authority strict — ensures host:port is valid per RFC
    host.parse::<http::uri::Authority>()
        .map_err(|e| crate::Error::Validation(format!("invalid host authority {host:?}: {e}")))?;
    Ok(())
}

/// Validate request path — reject `\r`/`\n`, ensure `HeaderValue`-like safety.
pub fn validate_path(path: &str) -> crate::Result<()> {
    if path.contains('\r') || path.contains('\n') {
        return Err(crate::Error::Validation(format!("path contains CRLF: {path:?}")));
    }
    // Path should be valid URI path — try parsing as PathAndQuery
    if path.parse::<http::uri::PathAndQuery>().is_err() {
        return Err(crate::Error::Validation(format!("invalid path {path:?}")));
    }
    Ok(())
}

/// Validate full request line components — host + path.
pub fn validate_request(host: &str, path: &str) -> crate::Result<()> {
    validate_host(host)?;
    validate_path(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ok() {
        assert!(validate_host("example.com").is_ok());
        assert!(validate_host("example.com:8080").is_ok());
        assert!(validate_host("192.168.1.1:3128").is_ok());
        assert!(validate_host("[::1]:8080").is_ok());
    }

    #[test]
    fn host_crlf_rejected() {
        assert!(validate_host("example.com\r\nX-Injected: evil").is_err());
        assert!(validate_host("example.com\n").is_err());
        assert!(validate_host("example.com\r").is_err());
        assert!(validate_host("example.com\r\n").is_err());
        assert!(validate_host("evil.com\r\nHost: victim.com").is_err());
    }

    #[test]
    fn host_header_value_strict() {
        // Control chars rejected by HeaderValue
        assert!(validate_host("example.com\x00").is_err());
        assert!(validate_host("example.com\x1f").is_err());
    }

    #[test]
    fn path_crlf_rejected() {
        assert!(validate_path("/path").is_ok());
        assert!(validate_path("/api/v1?foo=bar").is_ok());
        assert!(validate_path("/\r\nInjected: evil").is_err());
        assert!(validate_path("/path\n").is_err());
        assert!(validate_path("/path\r\n").is_err());
    }

    #[test]
    fn header_crlf_rejected() {
        assert!(validate_header("x-custom", "value").is_ok());
        assert!(validate_header("x-custom", "evil\r\nX-Injected: bad").is_err());
        assert!(validate_header("x\r\nInjected", "value").is_err());
        assert!(validate_header("host", "example.com\r\n").is_err());
    }

    #[test]
    fn request_validation() {
        assert!(validate_request("example.com", "/path").is_ok());
        assert!(validate_request("example.com\r\n", "/path").is_err());
        assert!(validate_request("example.com", "/\r\n").is_err());
    }

    #[test]
    fn host_empty_rejected() {
        assert!(validate_host("").is_err());
    }
}
