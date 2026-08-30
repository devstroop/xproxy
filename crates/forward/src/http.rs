//! Forward HTTP — absolute-form handling, hop-header strip, Via append.

use http::{HeaderName, HeaderValue, Request, Response};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

/// Hop-by-hop headers to strip before forwarding (RFC 2616).
const HOP_HEADERS: &[&str] = &[
    "proxy-connection",
    "keep-alive",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "connection",
];

fn is_hop_header(name: &HeaderName) -> bool {
    let lower = name.as_str().to_ascii_lowercase();
    HOP_HEADERS.contains(&lower.as_str())
        || lower == "proxy-authenticate"
        || lower == "proxy-authorization"
}

/// Strip hop-by-hop headers from request.
pub fn strip_hop_headers<T>(req: &mut Request<T>) {
    let headers = req.headers_mut();
    let to_remove: Vec<HeaderName> = headers.keys().filter(|k| is_hop_header(k)).cloned().collect();
    for k in to_remove {
        headers.remove(k);
    }
    // Remove Connection-listed headers
    if let Some(conn) = headers.get("connection").cloned() {
        if let Ok(val) = conn.to_str() {
            for name in val.split(',').map(|s| s.trim().to_ascii_lowercase()) {
                if let Ok(h) = HeaderName::from_bytes(name.as_bytes()) {
                    headers.remove(h);
                }
            }
        }
        headers.remove("connection");
    }
}

/// Append `Via: 1.1 xproxy` (not XFF duplicate).
pub fn append_via<T>(res: &mut Response<T>) {
    let via = HeaderValue::from_static("1.1 xproxy");
    res.headers_mut().append("via", via);
}

pub fn append_via_req<T>(req: &mut Request<T>) {
    let via = HeaderValue::from_static("1.1 xproxy");
    req.headers_mut().append("via", via);
}

/// Type alias for boxed body.
pub type BoxBytesBody = BoxBody<Bytes, hyper::Error>;

/// Build a hyper-util client for forwarding. Separate from reverse's pool.
pub fn forwarding_client()
-> Client<hyper_util::client::legacy::connect::HttpConnector, BoxBytesBody> {
    Client::builder(TokioExecutor::new()).build_http()
}

/// Check if request is absolute-form (forward) vs origin-form (reverse).
pub fn is_absolute_form(req: &Request<impl Sized>) -> bool {
    let uri = req.uri().to_string();
    uri.starts_with("http://") || uri.starts_with("https://")
}

/// Validate absolute-form for forward — must have host.
pub fn validate_absolute_form(req: &Request<impl Sized>) -> Result<(), String> {
    if !is_absolute_form(req) {
        return Err("not absolute-form".into());
    }
    if req.uri().host().is_none() {
        return Err("absolute-form missing host".into());
    }
    Ok(())
}

/// Helper to create a simple boxed body for tests.
pub fn full_body(bytes: impl Into<Bytes>) -> BoxBytesBody {
    Full::new(bytes.into()).map_err(|never| match never {}).boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    #[test]
    fn strip_hop() {
        let mut req = Request::builder()
            .uri("http://example.com/")
            .header("proxy-connection", "keep-alive")
            .header("keep-alive", "timeout=5")
            .header("connection", "keep-alive, proxy-connection")
            .header("x-custom", "keep")
            .body(())
            .unwrap();
        strip_hop_headers(&mut req);
        assert!(req.headers().get("proxy-connection").is_none());
        assert!(req.headers().get("keep-alive").is_none());
        assert!(req.headers().get("connection").is_none());
        assert_eq!(req.headers().get("x-custom").unwrap(), "keep");
    }

    #[test]
    fn via_append() {
        let mut res = Response::builder().body(()).unwrap();
        append_via(&mut res);
        assert_eq!(res.headers().get("via").unwrap(), "1.1 xproxy");
    }

    #[test]
    fn absolute_form() {
        let req = Request::builder().uri("http://example.com/path").body(()).unwrap();
        assert!(is_absolute_form(&req));
        assert!(validate_absolute_form(&req).is_ok());
        let req2 = Request::builder().uri("/path").body(()).unwrap();
        assert!(!is_absolute_form(&req2));
        assert!(validate_absolute_form(&req2).is_err());
    }

    #[test]
    fn client_builds() {
        let _client = forwarding_client();
    }
}
