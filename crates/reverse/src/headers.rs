//! Security headers — trusted_proxies strip XFF spoof.
//!
//! At edge before LB: if `!trusted_proxies.contains(client_ip)` remove
//! `x-forwarded-for`/`forwarded`/`x-real-ip` (spoof) then append correct
//! `X-Forwarded-For`/`Forwarded`/`X-Real-Ip` + `Via: 1.1 xproxy`.
//! Always strip `proxy-connection`/`keep-alive` (hop-by-hop).

use std::net::IpAddr;

use http::{HeaderMap, HeaderValue, Request};
use xproxy_core::net::{Cidr, is_trusted};

/// Sanitize `HeaderMap` in place.
///
/// - Always removes `proxy-connection` and `keep-alive`.
/// - If `client_ip` is not in `trusted`, removes spoofable forwarding headers
///   (`x-forwarded-for`, `forwarded`, `x-real-ip`, `x-forwarded-host`,
///   `x-forwarded-proto`, `x-forwarded-port`).
/// - Then injects correct `x-forwarded-for`, `forwarded`, `x-real-ip` and appends `via`.
pub fn sanitize_headers(headers: &mut HeaderMap, client_ip: IpAddr, trusted: &[Cidr]) {
    // Always strip hop-by-hop that must not be forwarded.
    headers.remove("proxy-connection");
    headers.remove("keep-alive");

    let trusted = is_trusted(client_ip, trusted);

    if !trusted {
        headers.remove("x-forwarded-for");
        headers.remove("forwarded");
        headers.remove("x-real-ip");
        headers.remove("x-forwarded-host");
        headers.remove("x-forwarded-proto");
        headers.remove("x-forwarded-port");
    }

    let client_str = client_ip.to_string();

    // X-Forwarded-For: append if trusted and existing, otherwise set to client_ip.
    if let Some(existing) = headers.get("x-forwarded-for").cloned() {
        if let Ok(existing_str) = existing.to_str() {
            let new_val = if existing_str.trim().is_empty() {
                client_str.clone()
            } else {
                format!("{}, {}", existing_str.trim(), client_str)
            };
            if let Ok(v) = HeaderValue::from_str(&new_val) {
                headers.insert("x-forwarded-for", v);
            }
        }
    } else {
        if let Ok(v) = HeaderValue::from_str(&client_str) {
            headers.insert("x-forwarded-for", v);
        }
    }

    // Forwarded: for="<ip>" — append if trusted, otherwise fresh.
    let fwd_val = format!("for=\"{client_str}\"");
    if trusted {
        if let Some(existing) = headers.get("forwarded").cloned() {
            if let Ok(existing_str) = existing.to_str() {
                let new_val = if existing_str.trim().is_empty() {
                    fwd_val.clone()
                } else {
                    format!("{}, {}", existing_str.trim(), fwd_val)
                };
                if let Ok(v) = HeaderValue::from_str(&new_val) {
                    headers.insert("forwarded", v);
                }
            }
        } else if let Ok(v) = HeaderValue::from_str(&fwd_val) {
            headers.insert("forwarded", v);
        }
    } else if let Ok(v) = HeaderValue::from_str(&fwd_val) {
        headers.insert("forwarded", v);
    }

    // X-Real-Ip always set to client_ip.
    if let Ok(v) = HeaderValue::from_str(&client_str) {
        headers.insert("x-real-ip", v);
    }

    // Via: 1.1 xproxy — always append (not replace) to preserve prior hops.
    headers.append("via", HeaderValue::from_static("1.1 xproxy"));
}

/// Sanitize `Request` headers in place.
pub fn sanitize_request<T>(req: &mut Request<T>, client_ip: IpAddr, trusted: &[Cidr]) {
    sanitize_headers(req.headers_mut(), client_ip, trusted);
}

/// Check whether ip is trusted.
pub fn is_client_trusted(client_ip: IpAddr, trusted: &[Cidr]) -> bool {
    is_trusted(client_ip, trusted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn cidrs(ss: &[&str]) -> Vec<Cidr> {
        ss.iter().map(|s| Cidr::parse(s).unwrap()).collect()
    }

    #[test]
    fn strip_spoof_when_not_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("9.9.9.9"));
        headers.insert("forwarded", HeaderValue::from_static("for=\"9.9.9.9\""));
        headers.insert("x-real-ip", HeaderValue::from_static("9.9.9.9"));
        headers.insert("proxy-connection", HeaderValue::from_static("keep-alive"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));

        let client = IpAddr::from_str("1.2.3.4").unwrap();
        sanitize_headers(&mut headers, client, &[]); // empty = strip all

        assert_eq!(headers.get("x-forwarded-for").unwrap().to_str().unwrap(), "1.2.3.4");
        assert_eq!(headers.get("forwarded").unwrap().to_str().unwrap(), "for=\"1.2.3.4\"");
        assert_eq!(headers.get("x-real-ip").unwrap().to_str().unwrap(), "1.2.3.4");
        assert!(headers.get("proxy-connection").is_none());
        assert!(headers.get("keep-alive").is_none());
        assert_eq!(headers.get("via").unwrap(), "1.1 xproxy");
    }

    #[test]
    fn keep_and_append_when_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("9.9.9.9"));
        headers.insert("forwarded", HeaderValue::from_static("for=\"9.9.9.9\""));

        let client = IpAddr::from_str("1.2.3.4").unwrap();
        let trusted = cidrs(&["1.2.3.4/32"]);
        sanitize_headers(&mut headers, client, &trusted);

        assert_eq!(headers.get("x-forwarded-for").unwrap().to_str().unwrap(), "9.9.9.9, 1.2.3.4");
        assert_eq!(
            headers.get("forwarded").unwrap().to_str().unwrap(),
            "for=\"9.9.9.9\", for=\"1.2.3.4\""
        );
        assert_eq!(headers.get("x-real-ip").unwrap().to_str().unwrap(), "1.2.3.4");
    }

    #[test]
    fn trusted_cidr_range() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("9.9.9.9"));
        let client = IpAddr::from_str("10.1.2.3").unwrap();
        let trusted = cidrs(&["10.0.0.0/8"]);
        sanitize_headers(&mut headers, client, &trusted);
        // trusted => keep existing + append
        assert_eq!(headers.get("x-forwarded-for").unwrap().to_str().unwrap(), "9.9.9.9, 10.1.2.3");

        let mut headers2 = HeaderMap::new();
        headers2.insert("x-forwarded-for", HeaderValue::from_static("9.9.9.9"));
        let untrusted = cidrs(&["192.168.0.0/16"]);
        sanitize_headers(&mut headers2, client, &untrusted);
        assert_eq!(headers2.get("x-forwarded-for").unwrap().to_str().unwrap(), "10.1.2.3");
    }

    #[test]
    fn always_strip_proxy_connection() {
        let mut headers = HeaderMap::new();
        headers.insert("proxy-connection", HeaderValue::from_static("keep-alive"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        let client = IpAddr::from_str("1.1.1.1").unwrap();
        let trusted = cidrs(&["1.1.1.1/32"]);
        sanitize_headers(&mut headers, client, &trusted);
        assert!(headers.get("proxy-connection").is_none());
        assert!(headers.get("keep-alive").is_none());
        // but x-forwarded-for still injected
        assert_eq!(headers.get("x-forwarded-for").unwrap().to_str().unwrap(), "1.1.1.1");
    }

    #[test]
    fn via_appended() {
        let mut headers = HeaderMap::new();
        let client = IpAddr::from_str("1.2.3.4").unwrap();
        sanitize_headers(&mut headers, client, &[]);
        assert_eq!(headers.get("via").unwrap(), "1.1 xproxy");
        // second call appends second Via
        sanitize_headers(&mut headers, client, &[]);
        let vias: Vec<_> = headers.get_all("via").iter().collect();
        assert_eq!(vias.len(), 2);
    }

    #[test]
    fn sanitize_request_wrapper() {
        let mut req = Request::builder()
            .uri("http://example.com/")
            .header("x-forwarded-for", "9.9.9.9")
            .body(())
            .unwrap();
        let client = IpAddr::from_str("5.6.7.8").unwrap();
        sanitize_request(&mut req, client, &[]);
        assert_eq!(req.headers().get("x-forwarded-for").unwrap().to_str().unwrap(), "5.6.7.8");
    }

    #[test]
    fn ipv6_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("2001:db8::1"));
        let client = IpAddr::from_str("2001:db8::2").unwrap();
        let trusted = cidrs(&["2001:db8::/32"]);
        sanitize_headers(&mut headers, client, &trusted);
        assert_eq!(
            headers.get("x-forwarded-for").unwrap().to_str().unwrap(),
            "2001:db8::1, 2001:db8::2"
        );
    }
}
