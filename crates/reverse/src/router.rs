//! Routing table for reverse proxy — host/path → upstream.
//! Uses `matchit` for path matching and `ArcSwap` for hot reload.

use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;

/// Single route entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Host to match, empty for any host.
    pub host: String,
    /// Path prefix, e.g. `/api/` or `/api/*` or `/`.
    pub path: String,
    /// Upstream name.
    pub upstream: String,
}

impl Route {
    pub fn new(
        host: impl Into<String>,
        path: impl Into<String>,
        upstream: impl Into<String>,
    ) -> Self {
        Self { host: host.into(), path: path.into(), upstream: upstream.into() }
    }
}

/// Table holding all routes with per-host `matchit` routers for exact matches plus prefix fallback.
#[derive(Debug, Default)]
pub struct RouteTable {
    /// Routes sorted by path length descending for prefix fallback.
    routes: Vec<Route>,
    /// Per-host matchit router for exact/wildcard matches: host -> Router<upstream>
    routers: HashMap<String, matchit::Router<String>>,
}

impl RouteTable {
    pub fn new(mut routes: Vec<Route>) -> Self {
        // Sort for deterministic prefix fallback (longest first).
        routes.sort_by_key(|r| std::cmp::Reverse(r.path.len()));

        let mut by_host: HashMap<String, Vec<Route>> = HashMap::new();
        for r in &routes {
            by_host.entry(r.host.clone()).or_default().push(r.clone());
        }

        let mut routers = HashMap::new();
        for (host, host_routes) in by_host {
            let mut router = matchit::Router::new();
            for r in host_routes {
                let pattern = to_matchit_pattern(&r.path);
                // Ignore duplicate insert errors — first wins due to sorted order.
                let _ = router.insert(pattern, r.upstream.clone());
            }
            routers.insert(host, router);
        }

        Self { routes, routers }
    }

    /// Find upstream for `host` and `path`. Host exact match preferred, fallback to "" host.
    /// Tries matchit exact/wildcard first, then prefix fallback.
    pub fn find(&self, host: &str, path: &str) -> Option<&str> {
        for h in [host, ""] {
            if let Some(router) = self.routers.get(h)
                && let Ok(m) = router.at(path)
            {
                return Some(m.value.as_str());
            }
            // Prefix fallback on original routes for this host.
            for r in &self.routes {
                let host_match = r.host.is_empty() || r.host == h;
                if !host_match {
                    continue;
                }
                if is_prefix_match(&r.path, path) {
                    return Some(&r.upstream);
                }
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

fn to_matchit_pattern(path: &str) -> String {
    if path == "/" {
        return "/".to_string();
    }
    if path.ends_with("/*") {
        let base = path.trim_end_matches("/*");
        return format!("{base}/{{*rest}}");
    }
    if path.ends_with('/') {
        // matchit router matches exact; add wildcard for prefix
        return format!("{path}{{*rest}}");
    }
    path.to_string()
}

fn is_prefix_match(pattern: &str, path: &str) -> bool {
    if pattern == "/" {
        return path.starts_with('/');
    }
    let base = pattern.trim_end_matches("/*").trim_end_matches('/');
    if base.is_empty() {
        return true;
    }
    if path == base {
        return true;
    }
    path.starts_with(&format!("{base}/"))
}

/// Shared, hot-swappable table.
#[derive(Debug, Default)]
pub struct SharedTable {
    inner: ArcSwap<RouteTable>,
}

impl SharedTable {
    pub fn new(routes: Vec<Route>) -> Self {
        Self { inner: ArcSwap::from_pointee(RouteTable::new(routes)) }
    }

    pub fn find(&self, host: &str, path: &str) -> Option<String> {
        self.inner.load().find(host, path).map(|s| s.to_string())
    }

    pub fn update(&self, routes: Vec<Route>) {
        self.inner.store(Arc::new(RouteTable::new(routes)));
    }

    pub fn len(&self) -> usize {
        self.inner.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.load().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_prefix() {
        let table = RouteTable::new(vec![
            Route::new("example.com", "/api/", "api"),
            Route::new("", "/", "static"),
        ]);
        assert_eq!(table.find("example.com", "/api/foo"), Some("api"));
        assert_eq!(table.find("example.com", "/api/"), Some("api"));
        assert_eq!(table.find("other", "/"), Some("static"));
        assert_eq!(table.find("example.com", "/other"), Some("static"));
    }

    #[test]
    fn host_specific_and_fallback() {
        let table = RouteTable::new(vec![
            Route::new("a.com", "/a", "a-up"),
            Route::new("", "/a", "fallback"),
        ]);
        assert_eq!(table.find("a.com", "/a"), Some("a-up"));
        assert_eq!(table.find("b.com", "/a"), Some("fallback"));
    }

    #[test]
    fn wildcard_pattern() {
        let table = RouteTable::new(vec![Route::new("", "/api/*", "api")]);
        assert_eq!(table.find("", "/api/foo/bar"), Some("api"));
    }

    #[test]
    fn shared_update() {
        let shared = SharedTable::new(vec![Route::new("", "/", "v1")]);
        assert_eq!(shared.find("", "/"), Some("v1".to_string()));
        shared.update(vec![Route::new("", "/", "v2")]);
        assert_eq!(shared.find("", "/"), Some("v2".to_string()));
    }
}
