//! Health checker — separate client concept, degraded after 3 consecutive failures.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

/// Per-upstream health state.
#[derive(Debug)]
pub struct UpstreamHealth {
    pub name: String,
    healthy: AtomicBool,
    consecutive_failures: AtomicUsize,
    threshold: usize,
}

impl UpstreamHealth {
    pub fn new(name: impl Into<String>, threshold: usize) -> Self {
        Self {
            name: name.into(),
            healthy: AtomicBool::new(true),
            consecutive_failures: AtomicUsize::new(0),
            threshold: threshold.max(1),
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.healthy.store(true, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.threshold {
            self.healthy.store(false, Ordering::Relaxed);
        }
    }

    pub fn failures(&self) -> usize {
        self.consecutive_failures.load(Ordering::Relaxed)
    }
}

/// Checker holding many upstreams. Client is separate concept — this struct is the state side.
/// Real probing would use `hyper-util` client with 2s timeout in a `tokio::spawn` loop; here we track state.
#[derive(Debug, Default)]
pub struct HealthChecker {
    upstreams: HashMap<String, Arc<UpstreamHealth>>,
}

impl HealthChecker {
    pub fn new(names: impl IntoIterator<Item = String>, threshold: usize) -> Self {
        let mut upstreams = HashMap::new();
        for n in names {
            upstreams.insert(n.clone(), Arc::new(UpstreamHealth::new(n, threshold)));
        }
        Self { upstreams }
    }

    pub fn get(&self, name: &str) -> Option<Arc<UpstreamHealth>> {
        self.upstreams.get(name).cloned()
    }

    pub fn is_healthy(&self, name: &str) -> bool {
        self.get(name).map(|h| h.is_healthy()).unwrap_or(false)
    }

    pub fn record_success(&self, name: &str) {
        if let Some(h) = self.get(name) {
            h.record_success();
        }
    }

    pub fn record_failure(&self, name: &str) {
        if let Some(h) = self.get(name) {
            h.record_failure();
        }
    }

    /// For determinism in tests, expose states.
    pub fn len(&self) -> usize {
        self.upstreams.len()
    }

    pub fn is_empty(&self) -> bool {
        self.upstreams.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_initial() {
        let c = HealthChecker::new(vec!["a".into()], 3);
        assert!(c.is_healthy("a"));
    }

    #[test]
    fn degraded_after_three() {
        let c = HealthChecker::new(vec!["a".into()], 3);
        c.record_failure("a");
        assert!(c.is_healthy("a"));
        c.record_failure("a");
        assert!(c.is_healthy("a"));
        c.record_failure("a");
        assert!(!c.is_healthy("a"));
        assert_eq!(c.get("a").unwrap().failures(), 3);
    }

    #[test]
    fn success_resets() {
        let c = HealthChecker::new(vec!["a".into()], 3);
        c.record_failure("a");
        c.record_failure("a");
        c.record_failure("a");
        assert!(!c.is_healthy("a"));
        c.record_success("a");
        assert!(c.is_healthy("a"));
        assert_eq!(c.get("a").unwrap().failures(), 0);
    }

    #[test]
    fn separate_client_concept() {
        // Two upstreams degrade independently
        let c = HealthChecker::new(vec!["a".into(), "b".into()], 3);
        for _ in 0..3 {
            c.record_failure("a");
        }
        assert!(!c.is_healthy("a"));
        assert!(c.is_healthy("b"));
    }
}
